defmodule Uketsuke.Store do
  use GenServer

  require Logger

  alias Uketsuke.{Error, Manifest}

  def start_link(config), do: GenServer.start_link(__MODULE__, config, name: __MODULE__)

  def with_slot!(id, deadline, fun) do
    case GenServer.call(__MODULE__, {:reserve, id, deadline}, :infinity) do
      {:ok, token, stage} ->
        try do
          create_stage!(stage)
          fun.(token, stage)
        after
          GenServer.call(__MODULE__, {:release, token}, :infinity)
        end

      {:error, code, message} ->
        Error.raise!(code, message)
    end
  end

  def body_complete!(token),
    do: GenServer.call(__MODULE__, {:body_complete, token}, :infinity)

  # Runs in the request process: a filesystem fault must become that request's
  # storage_failed response, not a crash of the Store and its supervision tree.
  defp create_stage!(stage) do
    with :ok <- File.mkdir(stage),
         :ok <- File.chmod(stage, 0o700) do
      :ok
    else
      {:error, reason} ->
        Error.raise!("storage_failed", "cannot create staging directory #{stage}: #{reason}")
    end
  end

  @impl true
  def init(config) do
    File.mkdir_p!(config.staging_dir)

    unless File.lstat!(config.staging_dir).type == :directory do
      raise "staging path is not a real directory: #{config.staging_dir}"
    end

    File.chmod!(config.staging_dir, 0o700)

    Enum.each(File.ls!(config.staging_dir), fn name ->
      unless Regex.match?(~r/\A[0-9a-f]{32}-[0-9a-f]{32}\z/, name) do
        raise "unrecognized staging entry: #{name}; refusing to remove it"
      end

      File.rm_rf!(Path.join(config.staging_dir, name))
    end)

    {:ok, %{config: config, active: %{}}}
  end

  @impl true
  def handle_call({:reserve, id, deadline}, {pid, _}, state) do
    cond do
      Enum.any?(state.active, fn {_, item} -> item.id == id end) ->
        {:reply, {:error, "upload_in_progress", "submission id is already in flight"}, state}

      map_size(state.active) >= state.config.max_inflight ->
        {:reply, {:error, "inflight_limit", "in-flight request limit reached"}, state}

      true ->
        unless Manifest.hex?(id, 32), do: raise("invalid reserved submission id: #{inspect(id)}")
        token = make_ref()
        monitor = Process.monitor(pid)
        timer = Process.send_after(self(), {:deadline, token}, max(0, deadline - now()))
        random = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
        stage = Path.join(state.config.staging_dir, id <> "-" <> random)
        # The request process creates the directory; release and DOWN remove it.
        item = %{id: id, pid: pid, monitor: monitor, timer: timer, stage: stage}
        {:reply, {:ok, token, stage}, put_in(state.active[token], item)}
    end
  end

  def handle_call({:body_complete, token}, {pid, _}, state) do
    item = owned!(state, token, pid)
    cancel_timer(item)
    {:reply, :ok, put_in(state.active[token].timer, nil)}
  end

  def handle_call({:release, token}, {pid, _}, state) do
    owned!(state, token, pid)
    {:reply, :ok, drop(state, token)}
  end

  @impl true
  def handle_info({:deadline, token}, state) do
    case Map.get(state.active, token) do
      %{timer: timer, pid: pid} when not is_nil(timer) -> Process.exit(pid, :kill)
      _ -> :ok
    end

    {:noreply, state}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    case Enum.find(state.active, fn {_, item} -> item.monitor == monitor end) do
      {token, _} -> {:noreply, drop(state, token)}
      nil -> {:noreply, state}
    end
  end

  defp owned!(state, token, pid) do
    case Map.fetch!(state.active, token) do
      %{pid: ^pid} = item -> item
      _ -> raise "reservation owner mismatch"
    end
  end

  defp drop(state, token) do
    {item, active} = Map.pop!(state.active, token)
    cancel_timer(item)
    Process.demonitor(item.monitor, [:flush])

    # The owner is gone or already answered (possibly with a durable Receipt), and
    # crashing here would restart every in-flight upload. A leaked stage cannot
    # collide (random suffix) and init clears it at the next boot.
    case File.rm_rf(item.stage) do
      {:ok, _} ->
        :ok

      {:error, reason, path} ->
        Logger.error("staging cleanup failed for #{item.stage} at #{path}: #{inspect(reason)}")
    end

    %{state | active: active}
  end

  defp cancel_timer(%{timer: nil}), do: :ok
  defp cancel_timer(%{timer: timer}), do: Process.cancel_timer(timer)
  defp now, do: System.monotonic_time(:millisecond)
end
