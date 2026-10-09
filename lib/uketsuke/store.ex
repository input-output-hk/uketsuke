defmodule Uketsuke.Store do
  use GenServer
  require Logger
  alias Uketsuke.Auth

  def start_link(config), do: GenServer.start_link(__MODULE__, config, name: __MODULE__)

  def reserve(id, manifest, mode, deadline),
    do: GenServer.call(__MODULE__, {:reserve, id, manifest, mode, deadline}, :infinity)

  def release(token), do: GenServer.call(__MODULE__, {:release, token}, :infinity)
  def body_complete(token), do: GenServer.call(__MODULE__, {:body_complete, token}, :infinity)

  def commit(token, published?),
    do: GenServer.call(__MODULE__, {:commit, token, published?}, :infinity)

  @doc "Renames the owner's sealed stage into the archive; raises `File.Error`."
  def publish!(token) do
    with {:error, exception} <- GenServer.call(__MODULE__, {:publish, token}, :infinity),
         do: raise(exception)
  end

  @impl true
  def init(config) do
    root = config["storage_dir"]
    archive = Path.join(root, "archive")
    staging = Path.join(root, "staging")
    created = Enum.flat_map([root, archive, staging], &private_dir!/1)

    # mkdir is durable only once the parent's entry is synced. A previous boot
    # may have died between its mkdir and this sync, so it runs on every boot.
    [Path.dirname(root), root | Enum.map(created, &Path.dirname/1)]
    |> Enum.uniq()
    |> Uketsuke.Native.sync_directories!()

    Enum.each(File.ls!(staging), fn name ->
      unless Regex.match?(~r/\A[0-9a-f]{32}-[0-9a-f]{32}\z/, name) do
        raise "unrecognized staging entry: #{name}; refusing to remove it"
      end

      File.rm_rf!(Path.join(staging, name))
    end)

    completed =
      Map.new(File.ls!(archive), fn id ->
        unless Auth.hex?(id, 32), do: raise("invalid archive entry: #{id}")
        path = Path.join(archive, id)
        entry = load_entry!(path, id)

        Uketsuke.Native.confirm!(path)

        {id, entry}
      end)

    used =
      Enum.reduce(completed, 0, fn {_id, entry}, sum -> sum + entry.manifest["file_size"] end)

    {:ok,
     %{
       config: config,
       archive: archive,
       staging: staging,
       completed: completed,
       used: used,
       active: %{}
     }}
  end

  @impl true
  def handle_call({:reserve, id, manifest, mode, deadline}, {pid, _tag}, state) do
    existing = Map.get(state.completed, id)
    bytes = if mode == :upload and is_nil(existing), do: manifest["file_size"], else: 0
    reserved = Enum.reduce(state.active, 0, fn {_token, item}, sum -> sum + item.bytes end)

    cond do
      Enum.any?(state.active, fn {_token, item} -> item.id == id end) ->
        {:reply, {:error, 409, "upload_in_progress", "submission id is already in flight"}, state}

      map_size(state.active) >= state.config["max_inflight"] ->
        {:reply, {:error, 429, "inflight_limit", "in-flight request limit reached"}, state}

      bytes > 0 and state.used + reserved + bytes > state.config["max_total_bytes"] ->
        {:reply, {:error, 507, "storage_quota", "archive byte quota exhausted"}, state}

      true ->
        token = make_ref()
        monitor = Process.monitor(pid)

        timer =
          Process.send_after(
            self(),
            {:deadline, token},
            max(0, deadline - System.monotonic_time(:millisecond))
          )

        random = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
        stage = Path.join(state.staging, id <> "-" <> random)
        item = %{id: id, pid: pid, monitor: monitor, timer: timer, bytes: bytes, stage: stage}
        {:reply, {:ok, token, existing, stage}, put_in(state.active[token], item)}
    end
  end

  def handle_call({:body_complete, token}, {pid, _}, state) do
    item = owned!(state, token, pid)
    cancel_timer(item)
    final = Path.join(state.archive, item.id)
    {:reply, final, put_in(state.active[token].timer, nil)}
  end

  def handle_call({:release, token}, {pid, _}, state) do
    owned!(state, token, pid)
    {:reply, :ok, drop(state, token)}
  end

  def handle_call({:commit, token, published?}, {pid, _}, state) do
    owned!(state, token, pid)
    {:reply, :ok, record_publication(state, token, published?)}
  end

  # The rename runs here rather than in the owner. Killing an owner does not
  # stop a dirty NIF it is running, so an owner-side rename could still be in
  # flight when its DOWN arrives and drop/2 removes the stage. Here, the owner's
  # DOWN can only be handled after the rename has returned.
  def handle_call({:publish, token}, {pid, _}, state) do
    item = owned!(state, token, pid)

    reply =
      try do
        Uketsuke.Native.rename!(item.stage, Path.join(state.archive, item.id))
      rescue
        exception in File.Error -> {:error, exception}
      end

    {:reply, reply, state}
  end

  @impl true
  def handle_info({:deadline, token}, state) do
    case Map.get(state.active, token) do
      %{timer: timer, pid: pid} when not is_nil(timer) ->
        # Bandit may perform several socket reads inside one read_body call.
        # Killing that owner is the absolute bound, even for a slow chunk drip.
        Process.exit(pid, :kill)

      _ ->
        :ok
    end

    {:noreply, state}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    case Enum.find(state.active, fn {_token, item} -> item.monitor == monitor end) do
      {token, _item} -> {:noreply, state |> record_publication(token, false) |> drop(token)}
      nil -> {:noreply, state}
    end
  end

  defp owned!(state, token, pid) do
    case Map.fetch!(state.active, token) do
      %{pid: ^pid} = item -> item
      _ -> raise "reservation owner mismatch"
    end
  end

  # A failed parent fsync, or an owner that died during publish, can leave a
  # complete final directory. Count it now; retries must confirm it before
  # acknowledging, and must never overwrite it.
  defp record_publication(state, token, published?) do
    item = Map.fetch!(state.active, token)
    final = Path.join(state.archive, item.id)

    if Map.has_key?(state.completed, item.id) do
      state
    else
      case File.lstat(final) do
        {:ok, _stat} ->
          entry = load_entry!(final, item.id)

          %{
            state
            | completed: Map.put(state.completed, item.id, entry),
              used: state.used + entry.manifest["file_size"]
          }
          |> put_in([:active, token, :bytes], 0)

        {:error, reason} when reason in [:enoent, :enotdir] and not published? ->
          state

        {:error, reason} ->
          raise "cannot inspect publication #{item.id}: #{inspect(reason)}"
      end
    end
  end

  defp drop(state, token) do
    {item, active} = Map.pop!(state.active, token)
    cancel_timer(item)
    Process.demonitor(item.monitor, [:flush])

    case File.rm_rf(item.stage) do
      {:ok, _paths} -> :ok
      {:error, reason, path} -> raise "cannot remove staging #{path}: #{inspect(reason)}"
    end

    %{state | active: active}
  end

  defp cancel_timer(%{timer: nil}), do: :ok
  defp cancel_timer(%{timer: timer}), do: Process.cancel_timer(timer)

  defp private_dir!(path) do
    created =
      path
      |> Stream.iterate(&Path.dirname/1)
      |> Enum.take_while(&(not File.exists?(&1)))

    File.mkdir_p!(path)

    unless File.lstat!(path).type == :directory,
      do: raise("storage path is not a real directory: #{path}")

    File.chmod!(path, 0o700)
    created
  end

  defp load_entry!(path, id) do
    unless File.lstat!(path).type == :directory,
      do: raise("archive entry is not a directory: #{path}")

    File.chmod!(path, 0o700)
    names = ~w(attestation.json manifest.json receipt.json report.zip roster.json)

    unless Enum.sort(File.ls!(path)) == names,
      do: raise("archive evidence is incomplete: #{path}")

    Enum.each(names, fn name ->
      file = Path.join(path, name)

      unless File.lstat!(file).type == :regular,
        do: raise("archive evidence is not regular: #{file}")

      File.chmod!(file, 0o600)
    end)

    manifest = Path.join(path, "manifest.json") |> File.read!() |> Jason.decode!()
    receipt = Path.join(path, "receipt.json") |> File.read!() |> Jason.decode!()
    size = File.stat!(Path.join(path, "report.zip")).size
    fields = ~w(submission_id file_hash file_size pool_id filename)

    unless is_map(manifest) and is_map(receipt) and manifest["submission_id"] == id and
             is_integer(manifest["file_size"]) and manifest["file_size"] > 0 and
             size == manifest["file_size"] and
             Map.take(manifest, fields) == Map.take(receipt, fields) and
             receipt["durability"] == "local-fsync" and is_binary(receipt["stored_at"]) do
      raise "archive metadata does not match report: #{path}"
    end

    %{manifest: manifest, receipt: receipt, path: path}
  end
end
