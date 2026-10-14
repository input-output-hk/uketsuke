defmodule Uketsuke.Roster do
  alias Uketsuke.{Error, Manifest}

  @enforce_keys [:epoch, :slot, :pools, :mtime]
  defstruct @enforce_keys

  # A Key Roster snapshot whose file mtime is within roster_max_age_secs.
  # :parse decodes the file every time; authorization uses it. :cached reuses
  # the last decode while the opened file's device, inode, mtime and size are
  # unchanged, so public /healthz probes and scrapes cost a stat, not a parse.
  def read!(config, mode) do
    roster = load!(config.roster_path, mode)

    Error.require!(
      fresh?(roster, config),
      "roster_unavailable",
      "roster is stale or has a future mtime"
    )

    roster
  end

  def fresh?(%__MODULE__{} = roster, config) do
    age = age_secs(roster)
    age >= 0 and age <= config.roster_max_age_secs
  end

  # Negative for a future mtime, which fresh?/2 rejects.
  def age_secs(%__MODULE__{mtime: mtime}), do: System.system_time(:second) - mtime

  # A valid snapshot regardless of age; metrics report a stale roster's mtime.
  def load!(path, mode) when mode in [:parse, :cached] do
    case File.open(path, [:read, :binary]) do
      {:ok, file} ->
        try do
          # Stat the opened snapshot, not a path that a roster rename can replace.
          with {:ok, record} <- :file.read_file_info(file, time: :posix),
               stat = File.Stat.from_record(record),
               true <- stat.type == :regular do
            identity = {stat.major_device, stat.inode, stat.mtime, stat.size}

            case {mode, :persistent_term.get({__MODULE__, path}, nil)} do
              {:cached, {^identity, roster}} ->
                roster

              _ ->
                roster = decode!(contents!(file), stat.mtime)

                if mode == :cached,
                  do: :persistent_term.put({__MODULE__, path}, {identity, roster})

                roster
            end
          else
            _ -> Error.raise!("roster_unavailable", "roster is unreadable or not a regular file")
          end
        after
          case File.close(file) do
            :ok ->
              :ok

            {:error, reason} ->
              Error.raise!("roster_unavailable", "cannot close roster: #{inspect(reason)}")
          end
        end

      {:error, _reason} ->
        Error.raise!("roster_unavailable", "roster could not be opened")
    end
  end

  defp contents!(file) do
    case IO.binread(file, :eof) do
      bytes when is_binary(bytes) -> bytes
      _ -> Error.raise!("roster_unavailable", "roster is unreadable")
    end
  end

  defp decode!(bytes, mtime) do
    roster =
      case Jason.decode(bytes) do
        {:ok, value} -> value
        {:error, _reason} -> Error.raise!("roster_unavailable", "invalid UTF-8 JSON")
      end

    valid =
      is_map(roster) and Enum.sort(Map.keys(roster)) == ~w(epoch pools slot) and
        is_integer(roster["epoch"]) and roster["epoch"] >= 0 and
        is_integer(roster["slot"]) and roster["slot"] >= 0 and is_map(roster["pools"]) and
        Enum.all?(roster["pools"], fn {pool, keys} ->
          Manifest.hex?(pool, 56) and is_list(keys) and Enum.all?(keys, &Manifest.hex?(&1, 192))
        end)

    Error.require!(valid, "roster_unavailable", "roster has an invalid schema")

    %__MODULE__{
      epoch: roster["epoch"],
      slot: roster["slot"],
      pools: roster["pools"],
      mtime: mtime
    }
  end
end
