defmodule Uketsuke.Config do
  @strings ~w(service network campaign storage_dir roster_path)
  @positive ~w(port max_file_bytes max_total_bytes max_inflight max_manifest_bytes max_lifetime_secs upload_timeout_ms roster_max_age_secs)

  def load! do
    path = System.fetch_env!("INBOX_CONFIG") |> Path.expand()
    config = path |> File.read!() |> Jason.decode!()

    unless is_map(config) and Enum.sort(Map.keys(config)) == Enum.sort(@strings ++ @positive) do
      raise "config must contain exactly #{inspect(@strings ++ @positive)}"
    end

    Enum.each(@strings, fn key ->
      unless is_binary(config[key]) and String.trim(config[key]) != "" do
        raise "config #{key} must be a nonempty string, got #{inspect(config[key])}"
      end
    end)

    Enum.each(@positive, fn key ->
      unless is_integer(config[key]) and config[key] > 0 do
        raise "config #{key} must be a positive integer, got #{inspect(config[key])}"
      end
    end)

    if config["port"] > 65_535, do: raise("config port exceeds 65535")

    Enum.reduce(~w(storage_dir roster_path), config, fn key, acc ->
      Map.update!(acc, key, &Path.expand(&1, Path.dirname(path)))
    end)
  end
end
