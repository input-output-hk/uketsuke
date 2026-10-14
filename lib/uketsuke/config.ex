defmodule Uketsuke.Config do
  @strings ~w(service network campaign staging_dir roster_path s3_bucket s3_region s3_endpoint s3_prefix)
  @positive ~w(max_file_bytes max_total_bytes max_inflight max_manifest_bytes max_lifetime_secs upload_timeout_ms roster_max_age_secs s3_timeout_ms)
  # metrics_port 0 lets the OS choose; the bound port is printed on the UKETSUKE_READY line.
  @ports %{"port" => 1..65_535, "metrics_port" => 0..65_535}
  @keys @strings ++ @positive ++ Map.keys(@ports)
  @fields Enum.map(@keys, &String.to_atom/1)
  @enforce_keys @fields ++ [:max_encoded_manifest_bytes, :max_header_bytes]
  defstruct @enforce_keys

  def load!, do: load!(System.fetch_env!("INBOX_CONFIG"))

  def load!(path) do
    path = Path.expand(path)
    path |> File.read!() |> Jason.decode!() |> from_map!(Path.dirname(path))
  end

  def from_map!(config, base_dir) do
    unless is_map(config) and Enum.sort(Map.keys(config)) == Enum.sort(@keys) do
      raise ArgumentError, "config must contain exactly #{inspect(@keys)}"
    end

    Enum.each(@strings, fn key ->
      unless is_binary(config[key]) and String.valid?(config[key]) and
               String.trim(config[key]) != "" do
        raise ArgumentError,
              "config #{key} must be a nonempty UTF-8 string, got #{inspect(config[key])}"
      end
    end)

    Enum.each(@positive, fn key ->
      unless is_integer(config[key]) and config[key] > 0 do
        raise ArgumentError,
              "config #{key} must be a positive integer, got #{inspect(config[key])}"
      end
    end)

    Enum.each(@ports, fn {key, range} ->
      unless is_integer(config[key]) and config[key] in range do
        raise ArgumentError,
              "config #{key} must be a port in #{inspect(range)}, got #{inspect(config[key])}"
      end
    end)

    if config["metrics_port"] == config["port"],
      do: raise(ArgumentError, "config metrics_port must differ from port")

    if config["max_file_bytes"] > 8_589_934_591,
      do: raise(ArgumentError, "config max_file_bytes exceeds the USTAR entry limit (8589934591)")

    validate_endpoint!(config["s3_endpoint"])
    validate_prefix!(config["s3_prefix"])

    unless Regex.match?(~r/\A[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\z/, config["s3_bucket"]) and
             not String.contains?(config["s3_bucket"], ["..", ".-", "-."]) do
      raise ArgumentError, "config s3_bucket must be a valid S3 bucket name"
    end

    encoded = 4 * div(config["max_manifest_bytes"] + 2, 3)

    values = Map.new(@fields, fn field -> {field, Map.fetch!(config, Atom.to_string(field))} end)

    values =
      Enum.reduce([:staging_dir, :roster_path], values, fn field, acc ->
        Map.update!(acc, field, &Path.expand(&1, base_dir))
      end)

    struct!(
      __MODULE__,
      Map.merge(values, %{
        max_encoded_manifest_bytes: encoded,
        max_header_bytes:
          max(
            byte_size("x-upload-manifest: \r\n") + encoded,
            byte_size("x-upload-key: \r\n") + 192
          )
      })
    )
  end

  defp validate_endpoint!(endpoint) do
    uri = URI.parse(endpoint)

    unless uri.scheme in ["http", "https"] and is_binary(uri.host) and uri.host != "" and
             is_nil(uri.userinfo) and is_nil(uri.query) and is_nil(uri.fragment) and
             uri.path in [nil, "", "/"] and is_integer(uri.port) and uri.port in 1..65_535 do
      raise ArgumentError,
            "config s3_endpoint must be an HTTP(S) origin without credentials, path, query, or fragment"
    end
  end

  defp validate_prefix!(prefix) do
    segments = String.split(prefix, "/")

    unless String.ends_with?(prefix, "/") and not String.starts_with?(prefix, ["/", "v1/"]) and
             Enum.all?(Enum.drop(segments, -1), fn segment ->
               segment not in ["", ".", ".."] and
                 Regex.match?(~r/\A[A-Za-z0-9_-][A-Za-z0-9._-]*\z/, segment)
             end) do
      raise ArgumentError,
            "config s3_prefix must be a safe relative prefix ending in / outside v1/"
    end
  end
end
