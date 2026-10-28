defmodule Uketsuke.Config do
  @strings ~w(service network campaign staging_dir roster_path s3_bucket s3_region s3_endpoint s3_prefix)
  @positive ~w(max_file_bytes max_total_bytes max_inflight max_manifest_bytes)
  # Strings such as "30s" or "15m", held as milliseconds in the <key>_ms field.
  @durations ~w(campaign_lifetime clock_skew upload_timeout roster_max_age s3_timeout progress_interval)
  # ukc cancels a transfer after this long without a byte; see client/src/main.zig.
  @client_stall_ms 60_000
  # metrics_port 0 lets the OS choose; the bound port is printed on the UKETSUKE_READY line.
  @ports %{"port" => 1..65_535, "metrics_port" => 0..65_535}
  @plain @strings ++ @positive ++ Map.keys(@ports)
  @keys @plain ++ @durations
  @enforce_keys Enum.map(@plain, &String.to_atom/1) ++
                  Enum.map(@durations, &String.to_atom(&1 <> "_ms")) ++
                  [:max_encoded_manifest_bytes, :max_header_bytes]
  defstruct @enforce_keys

  defguardp lower_alnum(c) when c in ?a..?z or c in ?0..?9
  defguardp name_char(c) when lower_alnum(c) or c in ?A..?Z or c in [?., ?_, ?-]

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

    # Served at /campaigns/<campaign>.json.
    unless name?(config["campaign"]),
      do:
        raise(
          ArgumentError,
          "config campaign must use only A-Z a-z 0-9 . _ -, got #{inspect(config["campaign"])}"
        )

    durations =
      Map.new(@durations, fn key ->
        {String.to_atom(key <> "_ms"), duration_ms!(key, config[key])}
      end)

    validate_lifetime!(durations.campaign_lifetime_ms, durations.clock_skew_ms)

    unless durations.progress_interval_ms < @client_stall_ms do
      raise ArgumentError,
            "config progress_interval must be under ukc's #{div(@client_stall_ms, 1000)} s stall limit, got #{config["progress_interval"]}"
    end

    validate_endpoint!(config["s3_endpoint"])
    validate_prefix!(config["s3_prefix"])

    unless bucket?(config["s3_bucket"]) do
      raise ArgumentError, "config s3_bucket must be a valid S3 bucket name"
    end

    encoded = 4 * div(config["max_manifest_bytes"] + 2, 3)

    values = Map.new(@plain, fn key -> {String.to_atom(key), Map.fetch!(config, key)} end)

    values =
      Enum.reduce([:staging_dir, :roster_path], values, fn field, acc ->
        Map.update!(acc, field, &Path.expand(&1, base_dir))
      end)

    struct!(
      __MODULE__,
      values
      |> Map.merge(durations)
      |> Map.merge(%{
        max_encoded_manifest_bytes: encoded,
        max_header_bytes:
          max(
            byte_size("x-upload-manifest: \r\n") + encoded,
            byte_size("x-upload-key: \r\n") + 192
          )
      })
    )
  end

  # The furthest expiry Manifest validation accepts, in seconds from now.
  def max_lifetime_secs(%__MODULE__{} = config),
    do: div(config.campaign_lifetime_ms + config.clock_skew_ms, 1000)

  # "15m" -> 900_000. The first byte must be 1-9: rejects sign, leading zero, empty.
  defp duration_ms!(key, <<first, _::binary>> = value) when first in ?1..?9 do
    case Integer.parse(value) do
      {n, "ms"} -> n
      {n, "s"} -> n * 1_000
      {n, "m"} -> n * 60_000
      {n, "h"} -> n * 3_600_000
      _ -> invalid_duration!(key, value)
    end
  end

  defp duration_ms!(key, value), do: invalid_duration!(key, value)

  defp invalid_duration!(key, value) do
    raise ArgumentError,
          "config #{key} must be a duration like 30s, 15m or 500ms, got #{inspect(value)}"
  end

  # Pools sign campaign_lifetime on their own clock, and Manifest validation
  # refuses an expiry past this server's now + campaign_lifetime + clock_skew.
  # A pool whose clock lags by the whole skew must still have clock_skew left
  # to start its upload. expires_at counts whole seconds.
  defp validate_lifetime!(lifetime_ms, skew_ms) do
    unless rem(lifetime_ms, 1000) == 0 and rem(skew_ms, 1000) == 0 do
      raise ArgumentError, "config campaign_lifetime and clock_skew must be whole seconds"
    end

    unless lifetime_ms >= 2 * skew_ms do
      raise ArgumentError,
            "config campaign_lifetime must be at least twice clock_skew, got #{lifetime_ms} ms and #{skew_ms} ms"
    end
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
             Enum.all?(Enum.drop(segments, -1), &segment?/1) do
      raise ArgumentError,
            "config s3_prefix must be a safe relative prefix ending in / outside v1/"
    end
  end

  # Excludes "", "." and "..": a segment cannot start with a dot.
  defp segment?(<<first, _::binary>> = segment) when name_char(first) and first != ?.,
    do: name?(segment)

  defp segment?(_), do: false

  defp name?(<<c>>) when name_char(c), do: true
  defp name?(<<c, rest::binary>>) when name_char(c), do: name?(rest)
  defp name?(_), do: false

  defp bucket?(bucket) when is_binary(bucket) and byte_size(bucket) in 3..63 do
    <<first, _::binary>> = bucket

    lower_alnum(first) and lower_alnum(:binary.last(bucket)) and bucket_chars?(bucket) and
      not String.contains?(bucket, ["..", ".-", "-."])
  end

  defp bucket?(_), do: false

  defp bucket_chars?(<<c, rest::binary>>) when lower_alnum(c) or c in [?., ?-],
    do: bucket_chars?(rest)

  defp bucket_chars?(<<>>), do: true
  defp bucket_chars?(_), do: false
end
