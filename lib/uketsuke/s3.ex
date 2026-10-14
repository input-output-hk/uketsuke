defmodule Uketsuke.S3 do
  alias Uketsuke.{Error, Metrics}

  @http Uketsuke.S3.HTTP
  @chunk_bytes 64 * 1024
  @error_body_bytes 4096

  @enforce_keys [
    :endpoint,
    :bucket,
    :region,
    :timeout,
    :access_key,
    :secret_key,
    :session_token,
    :small_object_bytes
  ]
  defstruct @enforce_keys

  def child_spec(config) do
    Finch.child_spec(
      name: @http,
      pools: %{
        default: [
          protocols: [:http1],
          conn_opts: [transport_opts: [timeout: config.s3_timeout_ms, verify: :verify_peer]]
        ]
      }
    )
  end

  def new(config) do
    %__MODULE__{
      endpoint: String.trim_trailing(config.s3_endpoint, "/"),
      bucket: config.s3_bucket,
      region: config.s3_region,
      timeout: config.s3_timeout_ms,
      small_object_bytes: ledger_size_bound(config),
      access_key: credential!("AWS_ACCESS_KEY_ID"),
      secret_key: credential!("AWS_SECRET_ACCESS_KEY"),
      session_token: optional_token!()
    }
  end

  def small_object_limit(s3), do: s3.small_object_bytes

  defp ledger_size_bound(config) do
    # Every reservation charges at least one ZIP byte. Its immutable metadata and
    # projected receipt each fit the accepted manifest, plus JSON/ID/time framing.
    128 + config.max_total_bytes * (2 * config.max_manifest_bytes + 1024)
  end

  def head!(s3, key) do
    operation!(s3, "HEAD", key, fn ->
      response = request!(s3, :head, key, "", [], :discard)

      case response.status do
        404 ->
          :missing

        200 ->
          %{
            etag: header!(response, "etag"),
            size: content_length!(response),
            metadata:
              Map.new(response.headers, fn {k, v} -> {k, v} end)
              |> Enum.filter(fn {k, _} -> String.starts_with?(k, "x-amz-meta-") end)
              |> Map.new(fn {k, v} -> {String.replace_prefix(k, "x-amz-meta-", ""), v} end)
          }

        _ ->
          unexpected!("HEAD", key, response)
      end
    end)
  end

  def get!(s3, key) do
    operation!(s3, "GET", key, fn ->
      response = request!(s3, :get, key, "", [], {:memory, s3.small_object_bytes})

      case response.status do
        404 ->
          :missing

        200 ->
          Error.require!(
            response.bytes == content_length!(response),
            "storage_failed",
            "S3 GET #{key}: downloaded length differs from Content-Length"
          )

          %{etag: header!(response, "etag"), body: response.body}

        _ ->
          unexpected!("GET", key, response)
      end
    end)
  end

  def get_file!(s3, key, path) do
    operation!(s3, "GET", key, fn ->
      file = File.open!(path, [:write, :exclusive, :binary])

      result =
        try do
          response = request!(s3, :get, key, "", [], {:file, file})

          case response.status do
            404 ->
              :missing

            200 ->
              Error.require!(
                response.bytes == content_length!(response),
                "storage_failed",
                "S3 GET #{key}: downloaded length differs from Content-Length"
              )

              :ok

            _ ->
              unexpected!("GET", key, response)
          end
        after
          case File.close(file) do
            :ok ->
              :ok

            {:error, reason} ->
              Error.raise!(
                "storage_failed",
                "cannot close S3 download #{path}: #{inspect(reason)}"
              )
          end
        end

      if result == :missing, do: File.rm!(path)
      result
    end)
  end

  def put!(s3, key, body, condition) do
    operation!(s3, "PUT", key, fn ->
      {payload, length, digest} = payload!(body)
      headers = [{"content-length", Integer.to_string(length)} | condition_headers(condition)]
      response = request!(s3, :put, key, payload, headers, :discard, digest)

      case response.status do
        200 ->
          :ok

        201 ->
          :ok

        204 ->
          :ok

        412 ->
          :precondition_failed

        # AWS may return ConditionalRequestConflict when conditional writes race.
        409 ->
          if String.contains?(response.body, "<Code>ConditionalRequestConflict</Code>"),
            do: :precondition_failed,
            else: unexpected!("PUT", key, response)

        _ ->
          unexpected!("PUT", key, response)
      end
    end)
  end

  defp credential!(name) do
    value = System.get_env(name)
    Error.require!(is_binary(value) and byte_size(value) > 0, "storage_failed", "missing #{name}")
    value
  end

  defp optional_token! do
    case System.get_env("AWS_SESSION_TOKEN") do
      nil -> nil
      "" -> Error.raise!("storage_failed", "AWS_SESSION_TOKEN is present but empty")
      token -> token
    end
  end

  defp condition_headers(:absent), do: [{"if-none-match", "*"}]

  defp condition_headers({:match, etag}) when is_binary(etag) and byte_size(etag) > 0,
    do: [{"if-match", etag}]

  defp payload!(body) when is_binary(body),
    do: {body, byte_size(body), sha256(body)}

  defp payload!({:file, path}) do
    stat = File.stat!(path)

    Error.require!(
      stat.type == :regular,
      "storage_failed",
      "S3 upload is not a regular file: #{path}"
    )

    stream = File.stream!(path, @chunk_bytes, [])

    digest =
      Enum.reduce(stream, :crypto.hash_init(:sha256), &:crypto.hash_update(&2, &1))
      |> :crypto.hash_final()
      |> Base.encode16(case: :lower)

    {{:stream, stream}, stat.size, digest}
  end

  defp sha256(body), do: :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)

  defp request!(s3, method, key, body, headers, sink, digest \\ nil) do
    url =
      s3.endpoint <>
        "/" <>
        encode_segment(s3.bucket) <>
        "/" <>
        (key |> String.split("/", trim: false) |> Enum.map_join("/", &encode_segment/1))

    headers =
      case s3.session_token do
        nil -> headers
        token -> [{"x-amz-security-token", token} | headers]
      end

    uri = URI.parse(url)

    host =
      URI.to_string(%URI{scheme: uri.scheme, host: uri.host, port: uri.port})
      |> String.replace_prefix(uri.scheme <> "://", "")

    headers = [{"host", host} | headers]
    options = [uri_encode_path: false, body_digest: digest || sha256("")]

    headers =
      :aws_signature.sign_v4(
        s3.access_key,
        s3.secret_key,
        s3.region,
        "s3",
        :calendar.universal_time(),
        method |> Atom.to_string() |> String.upcase(),
        url,
        headers,
        "",
        options
      )
      |> Enum.map(fn {k, v} -> {String.downcase(k), v} end)

    request = Finch.build(method, url, headers, body)
    initial = %{status: nil, headers: [], chunks: [], bytes: 0, error_bytes: 0}
    opts = [pool_timeout: s3.timeout, receive_timeout: s3.timeout, request_timeout: s3.timeout]

    started = System.monotonic_time()

    result =
      try do
        Finch.stream_while(request, @http, initial, &consume!(&1, &2, sink), opts)
      catch
        kind, reason ->
          Metrics.s3(method, "error", System.monotonic_time() - started)
          :erlang.raise(kind, reason, __STACKTRACE__)
      end

    case result do
      {:ok, response} ->
        Metrics.s3(method, response.status, System.monotonic_time() - started)
        Map.put(response, :body, response.chunks |> Enum.reverse() |> IO.iodata_to_binary())

      {:error, reason, _response} ->
        Metrics.s3(method, "error", System.monotonic_time() - started)

        Error.raise!(
          "storage_failed",
          "S3 #{method} #{key}: #{inspect(reason)}; write outcome may be uncertain"
        )
    end
  end

  defp encode_segment(segment), do: URI.encode(segment, &URI.char_unreserved?/1)

  defp consume!({:status, status}, acc, _sink), do: {:cont, %{acc | status: status}}

  defp consume!({:headers, headers}, %{status: 200} = acc, {:memory, limit}) do
    acc = %{acc | headers: acc.headers ++ headers}

    Error.require!(
      content_length!(acc) <= limit,
      "storage_failed",
      "S3 small object declared length exceeds #{limit} bytes"
    )

    {:cont, acc}
  end

  defp consume!({:headers, headers}, acc, _sink),
    do: {:cont, %{acc | headers: acc.headers ++ headers}}

  defp consume!({:trailers, _headers}, acc, _sink), do: {:cont, acc}

  defp consume!({:data, data}, %{status: 200} = acc, {:file, file}) do
    :ok = IO.binwrite(file, data)
    {:cont, %{acc | bytes: acc.bytes + byte_size(data)}}
  end

  defp consume!({:data, data}, %{status: 200} = acc, {:memory, limit}) do
    bytes = acc.bytes + byte_size(data)
    Error.require!(bytes <= limit, "storage_failed", "S3 small object exceeds #{limit} bytes")
    {:cont, %{acc | bytes: bytes, chunks: [data | acc.chunks]}}
  end

  defp consume!({:data, data}, acc, _sink) do
    remaining = max(0, @error_body_bytes - acc.error_bytes)
    chunk = binary_part(data, 0, min(byte_size(data), remaining))

    {:cont,
     %{acc | chunks: [chunk | acc.chunks], error_bytes: acc.error_bytes + byte_size(chunk)}}
  end

  defp header!(response, name) do
    case Enum.filter(response.headers, fn {key, _} -> key == name end) do
      [{_, value}] when byte_size(value) > 0 ->
        value

      values ->
        Error.raise!("storage_failed", "S3 response has invalid #{name}: #{inspect(values)}")
    end
  end

  defp content_length!(response) do
    value = header!(response, "content-length")

    case Integer.parse(value) do
      {length, ""} when length >= 0 ->
        length

      _ ->
        Error.raise!(
          "storage_failed",
          "S3 response has invalid Content-Length: #{inspect(value)}"
        )
    end
  end

  defp unexpected!(method, key, response) do
    Error.raise!(
      "storage_failed",
      "S3 #{method} #{key}: HTTP #{response.status}: #{response.body}"
    )
  end

  defp operation!(s3, method, key, fun) do
    op = Map.fetch!(%{"HEAD" => :head, "GET" => :get, "PUT" => :put}, method)
    started = System.monotonic_time()
    # Link cancellation to the caller; killing an intake also closes its HTTP/file work.
    task =
      Task.async(fn ->
        try do
          {:ok, fun.()}
        rescue
          error -> {:error, error, __STACKTRACE__}
        catch
          kind, reason -> {:failure, kind, reason}
        end
      end)

    case Task.yield(task, s3.timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, result}} ->
        result

      {:ok, {:error, %Error{} = error, stack}} ->
        reraise(error, stack)

      {:ok, {:error, error, _stack}} ->
        Error.raise!(
          "storage_failed",
          "S3 #{method} #{key}: #{Exception.message(error)}; write outcome may be uncertain"
        )

      {:ok, {:failure, kind, reason}} ->
        Error.raise!(
          "storage_failed",
          "S3 #{method} #{key}: #{kind} #{inspect(reason)}; write outcome may be uncertain"
        )

      result ->
        # nil: the deadline killed the worker, usually before it recorded its
        # request. A kill after recording counts that request twice; accepted.
        status = if result == nil, do: "timeout", else: "error"
        Metrics.s3(op, status, System.monotonic_time() - started)

        Error.raise!(
          "storage_failed",
          "S3 #{method} #{key}: operation deadline or worker failure #{inspect(result)}; write outcome may be uncertain"
        )
    end
  end
end
