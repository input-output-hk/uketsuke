defmodule Uketsuke.Router do
  @behaviour Plug
  import Plug.Conn
  require Logger
  alias Uketsuke.{Auth, Store}

  @impl true
  def init(config), do: config

  @impl true
  def call(conn, config) do
    case {conn.method, conn.path_info} do
      {"GET", ["health"]} -> json(conn, 200, %{status: "ready"})
      {"PUT", ["v1", "uploads", id]} -> request(conn, id, :upload, config)
      {"GET", ["v1", "receipts", id]} -> request(conn, id, :receipt, config)
      _ -> error(conn, 404, "not_found", "route not found")
    end
  rescue
    exception in File.Error ->
      Logger.error("inbox storage failed: #{Exception.message(exception)}")
      error(conn, 500, "storage_failed", "artifact storage failed")

    exception in Bandit.HTTPError ->
      error(
        conn,
        Plug.Conn.Status.code(exception.plug_status),
        "body_read_failed",
        "request body could not be read"
      )
  catch
    {:http_error, status, code, message} -> error(conn, status, code, message)
  end

  defp request(conn, id, mode, config) do
    deadline = System.monotonic_time(:millisecond) + config["upload_timeout_ms"]
    auth = Auth.parse!(conn, id, config)

    case Store.reserve(id, auth.manifest, mode, deadline) do
      {:ok, token, existing, stage} ->
        try do
          auth = Auth.authorize!(auth, config)

          cond do
            not is_nil(existing) ->
              existing_receipt(conn, auth, existing)

            mode == :receipt ->
              Auth.fail!(404, "receipt_not_found", "submission has no durable receipt")

            true ->
              upload(conn, auth, token, stage, deadline)
          end
        after
          Store.release(token)
        end

      {:error, status, code, message} ->
        Auth.fail!(status, code, message)
    end
  end

  defp existing_receipt(conn, auth, existing) do
    Auth.require!(
      Auth.immutable(auth.manifest) == Auth.immutable(existing.manifest),
      409,
      "submission_conflict",
      "submission id already has different immutable metadata"
    )

    try do
      Uketsuke.Native.confirm!(existing.path)
    rescue
      exception in File.Error ->
        Logger.error("receipt confirmation failed: #{Exception.message(exception)}")
        Auth.fail!(500, "storage_failed", "artifact durability could not be confirmed")
    end

    json(conn, 200, existing.receipt)
  end

  defp upload(conn, auth, token, stage, deadline) do
    manifest = auth.manifest
    check_content_length!(conn, manifest["file_size"])
    File.mkdir!(stage)
    File.chmod!(stage, 0o700)
    path = Path.join(stage, "report.zip")
    file = File.open!(path, [:write, :binary, :exclusive, :raw])

    conn =
      try do
        File.chmod!(path, 0o600)
        receive_body(conn, file, manifest, deadline, 0, :crypto.hash_init(:sha256))
      after
        case File.close(file) do
          :ok -> :ok
          {:error, reason} -> raise File.Error, reason: reason, action: "close", path: path
        end
      end

    final = Store.body_complete(token)

    receipt =
      manifest
      |> Map.take(~w(submission_id file_hash file_size pool_id filename))
      |> Map.merge(%{
        "durability" => "local-fsync",
        "stored_at" => DateTime.utc_now() |> DateTime.to_iso8601()
      })

    evidence!(stage, "manifest.json", auth.bytes)

    evidence!(
      stage,
      "attestation.json",
      Jason.encode!(%{public_key: auth.key, signature: auth.signature})
    )

    evidence!(stage, "roster.json", auth.roster_bytes)
    evidence!(stage, "receipt.json", Jason.encode!(receipt))

    result =
      try do
        Uketsuke.Native.seal!(stage)
        Store.publish!(token)
        Uketsuke.Native.settle!(stage, final)
      rescue
        exception in File.Error ->
          Logger.error(
            "publish #{manifest["submission_id"]} failed: #{Exception.message(exception)}"
          )

          {:error, 500, "storage_failed", "artifact publication could not be confirmed"}
      end

    Store.commit(token, result == :ok)

    case result do
      :ok -> json(conn, 201, receipt)
      {:error, status, code, message} -> Auth.fail!(status, code, message)
    end
  end

  defp receive_body(conn, file, manifest, deadline, size, hash) do
    remaining = deadline - System.monotonic_time(:millisecond)
    Auth.require!(remaining > 0, 408, "upload_timeout", "upload read deadline exceeded")
    # Copy granularity only: acceptance is bounded by the signed file_size.
    chunk_size = min(64 * 1024, manifest["file_size"] - size + 1)

    case read_body(conn, length: chunk_size, read_length: chunk_size, read_timeout: remaining) do
      {status, chunk, conn} when status in [:ok, :more] ->
        size = size + byte_size(chunk)

        Auth.require!(
          size <= manifest["file_size"],
          422,
          "size_mismatch",
          "body is larger than signed file_size"
        )

        Auth.require!(
          System.monotonic_time(:millisecond) < deadline,
          408,
          "upload_timeout",
          "upload read deadline exceeded"
        )

        case :file.write(file, chunk) do
          :ok ->
            :ok

          {:error, reason} ->
            raise File.Error, reason: reason, action: "write", path: "staged report.zip"
        end

        hash = :crypto.hash_update(hash, chunk)

        if status == :more do
          receive_body(conn, file, manifest, deadline, size, hash)
        else
          Auth.require!(
            size == manifest["file_size"],
            422,
            "size_mismatch",
            "body is shorter than signed file_size"
          )

          digest = :crypto.hash_final(hash) |> Base.encode16(case: :lower)

          Auth.require!(
            digest == manifest["file_hash"],
            422,
            "hash_mismatch",
            "body SHA-256 does not match signed file_hash"
          )

          conn
        end

      {:error, reason} ->
        Auth.fail!(400, "body_read_failed", "request body read failed: #{inspect(reason)}")
    end
  end

  defp check_content_length!(conn, expected) do
    case get_req_header(conn, "content-length") do
      [] ->
        :ok

      [value] ->
        case Integer.parse(value) do
          {size, ""} when size >= 0 ->
            Auth.require!(
              size == expected,
              422,
              "size_mismatch",
              "Content-Length differs from signed file_size"
            )

          _ ->
            Auth.fail!(
              400,
              "invalid_content_length",
              "Content-Length must be a nonnegative integer"
            )
        end

      _ ->
        Auth.fail!(400, "invalid_content_length", "duplicate Content-Length")
    end
  end

  defp evidence!(stage, name, bytes) do
    path = Path.join(stage, name)
    File.write!(path, bytes, [:exclusive])
    File.chmod!(path, 0o600)
  end

  defp error(conn, status, code, message),
    do: json(conn, status, %{error: %{code: code, message: message}})

  defp json(conn, status, value) do
    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "no-store")
    # Close rather than letting the adapter drain an unauthenticated/retried body.
    |> put_resp_header("connection", "close")
    |> send_resp(status, Jason.encode!(value))
  end
end
