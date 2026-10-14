defmodule Uketsuke.Intake do
  import Plug.Conn, only: [get_req_header: 2, read_body: 2]

  alias Uketsuke.{Auth, Bundle, Error, Manifest, Quota, RequestLog, S3, Store}

  # auth comes from Auth.parse!, which binds the path id to the Manifest's submission_id.
  def request!(conn, auth, %RequestLog{route: mode} = log, config, s3) do
    deadline = now() + config.upload_timeout_ms
    id = auth.manifest.fields["submission_id"]

    on_kill = fn -> RequestLog.finish(log, {:rejected, "upload_timeout"}, nil) end

    Store.with_slot!(id, deadline, on_kill, fn token, stage ->
      auth = Auth.authorize!(auth, config)
      key = object_key(config, id)

      case S3.head!(s3, key) do
        :missing when mode == :receipt ->
          Error.raise!("receipt_not_found", "submission has no durable receipt")

        :missing ->
          conn = receive_report!(conn, auth.manifest, stage, deadline)
          Store.body_complete!(token)
          receipt = Manifest.receipt(auth.manifest, DateTime.utc_now() |> DateTime.to_iso8601())
          path = Bundle.create!(stage, auth, receipt)
          {disposition, receipt} = publish!(s3, config, auth, stage, receipt, path)
          {conn, disposition, receipt}

        _existing ->
          Store.body_complete!(token)
          receipt = recover!(s3, config, auth.manifest, stage)
          {conn, :existing, receipt}
      end
    end)
  end

  def object_key(config, id), do: config.s3_prefix <> "submissions/" <> id <> ".tar"

  def publish!(s3, config, auth, stage, proposed_receipt, path) do
    receipt = Quota.reserve!(s3, config, auth.manifest, proposed_receipt)
    path = if receipt == proposed_receipt, do: path, else: Bundle.create!(stage, auth, receipt)
    key = object_key(config, auth.manifest.fields["submission_id"])

    case S3.put!(s3, key, {:file, path}, :absent) do
      :ok -> {:created, receipt}
      :precondition_failed -> {:existing, recover!(s3, config, auth.manifest, stage)}
    end
  end

  defp recover!(s3, config, manifest, stage) do
    key = object_key(config, manifest.fields["submission_id"])
    path = Path.join(stage, "recovered.tar")

    case S3.get_file!(s3, key, path) do
      :missing -> Error.raise!("storage_failed", "published bundle disappeared: #{key}")
      :ok -> :ok
    end

    entry = Bundle.load!(path)

    Error.require!(
      Manifest.immutable(manifest) == Manifest.immutable(entry.manifest),
      "submission_conflict",
      "submission id already has different immutable metadata"
    )

    receipt = Quota.fetch!(s3, config, entry.manifest)

    Error.require!(
      receipt == entry.receipt,
      "storage_failed",
      "bundle receipt disagrees with its durable quota reservation: #{key}"
    )

    receipt
  end

  defp receive_report!(conn, manifest, stage, deadline) do
    check_content_length!(conn, manifest.fields["file_size"])
    path = Path.join(stage, "report.zip")
    file = File.open!(path, [:write, :binary, :exclusive, :raw])

    try do
      File.chmod!(path, 0o600)
      receive_body(conn, file, manifest.fields, deadline, 0, :crypto.hash_init(:sha256))
    after
      case File.close(file) do
        :ok -> :ok
        {:error, reason} -> raise File.Error, reason: reason, action: "close", path: path
      end
    end
  end

  defp receive_body(conn, file, fields, deadline, size, hash) do
    remaining = deadline - now()
    Error.require!(remaining > 0, "upload_timeout", "upload read deadline exceeded")
    # Copy granularity only; acceptance is bounded by the signed file_size.
    chunk_size = min(64 * 1024, fields["file_size"] - size + 1)

    case read_body(conn, length: chunk_size, read_length: chunk_size, read_timeout: remaining) do
      {status, chunk, conn} when status in [:ok, :more] ->
        size = size + byte_size(chunk)

        Error.require!(
          size <= fields["file_size"],
          "size_mismatch",
          "body is larger than signed file_size"
        )

        Error.require!(now() < deadline, "upload_timeout", "upload read deadline exceeded")

        case :file.write(file, chunk) do
          :ok ->
            :ok

          {:error, reason} ->
            raise File.Error, reason: reason, action: "write", path: "staged report.zip"
        end

        hash = :crypto.hash_update(hash, chunk)

        if status == :more do
          receive_body(conn, file, fields, deadline, size, hash)
        else
          Error.require!(
            size == fields["file_size"],
            "size_mismatch",
            "body is shorter than signed file_size"
          )

          digest = :crypto.hash_final(hash) |> Base.encode16(case: :lower)

          Error.require!(
            digest == fields["file_hash"],
            "hash_mismatch",
            "body SHA-256 does not match signed file_hash"
          )

          conn
        end

      {:error, reason} ->
        Error.raise!("body_read_failed", "request body read failed: #{inspect(reason)}")
    end
  end

  defp check_content_length!(conn, expected) do
    case get_req_header(conn, "content-length") do
      [] ->
        :ok

      [value] ->
        case Integer.parse(value) do
          {size, ""} when size >= 0 ->
            Error.require!(
              size == expected,
              "size_mismatch",
              "Content-Length differs from signed file_size"
            )

          _ ->
            Error.raise!("invalid_content_length", "Content-Length must be a nonnegative integer")
        end

      _ ->
        Error.raise!("invalid_content_length", "duplicate Content-Length")
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end
