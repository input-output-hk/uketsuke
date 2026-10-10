defmodule Uketsuke.Router do
  @behaviour Plug
  import Plug.Conn
  require Logger
  alias Uketsuke.{Error, Intake}

  @statuses %{
    "invalid_id" => 400,
    "missing_header" => 400,
    "manifest_too_large" => 413,
    "invalid_manifest" => 400,
    "invalid_key" => 400,
    "invalid_signature" => 401,
    "invalid_signature_encoding" => 400,
    "wrong_protocol" => 400,
    "wrong_service" => 403,
    "wrong_network" => 403,
    "wrong_campaign" => 403,
    "id_mismatch" => 400,
    "invalid_pool" => 400,
    "invalid_hash" => 400,
    "invalid_size" => 400,
    "file_too_large" => 413,
    "invalid_filename" => 400,
    "invalid_expiry" => 400,
    "expired_manifest" => 401,
    "expiry_too_far" => 400,
    "key_not_registered" => 403,
    "roster_unavailable" => 503,
    "verifier_unavailable" => 503,
    "upload_in_progress" => 409,
    "inflight_limit" => 429,
    "storage_quota" => 507,
    "submission_conflict" => 409,
    "receipt_not_found" => 404,
    "storage_failed" => 500,
    "upload_timeout" => 408,
    "size_mismatch" => 422,
    "hash_mismatch" => 422,
    "body_read_failed" => 400,
    "invalid_content_length" => 400
  }

  @private_messages %{
    "storage_failed" => "artifact storage failed",
    "roster_unavailable" => "key roster is unavailable",
    "verifier_unavailable" => "signature verifier is unavailable"
  }

  @impl true
  def init(config), do: config

  @impl true
  def call(conn, context) do
    case {conn.method, conn.path_info} do
      {"GET", ["health"]} -> json(conn, 200, %{status: "ready"})
      {"PUT", ["v1", "uploads", id]} -> request(conn, id, :upload, context)
      {"GET", ["v1", "receipts", id]} -> request(conn, id, :receipt, context)
      _ -> error(conn, 404, "not_found", "route not found")
    end
  rescue
    exception in Error ->
      status = Map.fetch!(@statuses, exception.code)

      message =
        case Map.fetch(@private_messages, exception.code) do
          {:ok, public} ->
            Logger.error("#{exception.code}: #{Exception.message(exception)}")
            public

          :error ->
            exception.message
        end

      code =
        if exception.code == "invalid_signature_encoding",
          do: "invalid_signature",
          else: exception.code

      error(conn, status, code, message)

    exception in File.Error ->
      Logger.error("inbox staging failed: #{Exception.message(exception)}")
      error(conn, 500, "storage_failed", "artifact storage failed")

    exception in Bandit.HTTPError ->
      error(
        conn,
        Plug.Conn.Status.code(exception.plug_status),
        "body_read_failed",
        "request body could not be read"
      )
  end

  defp request(conn, id, mode, {config, s3}) do
    {conn, disposition, receipt} = Intake.request!(conn, id, mode, config, s3)

    status =
      case disposition do
        :created -> 201
        :existing -> 200
      end

    json(conn, status, receipt)
  end

  defp error(conn, status, code, message),
    do: json(conn, status, %{error: %{code: code, message: message}})

  defp json(conn, status, value) do
    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "no-store")
    # Reject rather than draining an unauthenticated or already-published body.
    |> put_resp_header("connection", "close")
    |> send_resp(status, Jason.encode!(value))
  end
end
