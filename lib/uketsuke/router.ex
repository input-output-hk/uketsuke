defmodule Uketsuke.Router do
  @behaviour Plug
  import Plug.Conn
  require Logger
  alias Uketsuke.{Auth, Campaign, Error, Intake, Metrics, RequestLog, Roster}

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

  # Uptime checkers and `curl -I` probe with HEAD; Bandit sends no body for it.
  @probe_methods ["GET", "HEAD"]

  @impl true
  def init({config, s3}), do: {config, s3, Campaign.new(config)}

  @impl true
  def call(conn, {config, s3, %Campaign{file: campaign_file} = campaign}) do
    case {conn.method, conn.path_info} do
      {method, ["healthz"]} when method in @probe_methods ->
        health(conn, config)

      {method, []} when method in @probe_methods ->
        public(conn, "text/html", campaign.page)

      {method, ["campaigns", ^campaign_file]} when method in @probe_methods ->
        public(conn, "application/json", campaign.json)

      {"PUT", ["v1", "uploads", id]} ->
        request(conn, id, :upload, {config, s3})

      {"GET", ["v1", "receipts", id]} ->
        request(conn, id, :receipt, {config, s3})

      _ ->
        Metrics.unrouted()
        error(conn, 404, "not_found", "route not found")
    end
  end

  defp request(conn, id, route, {config, s3}) do
    log = RequestLog.start(route, id)

    {conn, log, result, status, body} =
      case attempt(log, fn -> Auth.parse!(conn, id, config) end) do
        {:ok, auth} -> intake(conn, auth, RequestLog.manifest(log, auth.manifest), config, s3)
        {:rejected, code, status, body} -> {conn, log, {:rejected, code}, status, body}
      end

    respond(conn, log, result, status, body)
  end

  defp intake(conn, auth, log, config, s3) do
    case attempt(log, fn -> Intake.request!(conn, auth, log, config, s3) end) do
      {:ok, {conn, :created, receipt}} -> {conn, log, :accepted, 201, receipt}
      {:ok, {conn, :existing, receipt}} -> {conn, log, :recovered, 200, receipt}
      {:rejected, code, status, body} -> {conn, log, {:rejected, code}, status, body}
    end
  end

  # The single send: the outcome is known even if the client leaves before it.
  defp respond(conn, log, result, status, body) do
    conn = json(conn, status, body)
    RequestLog.finish(log, result, status)
    conn
  rescue
    exception in Bandit.TransportError ->
      RequestLog.finish(log, result, nil)
      reraise exception, __STACKTRACE__
  end

  # No S3 call: public probes must not drive Archive cost.
  defp health(conn, config) do
    roster = Roster.read!(config, :cached)

    json(conn, 200, %{
      status: "ready",
      roster: %{
        epoch: roster.epoch,
        slot: roster.slot,
        pools: map_size(roster.pools),
        age_secs: Roster.age_secs(roster)
      }
    })
  rescue
    error in Error -> json(conn, 503, %{status: "unavailable", error: %{code: error.code}})
  end

  # The one place a request stage can fail. A rejection becomes a response for
  # respond/5; a disconnect or crash finishes the log here, since respond never runs.
  defp attempt(log, fun) do
    {:ok, fun.()}
  rescue
    exception in Error ->
      status = Map.fetch!(@statuses, exception.code)

      message =
        case Map.fetch(@private_messages, exception.code) do
          {:ok, public} ->
            Logger.error(%{
              event: "private_error",
              code: exception.code,
              message: Exception.message(exception)
            })

            public

          :error ->
            exception.message
        end

      code =
        if exception.code == "invalid_signature_encoding",
          do: "invalid_signature",
          else: exception.code

      rejected(code, status, message)

    exception in File.Error ->
      Logger.error(%{
        event: "private_error",
        code: "storage_failed",
        message: "inbox staging failed: " <> Exception.message(exception)
      })

      rejected("storage_failed", 500, "artifact storage failed")

    exception in Bandit.HTTPError ->
      status = Plug.Conn.Status.code(exception.plug_status)
      rejected("body_read_failed", status, "request body could not be read")

    # The client is gone, so there is no one to answer; Bandit closes quietly.
    exception in Bandit.TransportError ->
      RequestLog.finish(log, {:rejected, "client_disconnected"}, nil)
      reraise exception, __STACKTRACE__
  catch
    # A server fault: count and log it, then let Bandit answer 500 and log the crash.
    kind, reason ->
      RequestLog.finish(log, {:rejected, "internal_error"}, nil)
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  # Built from config at init: no S3 call and no roster read.
  defp public(conn, type, body) do
    conn
    |> put_resp_content_type(type)
    |> put_resp_header("cache-control", "no-cache")
    |> send_resp(200, body)
  end

  defp rejected(code, status, message),
    do: {:rejected, code, status, %{error: %{code: code, message: message}}}

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
