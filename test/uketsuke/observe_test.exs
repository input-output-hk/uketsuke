defmodule Uketsuke.ObserveTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  import Plug.Test
  import Plug.Conn, only: [put_req_header: 3]

  alias Uketsuke.{Campaign, Config, JSONLog, Metrics, MetricsRouter, RequestLog, Router, Store}

  @pool String.duplicate("b", 56)

  @moduletag :tmp_dir
  setup %{tmp_dir: root} do
    config =
      "config.example.json"
      |> File.read!()
      |> Jason.decode!()
      |> Config.from_map!(root)

    File.write!(config.roster_path, Jason.encode!(%{epoch: 7, slot: 9, pools: %{@pool => []}}))
    start_supervised!(Metrics)
    start_supervised!({Store, config})
    %{config: config}
  end

  defp call(method, path, config), do: call(conn(method, path), config)
  defp call(conn, config), do: Router.call(conn, Router.init({config, nil}))

  defp scrape(config) do
    conn = MetricsRouter.call(conn(:get, "/metrics"), config)
    assert conn.status == 200
    conn.resp_body
  end

  test "healthz reports the roster without touching S3", %{config: config} do
    conn = call(:get, "/healthz", config)
    assert conn.status == 200

    assert %{"status" => "ready", "roster" => %{"epoch" => 7, "slot" => 9, "pools" => 1}} =
             Jason.decode!(conn.resp_body)

    stale = System.system_time(:second) - div(config.roster_max_age_ms, 1000) - 1
    File.touch!(config.roster_path, stale)
    conn = call(:get, "/healthz", config)
    assert conn.status == 503

    assert Jason.decode!(conn.resp_body) == %{
             "status" => "unavailable",
             "error" => %{"code" => "roster_unavailable"}
           }

    File.rm!(config.roster_path)
    assert call(:get, "/healthz", config).status == 503
    assert call(:get, "/health", config).status == 404
  end

  test "serves the Campaign JSON and the page announcing it, from config", %{config: config} do
    conn = call(:get, "/campaigns/glue.json", config)
    assert conn.status == 200
    assert Plug.Conn.get_resp_header(conn, "cache-control") == ["no-cache"]

    assert Jason.decode!(conn.resp_body) == %{
             "service" => config.service,
             "network" => config.network,
             "campaign" => "glue",
             "lifetime_secs" => div(config.campaign_lifetime_ms, 1000)
           }

    page = call(:get, "/", config)
    assert page.status == 200
    assert [type] = Plug.Conn.get_resp_header(page, "content-type")
    assert type =~ "text/html"
    sha = :crypto.hash(:sha256, conn.resp_body) |> Base.encode16(case: :lower)
    assert page.resp_body =~ "SHA-256 <code>#{sha}</code>"
    assert page.resp_body =~ "--campaign #{config.service}/campaigns/glue.json"
    assert page.resp_body =~ "ukc-#{client_version()}-x86_64-linux"

    capture_log(fn ->
      assert call(:get, "/campaigns/other.json", config).status == 404
      assert call(:put, "/", config).status == 404
    end)
  end

  test "HEAD probes the public routes", %{config: config} do
    for path <- ["/", "/campaigns/glue.json", "/healthz"] do
      assert call(:head, path, config).status == 200
    end
  end

  test "the page escapes configured strings", %{config: config} do
    page = call(:get, "/", %{config | network: "<b>net</b>"}).resp_body
    assert page =~ "&lt;b&gt;net&lt;/b&gt;"
    refute page =~ "<b>net"
  end

  test "the page names the client version and the release that carries it", %{config: config} do
    page = call(:get, "/", config).resp_body
    assert page =~ "ukc-#{client_version()}-x86_64-linux"
    assert page =~ "ukc #{client_version()}</a>"
    assert page =~ "/releases/download/v#{Mix.Project.config()[:version]}"
  end

  # The client version is ukc's own and moves apart from the server's; the
  # release tag in the download URL is the server's.
  defp client_version, do: Campaign.client_version()

  defp request_messages(fun),
    do: fun |> JSONLog.capture() |> JSONLog.requests() |> Enum.map(& &1["message"])

  test "each finished request logs one JSON report and counts once", %{config: config} do
    assert [message] =
             request_messages(fn ->
               assert call(:put, "/v1/uploads/NOT-HEX", config).status == 400
             end)

    assert %{
             "event" => "request",
             "route" => "upload",
             "outcome" => "rejected",
             "code" => "invalid_id",
             "status" => 400,
             "duration_ms" => duration
           } = message

    assert is_integer(duration)
    refute Map.has_key?(message, "submission_id")

    id = String.duplicate("a", 32)

    assert [%{"route" => "receipt", "code" => "missing_header", "submission_id" => ^id}] =
             request_messages(fn ->
               assert call(:get, "/v1/receipts/#{id}", config).status == 400
             end)

    capture_log(fn -> assert call(:get, "/elsewhere", config).status == 404 end)

    body = scrape(config)

    assert body =~
             ~s(uketsuke_requests_total{route="upload",outcome="rejected",code="invalid_id"} 1\n)

    assert body =~
             ~s(uketsuke_requests_total{route="receipt",outcome="rejected",code="missing_header"} 1\n)

    assert body =~
             ~s(uketsuke_requests_total{route="other",outcome="rejected",code="not_found"} 1\n)

    assert body =~ ~s(uketsuke_request_duration_seconds_bucket{route="upload",le="+Inf"} 1\n)
    assert body =~ ~s(uketsuke_request_duration_seconds_count{route="upload"} 1\n)
    refute body =~ ~s(uketsuke_request_duration_seconds_count{route="other"})
  end

  test "a server fault still finishes the request log, then crashes the request", %{
    config: config
  } do
    fields = %{
      protocol: "leios-artifact-upload/v1",
      service: config.service,
      network: config.network,
      campaign: config.campaign,
      submission_id: String.duplicate("a", 32),
      pool_id: @pool,
      file_hash: String.duplicate("c", 64),
      file_size: 4,
      filename: "report.zip",
      expires_at: System.system_time(:second) + 60
    }

    conn =
      conn(:put, "/v1/uploads/#{fields.submission_id}")
      |> put_req_header("x-upload-manifest", fields |> Jason.encode!() |> Base.encode64())
      |> put_req_header("x-upload-key", String.duplicate("a", 192))
      |> put_req_header("x-upload-signature", String.duplicate("b", 96))

    # Without a Store, admission exits: a fault no rescue clause names.
    stop_supervised!(Store)

    assert [message] =
             request_messages(fn ->
               assert {:noproc, _} = catch_exit(call(conn, config))
             end)

    assert %{"outcome" => "rejected", "code" => "internal_error", "pool_id" => @pool} = message
    refute Map.has_key?(message, "status")
  end

  test "healthz reuses the parsed roster until the file changes", %{config: config} do
    path = config.roster_path
    epoch = fn -> Jason.decode!(call(:get, "/healthz", config).resp_body)["roster"]["epoch"] end
    assert epoch.() == 7
    %{mtime: mtime} = File.stat!(path, time: :posix)

    # An in-place rewrite keeping inode, size and mtime is indistinguishable by
    # stat: the cached parse answers. Authorization always parses.
    File.write!(path, Jason.encode!(%{epoch: 8, slot: 9, pools: %{@pool => []}}))
    File.touch!(path, mtime)
    assert epoch.() == 7

    File.write!(path, Jason.encode!(%{epoch: 10, slot: 9, pools: %{@pool => []}}) <> " ")
    File.touch!(path, mtime)
    assert epoch.() == 10
  end

  test "a deadline kill logs upload_timeout without a status" do
    id = String.duplicate("a", 32)

    assert [message] =
             request_messages(fn ->
               RequestLog.finish(
                 RequestLog.start(:upload, id),
                 {:rejected, "upload_timeout"},
                 nil
               )
             end)

    assert %{"route" => "upload", "code" => "upload_timeout", "submission_id" => ^id} = message
    refute Map.has_key?(message, "status")
  end

  test "reserved quota only rises: a late, older ledger reading cannot lower it" do
    Metrics.quota_reserved(100)
    Metrics.quota_reserved(40)
    Metrics.quota_reserved(150)
    Metrics.quota_reserved(120)
    assert :ets.lookup(Metrics, :quota_reserved) == [{:quota_reserved, 150}]
  end

  test "metrics expose bounded series and scrape-time gauges", %{config: config} do
    body = scrape(config)
    assert body =~ "uketsuke_accepted_bytes_total 0\n"
    assert body =~ "uketsuke_inflight 0\n"
    assert body =~ "uketsuke_inflight_max #{config.max_inflight}\n"
    assert body =~ "uketsuke_quota_max_bytes #{config.max_total_bytes}\n"
    assert body =~ "uketsuke_roster_ok 1\n"
    assert body =~ "uketsuke_roster_epoch 7\n"
    assert body =~ "uketsuke_roster_pools 1\n"
    assert [_, after_name] = String.split(body, "\nuketsuke_roster_mtime_seconds ", parts: 2)
    assert {mtime, "\n" <> _} = Integer.parse(after_name)
    assert mtime > 0
    # Absent until a ledger read: 0 would claim an empty ledger.
    refute body =~ "uketsuke_quota_reserved_bytes"

    Metrics.quota_reserved(1234)
    Metrics.s3(:put, 412, System.convert_time_unit(2, :second, :native))
    Metrics.accepted_bytes(10)
    body = scrape(config)
    assert body =~ "uketsuke_quota_reserved_bytes 1234\n"
    assert body =~ "uketsuke_accepted_bytes_total 10\n"
    assert body =~ ~s(uketsuke_s3_requests_total{op="put",status="412"} 1\n)
    assert body =~ ~s(uketsuke_s3_request_duration_seconds_bucket{op="put",le="1"} 0\n)
    assert body =~ ~s(uketsuke_s3_request_duration_seconds_bucket{op="put",le="2.5"} 1\n)
    assert body =~ ~s(uketsuke_s3_request_duration_seconds_sum{op="put"} 2.0\n)

    File.write!(config.roster_path, "{}")
    test = self()
    lines = JSONLog.capture(fn -> send(test, {:body, scrape(config)}) end)
    assert_received {:body, body}

    assert [%{"severity" => "error", "message" => %{"event" => "roster_unavailable"} = message}] =
             lines

    assert message["message"] =~ "invalid schema"
    assert body =~ "uketsuke_roster_ok 0\n"
    refute body =~ "uketsuke_roster_epoch"

    assert MetricsRouter.call(conn(:get, "/v1/uploads"), config).status == 404
  end
end
