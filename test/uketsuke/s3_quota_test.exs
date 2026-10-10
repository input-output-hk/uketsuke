defmodule Uketsuke.S3QuotaTest do
  use ExUnit.Case, async: false
  alias Uketsuke.{Error, Manifest, Quota, S3}

  @moduletag :s3

  setup_all do
    {:ok, _} = Application.ensure_all_started(:finch)
    {:ok, _} = Application.ensure_all_started(:aws_signature)
    config = config()
    start_supervised!(S3.child_spec(config))
    :ok
  end

  setup do
    config = config()
    %{config: config, s3: S3.new(config)}
  end

  test "signed path-style requests preserve encoded keys and streamed bytes", %{
    s3: s3,
    config: config
  } do
    key = config.s3_prefix <> "spaces + percent % slash/日本語.bin"
    dir = Path.join(System.tmp_dir!(), "uketsuke-s3-" <> random_id())
    File.mkdir!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    source = Path.join(dir, "source")
    target = Path.join(dir, "target")
    bytes = :binary.copy(<<0, 1, 127, 128, 255>>, 60_000)
    File.write!(source, bytes)

    assert S3.head!(s3, key) == :missing
    assert S3.get!(s3, key) == :missing
    assert S3.get_file!(s3, key, target) == :missing
    refute File.exists?(target)
    assert S3.put!(s3, key, {:file, source}, :absent) == :ok
    assert %{etag: etag, size: size, metadata: %{}} = S3.head!(s3, key)
    assert size == byte_size(bytes)
    assert S3.get!(s3, key) == %{etag: etag, body: bytes}
    assert_storage_error(fn -> S3.get!(%{s3 | small_object_bytes: 10}, key) end)
    assert S3.get_file!(s3, key, target) == :ok
    assert File.read!(target) == bytes
    assert_storage_error(fn -> S3.get_file!(s3, key, target) end)
    assert File.read!(target) == bytes
  end

  test "conditional PUT never overwrites and stale ETags never win", %{s3: s3, config: config} do
    key = config.s3_prefix <> "conditional"

    results =
      Enum.map(1..8, fn n ->
        Task.async(fn -> S3.put!(s3, key, Integer.to_string(n), :absent) end)
      end)
      |> Enum.map(&Task.await(&1, 30_000))

    assert Enum.count(results, &(&1 == :ok)) == 1
    assert Enum.count(results, &(&1 == :precondition_failed)) == 7
    %{etag: old_etag, body: original} = S3.get!(s3, key)
    assert original in Enum.map(1..8, &Integer.to_string/1)
    assert S3.put!(s3, key, "changed", {:match, old_etag}) == :ok
    assert S3.put!(s3, key, "lost update", {:match, old_etag}) == :precondition_failed
    assert %{body: "changed"} = S3.get!(s3, key)
  end

  test "concurrent reservations cannot exceed signed ZIP-byte quota", %{s3: s3, config: config} do
    config = %{config | max_total_bytes: 8}

    tasks =
      Enum.map(1..4, fn _ ->
        Task.async(fn ->
          manifest = manifest(random_id(), 4)

          try do
            {:reserved, Quota.reserve!(s3, config, manifest, receipt(manifest))}
          rescue
            error in Error -> {:error, error.code}
          end
        end)
      end)

    results = Enum.map(tasks, &Task.await(&1, 30_000))
    assert Enum.count(results, &match?({:reserved, _}, &1)) == 2
    assert Enum.count(results, &(&1 == {:error, "storage_quota"})) == 2
    %{body: bytes} = S3.get!(s3, config.s3_prefix <> "quota.json")
    ledger = Jason.decode!(bytes)
    assert map_size(ledger["reservations"]) == 2

    assert Enum.reduce(ledger["reservations"], 0, fn {_id, entry}, total ->
             total + entry["immutable"]["file_size"]
           end) == 8
  end

  test "failed publication retains charge and same ID recovers original receipt", %{
    s3: s3,
    config: config
  } do
    config = %{config | max_total_bytes: 4}
    manifest = manifest(random_id(), 4)
    original = receipt(manifest)
    assert Quota.reserve!(s3, config, manifest, original) == original
    bundle_key = config.s3_prefix <> "submissions/" <> manifest.fields["submission_id"] <> ".tar"
    denied = %{s3 | secret_key: "incorrect-signing-secret"}
    assert_storage_error(fn -> S3.put!(denied, bundle_key, "bundle bytes", :absent) end)
    assert S3.head!(s3, bundle_key) == :missing

    restarted = S3.new(config)
    renewed = %{manifest | fields: Map.update!(manifest.fields, "expires_at", &(&1 + 60))}
    later = Manifest.receipt(renewed, "2026-10-09T12:00:00Z")
    assert Quota.reserve!(restarted, config, renewed, later) == original
    other = manifest(random_id(), 1)
    error = assert_raise Error, fn -> Quota.reserve!(restarted, config, other, receipt(other)) end
    assert error.code == "storage_quota"
    changed = %{manifest | fields: Map.put(manifest.fields, "filename", "different.zip")}

    error =
      assert_raise Error, fn -> Quota.reserve!(restarted, config, changed, receipt(changed)) end

    assert error.code == "submission_conflict"
    assert S3.put!(restarted, bundle_key, "bundle bytes", :absent) == :ok
    assert Quota.reserve!(restarted, config, renewed, later) == original
  end

  test "corrupt and duplicate-key quota ledgers fail without repair", %{s3: s3, config: config} do
    malformed = [
      "not JSON",
      ~s({"version":1,"version":1,"reservations":{}}),
      ~s({"version":1,"reservations":{"duplicate":{},"duplicate":{}}}),
      ~s({"version":2,"reservations":{}}),
      ~s({"version":1,"reservations":[]}),
      ~s({"version":1,"reservations":{"invalid":{}}})
    ]

    Enum.each(malformed, fn bytes ->
      config = %{config | s3_prefix: config.s3_prefix <> random_id() <> "/"}
      key = config.s3_prefix <> "quota.json"
      assert S3.put!(s3, key, bytes, :absent) == :ok
      manifest = manifest(random_id(), 1)

      error =
        assert_raise Error, fn -> Quota.reserve!(s3, config, manifest, receipt(manifest)) end

      assert error.code == "storage_failed"
      assert String.starts_with?(error.message, "corrupt quota ledger:")
      assert %{body: ^bytes} = S3.get!(s3, key)
    end)
  end

  test "recovery lookup never grants a reservation", %{s3: s3, config: config} do
    manifest = manifest(random_id(), 4)
    key = config.s3_prefix <> "quota.json"
    error = assert_raise Error, fn -> Quota.fetch!(s3, config, manifest) end
    assert error.message =~ "ledger is missing"
    assert S3.get!(s3, key) == :missing

    other = manifest(random_id(), 1)
    assert Quota.reserve!(s3, config, other, receipt(other)) == receipt(other)
    %{body: before} = S3.get!(s3, key)
    error = assert_raise Error, fn -> Quota.fetch!(s3, config, manifest) end
    assert error.code == "storage_failed"
    assert error.message =~ "no reservation"
    assert %{body: ^before} = S3.get!(s3, key)

    original = receipt(manifest)
    assert Quota.reserve!(s3, config, manifest, original) == original
    assert Quota.fetch!(s3, config, manifest) == original
    changed = %{manifest | fields: Map.put(manifest.fields, "filename", "different.zip")}
    error = assert_raise Error, fn -> Quota.fetch!(s3, config, changed) end
    assert error.code == "storage_failed"
  end

  test "lost real S3 PUT response retains reservation and recovers without double charge", %{
    s3: s3,
    config: config
  } do
    config = %{config | max_total_bytes: 4}
    manifest = manifest(random_id(), 4)
    original = receipt(manifest)
    assert Quota.reserve!(s3, config, manifest, original) == original
    key = config.s3_prefix <> "submissions/" <> manifest.fields["submission_id"] <> ".tar"
    {endpoint, proxy} = dropping_proxy(config.s3_endpoint)

    assert_storage_error(fn ->
      S3.put!(%{s3 | endpoint: endpoint}, key, "real bundle bytes", :absent)
    end)

    assert Task.await(proxy, 15_000) =~ ~r|^HTTP/1\.1 200 |
    assert %{body: "real bundle bytes"} = S3.get!(s3, key)
    later = Manifest.receipt(manifest, "2026-10-09T12:00:00Z")
    assert Quota.reserve!(S3.new(config), config, manifest, later) == original
    assert S3.put!(s3, key, "replacement", :absent) == :precondition_failed
    other = manifest(random_id(), 1)
    error = assert_raise Error, fn -> Quota.reserve!(s3, config, other, receipt(other)) end
    assert error.code == "storage_quota"
  end

  test "operation deadline bounds a withheld real S3 response", %{s3: s3, config: config} do
    manifest = manifest(random_id(), 4)
    original = receipt(manifest)
    assert Quota.reserve!(s3, config, manifest, original) == original
    key = config.s3_prefix <> "deadline"
    {endpoint, proxy} = dropping_proxy(config.s3_endpoint, :withhold)
    started = System.monotonic_time(:millisecond)

    error =
      assert_raise Error, fn ->
        S3.put!(%{s3 | endpoint: endpoint, timeout: 500}, key, "actual bytes", :absent)
      end

    assert error.code == "storage_failed"
    assert System.monotonic_time(:millisecond) - started < 5000
    send(proxy.pid, :release_response)
    assert Task.await(proxy, 15_000) =~ ~r|^HTTP/1\.1 200 |
    assert %{body: "actual bytes"} = S3.get!(s3, key)
    assert Quota.reserve!(S3.new(config), config, manifest, receipt(manifest)) == original
  end

  # Finch bounds only the response phase and Mint sets no send timeout, so a
  # peer that stops reading the body is bounded solely by the operation deadline.
  test "operation deadline bounds a stalled streamed request body", %{s3: s3, config: config} do
    path = Path.join(System.tmp_dir!(), "uketsuke-stalled-body-" <> random_id())
    File.write!(path, :binary.copy(<<0>>, 16 * 1024 * 1024))
    on_exit(fn -> File.rm!(path) end)
    key = config.s3_prefix <> "stalled-body"
    {endpoint, peer} = stalled_peer()
    started = System.monotonic_time(:millisecond)

    assert_storage_error(fn ->
      S3.put!(%{s3 | endpoint: endpoint, timeout: 500}, key, {:file, path}, :absent)
    end)

    assert System.monotonic_time(:millisecond) - started < 5000
    send(peer.pid, :release_peer)
    Task.await(peer, 15_000)
    assert S3.head!(s3, key) == :missing
  end

  defp stalled_peer do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true,
        recbuf: 4096
      ])

    {:ok, {_ip, port}} = :inet.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, client} = :gen_tcp.accept(listener, 10_000)
        :gen_tcp.close(listener)

        receive do
          :release_peer -> :gen_tcp.close(client)
        after
          10_000 -> flunk("stalled peer was not released")
        end
      end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(peer.pid), do: Process.exit(peer.pid, :kill)
    end)

    {"http://127.0.0.1:#{port}", peer}
  end

  defp dropping_proxy(endpoint, fault \\ :drop) do
    uri = URI.parse(endpoint)
    assert uri.scheme == "http", "S3 fault-injection test requires a plain-HTTP emulator endpoint"

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    {:ok, {_ip, port}} = :inet.sockname(listener)

    proxy =
      Task.async(fn ->
        {:ok, client} = :gen_tcp.accept(listener, 10_000)
        :gen_tcp.close(listener)

        {:ok, upstream} =
          :gen_tcp.connect(
            String.to_charlist(uri.host),
            uri.port,
            [:binary, active: false],
            10_000
          )

        try do
          request = receive_request!(client, "")
          :ok = :gen_tcp.send(upstream, request)
          {:ok, response} = :gen_tcp.recv(upstream, 0, 10_000)

          if fault == :withhold do
            receive do
              :release_response -> :ok
            after
              10_000 -> flunk("fault proxy was not released")
            end
          end

          response
        after
          :gen_tcp.close(upstream)
          :gen_tcp.close(client)
        end
      end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(proxy.pid), do: Process.exit(proxy.pid, :kill)
    end)

    {"http://127.0.0.1:#{port}" <> (uri.path || ""), proxy}
  end

  defp receive_request!(socket, bytes) do
    case :binary.match(bytes, "\r\n\r\n") do
      {offset, 4} ->
        headers = binary_part(bytes, 0, offset)
        [_, length] = Regex.run(~r/(?:^|\r\n)content-length:\s*(\d+)/i, headers)

        if byte_size(bytes) >= offset + 4 + String.to_integer(length) do
          bytes
        else
          {:ok, chunk} = :gen_tcp.recv(socket, 0, 10_000)
          receive_request!(socket, bytes <> chunk)
        end

      :nomatch ->
        {:ok, chunk} = :gen_tcp.recv(socket, 0, 10_000)
        receive_request!(socket, bytes <> chunk)
    end
  end

  defp assert_storage_error(fun) do
    error = assert_raise Error, fun
    assert error.code == "storage_failed"
  end

  defp config do
    %{
      s3_endpoint: System.fetch_env!("INBOX_S3_ENDPOINT"),
      s3_bucket: System.fetch_env!("INBOX_S3_BUCKET"),
      s3_region: System.fetch_env!("INBOX_S3_REGION"),
      s3_prefix: "uketsuke-storage-tests/" <> random_id() <> "/",
      s3_timeout_ms: 10_000,
      max_total_bytes: 1_000_000,
      max_manifest_bytes: 4096,
      service: "storage-test",
      network: "preview",
      campaign: "storage-test"
    }
  end

  defp manifest(id, size) do
    fields = %{
      "protocol" => "leios-artifact-upload/v1",
      "service" => "storage-test",
      "network" => "preview",
      "campaign" => "storage-test",
      "pool_id" => String.duplicate("a", 56),
      "submission_id" => id,
      "file_hash" => String.duplicate("b", 64),
      "file_size" => size,
      "filename" => "report.zip",
      "expires_at" => 1_800_000_000
    }

    %Manifest{fields: fields, bytes: Jason.encode!(fields)}
  end

  defp receipt(manifest), do: Manifest.receipt(manifest, "2026-10-09T10:00:00Z")
  defp random_id, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
end
