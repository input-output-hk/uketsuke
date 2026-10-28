defmodule Uketsuke.DomainTest do
  use ExUnit.Case, async: true
  alias Uketsuke.{Auth, Config, Error, Manifest}

  @id String.duplicate("a", 32)
  @pool String.duplicate("b", 56)
  @hash String.duplicate("c", 64)

  defp config_map, do: "config.example.json" |> File.read!() |> Jason.decode!()
  defp config, do: from_map!(config_map())
  defp from_map!(map), do: Config.from_map!(map, "/tmp/uketsuke-domain")

  defp fields do
    %{
      "protocol" => "leios-artifact-upload/v1",
      "service" => "http://127.0.0.1:4100",
      "network" => "leios-prototype",
      "campaign" => "glue",
      "submission_id" => @id,
      "pool_id" => @pool,
      "file_hash" => @hash,
      "file_size" => 4,
      "filename" => "report.zip",
      "expires_at" => 1100
    }
  end

  defp assert_message(part, fun) do
    error = assert_raise ArgumentError, fun
    assert Exception.message(error) =~ part
  end

  defp expect_code(code, fun) do
    error = assert_raise Error, fun
    assert error.code == code
  end

  test "configuration resolves paths and derives transport bounds" do
    config = from_map!(config_map())
    assert config.staging_dir == "/tmp/uketsuke-domain/var/staging"
    assert config.roster_path == "/tmp/uketsuke-domain/roster.json"
    assert config.max_encoded_manifest_bytes == 10_924
    assert config.max_header_bytes == byte_size("x-upload-manifest: \r\n") + 10_924
    assert config.campaign_lifetime_ms == 600_000
    assert config.clock_skew_ms == 300_000
    assert config.upload_timeout_ms == 120_000
    assert config.roster_max_age_ms == 3_600_000
    assert config.s3_timeout_ms == 30_000
    assert Config.max_lifetime_secs(config) == 900
  end

  test "configuration rejects campaigns that cannot be served or signed" do
    for campaign <- ["a/b", "glue json", "über"] do
      assert_message(~s(campaign must use only), fn ->
        from_map!(Map.put(config_map(), "campaign", campaign))
      end)
    end

    assert_message("at least twice clock_skew", fn ->
      from_map!(Map.put(config_map(), "campaign_lifetime", "599s"))
    end)

    assert_message("whole seconds", fn ->
      from_map!(Map.put(config_map(), "clock_skew", "1500ms"))
    end)

    assert from_map!(Map.put(config_map(), "campaign_lifetime", "600s")).campaign_lifetime_ms ==
             600_000
  end

  test "configuration keeps progress_interval under ukc's stall limit" do
    assert from_map!(Map.put(config_map(), "progress_interval", "59s")).progress_interval_ms ==
             59_000

    assert_message("under ukc's 60 s stall limit", fn ->
      from_map!(Map.put(config_map(), "progress_interval", "1m"))
    end)
  end

  test "configuration parses durations by unit and refuses anything else" do
    for {text, ms} <- [{"250ms", 250}, {"30s", 30_000}, {"2m", 120_000}, {"1h", 3_600_000}] do
      assert from_map!(Map.put(config_map(), "s3_timeout", text)).s3_timeout_ms == ms
    end

    for bad <- ["30", "0s", "05s", "-5s", "+5s", "5 s", "5S", "5d", "1.5s", "s", "", 30_000, nil] do
      assert_message("s3_timeout must be a duration", fn ->
        from_map!(Map.put(config_map(), "s3_timeout", bad))
      end)
    end
  end

  test "configuration requires every key and rejects unsafe storage destinations" do
    assert_raise ArgumentError, fn ->
      from_map!(Map.delete(config_map(), "s3_timeout"))
    end

    assert_raise ArgumentError, fn ->
      from_map!(Map.put(config_map(), "max_inflight", 0))
    end

    for port <- [nil, -1, 65_536, "4101", config_map()["port"]] do
      assert_raise ArgumentError, fn ->
        from_map!(Map.put(config_map(), "metrics_port", port))
      end
    end

    assert from_map!(Map.put(config_map(), "metrics_port", 0)).metrics_port == 0

    for port <- [0, 65_536, "4100"] do
      assert_raise ArgumentError, fn -> from_map!(Map.put(config_map(), "port", port)) end
    end

    assert_raise ArgumentError, fn ->
      from_map!(Map.put(config_map(), "max_file_bytes", 8_589_934_592))
    end

    for prefix <- [
          "v1/",
          "/inboxes/",
          "inboxes/../",
          "inboxes/./",
          "inboxes//",
          "inboxes",
          "inboxes/%2f/",
          "inboxes/.hidden/"
        ] do
      assert_raise ArgumentError, fn ->
        from_map!(Map.put(config_map(), "s3_prefix", prefix))
      end
    end

    assert from_map!(Map.put(config_map(), "s3_prefix", "a_b/c-d.e/")).s3_prefix == "a_b/c-d.e/"

    for bucket <- [
          "ab",
          String.duplicate("a", 64),
          "-ab",
          "ab-",
          "a..b",
          "a.-b",
          "a-.b",
          "aBc",
          "a_b"
        ] do
      assert_raise ArgumentError, fn ->
        from_map!(Map.put(config_map(), "s3_bucket", bucket))
      end
    end

    for bucket <- ["abc", String.duplicate("a", 63), "a.b-c9"] do
      assert from_map!(Map.put(config_map(), "s3_bucket", bucket)).s3_bucket == bucket
    end

    for endpoint <- [
          "file:///tmp/s3",
          "http://user:secret@localhost",
          "http://localhost/bucket",
          "http://localhost?x=1"
        ] do
      assert_raise ArgumentError, fn ->
        from_map!(Map.put(config_map(), "s3_endpoint", endpoint))
      end
    end
  end

  @tag :tmp_dir
  test "load resolves paths relative to config file", %{tmp_dir: root} do
    path = Path.join(root, "config.json")
    File.write!(path, Jason.encode!(config_map()))
    assert Config.load!(path).staging_dir == Path.join(root, "var/staging")
  end

  test "manifest preserves exact signed bytes and excludes only expiry from identity" do
    bytes = " \n" <> Jason.encode!(fields()) <> "\n"
    manifest = Manifest.decode!(bytes, @id, config(), 1000)
    assert manifest.bytes == bytes
    assert manifest.fields == fields()

    renewed =
      Manifest.decode!(Jason.encode!(Map.put(fields(), "expires_at", 1200)), @id, config(), 1000)

    assert Manifest.immutable(manifest) == Manifest.immutable(renewed)

    changed =
      Manifest.decode!(
        Jason.encode!(Map.put(fields(), "filename", "other.zip")),
        @id,
        config(),
        1000
      )

    refute Manifest.immutable(manifest) == Manifest.immutable(changed)

    assert Manifest.receipt(manifest, "2026-10-09T00:00:00Z") == %{
             "submission_id" => @id,
             "pool_id" => @pool,
             "file_hash" => @hash,
             "file_size" => 4,
             "filename" => "report.zip",
             "durability" => "s3",
             "stored_at" => "2026-10-09T00:00:00Z"
           }
  end

  test "manifest rejects duplicate, missing, extra and malformed members" do
    bytes = Jason.encode!(fields())
    duplicate = String.replace_prefix(bytes, "{", "{\"filename\":\"report.zip\",")
    escaped_duplicate = String.replace_prefix(bytes, "{", "{\"file\\u006eame\":\"report.zip\",")

    for invalid <- [
          duplicate,
          escaped_duplicate,
          Jason.encode!(Map.delete(fields(), "filename")),
          Jason.encode!(Map.put(fields(), "extra", true)),
          "[]",
          "{",
          <<255>>
        ] do
      expect_code("invalid_manifest", fn -> Manifest.decode!(invalid, @id, config(), 1000) end)
    end
  end

  test "manifest validates inbox identity, size and exact expiry boundaries" do
    for {field, value, code} <- [
          {"service", "elsewhere", "wrong_service"},
          {"network", "elsewhere", "wrong_network"},
          {"campaign", "elsewhere", "wrong_campaign"},
          {"pool_id", "invalid", "invalid_pool"},
          {"file_hash", "invalid", "invalid_hash"},
          {"file_size", 0, "invalid_size"},
          {"file_size", 104_857_601, "file_too_large"},
          {"filename", " ", "invalid_filename"},
          {"expires_at", 1000, "expired_manifest"},
          {"expires_at", 1901, "expiry_too_far"},
          {"expires_at", "1100", "invalid_expiry"}
        ] do
      expect_code(code, fn ->
        Manifest.decode!(Jason.encode!(Map.put(fields(), field, value)), @id, config(), 1000)
      end)
    end

    assert Manifest.decode!(
             Jason.encode!(Map.put(fields(), "expires_at", 1900)),
             @id,
             config(),
             1000
           )

    expect_code("id_mismatch", fn ->
      Manifest.decode!(Jason.encode!(fields()), String.duplicate("d", 32), config(), 1000)
    end)

    assert Manifest.decode_archive!(Jason.encode!(Map.put(fields(), "expires_at", 0))).fields[
             "expires_at"
           ] == 0
  end

  test "auth delegates manifest parsing and rejects noncanonical base64 and repeated headers" do
    bytes = fields() |> Map.put("expires_at", System.system_time(:second) + 60) |> Jason.encode!()

    headers = [
      {"x-upload-manifest", Base.encode64(bytes)},
      {"x-upload-key", String.duplicate("a", 192)},
      {"x-upload-signature", String.duplicate("b", 96)}
    ]

    conn = %{Plug.Test.conn(:put, "/") | req_headers: headers}
    auth = Auth.parse!(conn, @id, config())
    assert %Manifest{bytes: ^bytes} = auth.manifest
    assert auth.bytes == bytes

    expect_code("missing_header", fn ->
      Auth.parse!(%{conn | req_headers: headers ++ [hd(headers)]}, @id, config())
    end)

    bad = List.keyreplace(headers, "x-upload-manifest", 0, {"x-upload-manifest", "e30"})

    expect_code("invalid_manifest", fn ->
      Auth.parse!(%{conn | req_headers: bad}, @id, config())
    end)

    expect_code("manifest_too_large", fn ->
      Auth.parse!(conn, @id, %{config() | max_encoded_manifest_bytes: 1})
    end)
  end

  @tag :tmp_dir
  test "authorization preserves the checked roster snapshot and classifies BLS failures", %{
    tmp_dir: root
  } do
    key =
      "9772c16106e9c70b2073dfe17989225dd10f3adb675365fc6d833587ad4cbd3ae692ad1e20679003f676b0b089e83feb058b3e8b9fc9552e30787cb4a541a1c3bf67a02e91fc648b2c19f4bb333e14c5c73b9bfbc5ec56dadabb07ff15d45124"

    bytes =
      ~s({"protocol":"leios-artifact-upload/v1","service":"http://127.0.0.1:4100","network":"leios-prototype","campaign":"glue","submission_id":"#{@id}","pool_id":"#{@pool}","file_hash":"#{@hash}","file_size":4,"filename":"report.zip","expires_at":1100})

    auth = %{
      manifest: Manifest.decode_archive!(bytes),
      bytes: bytes,
      key: key,
      signature:
        "813d20af2e2ff9cf6100bc1c63d134ae16194af8b718b2ccb893261047f0a505ad99c622a10e0bd778a5b52fc4124f7c"
    }

    path = Path.join(root, "roster.json")
    config = %{config() | roster_path: path}
    File.write!(path, Jason.encode!(%{"epoch" => 1, "slot" => 2, "pools" => %{@pool => [key]}}))
    assert Auth.authorize!(auth, config).roster == %{epoch: 1, slot: 2}
    File.touch!(path, System.system_time(:second) - div(config.roster_max_age_ms, 1000) - 1)
    expect_code("roster_unavailable", fn -> Auth.authorize!(auth, config) end)
    File.touch!(path, System.system_time(:second) + 60)
    expect_code("roster_unavailable", fn -> Auth.authorize!(auth, config) end)
    File.touch!(path, System.system_time(:second))

    expect_code("invalid_signature", fn ->
      Auth.authorize!(%{auth | bytes: bytes <> " "}, config)
    end)

    expect_code("key_not_registered", fn ->
      Auth.authorize!(%{auth | key: String.duplicate("a", 192)}, config)
    end)

    infinity = "c0" <> String.duplicate("00", 95)

    File.write!(
      path,
      Jason.encode!(%{"epoch" => 1, "slot" => 2, "pools" => %{@pool => [infinity]}})
    )

    expect_code("verifier_unavailable", fn -> Auth.authorize!(%{auth | key: infinity}, config) end)

    File.write!(path, "{}")
    expect_code("roster_unavailable", fn -> Auth.authorize!(auth, config) end)
  end

  test "domain errors carry code and message without transport status" do
    assert Error.require!(true, "unused", "unused") == :ok

    error =
      assert_raise Error, "failure", fn ->
        Error.require!(false, "invalid_manifest", "failure")
      end

    assert error.code == "invalid_manifest"
    refute Map.has_key?(error, :status)
  end
end
