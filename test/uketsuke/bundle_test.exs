defmodule Uketsuke.BundleTest do
  use ExUnit.Case, async: true
  alias Uketsuke.{Bundle, Error, Manifest}

  # Signed with @noble/curves and the public 0x2a fixture scalar from NativeTest.
  # Whitespace is part of the proof; bundles must not re-encode this JSON.
  @manifest """
  {
    "protocol": "leios-artifact-upload/v1",
    "service": "http://127.0.0.1:4100",
    "network": "test",
    "campaign": "bundle",
    "pool_id": "abababababababababababababababababababababababababababab",
    "submission_id": "12121212121212121212121212121212",
    "file_hash": "054aae1ccde4a405d73dff0d7a31f40b515df9b8f16ec55e01d1e9b833733e47",
    "file_size": 210000,
    "filename": "report.zip",
    "expires_at": 100
  }
  """
  @key "9772c16106e9c70b2073dfe17989225dd10f3adb675365fc6d833587ad4cbd3ae692ad1e20679003f676b0b089e83feb058b3e8b9fc9552e30787cb4a541a1c3bf67a02e91fc648b2c19f4bb333e14c5c73b9bfbc5ec56dadabb07ff15d45124"
  @signature "affa4ebcc3dd406cbf9cf32d6b523f29f9af005ac97552aedb8c41c3e6cd7ad7ccbb0985b41201f55a4e7dbd1a3865bb"
  @stored_at "1970-01-01T00:01:00Z"
  @names ~w(report.zip manifest.json attestation.json receipt.json)

  setup %{tmp_dir: root} do
    stage = Path.join(root, "stage")
    File.mkdir!(stage)
    report = :binary.copy("report fixture bytes\n", 10_000)
    File.write!(Path.join(stage, "report.zip"), report)
    manifest = Manifest.decode_archive!(@manifest)

    auth = %{
      manifest: manifest,
      bytes: @manifest,
      key: @key,
      signature: @signature,
      roster: %{epoch: 42, slot: 1000}
    }

    receipt = Manifest.receipt(manifest, @stored_at)
    %{stage: stage, auth: auth, receipt: receipt, report: report}
  end

  @tag :tmp_dir
  test "creates a standard tar and loads exact signed bytes with a real BLS proof", context do
    path = Bundle.create!(context.stage, context.auth, context.receipt)
    assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
    loaded = Bundle.load!(path)
    assert loaded.manifest.bytes == @manifest
    assert loaded.manifest == context.auth.manifest
    assert loaded.receipt == context.receipt
    assert loaded.key == @key
    assert loaded.signature == @signature
    assert loaded.roster == context.auth.roster
    assert {:ok, entries} = :erl_tar.extract(String.to_charlist(path), [:memory])

    assert Enum.sort(Enum.map(entries, fn {name, _} -> List.to_string(name) end)) ==
             Enum.sort(@names)

    assert entries |> Map.new() |> Map.fetch!(~c"report.zip") == context.report
    assert entries |> Map.new() |> Map.fetch!(~c"manifest.json") == @manifest

    assert entries |> Map.new() |> Map.fetch!(~c"attestation.json") |> Jason.decode!() == %{
             "public_key" => @key,
             "signature" => @signature,
             "roster_epoch" => 42,
             "roster_slot" => 1000
           }

    canonical = Map.put(context.receipt, "stored_at", "1970-01-01T00:00:50Z")
    assert Bundle.create!(context.stage, context.auth, canonical) == path
    assert Bundle.load!(path).receipt == canonical
  end

  @tag :tmp_dir
  test "load refuses traversal, unknown names, nonregular types and path prefixes", context do
    path = Bundle.create!(context.stage, context.auth, context.receipt)
    original = File.read!(path)

    for {offset, bytes} <- [
          {0, "../report.zip" <> :binary.copy(<<0>>, 87)},
          {0, "extra" <> :binary.copy(<<0>>, 95)},
          {156, "2"},
          {156, "5"},
          {345, "nested" <> :binary.copy(<<0>>, 149)}
        ] do
      corrupted = original |> replace(offset, bytes) |> rechecksum()
      File.write!(path, corrupted)
      assert_raise Error, fn -> Bundle.load!(path) end
    end
  end

  @tag :tmp_dir
  test "load refuses duplicate and missing entries, corrupt headers and truncation", context do
    path = Bundle.create!(context.stage, context.auth, context.receipt)
    original = File.read!(path)
    report_entry_size = 512 + 210_000 + rem(512 - rem(210_000, 512), 512)
    <<first::binary-size(report_entry_size), rest::binary>> = original

    for corrupted <- [
          first <> first <> rest,
          <<0::8192>>,
          replace(original, 148, "999999"),
          binary_part(original, 0, byte_size(original) - 512),
          original <> <<1::4096>>
        ] do
      File.write!(path, corrupted)
      assert_raise Error, fn -> Bundle.load!(path) end
    end

    oversized = original |> replace(124, "77777777777\0") |> rechecksum()
    File.write!(path, oversized)
    assert_raise Error, ~r/exceeds the remaining/, fn -> Bundle.load!(path) end
  end

  @tag :tmp_dir
  test "load verifies report digest even when file size and all evidence match", context do
    path = Bundle.create!(context.stage, context.auth, context.receipt)
    bytes = File.read!(path) |> replace(512, "X")
    File.write!(path, bytes)
    assert_raise Error, ~r/SHA-256/, fn -> Bundle.load!(path) end
  end

  @tag :tmp_dir
  test "load verifies receipt projection, attestation schema and exact BLS bytes", context do
    path = Bundle.create!(context.stage, context.auth, context.receipt)
    original = File.read!(path)
    assert {:ok, entries} = :erl_tar.extract(String.to_charlist(path), [:memory])
    entries = Map.new(entries)
    attestation = Jason.decode!(entries[~c"attestation.json"])

    changes = [
      {~c"receipt.json", Jason.encode!(Map.put(context.receipt, "filename", "different.zip"))},
      {~c"attestation.json",
       Jason.encode!(Map.put(attestation, "signature", String.duplicate("0", 96)))},
      {~c"attestation.json", Jason.encode!(Map.put(attestation, "roster_slot", "1000"))},
      {~c"attestation.json", Jason.encode!(Map.delete(attestation, "roster_epoch"))},
      {~c"manifest.json",
       String.replace(@manifest, "\"expires_at\": 100", "\"expires_at\": 101")},
      {~c"receipt.json",
       String.replace(entries[~c"receipt.json"], "{", "{\"stored_at\":\"duplicate\",")}
    ]

    for {name, value} <- changes do
      rewritten = rewrite_metadata(original, List.to_string(name), value)
      File.write!(path, rewritten)
      assert_raise Error, fn -> Bundle.load!(path) end
    end
  end

  @tag :tmp_dir
  test "create checks projected receipt and streamed report rather than publishing corrupt evidence",
       context do
    assert_raise Error, ~r/projection/, fn ->
      Bundle.create!(context.stage, context.auth, Map.put(context.receipt, "file_size", 1))
    end

    File.write!(Path.join(context.stage, "report.zip"), "wrong bytes")

    assert_raise Error, ~r/size/, fn ->
      Bundle.create!(context.stage, context.auth, context.receipt)
    end
  end

  defp replace(bytes, offset, replacement) do
    <<before::binary-size(offset), _::binary-size(byte_size(replacement)), rest::binary>> = bytes
    before <> replacement <> rest
  end

  defp rechecksum(<<header::binary-size(512), rest::binary>>) do
    header = replace(header, 148, "        ")

    sum =
      header
      |> :binary.bin_to_list()
      |> Enum.sum()
      |> Integer.to_string(8)
      |> String.pad_leading(6, "0")

    replace(header, 148, sum <> <<0, 32>>) <> rest
  end

  defp rewrite_metadata(<<header::binary-size(512), rest::binary>>, name, bytes) do
    entry_name = header |> binary_part(0, 100) |> String.trim(<<0>>)
    size = header |> binary_part(124, 12) |> String.trim(<<0>>) |> String.to_integer(8)
    padded = size + rem(512 - rem(size, 512), 512)
    <<body::binary-size(padded), tail::binary>> = rest

    if entry_name == name do
      header =
        replace(
          header,
          124,
          String.pad_leading(Integer.to_string(byte_size(bytes), 8), 11, "0") <> <<0>>
        )

      rechecksum(
        header <> bytes <> :binary.copy(<<0>>, rem(512 - rem(byte_size(bytes), 512), 512)) <> tail
      )
    else
      header <> body <> rewrite_metadata(tail, name, bytes)
    end
  end
end
