defmodule Uketsuke.NativeTest do
  use ExUnit.Case, async: true
  alias Uketsuke.Native

  # Public test material from @noble/curves with secret key <<0x2a::256-repeated>>;
  # an independent implementation from the blst verifier under test.
  @key Base.decode16!(
         "9772c16106e9c70b2073dfe17989225dd10f3adb675365fc6d833587ad4cbd3ae692ad1e20679003f676b0b089e83feb058b3e8b9fc9552e30787cb4a541a1c3bf67a02e91fc648b2c19f4bb333e14c5c73b9bfbc5ec56dadabb07ff15d45124",
         case: :lower
       )
  @message ~s({"protocol":"leios-artifact-upload/v1"})
  @signature Base.decode16!(
               "ad8070edeceaa5d8ee8b951302d09224aac80f9067044c624796ae3ee284a266b24ac14f01c65ed86492d6f34d827357",
               case: :lower
             )
  # The same message signed under metsuke's submission domain tag.
  @metsuke_signature Base.decode16!(
                       "b9503f2b6d40c0197ca65d7bc9dd00323139a1d60ea558fa459fd7385bf1d710f8fbb39b6c007c9410ba78c57e33687f",
                       case: :lower
                     )
  @infinite_key <<0xC0, 0::size(95 * 8)>>
  @infinite_signature <<0xC0, 0::size(47 * 8)>>
  # On the curve but outside the prime-order subgroup: G2 x = 2 + 0i, G1 x = 0 (y = 2).
  # Decoding accepts both, so only the explicit group checks can classify them.
  @off_group_key <<0x80, 0::size(47 * 8), 0::size(46 * 8), 2::16>>
  @off_group_signature <<0x80, 0::size(47 * 8)>>

  test "verifies only the exact bytes under the artifact domain" do
    assert :verified = Native.verify(@key, @signature, @message)
    assert {:rejected, :verify_fail} = Native.verify(@key, @signature, "altered")
    assert {:rejected, :verify_fail} = Native.verify(@key, @metsuke_signature, @message)
  end

  test "separates unusable roster keys from rejected signatures" do
    assert {:invalid_key, :pk_is_infinity} = Native.verify(@infinite_key, @signature, @message)

    assert {:invalid_key, :pk_is_infinity} =
             Native.verify(@infinite_key, @infinite_signature, @message)

    assert {:invalid_key, :bad_encoding} =
             Native.verify(<<0::size(96 * 8)>>, @signature, @message)

    assert {:rejected, :pk_is_infinity} = Native.verify(@key, @infinite_signature, @message)
    assert {:rejected, :bad_encoding} = Native.verify(@key, <<0::size(48 * 8)>>, @message)

    assert {:invalid_key, :point_not_in_group} =
             Native.verify(@off_group_key, @signature, @message)

    assert {:rejected, :point_not_in_group} =
             Native.verify(@key, @off_group_signature, @message)
  end

  @names ~w(report.zip manifest.json attestation.json roster.json receipt.json)

  @tag :tmp_dir
  test "publishes files and never replaces an existing directory", %{tmp_dir: root} do
    stage = Path.join([root, "staging", "upload"])
    final = Path.join([root, "final", "upload"])
    File.mkdir_p!(stage)
    File.mkdir_p!(Path.dirname(final))
    Enum.each(@names, &File.write!(Path.join(stage, &1), &1))

    assert :ok = publish!(stage, final)
    refute File.exists?(stage)
    Enum.each(@names, &assert(File.read!(Path.join(final, &1)) == &1))

    File.mkdir!(stage)
    File.write!(Path.join(stage, "replacement"), "do not publish")
    assert_raise File.Error, ~r/file already exists/, fn -> publish!(stage, final) end
    assert File.exists?(Path.join(stage, "replacement"))
    refute File.exists?(Path.join(final, "replacement"))

    empty = Path.join([root, "final", "empty"])
    File.mkdir!(empty)
    assert_raise File.Error, ~r/file already exists/, fn -> publish!(stage, empty) end
    assert File.ls!(empty) == []
  end

  @tag :tmp_dir
  test "refuses to publish symlinks or nested directories", %{tmp_dir: root} do
    stage = Path.join(root, "stage")
    final = Path.join(root, "final")
    File.mkdir!(stage)
    outside = Path.join(root, "outside")
    File.write!(outside, "not staged")

    File.ln_s!(outside, Path.join(stage, "link"))

    assert_raise File.Error, ~r/too many levels of symbolic links/, fn ->
      publish!(stage, final)
    end

    File.rm!(Path.join(stage, "link"))

    File.mkdir!(Path.join(stage, "nested"))

    assert_raise File.Error, ~r/illegal operation on a directory/, fn ->
      publish!(stage, final)
    end

    stage_link = Path.join(root, "stage-link")
    File.ln_s!(stage, stage_link)

    assert_raise File.Error, ~r/not a directory/, fn ->
      publish!(stage_link, final)
    end

    File.rmdir!(Path.join(stage, "nested"))

    # O_NONBLOCK keeps open() from waiting for a writer on a dirty IO scheduler.
    {"", 0} = System.cmd("mkfifo", [Path.join(stage, "fifo")])
    error = assert_raise File.Error, fn -> publish!(stage, final) end
    assert error.reason == :eftype

    refute File.exists?(final)
  end

  @tag :tmp_dir
  test "raises when the rename lands but the new entry cannot be synced", %{tmp_dir: root} do
    stage = Path.join(root, "stage")
    real = Path.join(root, "real")
    linked = Path.join(root, "linked")
    File.mkdir!(stage)
    File.mkdir!(real)
    File.ln_s!(real, linked)
    Enum.each(@names, &File.write!(Path.join(stage, &1), &1))

    error = assert_raise File.Error, fn -> publish!(stage, Path.join(linked, "upload")) end
    assert %{reason: :enotdir, action: "sync", path: ^linked} = error
    refute File.exists?(stage)
    Enum.each(@names, &assert(File.read!(Path.join([real, "upload", &1])) == &1))
  end

  @tag :tmp_dir
  test "rejects paths the kernel would truncate or misread", %{tmp_dir: root} do
    error = assert_raise File.Error, fn -> Native.confirm!(Path.join(root, "a\0b")) end
    assert error.reason == :einval

    long = Path.join(root, String.duplicate("d", 4096))
    error = assert_raise File.Error, fn -> Native.confirm!(long) end
    assert error.reason == :enametoolong
  end

  @tag :tmp_dir
  test "confirms a regular archive and refuses malformed entries", %{tmp_dir: root} do
    archive = Path.join(root, "archive")
    File.mkdir!(archive)
    File.write!(Path.join(archive, "report.zip"), "report")

    assert :ok = Native.confirm!(archive)
    assert File.read!(Path.join(archive, "report.zip")) == "report"

    File.ln_s!(Path.join(archive, "report.zip"), Path.join(archive, "link"))

    assert_raise File.Error, ~r/too many levels of symbolic links/, fn ->
      Native.confirm!(archive)
    end

    File.rm!(Path.join(archive, "link"))

    File.mkdir!(Path.join(archive, "nested"))

    assert_raise File.Error, ~r/illegal operation on a directory/, fn ->
      Native.confirm!(archive)
    end

    File.rmdir!(Path.join(archive, "nested"))

    alias_path = Path.join(root, "alias")
    File.ln_s!(archive, alias_path)

    assert_raise File.Error, ~r/not a directory/, fn ->
      Native.confirm!(alias_path)
    end

    assert_raise File.Error, ~r/no such file or directory/, fn ->
      Native.confirm!(Path.join(root, "missing"))
    end
  end

  # The router's order; in production Store.publish!/1 performs the rename.
  defp publish!(stage, final) do
    Native.seal!(stage)
    Native.rename!(stage, final)
    Native.settle!(stage, final)
  end
end
