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
end
