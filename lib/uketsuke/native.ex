defmodule Uketsuke.Native do
  @moduledoc "BLS verification under the artifact-upload domain."

  @blst System.fetch_env!("BLST_DIR")

  use Zig,
    otp_app: :uketsuke,
    zig_code_path: "native.zig",
    c: [
      include_dirs: Path.join(@blst, "include"),
      headers: [blst: Path.join(@blst, "include/blst.h")],
      link_lib: Path.join(@blst, "lib/libblst.a")
    ],
    nifs: [verify: [:dirty_cpu]]

  # Mix tracks neither env reads nor the C inputs, and an old store path stays
  # on disk, so a flake bump would otherwise keep linking the previous libblst.a.
  @doc false
  def __mix_recompile__?, do: System.fetch_env!("BLST_DIR") != @blst
end
