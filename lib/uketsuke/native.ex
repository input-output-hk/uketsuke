defmodule Uketsuke.Native do
  @moduledoc """
  blst verification and Linux durability primitives that OTP lacks:
  directory fsync, `O_NOFOLLOW` opens and `renameat2(RENAME_NOREPLACE)`.
  """

  @blst System.fetch_env!("BLST_DIR")

  use Zig,
    otp_app: :uketsuke,
    zig_code_path: "native.zig",
    c: [
      include_dirs: Path.join(@blst, "include"),
      headers: [blst: Path.join(@blst, "include/blst.h")],
      link_lib: Path.join(@blst, "lib/libblst.a")
    ],
    nifs: [
      verify: [:dirty_cpu],
      fsync_directory: [:dirty_io],
      fsync_regular: [:dirty_io],
      rename_noreplace: [:dirty_io]
    ]

  # Mix tracks neither env reads nor the C inputs, and an old store path stays
  # on disk, so a flake bump would otherwise keep linking the previous libblst.a.
  @doc false
  def __mix_recompile__?, do: System.fetch_env!("BLST_DIR") != @blst

  @doc "Syncs a fully written private staging directory and every file in it."
  def seal!(staging), do: sync_contents!(staging)

  @doc "Moves a sealed staging directory to `destination` without replacing anything."
  def rename!(staging, destination),
    do: posix!(rename_noreplace(staging, destination), "rename to #{destination}", staging)

  @doc """
  Syncs both parents after `rename!/2`. Raises `File.Error` on failure:
  visibility is not durability.
  """
  def settle!(staging, destination) do
    final_sync = fsync_directory(Path.dirname(destination), false)
    stage_sync = fsync_directory(Path.dirname(staging), false)
    posix!(final_sync, "sync", Path.dirname(destination))
    posix!(stage_sync, "sync", Path.dirname(staging))
  end

  @doc "Re-syncs a published archive directory and its directory entry."
  def confirm!(destination) do
    sync_contents!(destination)
    posix!(fsync_directory(Path.dirname(destination), false), "sync", Path.dirname(destination))
  end

  @doc "Syncs directories, following symlinks, so earlier mkdirs are durable."
  def sync_directories!(paths) do
    Enum.each(paths, &posix!(fsync_directory(&1, true), "sync", &1))
  end

  # O_DIRECTORY|O_NOFOLLOW refuses a symlinked directory (ENOTDIR);
  # fsync_regular refuses symlinked or nested entries rather than syncing through them.
  defp sync_contents!(dir) do
    posix!(fsync_directory(dir, false), "sync", dir)

    Enum.each(File.ls!(dir), fn name ->
      path = Path.join(dir, name)
      posix!(fsync_regular(path), "sync", path)
    end)
  end

  defp posix!(:ok, _action, _path), do: :ok

  defp posix!({:error, reason}, action, path),
    do: raise(File.Error, reason: reason, action: action, path: path)
end
