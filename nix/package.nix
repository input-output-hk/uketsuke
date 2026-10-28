{ pkgs }:
let
  inherit (pkgs) lib;
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../mix.exs
      ../mix.lock
      ../lib
      # Campaign reads the client version from here at compile time.
      ../client/build.zig.zon
    ];
  };
  # Hex's outer archive SHA-256 is already pinned in mix.lock. Fail on any
  # unsupported lock entry instead of fetching an unpinned dependency.
  entries = lib.filter (line: line != "" && line != "%{" && line != "}") (
    lib.splitString "\n" (builtins.readFile ../mix.lock)
  );
  archives = map (
    line:
    let
      match = builtins.match ''[[:space:]]*"([^"]+)": [{]:hex, :[^,]+, "([^"]+)".*"hexpm", "([0-9a-f]+)"[}],?'' line;
    in
    if match == null then
      throw "Unsupported mix.lock entry: ${line}"
    else
      {
        name = builtins.elemAt match 0;
        archive = pkgs.fetchurl {
          url = "https://repo.hex.pm/tarballs/${builtins.elemAt match 0}-${builtins.elemAt match 1}.tar";
          sha256 = builtins.elemAt match 2;
        };
      }
  ) entries;
  # mix.exs is the one place the server version is written.
  version = builtins.head (builtins.match ''.*version: "([^"]+)".*'' (builtins.readFile ../mix.exs));
  deps = pkgs.runCommand "uketsuke-pinned-mix-deps" { } (
    ''
      mkdir -p "$out"
    ''
    + lib.concatMapStringsSep "\n" (dep: ''
      mkdir -p "$out/${dep.name}" unpack-${dep.name}
      tar -xf ${dep.archive} -C unpack-${dep.name}
      tar -xzf unpack-${dep.name}/contents.tar.gz -C "$out/${dep.name}"
    '') archives
  );
in
pkgs.beamMinimalPackages.mixRelease {
  pname = "uketsuke";
  inherit version src;
  mixFodDeps = deps;
  env = {
    ZIG_EXECUTABLE_PATH = lib.getExe pkgs.zig;
    BLST_DIR = "${pkgs.blst}";
    ERL_FLAGS = "+S 2:2";
  };
  preBuild = ''
    export HOME="$TMPDIR"
    export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-cache"
  '';
  meta = {
    description = "Signed Leios report inbox with immutable S3 archives";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
    mainProgram = "uketsuke";
  };
}
