{ pkgs, arch }:
let
  inherit (pkgs) lib;
  zon = builtins.readFile ../client/build.zig.zon;
  zonField = field: builtins.head (builtins.match ''.*\.${field} = "([^"]+)".*'' zon);
  blstHash = zonField "hash";
  # Zig looks packages up by name in --system without re-hashing them, so a
  # nixpkgs blst bump must fail here rather than build under the old pin.
  deps =
    assert lib.assertMsg (lib.hasPrefix "blst-${pkgs.blst.version}-" blstHash)
      "client/build.zig.zon pins ${blstHash}, nixpkgs has blst ${pkgs.blst.version}";
    pkgs.linkFarm "ukc-zig-deps" [
      {
        name = blstHash;
        path = pkgs.blst.src;
      }
    ];
  # Zig cross-compiles from any build host; the musl target makes the binary
  # static even if libc is linked one day (blst itself is freestanding).
  # ReleaseSafe keeps runtime safety checks in a binary that handles key
  # material; the nixpkgs hook defaults are off so they cannot change it.
  buildFlags = [
    "--system"
    "${deps}"
    "-Dtarget=${arch}-linux-musl"
    "-Dcpu=baseline"
    "-Doptimize=ReleaseSafe"
    "-Dstrip=true"
  ];
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "ukc";
  version = zonField "version";
  src = lib.fileset.toSource {
    root = ../client;
    fileset = lib.fileset.unions [
      ../client/build.zig
      ../client/build.zig.zon
      ../client/src
    ];
  };
  nativeBuildInputs = [ pkgs.zig ];
  zigBuildFlags = buildFlags;
  zigCheckFlags = buildFlags;
  dontSetZigDefaultFlags = true;
  # Release assets are copied off the store onto hosts without Nix.
  allowedReferences = [ ];
  # The test binary is built for `arch`; only the matching host can run it.
  doCheck = arch == pkgs.stdenv.buildPlatform.parsed.cpu.name;
  # Zig 0.16 expects this directory to exist (see nixpkgs zig fetcher).
  postConfigure = ''
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR/tmp"
  '';
  passthru.platform = "${arch}-linux";
  meta = {
    description = "BLS signer and uploader for Uketsuke reports";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
    mainProgram = "ukc";
  };
}
