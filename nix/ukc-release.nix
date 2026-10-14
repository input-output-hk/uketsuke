{ pkgs }:
let
  inherit (pkgs) lib;
  # Every release binary is cross-built from the one build host, so a
  # single `nix build` yields all assets and anyone can rebuild them.
  builds = map (arch: import ./ukc.nix { inherit pkgs arch; }) [
    "x86_64"
    "aarch64"
  ];
  asset = ukc: "ukc-${ukc.version}-${ukc.platform}";
in
pkgs.runCommand "ukc-release" { } ''
  mkdir "$out"
  cd "$out"
  ${lib.concatMapStrings (ukc: ''
    install -m 0755 ${lib.getExe ukc} ${asset ukc}
  '') builds}
  sha256sum -- * > SHA256SUMS
''
