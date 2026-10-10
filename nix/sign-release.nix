{ pkgs }:
let
  inherit (pkgs) lib;
  # Every release binary is cross-built from the one build host, so a
  # single `nix build` yields all assets and anyone can rebuild them.
  signers = map (arch: import ./sign.nix { inherit pkgs arch; }) [
    "x86_64"
    "aarch64"
  ];
  asset = signer: "uketsuke-sign-${signer.version}-${signer.platform}";
in
pkgs.runCommand "uketsuke-sign-release" { } ''
  mkdir "$out"
  cd "$out"
  ${lib.concatMapStrings (signer: ''
    install -m 0755 ${lib.getExe signer} ${asset signer}
  '') signers}
  sha256sum -- * > SHA256SUMS
''
