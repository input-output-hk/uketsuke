{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.floci-nix = {
    url = "github:imxade/floci-nix/159be03d4fb1d80172084e1df7d9ff13866f1334";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs =
    {
      self,
      nixpkgs,
      floci-nix,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        uketsuke = import ./nix/package.nix { inherit pkgs; };
        uketsuke-sign = import ./nix/sign.nix {
          inherit pkgs;
          arch = pkgs.stdenv.hostPlatform.parsed.cpu.name;
        };
        uketsuke-sign-release = import ./nix/sign-release.nix { inherit pkgs; };
        floci = import ./nix/floci.nix {
          inherit pkgs;
          image = floci-nix.packages.${pkgs.stdenv.hostPlatform.system}.aws-image;
        };
        floci-dev = import ./nix/floci-dev.nix { inherit pkgs floci; };
        default = uketsuke;
      });
      nixosModules.uketsuke = import ./nix/module.nix;
      nixosModules.default = self.nixosModules.uketsuke;
      checks = forAllSystems (pkgs: {
        release = self.packages.${pkgs.stdenv.hostPlatform.system}.uketsuke;
        sign = self.packages.${pkgs.stdenv.hostPlatform.system}.uketsuke-sign;
        smoke = import ./nix/e2e-test.nix {
          inherit pkgs;
          package = self.packages.${pkgs.stdenv.hostPlatform.system}.uketsuke;
          signer = self.packages.${pkgs.stdenv.hostPlatform.system}.uketsuke-sign;
          floci = self.packages.${pkgs.stdenv.hostPlatform.system}.floci;
          module = self.nixosModules.uketsuke;
        };
      });
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            beamMinimalPackages.elixir
            nodejs_24
            zig
            zip
            curl
            self.packages.${pkgs.stdenv.hostPlatform.system}.floci-dev
            awscli2
            gnutar
          ];
          MIX_REBAR3 = pkgs.lib.getExe pkgs.beamMinimalPackages.rebar3;
          ZIG_EXECUTABLE_PATH = pkgs.lib.getExe pkgs.zig;
          BLST_DIR = "${pkgs.blst}";
        };
      });
      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
