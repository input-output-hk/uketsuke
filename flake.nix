{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      # Native durability code uses renameat2, so only Linux is supported.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            beamMinimalPackages.elixir
            nodejs_24
            zig
            zip
          ];
          MIX_REBAR3 = pkgs.lib.getExe pkgs.beamMinimalPackages.rebar3;
          # Zigler must use this Zig, not one fetched by `mix zig.get`.
          ZIG_EXECUTABLE_PATH = pkgs.lib.getExe pkgs.zig;
          # Uketsuke.Native statically links blst from here.
          BLST_DIR = "${pkgs.blst}";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
