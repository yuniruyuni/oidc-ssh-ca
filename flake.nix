{
  description = "Issue short-lived, claim-bound SSH certificates from GitHub Actions OIDC";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        oidc-ssh-ca = pkgs.callPackage ./nix/package.nix { };
        default = oidc-ssh-ca;
      });

      nixosModules.default = import ./nix/module.nix;

      overlays.default = final: _prev: {
        oidc-ssh-ca = final.callPackage ./nix/package.nix { };
      };
    };
}
