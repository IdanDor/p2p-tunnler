{
  description = "Direct peer-to-peer UDP transport for WireGuard using OpenDHT";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forSystems = nixpkgs.lib.genAttrs systems;
      packageFor = system: nixpkgs.legacyPackages.${system}.callPackage ./nix/package.nix { };
    in
    {
      packages = forSystems (system: {
        p2p-tunnler = packageFor system;
        default = self.packages.${system}.p2p-tunnler;
      });
      apps = forSystems (system: {
        p2p-tunnler = {
          type = "app";
          meta.description = "Direct peer-to-peer UDP transport for WireGuard";
          program = "${self.packages.${system}.p2p-tunnler}/bin/p2p-tunnler";
        };
        default = self.apps.${system}.p2p-tunnler;
      });
      checks = forSystems (system: {
        package = self.packages.${system}.p2p-tunnler;
        tests = nixpkgs.legacyPackages.${system}.callPackage ./nix/package.nix { runTests = true; };
      });
      devShells = forSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.p2p-tunnler ];
            packages = with pkgs; [
              cargo
              rustc
              rustfmt
              clippy
              crate2nix
              pkg-config
            ];
            buildInputs = with pkgs; [
              (callPackage ./nix/opendht.nix { })
              gnutls
              msgpack-cxx
              fmt.dev
            ];
          };
        }
      );
      formatter = forSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
