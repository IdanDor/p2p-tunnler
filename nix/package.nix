# SPDX-License-Identifier: LGPL-2.1-or-later
# Adapted from IdanDor/p2p-tunnler-nix; see LICENSE.p2p-tunnler-nix.
{
  pkgs,
  runTests ? false,
}:
let
  opendht = pkgs.callPackage ./opendht.nix { };
  buildRustCrateForPkgs =
    rustPkgs:
    rustPkgs.buildRustCrate.override {
      defaultCrateOverrides = rustPkgs.defaultCrateOverrides // {
        opendht = _: {
          nativeBuildInputs = [ rustPkgs.pkg-config ];
          buildInputs = with rustPkgs; [
            opendht
            gnutls
            msgpack-cxx
            fmt.dev
          ];
          PKG_CONFIG_PATH = "${opendht}/lib/pkgconfig";
        };
        p2p-tunnler = _: {
          # Exclude flake, documentation and development files from the binary.
          src = rustPkgs.lib.fileset.toSource {
            root = ../.;
            fileset = rustPkgs.lib.fileset.unions [
              ../Cargo.toml
              ../Cargo.lock
              ../src
            ];
          };
          buildInputs = with rustPkgs; [
            fmt.dev
            openssl.dev
            nettle
            boost
            libargon2
            jsoncpp
            http-parser
          ];
        };
      };
    };
  crate = pkgs.callPackage ../Cargo.nix { inherit buildRustCrateForPkgs; };
in
(crate.rootCrate.build.override { inherit runTests; }).overrideAttrs (old: {
  meta = (old.meta or { }) // {
    description = "Direct peer-to-peer UDP transport for WireGuard using OpenDHT";
    mainProgram = "p2p-tunnler";
    license = pkgs.lib.licenses.lgpl21Plus;
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
})
