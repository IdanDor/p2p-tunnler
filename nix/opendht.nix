# SPDX-License-Identifier: LGPL-2.1-or-later
# Adapted from IdanDor/p2p-tunnler-nix; see LICENSE.p2p-tunnler-nix.
{ pkgs }:

pkgs.stdenv.mkDerivation {
  pname = "opendht";
  version = "3.7.8";

  src = pkgs.fetchFromGitHub {
    owner = "savoirfairelinux";
    repo = "opendht";
    rev = "c020d2e1ef730c076b172020f87195d261208489";
    hash = "sha256-LoM+5oinx2QDRMmcRx3HHvuW8maqsds2va2WwSUFPlw=";
  };

  # Tools required at build time (like compilers and build systems)
  nativeBuildInputs = [
    pkgs.cmake
    pkgs.pkg-config
    pkgs.ninja
  ];

  buildInputs = with pkgs; [
    boost
    libargon2
    asio
    fmt.dev
    msgpack-cxx
    nettle
    gnutls
  ];

  cmakeFlags = [
    "-DCMAKE_INSTALL_LIBDIR=lib"
    "-DOPENDHT_C=ON"
    "-DOPENDHT_PYTHON=OFF"
    "-DOPENDHT_PROXY_OPENSSL=OFF"
    "-DOPENDHT_HTTP=OFF"
    "-DOPENDHT_TOOLS=OFF"
    "-DBUILD_TESTING=OFF"
  ];

  cmakeBuildType = "MinSizeRel";
}
