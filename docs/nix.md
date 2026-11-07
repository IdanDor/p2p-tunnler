# Nix builds

The source repository owns its Nix package, OpenDHT recipe and native-library
linker overrides. `Cargo.nix`, `Cargo.lock` and the pinned OpenDHT sources remain
the dependency authority; adding the flake does not update them. The flake locks
Nixpkgs separately and declares the `nixos-unstable` update branch.

From this repository:

```sh
nix build
nix run . -- --help
nix flake check --option allow-import-from-derivation false
nix develop
```

`packages.<system>.default` and `packages.<system>.p2p-tunnler` are the executable
package; `apps.<system>.default` runs it. Linux x86_64 and aarch64 outputs are
provided. The package check builds the binary; the tests check also builds and
runs this crate's Rust unit tests. This does not start a tunnel, contact a STUN
server, generate production keys or configure WireGuard.

All package evaluation works with import-from-derivation disabled: the committed
`Cargo.nix` is imported directly from the flake source, not from a fetched build
output. Only Cargo manifests/lock and `src/` enter the application build source,
so changing Nix documentation does not rebuild the binary.

For development and the contributor gate:

```sh
nix develop --command cargo fmt --check
nix develop --command cargo clippy --all-targets -- -D warnings
nix develop --command cargo test --bin p2p-tunnler
```

The first Cargo build may download the exact Cargo.lock dependencies; use
`--locked` for Cargo commands that resolve dependencies. The flake's crate2nix
builds fetch hash-pinned sources in Nix instead and require no local Cargo cache.
When changing Cargo dependencies, regenerate `Cargo.nix` with `crate2nix generate`
and review both lock representations. Update the Nixpkgs lock deliberately with
`nix flake update nixpkgs`.

Consumers need only one input, optionally following their own Nixpkgs:

```nix
inputs.p2p-tunnler = {
  url = "github:IdanDor/p2p-tunnler/master";
  inputs.nixpkgs.follows = "nixpkgs";
};
# In a NixOS module with inputs and pkgs in scope:
environment.systemPackages = [ inputs.p2p-tunnler.packages.${pkgs.stdenv.hostPlatform.system}.default ];
```

[wireguard-p2p-nix](https://github.com/IdanDor/wireguard-p2p-nix) forwards these
flake outputs. Both repositories support `nix build` from a checkout and use as
an input in another flake, without consumer-side Cargo/OpenDHT overrides or a
second source input. Git submodules are unnecessary for flake consumption.

The Nix recipes adapted from `p2p-tunnler-nix` retain its LGPL-2.1+ license,
included in `nix/LICENSE.p2p-tunnler-nix`. The Rust program remains LGPL-2.1+.
