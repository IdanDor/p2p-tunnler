# Development and AI-assisted work

Start with [compatibility.md](compatibility.md) before changing networking,
cryptography, serialisation, configuration, or CLI behavior. The current
makeover goals are in [ai-makeover-goals.md](ai-makeover-goals.md), and the
short mandatory working rules are in the repository-root [AGENTS.md](../AGENTS.md).

## Local validation

Run these checks for a normal source change:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --bin p2p-tunnler
```

The UDP forwarding test binds loopback sockets. Run it in an environment that
allows normal local network access. The OpenDHT C++ dependency may emit its own
upstream deprecation warning; project Rust warnings and Clippy findings must
remain clean.

For a real control-plane smoke test, use a short-lived STUN command with an
explicit endpoint appropriate to the current network. Do not publish test
keys, captured payloads, or production DHT records in the repository.

## Dependency changes

Cargo dependency changes require both `Cargo.lock` and `Cargo.nix` updates:

```sh
crate2nix generate
```

The ignored `.cargo/config.toml` may locally patch OpenDHT to a sibling
checkout. Never commit `.cargo/`. Also preserve the pinned OpenDHT
`source = "git+https://github.com/IdanDor/opendht.git#..."` entry in
`Cargo.lock`; a local path patch can cause Cargo to omit it during local
builds.

## Required review

Each focused implementation change must be tested and adversarially reviewed
before it is committed. Check, at minimum:

- the 0.1.0 DHT key, JSON, crypto nonce/ciphertext, and CLI compatibility;
- malformed UDP/DHT input, unchecked lengths, and panic paths;
- secret exposure in errors and logs;
- task cancellation, socket ownership, and NAT-mapping lifetimes; and
- IPv4/IPv6 selection, direct-only behavior, and error reporting.

Keep documentation current when the architecture, operation, or compatibility
contract changes. Prefer concise, tested changes over broad rewrites.
