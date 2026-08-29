# Contributor and AI guide

## Project contract

`p2p-tunnler` forwards WireGuard UDP datagrams directly between peers. OpenDHT
is used only to exchange encrypted peer addresses. The highest-priority
constraint is wire compatibility with an unmodified 0.1.0 peer; read
[`docs/compatibility.md`](docs/compatibility.md) before changing networking,
serialization, cryptography, configuration, or command-line parsing.

## Working rules

- Make one focused, reviewable change at a time.
- Keep the public configuration shape and existing command-line options
  compatible unless a migration is explicitly approved.
- Never log secret keys, decrypted DHT values, or full encrypted payloads.
- Do not add a relay or require root, capabilities, firewall changes, or a
  public server for the WireGuard data path.
- Prefer ordinary Rust error propagation over panics; keep unsafe code out of
  this crate unless it is unavoidable and documented.

## Required completion gate for each implementation step

1. Run the relevant unit and integration tests, `cargo fmt --check`, and a
   proportionate `cargo clippy`/`cargo check`.
2. Perform an adversarial review of the diff: protocol compatibility,
   malformed/untrusted input, key and secret exposure, cancellation/resource
   lifetimes, IPv4/IPv6 behavior, and error paths.
3. Record any material limitation in documentation or the commit message.
4. Commit only the focused change after the gate passes.

## Documentation

Keep durable design and compatibility documentation in `docs/`; maintain its
index when adding a document. The roadmap is
[`docs/ai-makeover-goals.md`](docs/ai-makeover-goals.md).
