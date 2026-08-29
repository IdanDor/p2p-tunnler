# AI-assisted makeover goals

This document records the goals for the next modernization phase. It is a
living document: new goals may be added and priorities may change.

## Agreed goals

1. Produce clean, clear, maintainable, high-quality code.
2. Preserve network compatibility with version 0.1.0. A modernized peer must
   connect and exchange tunnel traffic with an unmodified 0.1.0 desktop peer.
   This includes the existing DHT message format, key handling, address
   exchange, and UDP/WireGuard forwarding behaviour unless a compatible
   migration is explicitly designed and tested.
3. Replace the deprecated `async-std` runtime with a maintained alternative.
   Tokio is the selected runtime because the NAT-mapping dependency already
   requires it and its event-loop model avoids operating two runtimes.
4. Replace `sodiumoxide` with `crypto_box` while preserving version 0.1.0
   cryptographic construction, wire representation, and key handling.
5. Update project dependencies deliberately, with compatibility and security
   review rather than indiscriminate version bumps.
6. Maintain a high Rust engineering standard comparable to the Sysarmor
   project: idiomatic APIs, clear ownership and error handling, useful tests,
   consistent formatting and linting, and minimal unsafe or unnecessary
   complexity.
7. Improve IPv4/IPv6 candidate selection and direct-connectivity diagnostics.
8. Add secret-safe structured logging for NAT mapping and packet forwarding.
9. Make protocol-affecting changes incremental, reversible, and well tested.
10. Document the repository well and make it easy to work on safely with AI:
    maintain useful project and AI guidance, organize durable documentation in
    `docs/`, and keep instructions current as the architecture evolves.

## Version 0.2.0 status

The agreed modernization scope is implemented in focused, reviewed commits:

- Tokio replaces `async-std`; `crypto_box` replaces `sodiumoxide` with a
  byte-for-byte legacy crypto fixture.
- DHT key ordering, JSON representation, encrypted payload handling, UDP
  forwarding, IPv4-only behavior, malformed DHT/STUN input, and secret
  redaction have regression coverage.
- `--filter-ipv6` now also prevents local IPv6 publication and has the clearer
  `--ipv4-only` alias. Direct local-router mapping is available with
  `--nat-map`.
- Direct dependencies and the corresponding Cargo/Nix graphs have been
  updated, and durable architecture, operations, compatibility, development,
  and AI-workflow documentation now lives under `docs/`.

The deliberately deferred ICE-style candidate-pair protocol described in
`direct-only-nat-traversal.md` is not a safe drop-in refactor: it would change
the legacy DHT value and peer behavior. It requires an explicitly designed,
backwards-compatible migration and must not be folded into routine cleanup.
