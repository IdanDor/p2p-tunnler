# Version 0.1.0 compatibility contract

The modernized program must interoperate with an unmodified version 0.1.0
peer. This document describes the behavior that is relied on by that peer and
must not change without a compatible migration.

## Connection model

- The WireGuard data path is direct UDP between peers. OpenDHT and STUN are
  control-plane services; neither relays WireGuard traffic.
- Each configured peer listens on the configured loopback UDP `local_port`.
  Datagrams received from that local WireGuard endpoint are forwarded to every
  currently known remote peer address. Datagrams received from a remote peer
  are forwarded back to the most recently observed local WireGuard endpoint.
- The remote peer needs only a normal `SocketAddr` candidate list. New local
  candidate-gathering features must continue publishing usable addresses in
  that existing form.

## Identity and encrypted DHT exchange

- Identity keys are standard Base64 encodings of exactly 32 bytes. They are
  Curve25519/X25519 public and secret key material used by the legacy
  `crypto_box` construction.
- The DHT key is the concatenation of the two public-key byte strings, ordered
  as the publisher's public key followed by its peer's public key. The other
  peer derives the same byte sequence from the opposite local/remote roles.
- The encrypted plaintext is JSON encoded from this logical structure:

  ```text
  Message {
      timestamp: SystemTime,
      ip_addr_list: Vec<SocketAddr>,
  }
  ```

  The JSON field names, timestamp serialization, and socket-address
  serialization are part of the compatibility surface.
- The encrypted DHT value begins with the 24-byte nonce, followed by the
  legacy precomputed `crypto_box` ciphertext. A replacement crypto crate must
  produce and consume this exact byte representation for legacy peers.

## User-facing compatibility

- Continue accepting existing YAML connection files, including `file:` key
  references.
- Keep existing command names and flags working. New behavior must be opt-in
  unless it is a bug fix that preserves the observed 0.1.0 protocol behavior.
- An IPv4-only peer must not be forced to send to IPv6 candidates. The current
  `--filter-ipv6` behavior remains supported while candidate handling is
  improved.

## Verification expectation

Every protocol, runtime, cryptography, serialization, or socket-management
change requires an interoperability test or fixture that proves a modern peer
can decrypt, publish to, and connect with the legacy representation. Until a
dedicated legacy binary fixture exists, preserve this document's formats
byte-for-byte and add focused regression tests for them.
