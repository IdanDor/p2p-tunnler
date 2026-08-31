# Threat model

`p2p-tunnler` uses OpenDHT to exchange encrypted peer UDP addresses, then
forwards WireGuard UDP packets directly between peers. STUN and optional router
mapping help discover reachable addresses. They never relay tunnel traffic.

Read this with [compatibility.md](compatibility.md): the DHT record format and
direct UDP design must remain compatible with version 0.1.0 peers.

## What we protect

- **Private keys:** must not appear in logs, errors, or the repository.
- **Peer addresses:** encrypted in DHT records, though DHT lookup metadata and
  update timing are still visible to the DHT network.
- **WireGuard packets:** forwarded as opaque UDP data. WireGuard, not this
  program, authenticates peers and encrypts tunnel traffic.
- **Process resources:** untrusted traffic should not cause unbounded memory
  growth or turn the service into a useful reflector.

## Who and what is trusted

The local host, its configuration files, WireGuard, and the configured public
keys are trusted. Public keys must be exchanged through an authentic channel;
the DHT cannot establish that initial trust.

Internet senders, OpenDHT, STUN, DNS, and the network can be malicious or
unavailable. A configured peer, or anyone with its private key, can publish
candidate addresses for that relationship. The optional router mapping also
depends on the local gateway behaving correctly.

## Current protections

- DHT records use the configured Curve25519 key pair. Invalid ciphertext or
  JSON is ignored.
- Received records must be recent and newer than the previous accepted record
  for the current process. At most 64 advertised addresses are retained.
- A source that presents the current local probe token becomes a bounded
  peer-reflexive candidate. This lets a peer recover from a wrong STUN address.
- Internet packets reach WireGuard only when their exact source address is an
  advertised or peer-reflexive candidate.
- Probe and STUN traffic are kept out of the WireGuard path. Malformed probe
  frames are dropped.
- UDP queues and probe state are bounded. On overload, packets are dropped
  instead of retained in memory. Failed background tasks stop the service.
- Normal logs omit private keys, decrypted DHT values, and complete encrypted
  payloads.

## Important limits

- This is not an anonymity, anti-censorship, or high-availability system. A
  network attacker can block, delay, replay, or flood traffic. There is no
  relay fallback.
- DHT encryption hides candidate contents but not DHT keys, ciphertext size,
  publication timing, or service availability.
- A valid old DHT record can be replayed within its freshness window; restarting
  the service resets its remembered replay state.
- `--no-clear` retains old endpoints. An old public address might later belong
  to an unrelated host, so use that option only for temporary endpoint churn.
- A probe token is a bearer capability: anyone who learns the current token can
  add a source address to the peer-reflexive candidate set. That set is capped
  at 64 addresses and lasts for the process lifetime, but token confidentiality
  still matters.
- Candidate filtering is intentionally basic. A configured peer can cause this
  process to send UDP to private or otherwise undesirable addresses.
- Compromising a private key can expose previously captured DHT records. This
  legacy control-plane design does not provide forward secrecy.
- Probe tokens limit reflection to a small, rate-limited same-size reply; they
  are not an identity mechanism.

## When changing this code

Keep the legacy DHT key order, JSON shape, and nonce/ciphertext layout. Treat
all DHT, STUN, probe, and UDP input as untrusted; retain bounds and error
handling; do not log secrets or decrypted records; and check IPv4, IPv6,
replay, peer-reflexive admission, task-lifetime, and compromised-peer behavior.

See [deferred-audit-items.md](deferred-audit-items.md) for hardening that needs
a separate compatibility design.
