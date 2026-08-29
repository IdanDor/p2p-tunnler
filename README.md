# p2p-tunnler

`p2p-tunnler` forwards WireGuard UDP packets directly between two peers whose
addresses are exchanged through OpenDHT. STUN is used to discover a public
IPv4 address. Neither OpenDHT nor STUN relays WireGuard traffic.

Version 0.1.0 was the last version written fully by humans. Starting with
version 0.2.0, AI has been used to write and modify this code.

## What it does

```text
WireGuard on loopback -> p2p-tunnler -> direct UDP -> peer p2p-tunnler -> WireGuard
                              |                 |
                              +-- OpenDHT/STUN --+
                                  control plane only
```

Each configured peer has a loopback UDP port. Packets arriving from WireGuard
are sent to the remote addresses currently published by the other peer;
packets received from a remote peer are forwarded back to the last observed
local WireGuard endpoint.

The encrypted DHT address exchange is compatible with 0.1.0 and uses the
pure-Rust `crypto_box` Curve25519/XSalsa20-Poly1305 construction. This program
does **not** encrypt, authenticate, or configure WireGuard traffic itself;
WireGuard must provide those properties.

## Quick start

Build with a current Rust toolchain:

```sh
cargo build --release
```

Generate an identity pair and keep the secret key private:

```sh
target/release/p2p-tunnler generate ./peer.key
```

Create a YAML connection file, for example `tunnels.yaml`:

```yaml
secret_key: "file:/absolute/path/to/peer.key"
peers:
  - name: desktop
    local_port: 10001
    public_key: "file:/absolute/path/to/desktop.key.pub"
```

Start the service and configure WireGuard to send UDP to `127.0.0.1:10001`.
The remote side uses its own YAML file with the key roles and loopback ports
reversed.

```sh
target/release/p2p-tunnler run ./tunnels.yaml
```

Use `p2p-tunnler run --help` for all flags. The included `test/` configuration
is for local development only; do not reuse its keys.

## NAT and IPv4-only peers

The data path stays direct. A direct connection may be impossible when both
peers are behind restrictive, symmetric, carrier-grade, or double NAT.
`--nat-map` asks the local router for a UDP mapping through PCP, NAT-PMP, or
UPnP IGD; it needs only ordinary user network access. A manual router port
forward can also help. There is deliberately no relay fallback.

For a peer that cannot use IPv6, pass `--filter-ipv6` (also available as
`--ipv4-only`). It prevents this process from publishing a local IPv6
candidate and rejects IPv6 candidates learned from the remote peer. This is
the appropriate flag when connecting this updated side to an unmodified
IPv4-only 0.1.0 desktop peer.

`--out-port` selects the local Internet UDP port. It is useful with a manual
router forwarding rule. `--no-clear` keeps old remote candidates and can delay
recovery after a network change, so use it only when that trade-off is wanted.

Read [the operational guide](docs/operations.md) and
[the direct-only NAT design](docs/direct-only-nat-traversal.md) before relying
on a connection across NATs.

## Security and scope

- Run it as an ordinary Linux user; it does not need root, capabilities, raw
  sockets, or firewall changes.
- Protect secret-key files with mode `0600`. The `generate` command applies
  that mode on Unix unless `--insecure-priv` is explicitly given.
- Do not place real keys, production endpoints, or packet captures in the
  repository or its documentation.
- OpenDHT and STUN are third-party control-plane services. They can learn
  metadata such as published encrypted values or STUN source addresses, but
  they do not carry the WireGuard packet stream.

## Documentation and development

The documentation index is in [docs/README.md](docs/README.md). In particular,
[the compatibility contract](docs/compatibility.md) defines the 0.1.0 wire
formats that changes must preserve, and [AGENTS.md](AGENTS.md) gives the
repository rules for human and AI-assisted work.

This project originated from the inactive
[wireguard-p2p](https://github.com/manuels/wireguard-p2p) project by manuels.
It is provided under LGPL-2.1+ without warranty.
