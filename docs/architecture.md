# Architecture

`p2p-tunnler` has a direct UDP data plane and a separate address-exchange
control plane. Keeping those separate is the central design constraint.

```text
local WireGuard UDP
        |
        v
loopback UDP listener <-> forwarding tasks <-> Internet UDP socket
                                              |
                    +-------------------------+--------------------------+
                    |                                                    |
                    v                                                    v
              STUN IPv4 lookup                                  encrypted OpenDHT
              candidate discovery                               address publication/listen
                    |                                                    |
                    +---------------- candidate list -------------------+
                                              |
                                              v
                                     direct remote UDP endpoint
```

## Identity and compatibility surface

Each YAML connection holds one 32-byte Curve25519 secret key and one or more
remote Curve25519 public keys. For every local/remote pair, the program:

1. derives a directional OpenDHT key from the ordered public keys;
2. serializes a timestamp and `Vec<SocketAddr>` to JSON;
3. encrypts that JSON with the legacy `crypto_box` construction; and
4. publishes or listens for the resulting DHT value.

The DHT key order, JSON field names, Base64 key representation, nonce prefix,
and ciphertext representation are a protocol contract. They are described in
detail in [compatibility.md](compatibility.md) and covered by regression
fixtures.

## Runtime and tasks

The binary uses a Tokio current-thread runtime. Long-lived UDP, STUN, DHT, and
forwarding operations are independent tasks. A failed background task logs a
structured error and terminates `run` with a nonzero result instead of leaving
an apparently healthy process with a broken data plane.

UDP work queues are deliberately bounded. During sustained overload, excess
datagrams are dropped rather than retained in process memory; this matches
UDP's lossy transport semantics and keeps a congested peer from exhausting
the service.

Router NAT mapping is an opt-in worker because the upstream mapping libraries
use blocking discovery APIs. It only talks to the local gateway and maintains
the mapping lease; it does not require privileges on the host.

## Address selection

STUN gathers an IPv4 server-reflexive address. Optional router mapping adds a
more reliable inbound IPv4 candidate when the router returns the same public
IP as STUN. `--filter-ipv6`/`--ipv4-only` disables local IPv6 candidate
publication and removes IPv6 remote candidates, including candidates retained
by `--no-clear`.

The exchanged candidate representation intentionally remains a plain
`Vec<SocketAddr>` so an updated peer interoperates with 0.1.0. See
[direct-only-nat-traversal.md](direct-only-nat-traversal.md) for capabilities
and unavoidable direct-connectivity limits.
