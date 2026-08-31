# Control-plane path probes

Control-plane probes show that an updated remote peer can exchange direct UDP
without waiting for WireGuard traffic. They never carry, relay, inspect, or
gate WireGuard datagrams. The data plane remains direct UDP between the two
peer endpoints.

## DHT record extension

The encrypted DHT plaintext retains the legacy `timestamp` and `ip_addr_list`
fields and may include this optional extension:

```json
{
  "timestamp": { "secs_since_epoch": 0, "nanos_since_epoch": 0 },
  "ip_addr_list": ["203.0.113.10:12345"],
  "control": {
    "probe_token": "exactly-16-random-bytes-as-base64"
  }
}
```

`probe_token` encodes exactly 16 random bytes. It is generated once for each
local/remote connection, remains unchanged while that connection runs, and is
replaced on restart. Older peers ignore the unknown `control` field and retain
their legacy candidate behavior. An absent or invalid extension means the
remote is control-unverified; it does not prevent ordinary candidate
forwarding.

The DHT publisher sends a record immediately, publishes again after candidate
updates, and refreshes it every 60 seconds. Every publication has a new legacy
timestamp but the same run token.

## UDP protocol and routing

A probe frame is exactly 20 bytes:

```text
0..4   ASCII magic: "P2PC"
4..20  16-byte probe token
```

`P2PC` cannot be a WireGuard prefix because WireGuard message types start with
the four-byte little-endian values 1 through 4. The Internet socket classifies
incoming datagrams in this order:

1. A `P2PC` prefix is control traffic. Only a 20-byte frame reaches the probe
   handler; any other length is discarded.
2. A matching STUN magic-cookie frame reaches STUN processing.
3. All other datagrams follow the WireGuard forwarding path.

This keeps malformed probe-shaped traffic out of WireGuard and uses one
bounded receive router rather than competing socket receive loops.

## Exchange and path state

An updated peer sends the remote record's token to each compatible remote
candidate using its normal Internet UDP socket. On receipt of a valid frame:

- A token equal to the local run token is a probe request and is echoed exactly
  once from the same socket.
- A token equal to the remote run token is an acknowledgement only when a
  probe is outstanding for that exact source candidate. It marks the path
  **control-verified this run** and records `last_control_response`.
- Every other frame is discarded.

The responder never echoes a remote token, so the protocol cannot create a
ping-pong loop. The constant token is a run-scoped capability, not an identity
or confidentiality mechanism; the configured Curve25519 keys and encrypted
DHT record remain those mechanisms. A replay of a current-run acknowledgement
is consequently valid, so verification means control-verified for this run,
not proof that the path is live at an exact instant.

Per candidate, the scheduler is independent of WireGuard traffic:

| Path state | Next control probe |
| --- | --- |
| New or unverified | immediately, then after 1 second and 2 seconds |
| Still unacknowledged | every 5 seconds, with up to 10% jitter |
| Verified | every 15 seconds, with up to 10% jitter |
| A verified request has no acknowledgement within 3 seconds | return to the unverified schedule |

## Bounds and trust boundary

Candidate and probe-path sets are capped, as are UDP receive queues, reply
source entries, and outstanding paths. Replies require the exact current local
token, are fixed-size, and are rate-limited per source; this prevents the
socket from becoming a useful reflector. IPv4 and IPv6 source candidates are
kept as exact `SocketAddr` paths, so an acknowledgement cannot validate a
different address family or source.

Only DHT-authenticated candidates become WireGuard data peers. Unsolicited UDP
sources are dropped from the data path. The implementation does not add router
rules, firewall changes, root privileges, a relay, or a public data-path
server.
