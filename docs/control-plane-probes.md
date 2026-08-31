# Control-plane path probes

## Status

Planned design. This document defines the small direct UDP probe protocol to
implement in a later focused change. It does not change the current wire
behavior by itself.

## Goal

An updated peer must be able to learn that a direct UDP path to its configured
remote peer works even while WireGuard sends no data. The probe protocol is
control-plane traffic only: it never relays WireGuard traffic and never adds a
server to the data path.

The control-plane scheduler is deliberately independent of the data plane. It
does not inspect outbound or inbound WireGuard packets, and those packets do
not delay, suppress, or mark control probes successful.

## DHT extension and legacy compatibility

Continue to publish the legacy encrypted JSON record with its existing
`timestamp` and `ip_addr_list` fields. An updated peer adds one optional field:

```json
{
  "timestamp": { "secs_since_epoch": 0, "nanos_since_epoch": 0 },
  "ip_addr_list": ["203.0.113.10:12345"],
  "control": {
    "probe_token": "exactly-16-random-bytes-as-base64"
  }
}
```

`probe_token` is exactly 16 random bytes. Generate it once when a connection
starts and retain it unchanged until that connection stops. A subsequent run
generates a different token, so its receiver rejects packets from a previous
run. Delayed or replayed packets containing the current run's token are
accepted by design.

The unmodified 0.1.0 `Message` derives ordinary Serde `Deserialize` and does
not use `deny_unknown_fields`; it ignores `control` while continuing to use
the two legacy fields. The implementation must add a regression fixture that
deserializes an extended record with the unmodified 0.1.0 representation.
The existing legacy serialization fixture must continue to assert the exact
two-field form when no control extension is emitted.

An updated peer that receives no `control` field treats the remote as a legacy
or not-yet-upgraded peer. It retains current candidate forwarding behavior and
reports the path as control-unverified; lack of the extension is not a
connection failure.

Publish the record immediately at startup and after candidate changes, then
refresh it every 60 seconds with the same token and a new legacy timestamp.
This makes a running peer discoverable without rotating its run identity.

## UDP frame

Every control UDP datagram is exactly 20 bytes:

```text
0..4   ASCII magic: "P2PC"
4..20  16-byte probe token
```

`P2PC` cannot be a valid WireGuard message prefix: WireGuard message types
begin with a four-byte little-endian value from 1 through 4. The Internet UDP
receive router classifies packets in this order:

1. A 20-byte packet beginning with `P2PC` goes to the probe handler.
2. A packet matching the existing STUN magic-cookie classifier goes to the
   STUN handler.
3. Every other packet follows the existing WireGuard forwarding path.

A packet beginning with `P2PC` but having the wrong length is discarded. It
must never be forwarded to WireGuard. The STUN discriminator already exists;
the implementation should extend that one receive-routing point to produce
three destinations rather than create another UDP receive loop.

## Probe and acknowledgement behavior

For every compatible remote candidate, an updated peer sends `P2PC` followed
by the remote record's token from its normal Internet UDP socket.

On receipt:

- If the token equals this connection's own run token, it is a probe request.
  Echo the exact 20-byte datagram to the source using the same Internet UDP
  socket.
- Otherwise, if the token equals a probe currently outstanding to that source,
  it is an acknowledgement. Record that candidate path as control-verified.
- Otherwise, silently discard it.

There is no ping-pong loop. A peer echoes only its own token; the probing peer
recognizes that echoed remote token only because it has an outstanding probe.

A valid acknowledgement shows that a peer able to decrypt the current
encrypted DHT record can exchange UDP on the observed path. The static
configured peer keys remain the identity and confidentiality mechanism. The
token is a run-scoped capability, not a replacement identity system.

Because the token is intentionally constant for a run, a replayed
acknowledgement from that run is valid. Therefore status must say
"control-verified this run" and record a `last_control_response` time; it must
not claim cryptographic proof that the path is live at this instant.

## Probe schedule

The following schedule applies per candidate path and is driven only by probe
requests and acknowledgements. It applies even when the WireGuard data plane
is continuously busy.

| Path state | Next control probe |
| --- | --- |
| New or unverified | immediately, then after 1 second and 2 seconds |
| Still no acknowledgement | every 5 seconds |
| Verified | every 15 seconds |
| A verified probe has no acknowledgement within 3 seconds | return to the 1-second, 2-second, then 5-second schedule |

Apply up to 10% random jitter to recurring 5- and 15-second intervals. The
fast retry path diagnoses failures and recovers quickly; the 15-second steady
rate keeps an idle UDP path active on common NATs without coupling it to
WireGuard traffic.

## Input, resource, and routing constraints

- Build and probe only IPv4-to-IPv4 or IPv6-to-IPv6 candidate pairs.
- Bound stored candidates, outstanding probes, and receive queues.
- Send replies only for an exact current local token and only one fixed-size
  frame; rate-limit replies per source. This avoids making the socket a useful
  UDP reflector.
- A token, decrypted DHT record, or full probe frame must never be logged.
- A valid acknowledgement may record its observed source as a peer-reflexive
  candidate, but arbitrary unsolicited UDP sources must not become data peers.
- No router mapping, firewall rule, relay, root privilege, or public server is
  added by this feature.

## Implementation acceptance criteria

1. Preserve the legacy DHT bytes when `control` is absent and prove a 0.1.0
   decoder accepts the extension.
2. Unit-test exact frame length, classification, request echo, acknowledgement
   matching, malformed-input drops, token secrecy in logs, and IPv4/IPv6
   family separation.
3. Integration-test two updated peers verifying an idle path and an updated
   peer retaining normal behavior with a legacy record.
4. Keep the existing direct data path available to legacy/unverified peers;
   this design records control health but does not gate WireGuard forwarding.
