# Direct-only NAT traversal

## Decision

The WireGuard data path must remain direct peer-to-peer. STUN and OpenDHT are
allowed only as rendezvous/control-plane services: neither carries WireGuard
traffic. No cloud relay or user-operated public server is part of this design.

The tunnler must run as an ordinary Linux user with normal network access. It
must not require `CAP_NET_ADMIN`, root, firewall-rule changes, raw sockets, or
a privileged port.

## Constraint

An IPv4-only peer must not send to, or select, an IPv6 address. The current
`--filter-ipv6` switch (also available as `--ipv4-only`) suppresses local IPv6
candidate publication and rejects IPv6 remote candidates, including candidates
otherwise retained by `--no-clear`. This preserves compatibility with an
unmodified IPv4-only 0.1.0 peer.

Instead, treat IPv4 and IPv6 as separate candidate families. An IPv4-only peer
creates only IPv4 candidate pairs; an IPv6 candidate is never probed unless
both peers have a usable IPv6 candidate. This avoids the observed failed IPv6
send/crash path without disabling IPv6 for peers that can use it.

The longer-term candidate-pair design should use distinct IPv4 and IPv6 UDP
sockets rather than one dual-stack wildcard socket. A socket is then associated
with candidates of its own address family, so the forwarding path cannot
accidentally send IPv4 WireGuard traffic to an IPv6 candidate or vice versa.

## Direct-only candidate strategy

Each peer binds unprivileged UDP sockets (port `0` or a configured port above
1024), gathers candidates, encrypts them with the existing peer key, and
publishes them through OpenDHT.

Candidate priority, from most to least reliable:

1. Globally routable IPv6, only when both peers have an IPv6 candidate.
2. A UDP mapping returned by PCP, NAT-PMP, or UPnP IGD on the local gateway.
3. A manually configured UDP port-forward on the local router.
4. An IPv4 server-reflexive address discovered with STUN.

The local router mapping must refer to the exact UDP socket and local port used
by the tunnel. The mapping result, not `--out-port`, is the public address to
publish. `--out-port` selects only a local port; a NAT can still choose a
different public port.

PCP is preferred because its MAP operation requests an explicit inbound
mapping, including when the ordinary NAT behavior is endpoint-dependent.
NAT-PMP and UPnP IGD are fallbacks for common consumer routers. All three are
ordinary user-space requests to the local gateway; they need no Linux
capabilities. Mapping creation is opt-in (`--nat-map`) and renewed before its
lease expires. The current implementation relies on router lease expiry when
the process exits rather than guaranteeing explicit removal on shutdown.

Useful Rust implementation options are
[`crab_nat`](https://docs.rs/crab_nat/latest/crab_nat/) for PCP/NAT-PMP and
[`igd-next`](https://docs.rs/igd-next/latest/igd_next/) for UPnP IGD.

## Connection establishment

Updated peers will gain direct control-plane path probes as specified in
[control-plane-probes.md](control-plane-probes.md). That design keeps the
legacy DHT fields and immediate data forwarding intact for unmodified peers;
it records verified direct paths without introducing a relay or gating
WireGuard traffic. It is intentionally smaller than a full ICE state machine.

## Failure handling

The program must report a precise direct-connectivity failure, for example:

- no compatible IPv4/IPv6 candidate family;
- router mapping unavailable;
- no direct candidate pair responded;
- host or network firewall blocks inbound UDP.

Do not attempt NAT port prediction. It is NAT-specific and not a dependable
solution. Keepalives preserve a mapping that already works; they cannot make
two unreachable NATs mutually reachable.

If neither peer has usable IPv6, a manual/automatic router mapping, nor a
successful UDP hole-punching pair, direct-only connectivity is impossible. In
particular, double NAT and carrier-grade NAT may require action by the router
owner or ISP. The correct result under this no-relay constraint is an explicit
failure, not a transport fallback.

If *all* third-party control-plane services are also disallowed, OpenDHT and
STUN must be replaced with an out-of-band candidate exchange such as a QR code
or copied connection offer. That does not alter the direct-path limitation.

## Standards basis

- [RFC 8445: ICE](https://datatracker.ietf.org/doc/html/rfc8445) defines host,
  server-reflexive, peer-reflexive, and relayed candidates, plus connectivity
  checks. This design uses the first three only.
- [RFC 6887: PCP](https://datatracker.ietf.org/doc/html/rfc6887) defines
  explicit inbound NAT/firewall mappings and their lifetime management.
- [RFC 6886: NAT-PMP](https://datatracker.ietf.org/doc/html/rfc6886) describes
  automatic NAT port mapping and external-address discovery.
- [RFC 4787: UDP NAT behavior](https://datatracker.ietf.org/doc/html/rfc4787)
  explains why a STUN mapping can differ by destination and why mapping and
  filtering behavior determine hole-punching success.
- [RFC 8656: TURN](https://datatracker.ietf.org/doc/html/rfc8656) documents
  that some NAT combinations cannot communicate directly; TURN is explicitly
  excluded here because it relays transport traffic.
