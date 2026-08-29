# Operations guide

## Configuration

The `run` command accepts one or more YAML connection files. A `.yaml`
extension is appended when omitted. Each file has one local identity and one
or more remote peers:

```yaml
secret_key: "file:/srv/p2p-tunnler/local.key"
peers:
  - name: desktop
    local_port: 10001
    public_key: "file:/srv/p2p-tunnler/desktop.key.pub"
```

`file:` reads the key text from a file. A key is Base64 for exactly 32 bytes.
Do not put production key material directly in YAML or commit it. The local
`local_port` is the loopback UDP port to which WireGuard sends packets.

## Common commands

```sh
# Generate a private key and a sibling .pub file.
p2p-tunnler generate /secure/path/peer.key

# Check the discovered public address through STUN.
p2p-tunnler stun

# Start every connection in a configuration file.
p2p-tunnler run /secure/path/tunnels.yaml
```

Add `--verbose` before the subcommand for structured debug logs. Logs include
candidate addresses and packet metadata, but never secret keys or decrypted
DHT payloads.

## Connectivity choices

| Situation | Recommended invocation | Effect |
| --- | --- | --- |
| Peer can use IPv4 and IPv6 | `run tunnels.yaml` | Gather normal candidates. |
| Remote desktop is IPv4-only | `run tunnels.yaml --filter-ipv6` | Publish only local IPv4 and reject remote IPv6. |
| Router supports PCP/NAT-PMP/UPnP | `run tunnels.yaml --nat-map` | Ask the local router for a renewable direct UDP mapping. |
| Manual router forwarding | `run tunnels.yaml --out-port 12345` | Bind the predictable local Internet port for the rule. |
| Temporary endpoint churn | `run tunnels.yaml --no-clear` | Retain old remote candidates; may preserve stale endpoints. |

`--nat-map` does not open a host firewall and does not use a cloud service. It
only requests a mapping on the local gateway. It may fail on routers that do
not support one of the protocols, on double NAT, or when policy disables
mapping; the service continues with STUN candidates and logs the result.

## Diagnosing no packets

1. Confirm WireGuard sends to the configured `local_port` on loopback. The
   tunnler logs the observed loopback endpoint after its first outgoing packet.
2. Run `stun` to confirm that outbound UDP works and note whether it finds an
   address. A timeout is an external-network condition and is retried by
   `run`.
3. Use `--verbose run ... --filter-ipv6` when the remote peer cannot use IPv6.
   Confirm the `IPv6 candidate gathering disabled` log appears.
4. Try `--nat-map` or a manual UDP forwarding rule when inbound packets do not
   arrive. For manual forwarding, send the chosen external UDP port to the
   selected local `--out-port`.
5. Check that the two peers use each other's public keys and the same OpenDHT
   bootstrap network. A successful DHT message decrypts silently except for
   candidate-change logs.

Some NAT pairs cannot establish a direct UDP path. With this project's
explicit no-relay design, the remedy is usable IPv6, an inbound router mapping
or forwarding rule, or a network/ISP change—not a hidden transport fallback.
