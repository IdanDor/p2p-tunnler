# Code map

This map is the starting point for source changes. Read
[compatibility.md](compatibility.md) before modifying any module that affects
the WireGuard data path, DHT representation, cryptography, configuration, or
command-line behavior.

```text
main.rs
  └── app.rs                 CLI dispatch and process/runtime setup
        ├── keygen.rs         generate command and secret-key file handling
        ├── service.rs        run command, per-peer setup, task supervision
        │     ├── transport.rs  loopback/internet UDP forwarding and sockets
        │     └── candidates.rs encrypted DHT candidates and STUN gathering
        └── dht.rs            OpenDHT lifecycle wrapper

shared support
  ├── config.rs              CLI and YAML configuration loading
  ├── crypto.rs              legacy-compatible crypto_box encoding
  ├── message.rs             legacy DHT JSON message shape
  ├── stun/                  STUN request/response protocol handling
  ├── nat.rs                 opt-in PCP, NAT-PMP, and UPnP mapping worker
  └── utils.rs               bounded UDP queues and task-failure monitoring
```

## Change guide

| Change area | Start here | Compatibility-sensitive? |
| --- | --- | --- |
| CLI, YAML, `file:` keys | `config.rs`, `app.rs`, `keygen.rs` | Yes |
| DHT key, JSON, encryption | `candidates.rs`, `message.rs`, `crypto.rs` | Yes — byte-for-byte |
| Candidate gathering / NAT | `candidates.rs`, `nat.rs`, `stun/` | Yes — preserve `Vec<SocketAddr>` |
| Direct UDP forwarding | `transport.rs`, `service.rs` | Yes — direct-only data path |
| Queueing and task failures | `utils.rs`, `service.rs` | Yes — preserve cancellation/error behavior |

Tests live beside the implementation they exercise. The `test/` directory is
only for local WireGuard smoke testing and contains development-only keys.
