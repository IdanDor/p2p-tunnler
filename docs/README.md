# Documentation index

- [AI-assisted makeover goals](ai-makeover-goals.md): agreed modernization
  targets.
- [Compatibility contract](compatibility.md): network and data-format behavior
  that must remain compatible with an unmodified 0.1.0 peer.
- [Threat model](threat-model.md): trust boundaries, security controls, and
  known residual risks for the direct UDP and DHT design.
- [Direct-only NAT traversal](direct-only-nat-traversal.md): design and
  constraints for direct connectivity without a traffic relay.
- [Control-plane path probes](control-plane-probes.md): idle-path verification
  protocol for updated peers.
- [Architecture](architecture.md): data/control-plane boundaries and runtime
  responsibilities.
- [Code map](code-map.md): source-module ownership and compatibility-sensitive
  change entry points.
- [Operations guide](operations.md): configuration, flags, and connectivity
  diagnosis.
- [Sysarmor runtime policy](sysarmor-policy.md): strict local runtime
  confinement for the debug binary and its dedicated configuration directory.
- [Development and AI-assisted work](development.md): validation, dependency,
  and review requirements.
- [Deferred audit items](deferred-audit-items.md): compatibility-sensitive
  hardening work intentionally left for separate changes.

Keep long-lived design decisions, compatibility constraints, and operational
guidance here. Do not place keys, production endpoints, or packet captures
containing sensitive material in this directory.
