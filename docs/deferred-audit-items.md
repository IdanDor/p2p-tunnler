# Deferred audit items

These findings remain intentionally deferred because they require a
compatibility design rather than routine hardening. Reconsider them as a
separate, reviewed change; do not silently fold them into unrelated work.

## Authenticated peer admission

The forwarding path currently learns a remote endpoint from inbound UDP. It
needs an authenticated, bounded, and expiring peer-reflexive-candidate design
before arbitrary sources can be excluded without breaking direct NAT traversal
with 0.1.0 peers.

## Composed legacy interoperability fixture

The repository has byte-level DHT-key, JSON, and crypto fixtures. Add a
composed publish/listen fixture using a captured 0.1.0 record or an isolated
legacy binary before changing the control-plane composition.

## Privileged smoke-test safety

`test.sh` needs unique network-namespace names and a cleanup trap. It is not
part of normal validation and requires a privileged, deliberately prepared
host.
