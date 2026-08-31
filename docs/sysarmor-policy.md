# Sysarmor runtime policy

[`../policies/p2p-tunnler-runtime.jsonc`](../policies/p2p-tunnler-runtime.jsonc)
is a strict runtime policy for the debug binary in this checkout. It is not a
Cargo build or test policy.

The policy restricts filesystem access to the executable/runtime closure,
system DNS configuration, device randomness, and a dedicated runtime
directory. It also denies audited high-risk kernel, namespace, process,
debugging, and Unix-socket operations while preserving the UDP operations that
the direct tunnel needs.

Before use, create a directory for the YAML configuration and keys, and ensure
all `file:` key references stay inside it:

```sh
install -d -m 700 /tmp/p2p-tunnler-runtime
/projects/sysarmor/target/debug/sysarmor run \
  --policy policies/p2p-tunnler-runtime.jsonc -- \
  ./target/debug/p2p-tunnler run /tmp/p2p-tunnler-runtime/tunnels.yaml
```

The policy intentionally does not grant the repository, home directory, or a
broad `/tmp` tree. It allows UDP because the application needs it; current
Landlock support cannot restrict UDP destination addresses or ports.

This policy uses a default-allow syscall baseline because Sysarmor tracing
cannot acquire a stable process identity in this environment, so a trustworthy
representative syscall allowlist could not be derived. Before using it outside
this checkout or treating it as a production default-deny policy, generate and
review a trace while running the actual configuration and connectivity paths.

It is coupled to the debug executable and `/nix/store`. Revalidate it after
changing the executable location, runtime closure, configuration location, or
network behavior.
