# agent-intercom-protected-service

This repository is the strictly non-privileged foundation for a future Agent
Intercom protected-service boundary. Today it provides only:

- a Rust library that validates and canonicalizes `provisioning-request.v1`;
- an inert validator for the exact `systemd-hardening.v1` data contract; and
- a private, data-only npm contract pack containing the two closed JSON
  schemas, type declarations, and hardening data.

Nothing here installs, provisions, authenticates, authorizes, starts, stops,
signals, or mutates a service, account, key, socket, provider, or host. There
is no binary, `main`, build script, service unit, JavaScript runtime, trust
root, release manifest, signature policy, installer, or integration wiring.

## Rust API

`canonicalize_provisioning_request(&[u8])` accepts at most 4096 bytes and
returns compact canonical bytes in this fixed lexicographic order:

```json
{"action":"provision","release":{"channel":"stable","target":"linux-amd64","version":"1.2.3"},"request_id":"0123456789abcdef0123456789abcdef","schema_version":1}
```

Version components are unsigned decimal 64-bit integers. Each component is
canonical decimal text: no sign and no leading zero except the single digit
`0`. Prerelease/build syntax is not representable.

`validate_systemd_hardening(&[u8])` accepts only the exact inert object in
[`data/systemd-hardening.v1.json`](data/systemd-hardening.v1.json). It does not
render or apply configuration.

## Contract pack

The root `package.json` describes
`@dataforxyz/agent-intercom-protected-service-contracts`, a private data/type
package. It deliberately has no `main`, `bin`, scripts, lifecycle hooks, or
dependencies. Exactly Node.js 26.3.0 and npm 11.16.0 are used only to prove
deterministic contents of this unprivileged data pack; Node is permanently
excluded from any future privileged or runtime trusted computing base.

See [SECURITY.md](SECURITY.md), [docs/TRUST.md](docs/TRUST.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and
[docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) for the exact boundary and
verification commands.
