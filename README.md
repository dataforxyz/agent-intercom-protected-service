# agent-intercom-protected-service

This repository is the strictly non-privileged foundation for a future Agent
Intercom protected-service boundary. Today it provides only:

- a Rust library that validates and canonicalizes `provisioning-request.v1`;
- an inert validator for the exact `systemd-hardening.v1` data contract;
- a bounded, format-only parser and canonicalizer for untrusted DSSE v1
  envelopes, including exact pre-authentication encoding;
- a bounded Rust-only parser and canonicalizer for one explicitly untrusted
  single-tuple release-inventory candidate;
- a bounded Rust-only parser and canonicalizer for one explicitly untrusted
  transparency-checkpoint claim;
- a bounded Rust-only parser and canonicalizer for one explicitly untrusted,
  self-contained transparency-consistency-proof claim; and
- a private, data-only npm contract pack containing the two closed JSON
  schemas, type declarations, and hardening data.

Nothing here installs, provisions, authenticates, authorizes, starts, stops,
signals, or mutates a service, account, key, socket, provider, or host. There
is no binary, `main`, build script, service unit, JavaScript runtime, trust
root, authoritative release manifest, signature policy, installer, or
integration wiring.
The DSSE surface adds no trust root, signature verification, cryptographic
algorithm, semantic payload policy, installer, or integration wiring.

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

`UntrustedDsseEnvelopeV1::parse(&[u8])` accepts at most 65536 bytes and only
the closed DSSE fields `payload`, `payloadType`, and `signatures`, with exactly
`keyid` and `sig` in each signature entry. Decoded payloads are capped at
32768 bytes, signature arrays at 32 entries, and each decoded signature at
1..=4096 bytes. `payloadType` is 1..=256 printable ASCII bytes; `keyid` is
0..=128 printable ASCII bytes. An empty, required `keyid` follows the DSSE
unspecified-key convention and remains attacker-chosen metadata.

Payload and signature strings must use canonical padded RFC 4648 standard
base64. Canonical JSON is compact and fixes the lexicographic order
`payload,payloadType,signatures` and `keyid,sig` while preserving signature
array order. `pre_authentication_encoding()` returns exactly
`DSSEv1 <payloadType-byte-length> <payloadType> <payload-byte-length> <payload>`.
The parser does not interpret payload semantics, infer an algorithm, verify a
signature, or authorize any action.

`UntrustedReleaseInventoryV1::parse(&[u8])` accepts at most 32768 bytes. Its
closed root contains exactly
`channel,evidence,installable,schema_version,target,version`, where
`schema_version` is the JSON integer `1` and
`installable` is one required descriptor with exactly `digest,length`.
Channel, target, version, and digest-algorithm claims use short bounded ASCII
identifier grammars. Claimed lengths are canonical JSON `u64` values.

The required evidence array contains 0..=32 ordered descriptors tagged only
`sbom`, `provenance`, `attestation`, `build_recipe`, `toolchain`, or
`builder_record`. Each evidence descriptor contains exactly
`digest,length,subject_digest,tag`. A subject digest's algorithm and value
strings must equal the singular installable digest's strings after JSON
decoding. This is opaque string equality only: no algorithm is selected, no
digest is decoded or computed, no bytes are compared, and no evidence is made
sufficient. Digest values are attacker-chosen printable ASCII claims. Compact
canonical JSON uses the fixed field order stated above, with `algorithm,value`
inside each digest claim. This Rust-only surface is absent from the JSON
Schemas, TypeScript declarations, and npm package metadata.

`UntrustedTransparencyCheckpointV1::parse(&[u8])` accepts at most 4096 bytes.
Its closed root contains exactly `root_digest,schema_version,tree_size`, where
`schema_version` is the JSON integer `1`, `tree_size` is a canonical unsigned
JSON `u64`, and `root_digest` reuses the bounded opaque digest-claim grammar.
Compact canonical JSON fixes root order as
`root_digest,schema_version,tree_size` and digest order as `algorithm,value`.
The parser selects no log or digest algorithm, checks no proof or witness,
performs no hashing, and establishes no freshness, monotonicity, append-only
property, quorum, identity, or release acceptance. This Rust-only surface is
also absent from JSON Schemas, TypeScript declarations, and npm metadata.

`UntrustedTransparencyConsistencyProofV1::parse(&[u8])` accepts at most 65536
bytes. Its closed root contains exactly
`from_checkpoint,proof,schema_version,to_checkpoint`. Both endpoints reuse the
exact checkpoint grammar. `proof` is an ordered array of 0..=64 opaque digest
claims; order and duplicates are preserved. Compact canonical JSON uses that
fixed root order, checkpoint order `root_digest,schema_version,tree_size`, and
digest order `algorithm,value`.

The parser does not compare endpoint sizes or roots, infer a proof length,
select an algorithm or log, perform Merkle operations, verify consistency, or
establish append-only behavior, monotonicity, freshness, witness authority,
quorum, durable high-water state, or release acceptance. Regressing sizes,
equal sizes with unequal roots, empty proofs, duplicate nodes, and mixed opaque
algorithms remain representable attacker claims. This Rust-only surface is
absent from JSON Schemas, TypeScript declarations, and npm metadata.

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
