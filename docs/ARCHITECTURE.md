# Architecture

The foundation has five independent, inert flows:

```text
untrusted request bytes (<=4096)
  -> UTF-8/BOM/NUL/ASCII checks
  -> bounded strict JSON parser + duplicate-key rejection
  -> exact provisioning-request.v1 projection
  -> fixed lexicographic canonical bytes

untrusted hardening bytes (<=4096)
  -> the same strict JSON boundary
  -> exact systemd-hardening.v1 comparison
  -> inert validation marker

untrusted DSSE envelope bytes (<=65536)
  -> the same strict JSON boundary
  -> exact payload,payloadType,signatures / keyid,sig projection
  -> canonical padded standard base64 decoding with bounded output
  -> untrusted decoded values + fixed-order JSON + exact DSSE v1 PAE

untrusted release-inventory bytes (<=32768)
  -> the same bounded strict JSON boundary
  -> one exact channel,target,version tuple + one installable descriptor
  -> 0..=32 closed evidence descriptors with opaque digest/length claims
  -> subject/installable digest-claim string equality only + fixed-order JSON

untrusted transparency-checkpoint bytes (<=4096)
  -> the same bounded strict JSON boundary
  -> one opaque root-digest claim + one canonical-u64 tree-size claim
  -> fixed-order root_digest,schema_version,tree_size JSON

untrusted transparency-consistency-proof bytes (<=65536)
  -> the same bounded strict JSON boundary
  -> exact from/to checkpoint claims + 0..=64 ordered opaque node claims
  -> fixed-order from_checkpoint,proof,schema_version,to_checkpoint JSON

untrusted transparency-inclusion-proof bytes (<=65536)
  -> the same bounded strict JSON boundary
  -> exact checkpoint + opaque leaf digest + canonical-u64 index + 0..=64 nodes
  -> fixed-order checkpoint,leaf_digest,leaf_index,proof,schema_version JSON
```

`src/strict_json.rs` is a dependency-free parser for the bounded contract
surface. It retains JSON number spelling so only the literal integer `1` can
satisfy `schema_version`; floating, exponent, signed, and other number forms
cannot normalize into it. Object keys are compared after JSON escape decoding,
so equivalent escaped duplicate keys are rejected.

`src/provisioning_request.rs` implements the closed request and decimal-u64
version grammar. Canonical bytes always order fields as
`action,release(channel,target,version),request_id,schema_version`.

The JSON Schemas are structural, non-authoritative views for data consumers;
they are not parity claims for the byte contract. A schema validator cannot
enforce duplicate-key rejection after a JSON implementation has projected an
object, cannot distinguish the raw numeric spellings `1` and `1.0`, and is not
the authority for Rust `u64` parsing semantics. Its ECMAScript patterns use an
explicit absolute-end assertion so trailing CR, LF, U+2028, and U+2029 cannot
pass through `$` line-terminator behavior. The bounded Rust byte parser is
mandatory for every trusted validation decision.

`src/systemd_hardening.rs` compares the closed hardening object. It cannot
render, install, or apply systemd configuration.

`src/base64.rs` implements canonical padded RFC 4648 standard base64 without a
dependency. It rejects whitespace, the URL-safe alphabet, misplaced or extra
padding, nonzero pad bits, and every spelling that does not round-trip to the
canonical encoder.

`src/dsse.rs` implements only the DSSE v1 envelope format. Canonical JSON uses
the fixed lexicographic field order `payload,payloadType,signatures` and
`keyid,sig`, minimally escapes printable-ASCII quote and backslash bytes, and
preserves signature order. Its PAE is exactly `DSSEv1 ` followed by the
decimal payload-type byte length, payload type, decimal decoded-payload byte
length, and decoded payload, with one ASCII space between components. Empty
payloads are representable. The required `keyid` may be empty because DSSE
permits an unspecified key identifier; it remains attacker-chosen routing
metadata and is never a trust decision.

There is no algorithm inference, cryptographic signature-length assumption,
semantic payload parsing, verification, trust argument or result, release
policy, install authorization, or runtime consumer in this flow.

`src/untrusted_release_inventory.rs` implements only an explicitly untrusted
inventory-candidate shape. The closed root requires one singular `installable`
object, so multiple installable descriptors are not representable. Evidence is
ordered, may be empty, is capped at 32 entries, and uses six closed tags. Each
evidence subject algorithm/value pair must equal the installable
algorithm/value pair after JSON decoding. That comparison is ordinary string
equality, not a digest operation or statement about external bytes. Digest
algorithms and values are attacker claims; the module performs no algorithm
dispatch, digest-format inference, hashing, evidence sufficiency decision, or
install selection. Canonical JSON orders root fields as
`channel,evidence,installable,schema_version,target,version`, descriptors as
`digest,length` or `digest,length,subject_digest,tag`, and digest fields as
`algorithm,value`. Claimed lengths are emitted as canonical decimal `u64`
integers.

`src/untrusted_transparency_checkpoint.rs` implements only an explicitly
untrusted checkpoint-claim shape. It reuses the opaque digest-claim grammar and
adds a canonical unsigned JSON `u64` tree size. Canonical JSON orders root
fields as `root_digest,schema_version,tree_size` and nested digest fields as
`algorithm,value`. There is no log selector, algorithm dispatch, digest
operation, inclusion or consistency proof, signature, witness, threshold,
identity, freshness, monotonicity, append-only check, or durable state.

`src/untrusted_transparency_consistency_proof.rs` implements only an explicitly
untrusted, self-contained consistency-proof claim. It reuses the exact
checkpoint grammar for both endpoints and preserves an ordered 0..=64 array of
opaque digest claims, including duplicates. Canonicalization orders root fields
as `from_checkpoint,proof,schema_version,to_checkpoint`. It intentionally
accepts regressing endpoint sizes, equal sizes with unequal roots, empty proofs,
duplicate nodes, mixed algorithms, and arbitrary printable digest values. It
performs no Merkle operation, proof-length inference, endpoint ordering or root
relation, algorithm/log selection, consistency verification, append-only check,
monotonicity/freshness decision, witness/quorum check, or durable-state update.

`src/untrusted_transparency_inclusion_proof.rs` implements only an explicitly
untrusted, self-contained inclusion-proof claim. It reuses the exact checkpoint
and opaque digest grammars, adds one canonical unsigned JSON `u64` leaf index,
and preserves an ordered 0..=64 proof array including duplicates.
Canonicalization orders root fields as
`checkpoint,leaf_digest,leaf_index,proof,schema_version`. It intentionally
accepts out-of-range indices, zero-size trees with arbitrary indices/proofs,
empty/duplicate nodes, mixed algorithms, and structurally valid but impossible
Merkle claims. It performs no leaf construction, digest or Merkle operation,
index/orientation/proof-length/root-relation check, manifest or release-tuple
binding, algorithm/log selection, inclusion verification, witness/quorum
check, durable-state update, release acceptance, or install authorization.

Untrusted inventory/evidence/checkpoint/consistency-proof/inclusion-proof data
is a separate layer from any future trusted metadata. This repository has no
trusted metadata, durable release state, state transition, transparency-log
proof checking, witness checking, or consumer that could turn a candidate into
authority.

The private npm package is an alternate static distribution of the two
schemas, their types, and fixed hardening data. It has no inventory exposure or
runtime surface. Rust tests pin the schema literals and data to the library
contract.

There is deliberately no product binary, main function, build script, native
code, JavaScript, service unit, provider, installer, IPC, network access,
system call integration, or host mutation. The sole executable repository file
is an ordinary-user shell checker that packs, compares, and removes temporary
artifacts; it is not shipped in either package.
