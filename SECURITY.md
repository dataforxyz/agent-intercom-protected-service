# Security policy

## Current security boundary

The shipped Rust and npm artifacts are non-privileged and have no operational
runtime. The only executable repository file is the ordinary-user package
determinism checker; it creates and removes temporary package proofs and
cannot perform a privileged action. The Rust crate accepts bounded bytes,
validates closed data contracts, and returns canonical bytes or an inert
validation marker. Its DSSE support only validates a closed envelope shape,
canonical base64, bounds, canonical JSON, and pre-authentication encoding. It
also parses one closed, bounded release-inventory candidate whose tuple,
singular installable descriptor, evidence descriptors, lengths, and digest
strings all remain attacker claims. It also parses one closed, bounded
transparency-checkpoint claim whose tree size and opaque root digest remain
attacker claims. It has no authority to provision, install,
authenticate, authorize, create accounts, manage keys, render service units,
contact systemd, start processes, open sockets, or mutate a host.

Validation is not authorization. A valid `provisioning-request.v1` is only
canonical untrusted data. A valid `systemd-hardening.v1` value is only a match
against fixed inert data. Neither result proves release identity, provenance,
signature, installation state, service identity, or caller permission.
A format-valid `UntrustedDsseEnvelopeV1` is likewise attacker-chosen data. Its
`keyid` may be empty under the DSSE unspecified-key convention; empty and
nonempty key identifiers have exactly the same non-authoritative status. No
parsed signature bytes are verified, and no payload is interpreted as policy.
An `UntrustedReleaseInventoryV1` is likewise only structural data. Its
evidence may be empty. Equality between an evidence `subject_digest` and the
singular installable `digest` compares only the two decoded algorithm strings
and two decoded value strings. It performs no digest decoding, computation,
algorithm selection, artifact-byte comparison, evidence assessment, or install
selection. Claimed lengths are not measurements. An
`UntrustedTransparencyCheckpointV1` similarly performs only closed structural
parsing and fixed-order canonicalization. Its tree size is not an observed
high-water mark, its root digest is not computed or decoded, and input cannot
name an active log. No inclusion proof, consistency proof, signature, witness
statement, identity, threshold, append-only property, freshness, monotonicity,
or release acceptance is checked.

## Parser defenses

The byte API rejects oversized input, BOM, NUL, invalid UTF-8, non-ASCII bytes
and decoded strings, duplicate keys at any accepted depth, excessive nesting,
non-canonical numbers, missing fields, and unknown fields. The request schema
can represent no path, URL, command, environment, digest, key, user, group, or
unit. The crate forbids unsafe Rust and has no dependencies or build script.
The DSSE parser additionally rejects noncanonical RFC 4648 encodings,
whitespace and URL-safe base64 alphabets, malformed or extra padding, nonzero
pad bits, nonprintable payload types or key identifiers, empty signature
arrays, and empty or oversized decoded signatures. The envelope, decoded
payload, and signature count are bounded before they can become trusted state.
The inventory parser caps total input at 32768 bytes and evidence at 32
entries; requires exactly one `installable` object; restricts tuple and
algorithm labels to bounded non-path ASCII identifiers; accepts only canonical
unsigned JSON `u64` length claims; and bounds digest value claims to printable
ASCII. Its digest labels and values remain opaque and receive no
algorithm-specific allowlist, decoding, or length inference. The checkpoint
parser caps total input at 4096 bytes, requires the exact three-field root and
exact two-field digest, accepts only canonical unsigned JSON `u64` tree-size
claims, and applies the same opaque bounded digest grammar without algorithm
dispatch or digest-length inference.
JSON Schema is only a structural, non-authoritative consumer aid; it cannot
enforce raw lexical duplicate/numeric rules or Rust `u64` conversion. The Rust
byte parser is mandatory for contract validation.

## Permanent runtime rule

Node.js is permanently forbidden from the privileged or runtime trusted
computing base. npm may only pack and inspect the private, data-only contract
artifact as an ordinary user. There is no JavaScript code, entrypoint, hook, or
dependency in that artifact.

## Reporting

Report suspected contract bypasses privately to the repository maintainers.
Include the exact input bytes, observed result, Rust version, and revision.
Do not test against a real signer or service: this repository has neither
cryptographic verification nor service integration.
