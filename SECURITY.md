# Security policy

## Current security boundary

The shipped Rust and npm artifacts are non-privileged and have no operational
runtime. The only executable repository file is the ordinary-user package
determinism checker; it creates and removes temporary package proofs and
cannot perform a privileged action. The Rust crate accepts bounded bytes,
validates closed data contracts, and returns canonical bytes or an inert
validation marker. Its DSSE support only validates a closed envelope shape,
canonical base64, bounds, canonical JSON, and pre-authentication encoding. It
has no authority to provision, install,
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
