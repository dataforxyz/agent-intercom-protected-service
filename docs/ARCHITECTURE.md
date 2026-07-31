# Architecture

The foundation has three independent, inert flows:

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

The private npm package is an alternate static distribution of the schemas,
types, and fixed hardening data. It has no runtime surface. Rust tests pin the
schema literals and data to the library contract.

There is deliberately no product binary, main function, build script, native
code, JavaScript, service unit, provider, installer, IPC, network access,
system call integration, or host mutation. The sole executable repository file
is an ordinary-user shell checker that packs, compares, and removes temporary
artifacts; it is not shipped in either package.
