# Architecture

The foundation has two independent, inert flows:

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

The private npm package is an alternate static distribution of the schemas,
types, and fixed hardening data. It has no runtime surface. Rust tests pin the
schema literals and data to the library contract.

There is deliberately no product binary, main function, build script, native
code, JavaScript, service unit, provider, installer, IPC, network access,
system call integration, or host mutation. The sole executable repository file
is an ordinary-user shell checker that packs, compares, and removes temporary
artifacts; it is not shipped in either package.
