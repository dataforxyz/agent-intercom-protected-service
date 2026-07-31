# Dependency inventory

The Rust package has zero direct, transitive, build, development, native, or
proc-macro dependencies. `Cargo.lock` contains only:

```text
agent-intercom-protected-service 0.1.0
```

The parser and version grammar use the Rust standard library. CI confirms the
inventory with `cargo tree --locked --offline --target=all` and fails if
`Cargo.toml` gains dependency sections without review.

The build and verification toolchain is pinned exactly to Rust/rustc 1.97.1
and Cargo 1.97.1, with the minimal rustup profile plus the `rustfmt` and
`clippy` components recorded for CI. Node.js is pinned to 26.3.0 and npm to
11.16.0 for static package verification. These pins are package/CI metadata,
not runtime or library dependencies. Local package checks require matching
direct tools to be active before they start and never invoke rustup selection
or tool acquisition.

The private npm package has zero dependencies of every kind and no scripts or
lifecycle hooks. npm itself is a packaging proof tool only; it is not a
project dependency and is permanently forbidden from any future privileged or
runtime trusted computing base.

Hosted CI may acquire only those exact tool versions in its ordinary-user,
ephemeral job environment. That bootstrap is operational preparation, not
package-proof evidence or cryptographic provenance.
