# Exact-tool package determinism proof

Run the proof as an ordinary, non-root user from a clean or dirty checkout:

```sh
tools/check-reproducible-packages.sh
```

Requirements are already-active direct executables for Rust/rustc 1.97.1,
Cargo 1.97.1, Node.js 26.3.0, and npm 11.16.0, plus POSIX `sh`, GNU `tar`, GNU
`readlink`, `sha256sum`, `cmp`, `diff`, `sort`, and `mktemp`.
`rust-toolchain.toml` records the project pin, but the local proof deliberately
does not ask rustup to select, install, or update it. Before creating package
state or running a package command, the script rejects `RUSTUP_TOOLCHAIN`,
rejects rustc/cargo paths that resolve to the rustup shim, and verifies the
direct output of all four pinned tools. A missing or mismatched tool makes the
proof fail.

The local proof does not use sudo, run package hooks, contact a service,
publish, sign, upload artifacts, or acquire tools. It demonstrates deterministic
package output with exact tool versions; it is not independent supply-chain or
tool provenance.

The script fixes the timezone, locale, source epoch, and process umask. It
creates one deterministic source snapshot outside the repository, excluding
`.git` and `target`, then extracts that snapshot into two isolated private
source trees. Each tree is packaged with an isolated home, Cargo home and
target directory, npm cache, and package destination. It then:

1. compares each pair byte-for-byte;
2. compares each pair's SHA-256 digest;
3. compares the two archive inventories;
4. compares each inventory with the committed exact allowlist; and
5. removes every generated package and temporary file on exit.

Cargo runs locked and offline. npm runs offline with scripts disabled. The
Cargo archive includes the pinned `rust-toolchain.toml` and omits VCS and build
state. The npm archive contains only `package.json`, `index.d.ts`, the two
schemas, fixed hardening data, README, and LICENSE.

## Hosted CI acquisition boundary

The hosted CI runner explicitly acquires Rust 1.97.1 and npm 11.16.0 in an
unprivileged, ephemeral bootstrap step; the immutable setup-node action pin
acquires Node.js 26.3.0. Those downloads happen before, and are not part of,
the package determinism proof. The subsequent checker still validates the
exact direct tools and uses isolated source, home, and cache trees. The pinned
`ubuntu-24.04` runner label constrains the execution environment, but a hosted
runner image is mutable infrastructure and is not cryptographic provenance.

The immutable action commit mappings were verified against their authoritative
remotes before being selected:

- `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5`
  maps to `v4.3.1`;
- `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020`
  maps to `v4.4.0`.

These pins freeze the action source used by this workflow. They do not turn
downloaded tools or the hosted runner into independent release provenance.
