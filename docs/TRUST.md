# Trust boundary

The current trust boundary stops at deterministic data validation.

Inputs are untrusted bytes. The library applies encoding and size checks,
parses JSON with duplicate-key rejection, projects only closed fields, and
either returns fixed-order request bytes or confirms that hardening data equals
the sole accepted object. The DSSE parser additionally returns bounded decoded
payload and signature bytes, fixed-order envelope JSON, or exact DSSE v1 PAE.
Every returned value remains untrusted with respect to any future privileged
action.

DSSE format validity is not signature verification. Both an empty `keyid`
(permitted as an unspecified key under DSSE conventions) and a nonempty
`keyid` are attacker-chosen metadata. Signature bytes are opaque variable
length input; the parser selects no algorithm and makes no signature-length
inference. Payload bytes receive no semantic interpretation.

This foundation contains no trust roots, trusted keys, cryptographic
verification, digest validation, policy engine, release manifest, release
catalog, identity mapping, installer, service unit, provider selection,
broker/Controller connection, trust argument or result, or privileged API. It
does not implement `VerifiedReleasePolicy` or `verify_install_input`. Those are
separate future slices requiring independent security review before any
integration.

The merged adapters and Orchestrator intentionally report that the protected
provisioner/authority is unavailable. This repository does not alter or bypass
that fail-closed state and has no wiring to those repositories.

Rust is the only permitted language at a future privileged boundary. Node.js
is permanently excluded from the privileged and runtime trusted computing
base. Its sole allowed role here is ordinary-user `npm pack` verification of
static JSON, declarations, README, and license data.
