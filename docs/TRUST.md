# Trust boundary

The current trust boundary stops at deterministic data validation.

Inputs are untrusted bytes. The library applies encoding and size checks,
parses JSON with duplicate-key rejection, projects only closed fields, and
either returns fixed-order request bytes or confirms that hardening data equals
the sole accepted object. Returned values remain untrusted with respect to any
future privileged action.

This foundation contains no trust roots, keys, signatures, digests, DSSE,
policy engine, release manifest, release catalog, identity mapping, installer,
service unit, provider selection, broker/Controller connection, or privileged
API. It does not implement `verify_install_input`. Those are separate future
slices requiring independent security review before any integration.

The merged adapters and Orchestrator intentionally report that the protected
provisioner/authority is unavailable. This repository does not alter or bypass
that fail-closed state and has no wiring to those repositories.

Rust is the only permitted language at a future privileged boundary. Node.js
is permanently excluded from the privileged and runtime trusted computing
base. Its sole allowed role here is ordinary-user `npm pack` verification of
static JSON, declarations, README, and license data.

