# Trust boundary

The current trust boundary stops at deterministic data validation.

Inputs are untrusted bytes. The library applies encoding and size checks,
parses JSON with duplicate-key rejection, projects only closed fields, and
either returns fixed-order request bytes or confirms that hardening data equals
the sole accepted object. The DSSE parser additionally returns bounded decoded
payload and signature bytes, fixed-order envelope JSON, or exact DSSE v1 PAE.
The release-inventory parser returns one bounded tuple, one singular
installable descriptor, and bounded evidence descriptors as fixed-order JSON.
The transparency-checkpoint parser returns one opaque root-digest claim and one
canonical-u64 tree-size claim as fixed-order JSON. The consistency-proof parser
returns exact untrusted from/to checkpoint claims plus 0..=64 ordered opaque
node claims as fixed-order JSON. The inclusion-proof parser returns one
untrusted checkpoint, opaque leaf digest, canonical-u64 leaf index, and 0..=64
ordered opaque nodes as fixed-order JSON. Every returned value remains
untrusted with respect to any future privileged action.

DSSE format validity is not signature verification. Both an empty `keyid`
(permitted as an unspecified key under DSSE conventions) and a nonempty
`keyid` are attacker-chosen metadata. Signature bytes are opaque variable
length input; the parser selects no algorithm and makes no signature-length
inference. Payload bytes receive no semantic interpretation.

Inventory digest algorithms, digest values, and lengths are attacker claims.
An evidence subject digest is required to have algorithm and value strings
equal to the singular installable digest strings, but that is only decoded-byte
string equality. It neither computes nor validates a digest, identifies bytes,
assesses evidence, nor selects an installable. The evidence array may be empty.
No transparency inclusion, consistency, or witness claim is checked.

A format-valid checkpoint does not identify an active log, compute a root,
observe or persist a high-water mark, prove append-only behavior, establish
freshness or monotonicity, bind a release tuple, validate a proof or signature,
or satisfy any witness threshold. It exists only as a canonical attacker claim
for a later independently reviewed layer to bind.

A format-valid consistency-proof claim also establishes no relation between its
endpoints or nodes. Regressing sizes, unequal roots at equal sizes, an empty
proof, duplicate nodes, and mixed opaque algorithms are intentionally accepted.
No Merkle operation, proof sufficiency, consistency, append-only property,
monotonicity, freshness, active-log identity, witness authority, quorum, or
state transition follows from parse success.

A format-valid inclusion-proof claim establishes no inclusion relation. An
index may be outside the claimed tree; a zero-size tree may have any index and
proof; nodes may be empty, duplicated, reordered, or use unrelated algorithm
labels. No leaf is constructed from a canonical manifest digest or exact
release tuple, no digest or Merkle algorithm/log is selected, and no index
range, orientation, proof length, root relation, witness evidence, high-water
state, release acceptance, or installation authorization is checked.

The current inventory, evidence, checkpoint, consistency proof, and inclusion
proof are solely untrusted input. Future trusted metadata, durable rollback or
enrollment state, and authorization/state
transitions are separate layers and are all absent. This foundation contains
no trust roots, trusted keys, cryptographic verification, digest validation,
policy engine, authoritative release manifest or catalog, identity mapping,
installer, service unit, provider selection, broker/Controller connection,
trust argument or result, or privileged API. It does not implement
`VerifiedReleasePolicy` or `verify_install_input`. Those are separate future
slices requiring independent security review before any integration.

The merged adapters and Orchestrator intentionally report that the protected
provisioner/authority is unavailable. This repository does not alter or bypass
that fail-closed state and has no wiring to those repositories.

Rust is the only permitted language at a future privileged boundary. Node.js
is permanently excluded from the privileged and runtime trusted computing
base. Its sole allowed role here is ordinary-user `npm pack` verification of
static JSON, declarations, README, and license data.
