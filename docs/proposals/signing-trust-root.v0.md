# Signing trust-root proposal v0

> **DRAFT — NON-OPERATIONAL — CEREMONY NOT PERFORMED — NO POLICY APPROVED**
>
> **EVERY OPTION, RECOMMENDATION, THRESHOLD, ROLE RULE, FIELD SET, AND GATE IN
> THIS DOCUMENT IS UNAPPROVED.** Nothing here is a production configuration or
> authorization.

## Plain-language meaning

This Markdown file creates no key, trust root, delegation, permission, trusted
identity, release authority, or operating-system root privilege. It performs no
ceremony and enables no code path. It only lays out questions and an
**UNAPPROVED** recommendation for humans to review later.

The current repository remains a format-only, non-privileged foundation. It
does not verify releases or authorize installation. Production verification and
Boss remain unavailable. This draft does not establish or claim Revision-17 or
Fable compliance.

## Status and interpretation

- Status: **DRAFT / NON-OPERATIONAL / UNAPPROVED**.
- Ceremony status: **NOT PERFORMED**.
- Production use: **FORBIDDEN UNTIL THE GO-LIVE GATE IS COMPLETED**.
- Concrete participants and cryptographic material: intentionally absent.
- Proposed root model: **UNAPPROVED 2-of-3 offline root delegation quorum**.
- Proposed release model: **UNAPPROVED 2-of-3 independently controlled online
  release quorum**.
- Algorithm, signed-payload encoding, digest choices, identifier derivation,
  and DSSE `keyid` policy: **TBD AND UNAPPROVED**.
- Words such as “would,” “require,” and “reject” describe the behavior of a
  possible future policy only. They do not describe current behavior.

## Security objective

**UNAPPROVED objective:** a future verifier would accept a release only when
the exact intended manifest and artifact set are authorized by a current
delegation from an offline trust root, meet an independently controlled online
release quorum, and do not move any persisted trust or release high-water mark
backward.

The design should preserve the existing fail-closed boundary: parse success,
DSSE framing, a matching `keyid`, a CI result, or possession of one signing
capability must never imply release authorization.

## Threat model

This is a proposal for human review, not a completed threat assessment.

### Assets an eventual design would protect

- The mapping from a requested channel, target, and version to exact artifact
  bytes.
- The offline root delegation authority and the online release authority.
- The verifier's compiled trust metadata and persistent rollback state.
- The separation and independence of custodians, builders, reviewers, and
  release operators.
- The ability to revoke or replace compromised release authority without
  silently weakening policy.

### In-scope threats

- A malicious or compromised CI job, build worker, release assembler, mirror,
  registry, transport, or runtime configuration source.
- One lost, stolen, copied, coerced, or malicious signing capability.
- Collusion or common control hidden behind nominally different signer labels.
- Manifest substitution, artifact substitution, mix-and-match releases,
  equivocation, replay, freeze, rollback, and version reuse.
- Trust-root substitution, delegation downgrade, threshold downgrade, and
  algorithm or encoding confusion.
- Attacker-chosen DSSE metadata, including empty, duplicated in effect, stale,
  or misleading `keyid` values.
- Parser differentials, duplicate fields, non-canonical encodings, ambiguous
  identifiers, signature malleability, and unbounded verification work.
- Clock error, stale delegation, lost custody, unavailable quorum, and
  incomplete revocation propagation.
- A maintainer, signer, builder, or operator attempting to approve their own
  incompatible work.
- Runtime flags, files, environment variables, or network data attempting to
  replace compiled root metadata or lower a threshold.

### Explicit non-goals of this draft

- Creating or handling any cryptographic material.
- Selecting or implementing a cryptographic primitive or byte encoding.
- Naming participants, systems, accounts, or vendors.
- Making production available or changing the current Boss integration state.
- Defining availability guarantees when a required quorum is unavailable.

## Authority layers and quorum decision

### Offline root delegation quorum

Options for human decision, all **UNAPPROVED**:

1. One-of-three: operationally simple but permits one compromise to delegate a
   release authority. **REJECTED SHORTCUT.**
2. 2-of-3: tolerates one unavailable root custodian and one compromised
   root capability, assuming genuine independent control.
3. Three-of-three: strongest resistance to partial compromise but no tolerance
   for one unavailable custodian.

**UNAPPROVED recommendation:** use a proposed **2-of-3 offline root
delegation quorum**. Root capabilities would remain offline except for a
planned delegation, revocation, rotation, or recovery ceremony. The quorum
would authorize a closed delegation record naming the permitted release
verification set, threshold, scope, validity, and generation. It would not sign
ordinary release manifests.

Whether this is three independent signatures or a threshold-signature scheme
is **TBD AND UNAPPROVED**. Counting is by cryptographically verified authority,
never by the number or spelling of DSSE entries.

### Online release quorum

Options for human decision, all **UNAPPROVED**:

1. One online signer: fastest but turns one compromise into a release.
   **REJECTED SHORTCUT.**
2. 2-of-3 independent online signers: tolerates one unavailable signer
   and requires compromise or collusion across two control domains.
3. Three-of-three online signers: reduces compromise tolerance but makes one
   outage halt every release.

**UNAPPROVED recommendation:** use a proposed **2-of-3 independently
controlled online release quorum**. Each member would verify the exact manifest
bytes and release evidence before authorizing. A root delegation would fix the
three eligible verification authorities and the threshold; the manifest could
not select its own authorities or threshold.

“Online” means available for a deliberately initiated release operation. It
does not mean embedded in CI, exposed through an unattended general-purpose
signing endpoint, or allowed to authorize automatically.

## Cryptographic and encoding decisions still open

No cryptographic choice is made by this document.

| Decision | **UNAPPROVED** options to assess | Current result |
| --- | --- | --- |
| Signature construction | A conservative fixed-format signature scheme; a threshold construction; or multiple independent ordinary signatures | **TBD** |
| Public verification material encoding | A single strictly canonical binary or textual representation with duplicate and non-canonical encodings rejected | **TBD** |
| Signed manifest encoding | A closed canonical data format or a separately specified deterministic encoding | **TBD** |
| Artifact and evidence digest | A fixed compile-time algorithm and fixed lowercase or binary encoding, with no manifest-selected downgrade | **TBD** |
| Identifier derivation | A domain-separated digest of canonical verification material, or another collision-resistant deterministic scheme | **TBD** |
| DSSE `payloadType` value | One exact, versioned value with no aliases | **TBD** |
| DSSE `keyid` behavior | Required derived identifier, or bounded routing hint followed by verification against eligible compiled/delegated authorities | **TBD** |

**UNAPPROVED recommendation:** decide these only after a focused cryptographic,
interoperability, parser, and migration review. The eventual verifier would pin
the accepted choices in code and trusted metadata. It would not infer an
algorithm from signature length, accept manifest-selected algorithms, or trust
`keyid` as proof of identity. Until these decisions are approved and
implemented, verification remains unavailable.

## Roles, independence, and forbidden combinations

Proposed roles, all **UNAPPROVED**:

- Policy approver: decides the human-approved policy and changes to it.
- Offline root custodian: controls one member of the root quorum.
- Online release custodian: controls one member of the release quorum.
- Independent builder: produces reproducibility evidence under a definition
  that remains TBD.
- Release assembler: constructs the candidate manifest and artifact set.
- Verifier maintainer: implements or reviews verification code.
- Deployment operator: invokes an already approved, fail-closed verifier.
- Incident coordinator: records evidence and coordinates stop, revoke, and
  recovery decisions without acquiring unilateral signing power.

Proposed independence test, **UNAPPROVED**: two quorum members count as
independent only if no single control domain can operate, recover, replace, or
silently reconfigure both. Separate labels alone are insufficient. The final
test for administrative, credential-recovery, device, automation, financial,
and organizational common control is **TBD**.

Proposed forbidden combinations, all **UNAPPROVED**:

- No control domain may hold or recover two members of the same three-member
  quorum.
- An offline root custodian may not also be an online release custodian.
- A release assembler may not also satisfy the release quorum by itself.
- A sole or decisive builder may not also provide the decisive release
  authorization for that output.
- A verifier change author may not be the sole reviewer of that change or the
  sole policy approver for its rollout.
- A deployment operator may not replace trust metadata, reset rollback state,
  waive builder evidence, or lower a threshold.
- CI is not a custodian, policy approver, ceremony participant, or quorum
  member.

Exception handling for small teams and temporary conflicts is **TBD AND
UNAPPROVED**. No exception exists merely because it is documented, convenient,
or needed to meet a deadline.

## Custody options

All custody models below are **UNAPPROVED** and require a later operational
review without placing sensitive material in this repository.

### Offline root custody

- Dedicated offline signing devices with separately controlled recovery
  material.
- Encrypted offline removable media used only from a dedicated offline
  environment.
- A threshold construction whose shares cannot be reconstructed by one
  custodian.

**UNAPPROVED recommendation:** prefer dedicated offline, tamper-evident custody
with one separately recoverable capability per control domain, inventory and
access logging that reveal no secret material, and a periodic non-production
readiness exercise. Root material would never enter a networked workstation,
CI, source control, an issue tracker, chat, or a ceremony transcript.

### Online release custody

- Dedicated interactive signing devices attached only for a release.
- Separately administered signing services with human-mediated authorization.
- Isolated signer hosts that receive only the bounded manifest bytes and
  return only an authorization result.

**UNAPPROVED recommendation:** use three independently administered signer
contexts, require an intentional action for each release, restrict each context
to the delegated purpose, and prevent export of sensitive material. Selection
between device-backed and service-backed custody is **TBD**. No vendor or
product is selected here.

## Draft manifest binding

This section proposes the exact logical field set to be signed. It does not
choose the byte encoding or provide a manifest instance. Every field and rule
is **DRAFT AND UNAPPROVED**.

The release payload would be a closed object containing exactly these required
fields:

| Logical field | Proposed meaning |
| --- | --- |
| `manifest_schema` | Exact manifest contract version |
| `payload_purpose` | Domain separation for a protected-service release manifest |
| `root_generation` | Root generation under which the release delegation is valid |
| `delegation_generation` | Exact release delegation generation |
| `release_sequence` | Monotonically increasing unsigned release number within its scope |
| `release.channel` | Channel requested by the caller |
| `release.version` | Canonical release version requested by the caller |
| `source.repository_identity` | Canonical identity of the reviewed source repository |
| `source.revision` | Immutable reviewed source revision |
| `source.tree_digest.algorithm` | Policy-fixed source-tree digest algorithm label |
| `source.tree_digest.value` | Digest of the exact reviewed source tree |
| `build.recipe_digest.algorithm` | Policy-fixed build-recipe digest algorithm label |
| `build.recipe_digest.value` | Digest of the complete reproducible build recipe |
| `build.toolchain_digest.algorithm` | Policy-fixed toolchain-set digest algorithm label |
| `build.toolchain_digest.value` | Digest of the complete pinned toolchain set |
| `build.builder_records[]` | Nonempty closed list of builder evidence records |
| `build.builder_records[].builder_reference` | Reference defined by the future independent-builder policy |
| `build.builder_records[].artifact_set_digest.algorithm` | Policy-fixed artifact-set digest algorithm label |
| `build.builder_records[].artifact_set_digest.value` | Digest of the builder's exact ordered artifact set |
| `artifacts[]` | Nonempty closed list of released artifacts |
| `artifacts[].logical_name` | Canonical non-path artifact name |
| `artifacts[].target` | Exact target matched to the provisioning request |
| `artifacts[].media_type` | Exact artifact media type |
| `artifacts[].length` | Exact unsigned byte length |
| `artifacts[].digest.algorithm` | Policy-fixed artifact digest algorithm label |
| `artifacts[].digest.value` | Digest of the exact artifact bytes |
| `validity.not_before` | Start of the manifest validity interval |
| `validity.not_after` | End of the manifest validity interval |

Proposed binding rules, all **UNAPPROVED**:

1. Unknown, missing, duplicate, aliased, ill-typed, non-canonical, or
   out-of-bound fields would fail closed.
2. The eventually approved `payloadType` and the decoded payload bytes would be
   covered exactly by DSSE pre-authentication encoding. Envelope `keyid` values
   and signature ordering would not alter manifest meaning or quorum counting.
3. The caller's channel, target, and version would have to equal
   `release.channel`, one and only one `artifacts[].target`, and
   `release.version` exactly. No case folding, path normalization, or “latest”
   resolution would occur inside the trusted decision.
4. Retrieved artifact bytes would have to match both the selected artifact's
   `length` and `digest` before any privileged use.
5. The future contract would define one canonical, domain-separated digest of
   the complete ordered `artifacts[]` array, including every artifact field and
   exact array order. Every accepted `build.builder_records[]` entry would have
   to use the policy-fixed artifact-set digest algorithm and carry exactly that
   computed digest. Builder records for any different, partial, reordered, or
   additional artifact set would fail closed; matching builder evidence for set
   A could never authorize releasing set B.
6. All artifacts in one manifest would share the exact source revision, build
   recipe, toolchain set, builder evidence, root generation, delegation
   generation, release sequence, and validity interval recorded above.
7. The policy-fixed values allowed in every `.algorithm` field, the canonical
   encoding, integer bounds, string grammar, array order, cardinality limits,
   time representation, and exact constant values remain **TBD**. A manifest
   could not introduce a new choice by naming it.
8. Authorization would require two distinct cryptographically verified members
   of the currently delegated three-member online set. Repeated entries from
   one member would count once.

The proposed field set deliberately includes builder records but does not yet
make them sufficient evidence. The independent-builder definition and
exception policy remain **TBD AND UNAPPROVED**.

## Independent builders and exceptions

Options for human decision, all **UNAPPROVED**:

- Require two builders whose output artifact sets match byte-for-byte.
- Require more than two matching builders for higher-risk releases.
- Permit a narrowly scoped root-authorized exception when the approved minimum
  cannot be met.
- Permit no exceptions and halt release until independence is restored.

**UNAPPROVED recommendation:** normally require at least two byte-for-byte
matching builds from independently controlled builder domains. Independence
would cover administration, source acquisition, build execution, toolchain
acquisition, evidence storage, and failure modes—not merely two CI jobs or two
labels.

The authoritative definition, evidence format, mismatch response, and
exception policy are **TBD**. Until approved, the safe interpretation is that
no builder exception is authorized. If humans later allow exceptions, the
proposed direction is a narrowly scoped, expiring root-quorum authorization
bound to one release tuple and recorded separately; this direction is also
**UNAPPROVED** and its exact fields are TBD.

## Validity, rotation, revocation, and quorum loss

All values and procedures in this section are **UNAPPROVED**.

### Validity and routine rotation

Options include short release delegations with more ceremonies, longer
delegations with greater exposure, and overlapping delegations for orderly
rotation. Root generations may be longer-lived than release delegations, but
ordinary release signing would never use root authority.

**UNAPPROVED recommendation:** choose a short, operationally tested release
delegation interval; rotate release authority before expiry or immediately on
suspected compromise; set a separately reviewed root validity limit; and
exercise offline custody before it is needed. Exact durations, overlap limits,
trusted-clock requirements, and grace behavior remain **TBD**. Expiry would
fail closed, without a local clock override.

### Revocation

**UNAPPROVED recommendation:** revocation would be monotonic and root-quorum
authorized. A revocation record would name the affected delegation generation,
advance a revocation sequence, bind a replacement when one exists, and never
make an already rejected generation valid again. Exact revocation record
fields and distribution are **TBD**.

Suspected release-authority compromise would stop releases, preserve evidence,
revoke the affected delegation with the offline root quorum, create a new
independent release set, and advance the delegation generation. Suspected root
compromise would stop both releases and root changes until the root-rotation or
emergency path satisfies its own gate.

### Quorum loss

- Loss of one member of a three-member set leaves the proposed two-member
  quorum possible, but replacement would still require the relevant approved
  ceremony.
- Loss of two release members halts release. The offline root quorum could
  delegate a replacement set; there is no one-signer bypass.
- Loss of the offline root quorum halts delegation, revocation, and ordinary
  root rotation. It does not lower the threshold.

Availability pressure is not authorization. Quorum loss is a fail-closed
incident, not an implicit exception.

## Compile-time root metadata

**UNAPPROVED recommendation:** a future production verifier would compile in a
closed root-metadata object containing the root contract version, root
generation, eligible public verification material, threshold, permitted
algorithms and encodings, identifier derivation rule, and delegation purpose.
This draft contains none of that material or any concrete value.

No runtime argument, environment variable, configuration file, mutable search
path, plugin, network response, manifest field, DSSE `keyid`, or emergency flag
would be allowed to add a root, replace a root, reduce a threshold, expand a
purpose, or enable an algorithm. Runtime state could only narrow trust and
record monotonic progress. An intentional root change would require reviewed
source or generated-data changes, reproducible build evidence, the rotation
rules below, and a separate go-live decision.

## High-water rollback protection

**UNAPPROVED recommendation:** the verifier would maintain durable monotonic
high-water state for:

- highest accepted `root_generation` globally;
- highest accepted `delegation_generation` for each delegated scope;
- highest accepted revocation sequence for each relevant scope; and
- highest accepted `release_sequence` for each exact channel-and-target scope.

A lower value would fail closed. Reuse of the same release sequence would be
accepted only as an idempotent retry when the complete canonical manifest
digest is identical; a different digest at the same sequence would be treated
as equivocation and fail closed. The high-water update would be durable and
atomic before privileged effects.

Missing or corrupt state after initial enrollment would fail closed. There
would be no delete-to-reset behavior and no clock-only rollback defense.
Backup, restoration, transactional storage, first-enrollment rules, scope
definition, and safe migration are **TBD AND UNAPPROVED**.

## Root rotation with dual threshold

Options for human decision, all **UNAPPROVED**:

- Old-root authorization alone: vulnerable if the current root quorum is
  already compromised. **REJECTED SHORTCUT.**
- New-root self-authorization alone: permits unilateral replacement.
  **REJECTED SHORTCUT.**
- Dual threshold: require both the current root quorum and the candidate root
  quorum over one exact transition statement.

**UNAPPROVED recommendation:** root generation changes would require a single
closed transition payload authorized by a 2-of-3 current-root threshold and a
2-of-3 candidate-root threshold. The payload would
bind the old generation, new generation, exact old and new root metadata
digests, thresholds, purposes, validity, and transition sequence. The new
generation would increase monotonically and the verifier would persist it
before accepting a release under it.

The transition encoding, metadata field set, overlap window, and bootstrap into
a newly compiled verifier remain **TBD**. A dual-threshold transition cannot be
simulated by two statements that bind different bytes.

## Emergency recovery

All emergency paths are **UNAPPROVED**. There is no standing break-glass key,
single-person override, threshold downgrade, local trust-on-first-use path, or
hidden recovery root.

**UNAPPROVED recommendation:**

1. Stop release and privileged verification on suspected compromise,
   equivocation, corrupt rollback state, or lost required quorum.
2. Preserve non-sensitive evidence and determine whether the release quorum,
   root quorum, verifier, or rollback state is affected.
3. If the root quorum remains valid, use it only to revoke and delegate a fresh
   independently controlled release set.
4. If the current root quorum and candidate root quorum are available, use the
   dual-threshold rotation path.
5. If the current root quorum cannot be recovered, remain fail closed. Recovery
   would require a newly reviewed verifier with new compile-time root metadata,
   an explicit discontinuity record, preservation or conservative advancement
   of rollback state, an independent security review, and a fresh human
   go-live decision. This document does not authorize that change.

Emergency availability never establishes cryptographic continuity. Exact
incident roles, discontinuity record fields, recovery media rules, and recovery
test cadence remain **TBD**.

## CI exclusion

**UNAPPROVED policy direction:** CI may build unsigned candidates, run tests,
compare reproducible outputs, and emit non-authoritative evidence. CI would not:

- possess, reconstruct, recover, request unattended use of, or proxy root or
  release signing authority;
- count as a custodian, independent human authorization, policy approver, or
  ceremony witness;
- finalize a production manifest, satisfy either quorum, rotate or revoke
  authority, reset high-water state, or decide an exception;
- fetch or inject runtime trust roots; or
- turn a green job, tag, branch, merge, artifact upload, or scheduled task into
  release authorization.

Test-only material, if later introduced, would be visibly non-production and
cryptographically disjoint from production. No such material is introduced by
this draft.

## Explicitly rejected shortcuts

Each item below is an **UNAPPROVED AND REJECTED** design shortcut:

- Treating this document, a merge, or repository write access as approval.
- Creating one signer, one emergency signer, or one shared recovery path that
  can satisfy a two-member quorum.
- Giving root or release signing authority to CI or to an unattended build.
- Keeping the root routinely online.
- Counting two labels, processes, jobs, or devices under one control domain as
  independent.
- Letting a manifest choose its verifier, algorithm, encoding, threshold, or
  trust root.
- Treating DSSE parsing, signature count, signature length, or `keyid` spelling
  as cryptographic verification.
- Trusting a key on first use, fetching a root at runtime, or permitting a
  runtime root override.
- Accepting unknown fields, ambiguous canonicalization, partial-manifest
  signing, detached artifact names, or an unbound target.
- Using version text or wall-clock time alone as rollback protection.
- Deleting rollback state to recover availability.
- Rotating a root with only old-root or only new-root authorization.
- Lowering a threshold because a custodian is unavailable.
- Waiving independent-builder requirements without an approved, bounded
  exception policy.
- Treating an emergency, deadline, or production outage as implicit approval.

## Human decisions required

Nothing in this list has been approved. Human review would need to resolve and
record at least:

- the root and release quorum models;
- exact independence criteria and forbidden role combinations;
- algorithms, canonical encodings, identifier derivation, digest choices, and
  DSSE handling;
- exact delegation, revocation, transition, and discontinuity record schemas;
- manifest constants, bounds, sorting, time representation, and payload type;
- custody models, recovery controls, validity limits, and rotation cadence;
- independent-builder definition, evidence requirements, mismatch handling,
  and exception policy;
- rollback-state scope, durability, backup, restore, and enrollment;
- implementation, test, review, operational, and audit ownership; and
- whether the complete evidence satisfies the go-live gate.

## Blank ceremony and decision transcript template

This template is intentionally blank and contains placeholders only. It is not
a ceremony record. A real transcript must live in a separately controlled
location and must not place secret material in this repository.

```text
document_revision: <placeholder>
ceremony_record_reference: <placeholder>
scope_reviewed: <placeholder>
threat_model_review_result: <placeholder>
root_quorum_decision: <placeholder>
release_quorum_decision: <placeholder>
independence_review_result: <placeholder>
role_separation_review_result: <placeholder>
cryptographic_decision_record_reference: <placeholder>
manifest_contract_review_result: <placeholder>
custody_review_result: <placeholder>
builder_policy_review_result: <placeholder>
rollback_review_result: <placeholder>
rotation_and_revocation_review_result: <placeholder>
emergency_recovery_review_result: <placeholder>
implementation_evidence_reference: <placeholder>
independent_security_review_reference: <placeholder>
production_readiness_result: <placeholder>
go_live_decision: <placeholder>
open_issues: <placeholder>
```

The transcript must not contain secret material. This repository draft also
must not be populated with participant identities, public-key bytes,
fingerprints, concrete key identifiers, or cryptographic signatures.

## Go-live gate

Every gate below is **UNAPPROVED**, unmet, and fail-closed. A future production
verifier would remain unavailable until humans separately confirm all of them:

1. The threat model and complete policy are approved through an identified
   governance process that is not created by this document.
2. Algorithms, encodings, identifier rules, manifest constants, bounds, and all
   TBD items are closed by reviewed specifications.
3. Role independence, custody, builder policy, exception policy, recovery, and
   rollback operations are documented and independently reviewed.
4. Production implementation is complete, fail-closed, reproducibly built, and
   tested against positive, negative, downgrade, rollback, equivocation,
   rotation, revocation, corruption, and quorum-loss cases.
5. Compile-time root metadata is reviewed with no runtime override, and the
   root and release material is created in separate completed ceremonies.
6. The blank template above is replaced by separately controlled ceremony and
   decision records containing the required evidence, without committing
   sensitive material here.
7. Independent security review findings are resolved or explicitly rejected by
   the future governance authority under a policy that does not yet exist.
8. Production verification and Boss availability are separately implemented
   and verified; they remain unavailable now.
9. A final explicit go-live decision is recorded outside this draft.

Until every gate is satisfied, the only valid outcome is **NO PRODUCTION
VERIFICATION / NO RELEASE AUTHORIZATION / BOSS UNAVAILABLE**.
