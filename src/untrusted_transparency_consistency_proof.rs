use crate::strict_json::{exact_object, exact_one, parse_strict_json, take, StrictJsonValue};
use crate::untrusted_release_inventory::{
    parse_digest_claim, push_digest_claim, UntrustedDigestClaim,
};
use crate::untrusted_transparency_checkpoint::{
    parse_checkpoint_claim, push_checkpoint_claim, CheckpointClaimPaths,
    UntrustedTransparencyCheckpointV1,
};
use crate::{ContractError, ContractErrorKind};

/// Maximum accepted byte length for an untrusted transparency-consistency proof claim.
pub const MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_BYTES: usize = 65_536;
/// Maximum number of ordered opaque node claims in an untrusted consistency proof.
pub const MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_NODES: usize = 64;

const ROOT_FIELDS: &[(&str, &str)] = &[
    ("from_checkpoint", "$.from_checkpoint"),
    ("proof", "$.proof"),
    ("schema_version", "$.schema_version"),
    ("to_checkpoint", "$.to_checkpoint"),
];
const FROM_CHECKPOINT_FIELDS: &[(&str, &str)] = &[
    ("root_digest", "$.from_checkpoint.root_digest"),
    ("schema_version", "$.from_checkpoint.schema_version"),
    ("tree_size", "$.from_checkpoint.tree_size"),
];
const FROM_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.from_checkpoint.root_digest.algorithm"),
    ("value", "$.from_checkpoint.root_digest.value"),
];
const TO_CHECKPOINT_FIELDS: &[(&str, &str)] = &[
    ("root_digest", "$.to_checkpoint.root_digest"),
    ("schema_version", "$.to_checkpoint.schema_version"),
    ("tree_size", "$.to_checkpoint.tree_size"),
];
const TO_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.to_checkpoint.root_digest.algorithm"),
    ("value", "$.to_checkpoint.root_digest.value"),
];
const PROOF_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.proof[].algorithm"),
    ("value", "$.proof[].value"),
];
const FROM_CHECKPOINT_PATHS: CheckpointClaimPaths = CheckpointClaimPaths {
    fields: FROM_CHECKPOINT_FIELDS,
    digest_fields: FROM_DIGEST_FIELDS,
    path: "$.from_checkpoint",
    digest_path: "$.from_checkpoint.root_digest",
    algorithm_path: "$.from_checkpoint.root_digest.algorithm",
    value_path: "$.from_checkpoint.root_digest.value",
    schema_path: "$.from_checkpoint.schema_version",
    tree_size_path: "$.from_checkpoint.tree_size",
};
const TO_CHECKPOINT_PATHS: CheckpointClaimPaths = CheckpointClaimPaths {
    fields: TO_CHECKPOINT_FIELDS,
    digest_fields: TO_DIGEST_FIELDS,
    path: "$.to_checkpoint",
    digest_path: "$.to_checkpoint.root_digest",
    algorithm_path: "$.to_checkpoint.root_digest.algorithm",
    value_path: "$.to_checkpoint.root_digest.value",
    schema_path: "$.to_checkpoint.schema_version",
    tree_size_path: "$.to_checkpoint.tree_size",
};

/// A closed, bounded, entirely attacker-chosen consistency-proof claim.
///
/// Parse success preserves the association between two untrusted checkpoint
/// claims and an ordered sequence of opaque node claims. It does not establish
/// ordering, a root relation, proof sufficiency, append-only behavior, a log
/// identity, monotonicity, freshness, witness authorization, or acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedTransparencyConsistencyProofV1 {
    from_checkpoint: UntrustedTransparencyCheckpointV1,
    proof: Vec<UntrustedDigestClaim>,
    schema_version: u8,
    to_checkpoint: UntrustedTransparencyCheckpointV1,
}

impl UntrustedTransparencyConsistencyProofV1 {
    /// Parses the closed consistency-proof shape and bounded attacker claims.
    pub fn parse(input: &[u8]) -> Result<Self, ContractError> {
        let root = parse_strict_json(
            input,
            MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_BYTES,
            "$",
        )?;
        let mut root = exact_object(root, ROOT_FIELDS, "$")?;
        let from_checkpoint =
            parse_checkpoint_claim(take(&mut root, "from_checkpoint"), &FROM_CHECKPOINT_PATHS)?;
        let proof = parse_proof(take(&mut root, "proof"))?;
        exact_one(take(&mut root, "schema_version"), "$.schema_version")?;
        let to_checkpoint =
            parse_checkpoint_claim(take(&mut root, "to_checkpoint"), &TO_CHECKPOINT_PATHS)?;
        Ok(Self {
            from_checkpoint,
            proof,
            schema_version: 1,
            to_checkpoint,
        })
    }

    /// Returns the attacker-chosen starting checkpoint claim.
    #[must_use]
    pub const fn from_checkpoint(&self) -> &UntrustedTransparencyCheckpointV1 {
        &self.from_checkpoint
    }

    /// Returns the ordered, possibly empty opaque node claims.
    #[must_use]
    pub fn proof(&self) -> &[UntrustedDigestClaim] {
        &self.proof
    }

    /// Returns the schema version, always `1`.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }

    /// Returns the attacker-chosen ending checkpoint claim.
    #[must_use]
    pub const fn to_checkpoint(&self) -> &UntrustedTransparencyCheckpointV1 {
        &self.to_checkpoint
    }

    /// Returns compact fixed-order canonical JSON bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(b"{\"from_checkpoint\":");
        push_checkpoint_claim(&mut output, &self.from_checkpoint);
        output.extend_from_slice(b",\"proof\":[");
        for (index, node) in self.proof.iter().enumerate() {
            if index != 0 {
                output.push(b',');
            }
            push_digest_claim(&mut output, node);
        }
        output.extend_from_slice(b"],\"schema_version\":1,\"to_checkpoint\":");
        push_checkpoint_claim(&mut output, &self.to_checkpoint);
        output.push(b'}');
        output
    }
}

/// Validates and canonicalizes an untrusted consistency-proof claim.
///
/// Returned bytes remain attacker claims and are not a verified consistency
/// proof, append-only statement, accepted checkpoint transition, or log fact.
pub fn canonicalize_untrusted_transparency_consistency_proof(
    input: &[u8],
) -> Result<Vec<u8>, ContractError> {
    UntrustedTransparencyConsistencyProofV1::parse(input).map(|claim| claim.canonical_bytes())
}

fn parse_proof(value: StrictJsonValue) -> Result<Vec<UntrustedDigestClaim>, ContractError> {
    let StrictJsonValue::Array(values) = value else {
        return Err(ContractError::new(
            ContractErrorKind::InvalidField,
            "$.proof",
            "proof must be a JSON array",
        ));
    };
    if values.len() > MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_NODES {
        return Err(ContractError::new(
            ContractErrorKind::InvalidField,
            "$.proof",
            "proof must contain 0..=64 opaque node claims",
        ));
    }
    values
        .into_iter()
        .map(|value| {
            parse_digest_claim(
                value,
                PROOF_DIGEST_FIELDS,
                "$.proof[]",
                "$.proof[].algorithm",
                "$.proof[].value",
            )
        })
        .collect()
}
