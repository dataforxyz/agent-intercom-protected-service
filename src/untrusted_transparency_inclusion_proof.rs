use crate::strict_json::{exact_object, exact_one, parse_strict_json, take, StrictJsonValue};
use crate::untrusted_release_inventory::{
    parse_digest_claim, push_digest_claim, UntrustedDigestClaim,
};
use crate::untrusted_transparency_checkpoint::{
    parse_checkpoint_claim, push_checkpoint_claim, CheckpointClaimPaths,
    UntrustedTransparencyCheckpointV1,
};
use crate::{ContractError, ContractErrorKind};

/// Maximum accepted byte length for an untrusted transparency-inclusion proof claim.
pub const MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_BYTES: usize = 65_536;
/// Maximum number of ordered opaque node claims in an untrusted inclusion proof.
pub const MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_NODES: usize = 64;

const ROOT_FIELDS: &[(&str, &str)] = &[
    ("checkpoint", "$.checkpoint"),
    ("leaf_digest", "$.leaf_digest"),
    ("leaf_index", "$.leaf_index"),
    ("proof", "$.proof"),
    ("schema_version", "$.schema_version"),
];
const CHECKPOINT_FIELDS: &[(&str, &str)] = &[
    ("root_digest", "$.checkpoint.root_digest"),
    ("schema_version", "$.checkpoint.schema_version"),
    ("tree_size", "$.checkpoint.tree_size"),
];
const CHECKPOINT_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.checkpoint.root_digest.algorithm"),
    ("value", "$.checkpoint.root_digest.value"),
];
const LEAF_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.leaf_digest.algorithm"),
    ("value", "$.leaf_digest.value"),
];
const PROOF_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.proof[].algorithm"),
    ("value", "$.proof[].value"),
];
const CHECKPOINT_PATHS: CheckpointClaimPaths = CheckpointClaimPaths {
    fields: CHECKPOINT_FIELDS,
    digest_fields: CHECKPOINT_DIGEST_FIELDS,
    path: "$.checkpoint",
    digest_path: "$.checkpoint.root_digest",
    algorithm_path: "$.checkpoint.root_digest.algorithm",
    value_path: "$.checkpoint.root_digest.value",
    schema_path: "$.checkpoint.schema_version",
    tree_size_path: "$.checkpoint.tree_size",
};

/// A closed, bounded, entirely attacker-chosen inclusion-proof claim.
///
/// Parse success preserves an association between one untrusted checkpoint,
/// leaf digest, leaf index, and ordered sequence of opaque node claims. It does
/// not establish an index range, root relation, proof sufficiency, inclusion,
/// log identity, algorithm, manifest or release binding, trust, or acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedTransparencyInclusionProofV1 {
    checkpoint: UntrustedTransparencyCheckpointV1,
    leaf_digest: UntrustedDigestClaim,
    leaf_index: u64,
    proof: Vec<UntrustedDigestClaim>,
    schema_version: u8,
}

impl UntrustedTransparencyInclusionProofV1 {
    /// Parses the closed inclusion-proof shape and bounded attacker claims.
    pub fn parse(input: &[u8]) -> Result<Self, ContractError> {
        let root = parse_strict_json(input, MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_BYTES, "$")?;
        let mut root = exact_object(root, ROOT_FIELDS, "$")?;
        let checkpoint = parse_checkpoint_claim(take(&mut root, "checkpoint"), &CHECKPOINT_PATHS)?;
        let leaf_digest = parse_digest_claim(
            take(&mut root, "leaf_digest"),
            LEAF_DIGEST_FIELDS,
            "$.leaf_digest",
            "$.leaf_digest.algorithm",
            "$.leaf_digest.value",
        )?;
        let leaf_index = canonical_leaf_index(take(&mut root, "leaf_index"))?;
        let proof = parse_proof(take(&mut root, "proof"))?;
        exact_one(take(&mut root, "schema_version"), "$.schema_version")?;
        Ok(Self {
            checkpoint,
            leaf_digest,
            leaf_index,
            proof,
            schema_version: 1,
        })
    }

    /// Returns the attacker-chosen checkpoint claim.
    #[must_use]
    pub const fn checkpoint(&self) -> &UntrustedTransparencyCheckpointV1 {
        &self.checkpoint
    }

    /// Returns the opaque attacker-chosen leaf-digest claim.
    #[must_use]
    pub const fn leaf_digest(&self) -> &UntrustedDigestClaim {
        &self.leaf_digest
    }

    /// Returns the attacker-chosen leaf-index claim.
    #[must_use]
    pub const fn leaf_index(&self) -> u64 {
        self.leaf_index
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

    /// Returns compact fixed-order canonical JSON bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(b"{\"checkpoint\":");
        push_checkpoint_claim(&mut output, &self.checkpoint);
        output.extend_from_slice(b",\"leaf_digest\":");
        push_digest_claim(&mut output, &self.leaf_digest);
        output.extend_from_slice(b",\"leaf_index\":");
        output.extend_from_slice(self.leaf_index.to_string().as_bytes());
        output.extend_from_slice(b",\"proof\":[");
        for (index, node) in self.proof.iter().enumerate() {
            if index != 0 {
                output.push(b',');
            }
            push_digest_claim(&mut output, node);
        }
        output.extend_from_slice(b"],\"schema_version\":1}");
        output
    }
}

/// Validates and canonicalizes an untrusted inclusion-proof claim.
///
/// Returned bytes remain attacker claims and are not a verified inclusion
/// proof, accepted checkpoint, release binding, or log fact.
pub fn canonicalize_untrusted_transparency_inclusion_proof(
    input: &[u8],
) -> Result<Vec<u8>, ContractError> {
    UntrustedTransparencyInclusionProofV1::parse(input).map(|claim| claim.canonical_bytes())
}

fn canonical_leaf_index(value: StrictJsonValue) -> Result<u64, ContractError> {
    let StrictJsonValue::Number(number) = value else {
        return invalid_leaf_index();
    };
    if number.is_empty()
        || (number.len() > 1 && number.starts_with('0'))
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return invalid_leaf_index();
    }
    number.parse::<u64>().map_err(|_| {
        ContractError::new(
            ContractErrorKind::InvalidField,
            "$.leaf_index",
            "leaf_index must be a canonical unsigned JSON u64",
        )
    })
}

fn invalid_leaf_index<T>() -> Result<T, ContractError> {
    Err(ContractError::new(
        ContractErrorKind::InvalidField,
        "$.leaf_index",
        "leaf_index must be a canonical unsigned JSON u64",
    ))
}

fn parse_proof(value: StrictJsonValue) -> Result<Vec<UntrustedDigestClaim>, ContractError> {
    let StrictJsonValue::Array(values) = value else {
        return Err(ContractError::new(
            ContractErrorKind::InvalidField,
            "$.proof",
            "proof must be a JSON array",
        ));
    };
    if values.len() > MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_NODES {
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
