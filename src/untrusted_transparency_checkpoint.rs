use crate::strict_json::{exact_object, exact_one, parse_strict_json, take, StrictJsonValue};
use crate::untrusted_release_inventory::{
    parse_digest_claim, push_digest_claim, UntrustedDigestClaim,
};
use crate::{ContractError, ContractErrorKind};

/// Maximum accepted byte length for an untrusted transparency-checkpoint claim.
pub const MAX_UNTRUSTED_TRANSPARENCY_CHECKPOINT_BYTES: usize = 4_096;

const ROOT_FIELDS: &[(&str, &str)] = &[
    ("root_digest", "$.root_digest"),
    ("schema_version", "$.schema_version"),
    ("tree_size", "$.tree_size"),
];
const ROOT_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.root_digest.algorithm"),
    ("value", "$.root_digest.value"),
];

/// A closed, bounded, entirely attacker-chosen transparency-checkpoint claim.
///
/// Parse success establishes only a canonical pair of an opaque root-digest
/// claim and a tree-size claim. It does not establish a log identity,
/// append-only behavior, freshness, monotonicity, inclusion, consistency,
/// witness authorization, quorum sufficiency, or release acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedTransparencyCheckpointV1 {
    root_digest: UntrustedDigestClaim,
    schema_version: u8,
    tree_size: u64,
}

impl UntrustedTransparencyCheckpointV1 {
    /// Parses the closed checkpoint shape and its bounded attacker claims.
    pub fn parse(input: &[u8]) -> Result<Self, ContractError> {
        let root = parse_strict_json(input, MAX_UNTRUSTED_TRANSPARENCY_CHECKPOINT_BYTES, "$")?;
        let mut root = exact_object(root, ROOT_FIELDS, "$")?;
        let root_digest = parse_digest_claim(
            take(&mut root, "root_digest"),
            ROOT_DIGEST_FIELDS,
            "$.root_digest",
            "$.root_digest.algorithm",
            "$.root_digest.value",
        )?;
        exact_one(take(&mut root, "schema_version"), "$.schema_version")?;
        let tree_size = canonical_tree_size(take(&mut root, "tree_size"))?;
        Ok(Self {
            root_digest,
            schema_version: 1,
            tree_size,
        })
    }

    /// Returns the opaque attacker-chosen root-digest claim.
    #[must_use]
    pub const fn root_digest(&self) -> &UntrustedDigestClaim {
        &self.root_digest
    }

    /// Returns the schema version, always `1`.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }

    /// Returns the attacker-chosen tree-size claim.
    #[must_use]
    pub const fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Returns compact fixed-order canonical JSON bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(b"{\"root_digest\":");
        push_digest_claim(&mut output, &self.root_digest);
        output.extend_from_slice(b",\"schema_version\":1,\"tree_size\":");
        output.extend_from_slice(self.tree_size.to_string().as_bytes());
        output.push(b'}');
        output
    }
}

/// Validates and canonicalizes an untrusted transparency-checkpoint claim.
///
/// The returned bytes remain attacker claims and are not a verified, witnessed,
/// accepted, or active-log checkpoint.
pub fn canonicalize_untrusted_transparency_checkpoint(
    input: &[u8],
) -> Result<Vec<u8>, ContractError> {
    UntrustedTransparencyCheckpointV1::parse(input).map(|checkpoint| checkpoint.canonical_bytes())
}

fn canonical_tree_size(value: StrictJsonValue) -> Result<u64, ContractError> {
    let StrictJsonValue::Number(number) = value else {
        return invalid_tree_size();
    };
    if number.is_empty()
        || (number.len() > 1 && number.starts_with('0'))
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return invalid_tree_size();
    }
    number.parse::<u64>().map_err(|_| {
        ContractError::new(
            ContractErrorKind::InvalidField,
            "$.tree_size",
            "tree_size must be a canonical unsigned JSON u64",
        )
    })
}

fn invalid_tree_size<T>() -> Result<T, ContractError> {
    Err(ContractError::new(
        ContractErrorKind::InvalidField,
        "$.tree_size",
        "tree_size must be a canonical unsigned JSON u64",
    ))
}
