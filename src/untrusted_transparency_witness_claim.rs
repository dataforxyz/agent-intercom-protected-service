use crate::base64::{decode_canonical_padded, encode_padded, Base64Error};
use crate::strict_json::{exact_object, exact_one, parse_strict_json, string, take};
use crate::untrusted_transparency_checkpoint::{
    parse_checkpoint_claim, push_checkpoint_claim, CheckpointClaimPaths,
    UntrustedTransparencyCheckpointV1,
};
use crate::{ContractError, ContractErrorKind};

/// Maximum accepted byte length for an untrusted transparency-witness claim.
pub const MAX_UNTRUSTED_TRANSPARENCY_WITNESS_CLAIM_BYTES: usize = 8_192;
/// Maximum accepted byte length for an attacker-chosen witness key identifier.
pub const MAX_UNTRUSTED_TRANSPARENCY_WITNESS_KEY_ID_BYTES: usize = 128;
/// Maximum accepted byte length for an attacker-chosen transparency-log identifier.
pub const MAX_UNTRUSTED_TRANSPARENCY_WITNESS_LOG_ID_BYTES: usize = 128;
/// Maximum decoded byte length for an attacker-chosen witness signature.
pub const MAX_UNTRUSTED_TRANSPARENCY_WITNESS_SIGNATURE_BYTES: usize = 4_096;

const ROOT_FIELDS: &[(&str, &str)] = &[
    ("checkpoint", "$.checkpoint"),
    ("keyid", "$.keyid"),
    ("log_id", "$.log_id"),
    ("schema_version", "$.schema_version"),
    ("sig", "$.sig"),
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

/// A singular, closed, bounded, entirely attacker-chosen witness claim.
///
/// Parse success preserves only an alleged association among one checkpoint,
/// key identifier, log identifier, and signature byte string. It does not
/// define signed bytes or establish a signature algorithm, witness identity,
/// eligible witness, log authority, independence, uniqueness, quorum,
/// checkpoint validity, release binding, trust, or acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedTransparencyWitnessClaimV1 {
    checkpoint: UntrustedTransparencyCheckpointV1,
    key_id: String,
    log_id: String,
    schema_version: u8,
    signature_bytes: Vec<u8>,
}

impl UntrustedTransparencyWitnessClaimV1 {
    /// Parses the closed witness-claim shape and bounded attacker claims.
    pub fn parse(input: &[u8]) -> Result<Self, ContractError> {
        let root = parse_strict_json(input, MAX_UNTRUSTED_TRANSPARENCY_WITNESS_CLAIM_BYTES, "$")?;
        let mut root = exact_object(root, ROOT_FIELDS, "$")?;
        let checkpoint = parse_checkpoint_claim(take(&mut root, "checkpoint"), &CHECKPOINT_PATHS)?;

        let key_id = string(take(&mut root, "keyid"), "$.keyid")?;
        if key_id.len() > MAX_UNTRUSTED_TRANSPARENCY_WITNESS_KEY_ID_BYTES
            || !is_printable_ascii(&key_id)
        {
            return Err(ContractError::new(
                ContractErrorKind::InvalidField,
                "$.keyid",
                "keyid must be 0..=128 printable ASCII bytes",
            ));
        }

        let log_id = string(take(&mut root, "log_id"), "$.log_id")?;
        if log_id.is_empty()
            || log_id.len() > MAX_UNTRUSTED_TRANSPARENCY_WITNESS_LOG_ID_BYTES
            || !log_id.bytes().all(is_identifier_byte)
        {
            return Err(ContractError::new(
                ContractErrorKind::InvalidField,
                "$.log_id",
                "log_id must be 1..=128 bytes in [A-Za-z0-9._-]",
            ));
        }

        exact_one(take(&mut root, "schema_version"), "$.schema_version")?;

        let encoded_signature = string(take(&mut root, "sig"), "$.sig")?;
        let signature_bytes = match decode_canonical_padded(
            &encoded_signature,
            MAX_UNTRUSTED_TRANSPARENCY_WITNESS_SIGNATURE_BYTES,
        ) {
            Ok(bytes) if !bytes.is_empty() => bytes,
            Ok(_) => {
                return Err(ContractError::new(
                    ContractErrorKind::InvalidField,
                    "$.sig",
                    "decoded signature must contain 1..=4096 bytes",
                ));
            }
            Err(Base64Error::InvalidEncoding) => {
                return Err(ContractError::new(
                    ContractErrorKind::InvalidBase64,
                    "$.sig",
                    "sig must use canonical padded RFC 4648 standard base64",
                ));
            }
            Err(Base64Error::DecodedTooLarge) => {
                return Err(ContractError::new(
                    ContractErrorKind::InvalidField,
                    "$.sig",
                    "decoded signature must contain 1..=4096 bytes",
                ));
            }
        };

        Ok(Self {
            checkpoint,
            key_id,
            log_id,
            schema_version: 1,
            signature_bytes,
        })
    }

    /// Returns the attacker-chosen checkpoint claim.
    #[must_use]
    pub const fn checkpoint(&self) -> &UntrustedTransparencyCheckpointV1 {
        &self.checkpoint
    }

    /// Returns the attacker-chosen key identifier, which may be empty.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the grammar-bounded attacker-chosen log identifier.
    #[must_use]
    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// Returns the schema version, always `1`.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }

    /// Returns the decoded, unverified attacker-chosen signature bytes.
    #[must_use]
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature_bytes
    }

    /// Returns compact fixed-order canonical JSON bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(b"{\"checkpoint\":");
        push_checkpoint_claim(&mut output, &self.checkpoint);
        output.extend_from_slice(b",\"keyid\":");
        push_json_string(&mut output, &self.key_id);
        output.extend_from_slice(b",\"log_id\":");
        push_json_string(&mut output, &self.log_id);
        output.extend_from_slice(b",\"schema_version\":1,\"sig\":\"");
        output.extend_from_slice(encode_padded(&self.signature_bytes).as_bytes());
        output.extend_from_slice(b"\"}");
        output
    }
}

/// Validates and canonicalizes an untrusted transparency-witness claim.
///
/// Returned bytes remain a singular attacker claim and are not a verified
/// signature, trusted witness statement, quorum, accepted checkpoint, or
/// release authorization.
pub fn canonicalize_untrusted_transparency_witness_claim(
    input: &[u8],
) -> Result<Vec<u8>, ContractError> {
    UntrustedTransparencyWitnessClaimV1::parse(input).map(|claim| claim.canonical_bytes())
}

fn is_printable_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn push_json_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for byte in value.bytes() {
        match byte {
            b'"' => output.extend_from_slice(b"\\\""),
            b'\\' => output.extend_from_slice(b"\\\\"),
            _ => output.push(byte),
        }
    }
    output.push(b'"');
}
