use crate::strict_json::{
    exact_object, exact_one, parse_strict_json, string, take, StrictJsonValue,
};
use crate::{ContractError, ContractErrorKind};

/// Maximum accepted byte length for an untrusted release-inventory document.
pub const MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES: usize = 32_768;
/// Maximum number of claims in the untrusted evidence array.
pub const MAX_UNTRUSTED_EVIDENCE_CLAIMS: usize = 32;

const MAX_CHANNEL_BYTES: usize = 64;
const MAX_TARGET_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 128;
const MAX_DIGEST_ALGORITHM_BYTES: usize = 64;
const MAX_DIGEST_VALUE_BYTES: usize = 512;

const ROOT_FIELDS: &[(&str, &str)] = &[
    ("channel", "$.channel"),
    ("evidence", "$.evidence"),
    ("installable", "$.installable"),
    ("schema_version", "$.schema_version"),
    ("target", "$.target"),
    ("version", "$.version"),
];
const ARTIFACT_FIELDS: &[(&str, &str)] = &[
    ("digest", "$.installable.digest"),
    ("length", "$.installable.length"),
];
const EVIDENCE_FIELDS: &[(&str, &str)] = &[
    ("digest", "$.evidence[].digest"),
    ("length", "$.evidence[].length"),
    ("subject_digest", "$.evidence[].subject_digest"),
    ("tag", "$.evidence[].tag"),
];
const INSTALLABLE_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.installable.digest.algorithm"),
    ("value", "$.installable.digest.value"),
];
const EVIDENCE_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.evidence[].digest.algorithm"),
    ("value", "$.evidence[].digest.value"),
];
const SUBJECT_DIGEST_FIELDS: &[(&str, &str)] = &[
    ("algorithm", "$.evidence[].subject_digest.algorithm"),
    ("value", "$.evidence[].subject_digest.value"),
];

/// An attacker-chosen digest algorithm and value claim.
///
/// The strings are opaque. This type does not decode, hash, dispatch on, or
/// otherwise establish any property of the claimed digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedDigestClaim {
    algorithm: String,
    value: String,
}

impl UntrustedDigestClaim {
    /// Returns the attacker-chosen algorithm label.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns the attacker-chosen opaque value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A singular attacker-chosen artifact descriptor claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedArtifactClaim {
    digest: UntrustedDigestClaim,
    length: u64,
}

impl UntrustedArtifactClaim {
    /// Returns the opaque digest claim.
    #[must_use]
    pub const fn digest(&self) -> &UntrustedDigestClaim {
        &self.digest
    }

    /// Returns the claimed byte length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }
}

/// A closed tag on an attacker-chosen evidence descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UntrustedEvidenceTag {
    /// An SBOM claim.
    Sbom,
    /// A provenance claim.
    Provenance,
    /// An attestation claim.
    Attestation,
    /// A build-recipe claim.
    BuildRecipe,
    /// A toolchain claim.
    Toolchain,
    /// A builder-record claim.
    BuilderRecord,
}

impl UntrustedEvidenceTag {
    /// Returns the exact wire spelling of the tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sbom => "sbom",
            Self::Provenance => "provenance",
            Self::Attestation => "attestation",
            Self::BuildRecipe => "build_recipe",
            Self::Toolchain => "toolchain",
            Self::BuilderRecord => "builder_record",
        }
    }
}

/// An attacker-chosen evidence descriptor and its opaque subject claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedEvidenceClaim {
    digest: UntrustedDigestClaim,
    length: u64,
    subject_digest: UntrustedDigestClaim,
    tag: UntrustedEvidenceTag,
}

impl UntrustedEvidenceClaim {
    /// Returns the evidence object's opaque digest claim.
    #[must_use]
    pub const fn digest(&self) -> &UntrustedDigestClaim {
        &self.digest
    }

    /// Returns the claimed evidence byte length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns the opaque subject claim copied from the singular installable.
    ///
    /// Parsing checks only byte-for-byte string equality for the algorithm and
    /// value. Equality does not establish that either claim describes bytes.
    #[must_use]
    pub const fn subject_digest(&self) -> &UntrustedDigestClaim {
        &self.subject_digest
    }

    /// Returns the closed evidence tag.
    #[must_use]
    pub const fn tag(&self) -> UntrustedEvidenceTag {
        self.tag
    }
}

/// A closed, bounded, but entirely untrusted single-tuple inventory candidate.
///
/// The singular `installable` descriptor is structural. Parse success and
/// subject-claim string equality grant no authority and establish no property
/// of any external bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedReleaseInventoryV1 {
    channel: String,
    evidence: Vec<UntrustedEvidenceClaim>,
    installable: UntrustedArtifactClaim,
    schema_version: u8,
    target: String,
    version: String,
}

impl UntrustedReleaseInventoryV1 {
    /// Parses the closed inventory shape and its bounded attacker claims.
    pub fn parse(input: &[u8]) -> Result<Self, ContractError> {
        let root = parse_strict_json(input, MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES, "$")?;
        let mut root = exact_object(root, ROOT_FIELDS, "$")?;

        let channel = bounded_identifier(
            string(take(&mut root, "channel"), "$.channel")?,
            MAX_CHANNEL_BYTES,
            "$.channel",
            "channel must be 1..=64 bytes using only ASCII alphanumeric, '.', '_', or '-'",
        )?;
        let target = bounded_identifier(
            string(take(&mut root, "target"), "$.target")?,
            MAX_TARGET_BYTES,
            "$.target",
            "target must be 1..=128 bytes using only ASCII alphanumeric, '.', '_', or '-'",
        )?;
        let version = bounded_identifier(
            string(take(&mut root, "version"), "$.version")?,
            MAX_VERSION_BYTES,
            "$.version",
            "version must be 1..=128 bytes using only ASCII alphanumeric, '.', '_', or '-'",
        )?;
        exact_one(take(&mut root, "schema_version"), "$.schema_version")?;

        let installable = parse_artifact_claim(take(&mut root, "installable"))?;
        let evidence = parse_evidence_claims(take(&mut root, "evidence"), installable.digest())?;

        Ok(Self {
            channel,
            evidence,
            installable,
            schema_version: 1,
            target,
            version,
        })
    }

    /// Returns the untrusted channel text.
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Returns the ordered, possibly empty evidence claims.
    #[must_use]
    pub fn evidence(&self) -> &[UntrustedEvidenceClaim] {
        &self.evidence
    }

    /// Returns the required singular installable descriptor claim.
    #[must_use]
    pub const fn installable(&self) -> &UntrustedArtifactClaim {
        &self.installable
    }

    /// Returns the schema version, always `1`.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }

    /// Returns the untrusted target text.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the untrusted version text.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns compact fixed-order canonical JSON bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(b"{\"channel\":");
        push_json_string(&mut output, &self.channel);
        output.extend_from_slice(b",\"evidence\":[");
        for (index, evidence) in self.evidence.iter().enumerate() {
            if index != 0 {
                output.push(b',');
            }
            output.extend_from_slice(b"{\"digest\":");
            push_digest_claim(&mut output, evidence.digest());
            output.extend_from_slice(b",\"length\":");
            output.extend_from_slice(evidence.length().to_string().as_bytes());
            output.extend_from_slice(b",\"subject_digest\":");
            push_digest_claim(&mut output, evidence.subject_digest());
            output.extend_from_slice(b",\"tag\":\"");
            output.extend_from_slice(evidence.tag().as_str().as_bytes());
            output.extend_from_slice(b"\"}");
        }
        output.extend_from_slice(b"],\"installable\":{\"digest\":");
        push_digest_claim(&mut output, self.installable.digest());
        output.extend_from_slice(b",\"length\":");
        output.extend_from_slice(self.installable.length().to_string().as_bytes());
        output.extend_from_slice(b"},\"schema_version\":1,\"target\":");
        push_json_string(&mut output, &self.target);
        output.extend_from_slice(b",\"version\":");
        push_json_string(&mut output, &self.version);
        output.push(b'}');
        output
    }
}

/// Validates and canonicalizes an untrusted release-inventory candidate.
///
/// The returned bytes remain attacker claims and are not an install choice.
pub fn canonicalize_untrusted_release_inventory(input: &[u8]) -> Result<Vec<u8>, ContractError> {
    UntrustedReleaseInventoryV1::parse(input).map(|inventory| inventory.canonical_bytes())
}

fn parse_artifact_claim(value: StrictJsonValue) -> Result<UntrustedArtifactClaim, ContractError> {
    let mut artifact = exact_object(value, ARTIFACT_FIELDS, "$.installable")?;
    let digest = parse_digest_claim(
        take(&mut artifact, "digest"),
        INSTALLABLE_DIGEST_FIELDS,
        "$.installable.digest",
        "$.installable.digest.algorithm",
        "$.installable.digest.value",
    )?;
    let length = canonical_u64(take(&mut artifact, "length"), "$.installable.length")?;
    Ok(UntrustedArtifactClaim { digest, length })
}

fn parse_evidence_claims(
    value: StrictJsonValue,
    installable_digest: &UntrustedDigestClaim,
) -> Result<Vec<UntrustedEvidenceClaim>, ContractError> {
    let StrictJsonValue::Array(values) = value else {
        return Err(ContractError::new(
            ContractErrorKind::InvalidField,
            "$.evidence",
            "evidence must be a JSON array",
        ));
    };
    if values.len() > MAX_UNTRUSTED_EVIDENCE_CLAIMS {
        return Err(ContractError::new(
            ContractErrorKind::InvalidField,
            "$.evidence",
            "evidence must contain 0..=32 entries",
        ));
    }

    let mut evidence_claims = Vec::with_capacity(values.len());
    for value in values {
        let mut evidence = exact_object(value, EVIDENCE_FIELDS, "$.evidence[]")?;
        let digest = parse_digest_claim(
            take(&mut evidence, "digest"),
            EVIDENCE_DIGEST_FIELDS,
            "$.evidence[].digest",
            "$.evidence[].digest.algorithm",
            "$.evidence[].digest.value",
        )?;
        let length = canonical_u64(take(&mut evidence, "length"), "$.evidence[].length")?;
        let subject_digest = parse_digest_claim(
            take(&mut evidence, "subject_digest"),
            SUBJECT_DIGEST_FIELDS,
            "$.evidence[].subject_digest",
            "$.evidence[].subject_digest.algorithm",
            "$.evidence[].subject_digest.value",
        )?;
        if subject_digest != *installable_digest {
            return Err(ContractError::new(
                ContractErrorKind::InvalidField,
                "$.evidence[].subject_digest",
                "subject digest claim strings must exactly equal the installable digest claim strings",
            ));
        }
        let tag = parse_evidence_tag(string(take(&mut evidence, "tag"), "$.evidence[].tag")?)?;
        evidence_claims.push(UntrustedEvidenceClaim {
            digest,
            length,
            subject_digest,
            tag,
        });
    }
    Ok(evidence_claims)
}

fn parse_digest_claim(
    value: StrictJsonValue,
    fields: &[(&'static str, &'static str)],
    path: &'static str,
    algorithm_path: &'static str,
    value_path: &'static str,
) -> Result<UntrustedDigestClaim, ContractError> {
    let mut digest = exact_object(value, fields, path)?;
    let algorithm = bounded_identifier(
        string(take(&mut digest, "algorithm"), algorithm_path)?,
        MAX_DIGEST_ALGORITHM_BYTES,
        algorithm_path,
        "digest algorithm claim must be 1..=64 bytes using only ASCII alphanumeric, '.', '_', or '-'",
    )?;
    let value = string(take(&mut digest, "value"), value_path)?;
    if value.is_empty() || value.len() > MAX_DIGEST_VALUE_BYTES || !is_printable_ascii(&value) {
        return Err(ContractError::new(
            ContractErrorKind::InvalidField,
            value_path,
            "digest value claim must be 1..=512 printable ASCII bytes",
        ));
    }
    Ok(UntrustedDigestClaim { algorithm, value })
}

fn parse_evidence_tag(value: String) -> Result<UntrustedEvidenceTag, ContractError> {
    match value.as_str() {
        "sbom" => Ok(UntrustedEvidenceTag::Sbom),
        "provenance" => Ok(UntrustedEvidenceTag::Provenance),
        "attestation" => Ok(UntrustedEvidenceTag::Attestation),
        "build_recipe" => Ok(UntrustedEvidenceTag::BuildRecipe),
        "toolchain" => Ok(UntrustedEvidenceTag::Toolchain),
        "builder_record" => Ok(UntrustedEvidenceTag::BuilderRecord),
        _ => Err(ContractError::new(
            ContractErrorKind::InvalidField,
            "$.evidence[].tag",
            "tag is outside the closed untrusted evidence vocabulary",
        )),
    }
}

fn canonical_u64(value: StrictJsonValue, path: &'static str) -> Result<u64, ContractError> {
    let StrictJsonValue::Number(number) = value else {
        return invalid_u64(path);
    };
    if number.is_empty()
        || (number.len() > 1 && number.starts_with('0'))
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return invalid_u64(path);
    }
    number.parse::<u64>().map_err(|_| {
        ContractError::new(
            ContractErrorKind::InvalidField,
            path,
            "length must be a canonical unsigned JSON u64",
        )
    })
}

fn invalid_u64<T>(path: &'static str) -> Result<T, ContractError> {
    Err(ContractError::new(
        ContractErrorKind::InvalidField,
        path,
        "length must be a canonical unsigned JSON u64",
    ))
}

fn bounded_identifier(
    value: String,
    maximum_bytes: usize,
    path: &'static str,
    message: &'static str,
) -> Result<String, ContractError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ContractError::new(
            ContractErrorKind::InvalidField,
            path,
            message,
        ));
    }
    Ok(value)
}

fn is_printable_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn push_digest_claim(output: &mut Vec<u8>, digest: &UntrustedDigestClaim) {
    output.extend_from_slice(b"{\"algorithm\":");
    push_json_string(output, digest.algorithm());
    output.extend_from_slice(b",\"value\":");
    push_json_string(output, digest.value());
    output.push(b'}');
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
