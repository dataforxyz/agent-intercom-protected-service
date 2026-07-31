use core::fmt;

use crate::strict_json::{exact_object, exact_one, exact_string, parse_strict_json, string, take};
use crate::{ContractError, ContractErrorKind};

/// Maximum accepted byte length for a provisioning-request.v1 document.
pub const MAX_PROVISIONING_REQUEST_BYTES: usize = 4_096;

const ROOT_FIELDS: &[(&str, &str)] = &[
    ("action", "$.action"),
    ("release", "$.release"),
    ("request_id", "$.request_id"),
    ("schema_version", "$.schema_version"),
];
const RELEASE_FIELDS: &[(&str, &str)] = &[
    ("channel", "$.release.channel"),
    ("target", "$.release.target"),
    ("version", "$.release.version"),
];

/// The only action representable by provisioning-request.v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningAction {
    /// Request provisioning of the pinned stable Linux release.
    Provision,
}

/// The only release channel representable by provisioning-request.v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseChannel {
    /// The stable channel.
    Stable,
}

/// The only release target representable by provisioning-request.v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseTarget {
    /// The Linux AMD64 target.
    LinuxAmd64,
}

/// A canonical stable version with three decimal `u64` components.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StableVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl StableVersion {
    /// Returns the major component.
    #[must_use]
    pub const fn major(self) -> u64 {
        self.major
    }

    /// Returns the minor component.
    #[must_use]
    pub const fn minor(self) -> u64 {
        self.minor
    }

    /// Returns the patch component.
    #[must_use]
    pub const fn patch(self) -> u64 {
        self.patch
    }
}

impl fmt::Display for StableVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The closed release object in provisioning-request.v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningReleaseV1 {
    /// Always [`ReleaseChannel::Stable`].
    channel: ReleaseChannel,
    /// Always [`ReleaseTarget::LinuxAmd64`].
    target: ReleaseTarget,
    /// Three canonical decimal `u64` components.
    version: StableVersion,
}

impl ProvisioningReleaseV1 {
    /// Returns the fixed stable channel.
    #[must_use]
    pub const fn channel(&self) -> ReleaseChannel {
        self.channel
    }

    /// Returns the fixed Linux AMD64 target.
    #[must_use]
    pub const fn target(&self) -> ReleaseTarget {
        self.target
    }

    /// Returns the validated stable version.
    #[must_use]
    pub const fn version(&self) -> StableVersion {
        self.version
    }
}

/// A validated provisioning-request.v1 value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningRequestV1 {
    /// Always `1`.
    schema_version: u8,
    /// Exactly 32 lowercase hexadecimal characters.
    request_id: String,
    /// Always [`ProvisioningAction::Provision`].
    action: ProvisioningAction,
    /// The exact stable Linux release tuple.
    release: ProvisioningReleaseV1,
}

impl ProvisioningRequestV1 {
    /// Parses and validates a provisioning-request.v1 byte document.
    pub fn parse(input: &[u8]) -> Result<Self, ContractError> {
        let root = parse_strict_json(input, MAX_PROVISIONING_REQUEST_BYTES, "$")?;
        let mut root = exact_object(root, ROOT_FIELDS, "$")?;
        exact_string(take(&mut root, "action"), "provision", "$.action")?;
        exact_one(take(&mut root, "schema_version"), "$.schema_version")?;

        let request_id = string(take(&mut root, "request_id"), "$.request_id")?;
        if request_id.len() != 32
            || !request_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::new(
                ContractErrorKind::InvalidField,
                "$.request_id",
                "request_id must be exactly 32 lowercase hexadecimal characters",
            ));
        }

        let mut release = exact_object(take(&mut root, "release"), RELEASE_FIELDS, "$.release")?;
        exact_string(take(&mut release, "channel"), "stable", "$.release.channel")?;
        exact_string(
            take(&mut release, "target"),
            "linux-amd64",
            "$.release.target",
        )?;
        let version =
            parse_stable_version(string(take(&mut release, "version"), "$.release.version")?)?;

        Ok(Self {
            schema_version: 1,
            request_id,
            action: ProvisioningAction::Provision,
            release: ProvisioningReleaseV1 {
                channel: ReleaseChannel::Stable,
                target: ReleaseTarget::LinuxAmd64,
                version,
            },
        })
    }

    /// Returns the schema version, always `1`.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }

    /// Returns the validated lowercase hexadecimal request identifier.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the fixed provisioning action.
    #[must_use]
    pub const fn action(&self) -> ProvisioningAction {
        self.action
    }

    /// Returns the validated stable Linux release tuple.
    #[must_use]
    pub const fn release(&self) -> &ProvisioningReleaseV1 {
        &self.release
    }

    /// Returns compact fixed-order canonical JSON bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            concat!(
                "{{\"action\":\"provision\",",
                "\"release\":{{\"channel\":\"stable\",\"target\":\"linux-amd64\",\"version\":\"{}\"}},",
                "\"request_id\":\"{}\",\"schema_version\":1}}"
            ),
            self.release.version, self.request_id
        )
        .into_bytes()
    }
}

fn parse_stable_version(value: String) -> Result<StableVersion, ContractError> {
    let mut components = value.split('.');
    let Some(major) = components.next() else {
        return invalid_version();
    };
    let Some(minor) = components.next() else {
        return invalid_version();
    };
    let Some(patch) = components.next() else {
        return invalid_version();
    };
    if components.next().is_some() {
        return invalid_version();
    }

    Ok(StableVersion {
        major: decimal_u64(major)?,
        minor: decimal_u64(minor)?,
        patch: decimal_u64(patch)?,
    })
}

fn decimal_u64(value: &str) -> Result<u64, ContractError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return invalid_version();
    }
    value.parse::<u64>().map_err(|_| version_error())
}

fn invalid_version<T>() -> Result<T, ContractError> {
    Err(version_error())
}

const fn version_error() -> ContractError {
    ContractError::new(
        ContractErrorKind::InvalidField,
        "$.release.version",
        "version must be canonical decimal u64 major.minor.patch",
    )
}

/// Validates and canonicalizes a provisioning-request.v1 byte document.
///
/// The returned bytes always use the fixed lexicographic field order
/// `action`, `release(channel,target,version)`, `request_id`,
/// `schema_version`, with no insignificant whitespace or trailing newline.
pub fn canonicalize_provisioning_request(input: &[u8]) -> Result<Vec<u8>, ContractError> {
    ProvisioningRequestV1::parse(input).map(|request| request.canonical_bytes())
}
