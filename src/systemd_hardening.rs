use crate::strict_json::{
    empty_array, exact_object, exact_one, exact_string, parse_strict_json, singleton_string_array,
    take,
};
use crate::ContractError;

/// Defensive byte limit for the fixed systemd-hardening.v1 JSON document.
pub const MAX_SYSTEMD_HARDENING_BYTES: usize = 4_096;

/// Canonical inert hardening contract data shipped by this package.
pub const SYSTEMD_HARDENING_V1_JSON: &[u8] = include_bytes!("../data/systemd-hardening.v1.json");

const FIELDS: &[(&str, &str)] = &[
    ("AmbientCapabilities", "$.AmbientCapabilities"),
    ("CapabilityBoundingSet", "$.CapabilityBoundingSet"),
    ("NoNewPrivileges", "$.NoNewPrivileges"),
    ("PrivateTmp", "$.PrivateTmp"),
    ("ProtectHome", "$.ProtectHome"),
    ("ProtectSystem", "$.ProtectSystem"),
    ("RestrictAddressFamilies", "$.RestrictAddressFamilies"),
    ("RestrictSUIDSGID", "$.RestrictSUIDSGID"),
    ("schema_version", "$.schema_version"),
];

/// Marker returned only after exact systemd-hardening.v1 validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemdHardeningV1 {
    private: (),
}

/// Validates an inert systemd-hardening.v1 JSON document.
///
/// This function performs data validation only. It never renders a unit,
/// invokes systemd, changes the host, or grants authority.
pub fn validate_systemd_hardening(input: &[u8]) -> Result<SystemdHardeningV1, ContractError> {
    let root = parse_strict_json(input, MAX_SYSTEMD_HARDENING_BYTES, "$")?;
    let mut root = exact_object(root, FIELDS, "$")?;

    exact_one(take(&mut root, "schema_version"), "$.schema_version")?;
    exact_string(take(&mut root, "ProtectHome"), "yes", "$.ProtectHome")?;
    exact_string(
        take(&mut root, "ProtectSystem"),
        "strict",
        "$.ProtectSystem",
    )?;
    exact_string(
        take(&mut root, "NoNewPrivileges"),
        "yes",
        "$.NoNewPrivileges",
    )?;
    empty_array(
        take(&mut root, "CapabilityBoundingSet"),
        "$.CapabilityBoundingSet",
    )?;
    empty_array(
        take(&mut root, "AmbientCapabilities"),
        "$.AmbientCapabilities",
    )?;
    exact_string(
        take(&mut root, "RestrictSUIDSGID"),
        "yes",
        "$.RestrictSUIDSGID",
    )?;
    exact_string(take(&mut root, "PrivateTmp"), "yes", "$.PrivateTmp")?;
    singleton_string_array(
        take(&mut root, "RestrictAddressFamilies"),
        "AF_UNIX",
        "$.RestrictAddressFamilies",
    )?;

    Ok(SystemdHardeningV1 { private: () })
}
