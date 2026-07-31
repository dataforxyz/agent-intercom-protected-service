#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Strict, inert data contracts for a future protected-service boundary.
//!
//! This crate does not provision, install, authenticate, authorize, start, or
//! mutate anything. It contains only byte-oriented validation and
//! canonicalization.

mod error;
mod provisioning_request;
mod strict_json;
mod systemd_hardening;

pub use error::{ContractError, ContractErrorKind};
pub use provisioning_request::{
    canonicalize_provisioning_request, ProvisioningAction, ProvisioningReleaseV1,
    ProvisioningRequestV1, ReleaseChannel, ReleaseTarget, StableVersion,
    MAX_PROVISIONING_REQUEST_BYTES,
};
pub use systemd_hardening::{
    validate_systemd_hardening, SystemdHardeningV1, MAX_SYSTEMD_HARDENING_BYTES,
    SYSTEMD_HARDENING_V1_JSON,
};
