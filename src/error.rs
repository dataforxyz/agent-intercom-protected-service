use core::fmt;

/// Stable, non-sensitive categories returned by contract validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContractErrorKind {
    /// Input exceeded the contract's byte limit.
    InputTooLarge,
    /// Input was not valid UTF-8.
    InvalidUtf8,
    /// Input began with a UTF-8 byte-order mark.
    ByteOrderMark,
    /// Input contained a NUL byte.
    NulByte,
    /// Input contained a non-ASCII byte or decoded string.
    NonAscii,
    /// JSON syntax or a JSON value shape was invalid.
    InvalidJson,
    /// A decoded JSON object contained the same key more than once.
    DuplicateKey,
    /// A required field was absent.
    MissingField,
    /// A field was not part of the closed contract.
    UnknownField,
    /// A field value did not satisfy the exact contract.
    InvalidField,
}

/// A validation failure with a stable category and field path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractError {
    kind: ContractErrorKind,
    path: &'static str,
    message: &'static str,
}

impl ContractError {
    pub(crate) const fn new(
        kind: ContractErrorKind,
        path: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            kind,
            path,
            message,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> ContractErrorKind {
        self.kind
    }

    /// Returns the static contract path associated with the failure.
    #[must_use]
    pub const fn path(&self) -> &'static str {
        self.path
    }

    /// Returns a non-sensitive static explanation.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ContractError {}
