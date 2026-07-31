use crate::base64::{decode_canonical_padded, encode_padded, Base64Error};
use crate::strict_json::{exact_object, parse_strict_json, string, take, StrictJsonValue};
use crate::{ContractError, ContractErrorKind};

/// Maximum accepted byte length for an untrusted DSSE envelope document.
pub const MAX_DSSE_ENVELOPE_BYTES: usize = 65_536;
/// Maximum decoded byte length for an untrusted DSSE payload.
pub const MAX_DSSE_PAYLOAD_BYTES: usize = 32_768;
/// Maximum number of signatures in an untrusted DSSE envelope.
pub const MAX_DSSE_SIGNATURES: usize = 32;

const MAX_PAYLOAD_TYPE_BYTES: usize = 256;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_SIGNATURE_BYTES: usize = 4_096;

const ROOT_FIELDS: &[(&str, &str)] = &[
    ("payload", "$.payload"),
    ("payloadType", "$.payloadType"),
    ("signatures", "$.signatures"),
];
const SIGNATURE_FIELDS: &[(&str, &str)] = &[
    ("keyid", "$.signatures[].keyid"),
    ("sig", "$.signatures[].sig"),
];

/// An attacker-chosen signature entry from a format-valid DSSE envelope.
///
/// This value carries no verification or authorization meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedDsseSignature {
    key_id: String,
    signature_bytes: Vec<u8>,
}

impl UntrustedDsseSignature {
    /// Returns the attacker-chosen key identifier, which may be empty.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the decoded, unverified signature bytes.
    #[must_use]
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature_bytes
    }
}

/// A closed, format-valid, but entirely untrusted DSSE v1 envelope.
///
/// Parsing performs no cryptographic verification and grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedDsseEnvelopeV1 {
    payload_type: String,
    payload_bytes: Vec<u8>,
    signatures: Vec<UntrustedDsseSignature>,
}

impl UntrustedDsseEnvelopeV1 {
    /// Parses the closed DSSE envelope shape and its canonical base64 values.
    pub fn parse(input: &[u8]) -> Result<Self, ContractError> {
        let root = parse_strict_json(input, MAX_DSSE_ENVELOPE_BYTES, "$")?;
        let mut root = exact_object(root, ROOT_FIELDS, "$")?;

        let payload_type = string(take(&mut root, "payloadType"), "$.payloadType")?;
        if payload_type.is_empty()
            || payload_type.len() > MAX_PAYLOAD_TYPE_BYTES
            || !is_printable_ascii(&payload_type)
        {
            return Err(ContractError::new(
                ContractErrorKind::InvalidField,
                "$.payloadType",
                "payloadType must be 1..=256 printable ASCII bytes",
            ));
        }

        let payload = string(take(&mut root, "payload"), "$.payload")?;
        let payload_bytes = decode_base64(
            &payload,
            MAX_DSSE_PAYLOAD_BYTES,
            "$.payload",
            "decoded payload exceeds 32768 bytes",
        )?;

        let StrictJsonValue::Array(signature_values) = take(&mut root, "signatures") else {
            return Err(ContractError::new(
                ContractErrorKind::InvalidField,
                "$.signatures",
                "signatures must be a JSON array",
            ));
        };
        if signature_values.is_empty() || signature_values.len() > MAX_DSSE_SIGNATURES {
            return Err(ContractError::new(
                ContractErrorKind::InvalidField,
                "$.signatures",
                "signatures must contain 1..=32 entries",
            ));
        }

        let mut signatures = Vec::with_capacity(signature_values.len());
        for signature_value in signature_values {
            let mut signature = exact_object(signature_value, SIGNATURE_FIELDS, "$.signatures[]")?;
            let key_id = string(take(&mut signature, "keyid"), "$.signatures[].keyid")?;
            if key_id.len() > MAX_KEY_ID_BYTES || !is_printable_ascii(&key_id) {
                return Err(ContractError::new(
                    ContractErrorKind::InvalidField,
                    "$.signatures[].keyid",
                    "keyid must be 0..=128 printable ASCII bytes",
                ));
            }

            let encoded_signature = string(take(&mut signature, "sig"), "$.signatures[].sig")?;
            let signature_bytes = decode_base64(
                &encoded_signature,
                MAX_SIGNATURE_BYTES,
                "$.signatures[].sig",
                "decoded signature exceeds 4096 bytes",
            )?;
            if signature_bytes.is_empty() {
                return Err(ContractError::new(
                    ContractErrorKind::InvalidField,
                    "$.signatures[].sig",
                    "decoded signature must contain at least one byte",
                ));
            }
            signatures.push(UntrustedDsseSignature {
                key_id,
                signature_bytes,
            });
        }

        Ok(Self {
            payload_type,
            payload_bytes,
            signatures,
        })
    }

    /// Returns the nonempty printable-ASCII DSSE payload type.
    #[must_use]
    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }

    /// Returns the decoded, semantically unparsed, untrusted payload bytes.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }

    /// Returns the ordered attacker-chosen, unverified signature entries.
    #[must_use]
    pub fn signatures(&self) -> &[UntrustedDsseSignature] {
        &self.signatures
    }

    /// Returns compact fixed-order canonical JSON bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(b"{\"payload\":\"");
        output.extend_from_slice(encode_padded(&self.payload_bytes).as_bytes());
        output.extend_from_slice(b"\",\"payloadType\":");
        push_json_string(&mut output, &self.payload_type);
        output.extend_from_slice(b",\"signatures\":[");
        for (index, signature) in self.signatures.iter().enumerate() {
            if index != 0 {
                output.push(b',');
            }
            output.extend_from_slice(b"{\"keyid\":");
            push_json_string(&mut output, &signature.key_id);
            output.extend_from_slice(b",\"sig\":\"");
            output.extend_from_slice(encode_padded(&signature.signature_bytes).as_bytes());
            output.extend_from_slice(b"\"}");
        }
        output.extend_from_slice(b"]}");
        output
    }

    /// Returns the exact DSSE v1 pre-authentication encoding for this payload.
    #[must_use]
    pub fn pre_authentication_encoding(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(b"DSSEv1 ");
        output.extend_from_slice(self.payload_type.len().to_string().as_bytes());
        output.push(b' ');
        output.extend_from_slice(self.payload_type.as_bytes());
        output.push(b' ');
        output.extend_from_slice(self.payload_bytes.len().to_string().as_bytes());
        output.push(b' ');
        output.extend_from_slice(&self.payload_bytes);
        output
    }
}

/// Validates and canonicalizes an untrusted DSSE v1 envelope.
///
/// The returned bytes remain unverified and non-authoritative.
pub fn canonicalize_untrusted_dsse_envelope(input: &[u8]) -> Result<Vec<u8>, ContractError> {
    UntrustedDsseEnvelopeV1::parse(input).map(|envelope| envelope.canonical_bytes())
}

fn decode_base64(
    encoded: &str,
    maximum_decoded_bytes: usize,
    path: &'static str,
    too_large_message: &'static str,
) -> Result<Vec<u8>, ContractError> {
    match decode_canonical_padded(encoded, maximum_decoded_bytes) {
        Ok(decoded) => Ok(decoded),
        Err(Base64Error::InvalidEncoding) => Err(ContractError::new(
            ContractErrorKind::InvalidBase64,
            path,
            "field must use canonical padded RFC 4648 standard base64",
        )),
        Err(Base64Error::DecodedTooLarge) => Err(ContractError::new(
            ContractErrorKind::InvalidField,
            path,
            too_large_message,
        )),
    }
}

fn is_printable_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
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
