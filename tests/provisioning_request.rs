use agent_intercom_protected_service::{
    canonicalize_provisioning_request, ContractErrorKind, ProvisioningAction,
    ProvisioningRequestV1, ReleaseChannel, ReleaseTarget, MAX_PROVISIONING_REQUEST_BYTES,
};

const REQUEST_ID: &str = "0123456789abcdef0123456789abcdef";
const CANONICAL: &str = concat!(
    "{\"action\":\"provision\",",
    "\"release\":{\"channel\":\"stable\",\"target\":\"linux-amd64\",\"version\":\"1.2.3\"},",
    "\"request_id\":\"0123456789abcdef0123456789abcdef\",\"schema_version\":1}"
);

fn request(version: &str) -> String {
    format!(
        "{{\"schema_version\":1,\"request_id\":\"{REQUEST_ID}\",\"action\":\"provision\",\"release\":{{\"channel\":\"stable\",\"version\":\"{version}\",\"target\":\"linux-amd64\"}}}}"
    )
}

fn kind(input: &[u8]) -> ContractErrorKind {
    canonicalize_provisioning_request(input)
        .expect_err("hostile request must fail")
        .kind()
}

#[test]
fn canonicalizes_whitespace_and_arbitrary_input_key_order() {
    let input = format!(
        " \n{{ \"request_id\" : \"{REQUEST_ID}\", \"release\" : {{ \"version\":\"1.2.3\", \"target\":\"linux-amd64\", \"channel\":\"stable\" }}, \"schema_version\":1, \"action\":\"provision\" }}\t"
    );
    let canonical = canonicalize_provisioning_request(input.as_bytes()).unwrap();
    assert_eq!(canonical, CANONICAL.as_bytes());
    assert!(!canonical.ends_with(b"\n"));
}

#[test]
fn canonicalization_is_idempotent() {
    let once = canonicalize_provisioning_request(CANONICAL.as_bytes()).unwrap();
    let twice = canonicalize_provisioning_request(&once).unwrap();
    assert_eq!(once, twice);
}

#[test]
fn typed_parse_surface_preserves_validated_invariants() {
    let parsed = ProvisioningRequestV1::parse(request("1.2.3").as_bytes()).unwrap();
    assert_eq!(parsed.schema_version(), 1);
    assert_eq!(parsed.request_id(), REQUEST_ID);
    assert_eq!(parsed.action(), ProvisioningAction::Provision);
    assert_eq!(parsed.release().channel(), ReleaseChannel::Stable);
    assert_eq!(parsed.release().target(), ReleaseTarget::LinuxAmd64);
    assert_eq!(parsed.release().version().major(), 1);
    assert_eq!(parsed.release().version().minor(), 2);
    assert_eq!(parsed.release().version().patch(), 3);
    assert_eq!(parsed.canonical_bytes(), CANONICAL.as_bytes());
}

#[test]
fn enforces_the_byte_limit_before_json_parsing() {
    let core = request("1.2.3");
    let mut exact = core.into_bytes();
    exact.resize(MAX_PROVISIONING_REQUEST_BYTES, b' ');
    assert_eq!(exact.len(), MAX_PROVISIONING_REQUEST_BYTES);
    assert!(canonicalize_provisioning_request(&exact).is_ok());

    exact.push(b' ');
    assert_eq!(kind(&exact), ContractErrorKind::InputTooLarge);

    let oversized_invalid = vec![0xff; MAX_PROVISIONING_REQUEST_BYTES + 1];
    assert_eq!(kind(&oversized_invalid), ContractErrorKind::InputTooLarge);
}

#[test]
fn rejects_bom_nul_invalid_utf8_and_non_ascii_or_confusable_text() {
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(request("1.2.3").as_bytes());
    assert_eq!(kind(&bom), ContractErrorKind::ByteOrderMark);

    let mut nul = request("1.2.3").into_bytes();
    nul.insert(3, 0);
    assert_eq!(kind(&nul), ContractErrorKind::NulByte);

    assert_eq!(kind(&[0xff, b'{', b'}']), ContractErrorKind::InvalidUtf8);

    let raw_confusable = request("1.2.3").replace("stable", "stаble");
    assert_eq!(kind(raw_confusable.as_bytes()), ContractErrorKind::NonAscii);

    let escaped_confusable = request("1.2.3").replace("stable", "st\\u0430ble");
    assert_eq!(
        kind(escaped_confusable.as_bytes()),
        ContractErrorKind::NonAscii
    );

    let escaped_utf8_sequence = request("1.2.3").replace("stable", "\\u00c3\\u00a9");
    assert_eq!(
        kind(escaped_utf8_sequence.as_bytes()),
        ContractErrorKind::NonAscii
    );

    for value in 0x80..=0xff {
        let escaped_non_ascii =
            request("1.2.3").replace("stable", &format!("st\\u{value:04x}able"));
        assert_eq!(
            kind(escaped_non_ascii.as_bytes()),
            ContractErrorKind::NonAscii,
            "escaped non-ASCII value U+{value:04X} was not rejected"
        );
    }
}

#[test]
fn rejects_duplicate_keys_at_every_depth_before_projection() {
    let root_duplicate = format!(
        "{{\"action\":\"provision\",\"action\":\"provision\",\"release\":{{\"channel\":\"stable\",\"target\":\"linux-amd64\",\"version\":\"1.2.3\"}},\"request_id\":\"{REQUEST_ID}\",\"schema_version\":1}}"
    );
    assert_eq!(
        kind(root_duplicate.as_bytes()),
        ContractErrorKind::DuplicateKey
    );

    let release_duplicate = format!(
        "{{\"action\":\"provision\",\"release\":{{\"channel\":\"stable\",\"target\":\"linux-amd64\",\"version\":\"1.2.3\",\"version\":\"1.2.3\"}},\"request_id\":\"{REQUEST_ID}\",\"schema_version\":1}}"
    );
    assert_eq!(
        kind(release_duplicate.as_bytes()),
        ContractErrorKind::DuplicateKey
    );

    let duplicate_inside_unknown = format!(
        "{{\"action\":\"provision\",\"release\":{{\"channel\":\"stable\",\"target\":\"linux-amd64\",\"version\":\"1.2.3\"}},\"request_id\":\"{REQUEST_ID}\",\"schema_version\":1,\"unknown\":{{\"x\":1,\"x\":1}}}}"
    );
    assert_eq!(
        kind(duplicate_inside_unknown.as_bytes()),
        ContractErrorKind::DuplicateKey
    );

    let escaped_duplicate = format!(
        "{{\"action\":\"provision\",\"acti\\u006fn\":\"provision\",\"release\":{{\"channel\":\"stable\",\"target\":\"linux-amd64\",\"version\":\"1.2.3\"}},\"request_id\":\"{REQUEST_ID}\",\"schema_version\":1}}"
    );
    assert_eq!(
        kind(escaped_duplicate.as_bytes()),
        ContractErrorKind::DuplicateKey
    );

    let nested_prefix = "{\"nested\":".repeat(40);
    let nested_suffix = "}".repeat(40);
    let deep_duplicate = format!(
        "{{\"action\":\"provision\",\"release\":{{\"channel\":\"stable\",\"target\":\"linux-amd64\",\"version\":\"1.2.3\"}},\"request_id\":\"{REQUEST_ID}\",\"schema_version\":1,\"unknown\":{nested_prefix}{{\"x\":1,\"x\":1}}{nested_suffix}}}"
    );
    assert_eq!(
        kind(deep_duplicate.as_bytes()),
        ContractErrorKind::DuplicateKey
    );
}

#[test]
fn rejects_noncanonical_number_spellings_and_types() {
    for schema_version in ["1.0", "1e0", "1E+0", "-0", "-1", "0", "2"] {
        let hostile = request("1.2.3").replace(
            "\"schema_version\":1",
            &format!("\"schema_version\":{schema_version}"),
        );
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }

    for schema_version in ["true", "false", "null", "\"1\"", "[]", "{}"] {
        let hostile = request("1.2.3").replace(
            "\"schema_version\":1",
            &format!("\"schema_version\":{schema_version}"),
        );
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }
}

#[test]
fn accepts_only_three_canonical_decimal_u64_version_components() {
    for valid in [
        "0.0.0",
        "1.2.3",
        "10.20.30",
        "18446744073709551615.18446744073709551615.18446744073709551615",
    ] {
        assert!(
            canonicalize_provisioning_request(request(valid).as_bytes()).is_ok(),
            "valid version rejected: {valid}"
        );
    }

    for invalid in [
        "",
        "1",
        "1.2",
        "1.2.3.4",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "+1.2.3",
        "-1.2.3",
        "v1.2.3",
        "1.2.3-alpha",
        "1.2.3+build",
        "1.2.3 ",
        "18446744073709551616.0.0",
        "0.18446744073709551616.0",
        "0.0.18446744073709551616",
    ] {
        assert_eq!(
            kind(request(invalid).as_bytes()),
            ContractErrorKind::InvalidField,
            "invalid version accepted: {invalid}"
        );
    }
}

#[test]
fn rejects_line_terminators_after_schema_pattern_fields() {
    for (escaped_terminator, expected) in [
        ("\\r", ContractErrorKind::InvalidField),
        ("\\n", ContractErrorKind::InvalidField),
        ("\\u2028", ContractErrorKind::NonAscii),
        ("\\u2029", ContractErrorKind::NonAscii),
    ] {
        let version = request(&format!("1.2.3{escaped_terminator}"));
        assert_eq!(
            kind(version.as_bytes()),
            expected,
            "version accepted a trailing {escaped_terminator}"
        );

        let request_id =
            request("1.2.3").replace(REQUEST_ID, &format!("{REQUEST_ID}{escaped_terminator}"));
        assert_eq!(
            kind(request_id.as_bytes()),
            expected,
            "request_id accepted a trailing {escaped_terminator}"
        );
    }
}

#[test]
fn rejects_bad_identifiers_literals_missing_and_unknown_fields() {
    for request_id in [
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef0",
        "0123456789ABCDEF0123456789ABCDEF",
        "g123456789abcdef0123456789abcdef",
    ] {
        let hostile = request("1.2.3").replace(REQUEST_ID, request_id);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }

    for (needle, replacement) in [
        ("\"provision\"", "\"install\""),
        ("\"stable\"", "\"latest\""),
        ("\"linux-amd64\"", "\"linux-arm64\""),
    ] {
        let hostile = request("1.2.3").replacen(needle, replacement, 1);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }

    for hostile in [
        request("1.2.3").replace("\"action\":\"provision\",", ""),
        request("1.2.3").replace(
            ",\"release\":{\"channel\":\"stable\",\"version\":\"1.2.3\",\"target\":\"linux-amd64\"}",
            "",
        ),
        request("1.2.3").replace(
            &format!("\"request_id\":\"{REQUEST_ID}\","),
            "",
        ),
        request("1.2.3").replace("\"schema_version\":1,", ""),
        request("1.2.3").replace("\"channel\":\"stable\",", ""),
        request("1.2.3").replace(",\"version\":\"1.2.3\"", ""),
        request("1.2.3").replace(",\"target\":\"linux-amd64\"", ""),
    ] {
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::MissingField);
    }
}

#[test]
fn rejects_every_forbidden_field_family_as_unknown_data() {
    for field in [
        "path",
        "url",
        "command",
        "env",
        "digest",
        "key",
        "user",
        "group",
        "unit",
        "signature",
        "trustedReleaseKeys",
        "__proto__",
        "constructor",
    ] {
        let mut hostile = request("1.2.3");
        hostile.pop();
        hostile.push_str(&format!(",\"{field}\":\"attacker-controlled\"}}"));
        assert_eq!(
            kind(hostile.as_bytes()),
            ContractErrorKind::UnknownField,
            "forbidden field accepted: {field}"
        );
    }

    for field in ["path", "url", "command", "env", "digest", "key", "unit"] {
        let hostile = request("1.2.3").replace(
            "\"target\":\"linux-amd64\"",
            &format!("\"target\":\"linux-amd64\",\"{field}\":\"attacker\""),
        );
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::UnknownField);
    }
}

#[test]
fn rejects_non_object_inherited_analogs_and_trailing_values() {
    for input in [
        b"null".as_slice(),
        b"[]".as_slice(),
        b"true".as_slice(),
        b"1".as_slice(),
        b"\"request\"".as_slice(),
        b"".as_slice(),
    ] {
        assert!(canonicalize_provisioning_request(input).is_err());
    }

    let trailing = format!("{} {{}}", request("1.2.3"));
    assert_eq!(kind(trailing.as_bytes()), ContractErrorKind::InvalidJson);
}

#[test]
fn normalizes_ascii_escapes_and_rejects_malformed_or_excessively_nested_json() {
    let escaped = request("1.2.3")
        .replace("\"action\"", "\"acti\\u006fn\"")
        .replace("stable", "st\\u0061ble")
        .replace("linux-amd64", "linux-amd\\u0036\\u0034");
    assert_eq!(
        canonicalize_provisioning_request(escaped.as_bytes()).unwrap(),
        CANONICAL.as_bytes()
    );

    let escaped_nul = request("1.2.3").replace("stable", "st\\u0000able");
    assert_eq!(kind(escaped_nul.as_bytes()), ContractErrorKind::NulByte);

    for malformed in [
        "{",
        "{} trailing",
        "{\"action\":}",
        "{\"action\":\"bad\\xescape\"}",
        "{\"action\":\"bad\\u12zz\"}",
        "{\"schema_version\":01}",
        "{\"schema_version\":1.}",
        "{\"schema_version\":1e}",
        "{\"schema_version\":+1}",
        "[, ]",
        "{\"x\":1,}",
    ] {
        assert_eq!(kind(malformed.as_bytes()), ContractErrorKind::InvalidJson);
    }

    let too_deep = format!("{}0{}", "[".repeat(66), "]".repeat(66));
    assert_eq!(kind(too_deep.as_bytes()), ContractErrorKind::InvalidJson);
}
