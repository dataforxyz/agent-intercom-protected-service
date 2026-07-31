use agent_intercom_protected_service::{
    validate_systemd_hardening, ContractErrorKind, MAX_SYSTEMD_HARDENING_BYTES,
    SYSTEMD_HARDENING_V1_JSON,
};

const COMPACT: &str = concat!(
    "{\"schema_version\":1,\"ProtectHome\":\"yes\",\"ProtectSystem\":\"strict\",",
    "\"NoNewPrivileges\":\"yes\",\"CapabilityBoundingSet\":[],\"AmbientCapabilities\":[],",
    "\"RestrictSUIDSGID\":\"yes\",\"PrivateTmp\":\"yes\",",
    "\"RestrictAddressFamilies\":[\"AF_UNIX\"]}"
);

fn kind(input: &[u8]) -> ContractErrorKind {
    validate_systemd_hardening(input)
        .expect_err("hostile hardening data must fail")
        .kind()
}

#[test]
fn accepts_only_the_exact_inert_contract_semantics_in_any_key_order() {
    assert!(validate_systemd_hardening(SYSTEMD_HARDENING_V1_JSON).is_ok());
    assert!(validate_systemd_hardening(COMPACT.as_bytes()).is_ok());
}

#[test]
fn rejects_every_weakening_or_unsupported_value() {
    for (needle, replacement) in [
        ("\"ProtectHome\":\"yes\"", "\"ProtectHome\":\"read-only\""),
        ("\"ProtectSystem\":\"strict\"", "\"ProtectSystem\":\"full\""),
        ("\"NoNewPrivileges\":\"yes\"", "\"NoNewPrivileges\":\"no\""),
        (
            "\"RestrictSUIDSGID\":\"yes\"",
            "\"RestrictSUIDSGID\":\"no\"",
        ),
        ("\"PrivateTmp\":\"yes\"", "\"PrivateTmp\":\"no\""),
    ] {
        let hostile = COMPACT.replace(needle, replacement);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }
}

#[test]
fn rejects_capabilities_and_network_address_families() {
    for replacement in [
        "[\"CAP_SYS_ADMIN\"]",
        "[\"CAP_NET_ADMIN\"]",
        "[\"\"]",
        "\"\"",
        "null",
    ] {
        let bounding = COMPACT.replace(
            "\"CapabilityBoundingSet\":[]",
            &format!("\"CapabilityBoundingSet\":{replacement}"),
        );
        assert_eq!(kind(bounding.as_bytes()), ContractErrorKind::InvalidField);

        let ambient = COMPACT.replace(
            "\"AmbientCapabilities\":[]",
            &format!("\"AmbientCapabilities\":{replacement}"),
        );
        assert_eq!(kind(ambient.as_bytes()), ContractErrorKind::InvalidField);
    }

    for replacement in [
        "[]",
        "[\"AF_INET\"]",
        "[\"AF_INET6\"]",
        "[\"AF_UNIX\",\"AF_INET\"]",
        "[\"AF_UNIX\",\"AF_UNIX\"]",
        "\"AF_UNIX\"",
    ] {
        let hostile = COMPACT.replace("[\"AF_UNIX\"]", replacement);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }
}

#[test]
fn rejects_additions_omissions_duplicates_and_number_variants() {
    let addition = COMPACT.replacen('{', "{\"IPAddressDeny\":\"any\",", 1);
    assert_eq!(kind(addition.as_bytes()), ContractErrorKind::UnknownField);

    let nested_duplicate = COMPACT.replacen('{', "{\"unknown\":{\"x\":1,\"x\":1},", 1);
    assert_eq!(
        kind(nested_duplicate.as_bytes()),
        ContractErrorKind::DuplicateKey
    );

    let duplicate = COMPACT.replace(
        "\"ProtectHome\":\"yes\"",
        "\"ProtectHome\":\"yes\",\"ProtectHome\":\"yes\"",
    );
    assert_eq!(kind(duplicate.as_bytes()), ContractErrorKind::DuplicateKey);

    for needle in [
        "\"schema_version\":1,",
        "\"ProtectHome\":\"yes\",",
        "\"ProtectSystem\":\"strict\",",
        "\"NoNewPrivileges\":\"yes\",",
        "\"CapabilityBoundingSet\":[],",
        "\"AmbientCapabilities\":[],",
        "\"RestrictSUIDSGID\":\"yes\",",
        "\"PrivateTmp\":\"yes\",",
        ",\"RestrictAddressFamilies\":[\"AF_UNIX\"]",
    ] {
        let missing = COMPACT.replace(needle, "");
        assert_eq!(kind(missing.as_bytes()), ContractErrorKind::MissingField);
    }

    for replacement in ["1.0", "1e0", "-0", "0", "2", "\"1\""] {
        let hostile = COMPACT.replace(
            "\"schema_version\":1",
            &format!("\"schema_version\":{replacement}"),
        );
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }
}

#[test]
fn rejects_encoding_attacks_and_excessive_input() {
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(COMPACT.as_bytes());
    assert_eq!(kind(&bom), ContractErrorKind::ByteOrderMark);

    let mut nul = COMPACT.as_bytes().to_vec();
    nul.insert(1, 0);
    assert_eq!(kind(&nul), ContractErrorKind::NulByte);
    assert_eq!(kind(&[0xff]), ContractErrorKind::InvalidUtf8);

    let confusable = COMPACT.replace("AF_UNIX", "AF_UNІX");
    assert_eq!(kind(confusable.as_bytes()), ContractErrorKind::NonAscii);

    let escaped = COMPACT.replace("AF_UNIX", "AF_UN\\u0406X");
    assert_eq!(kind(escaped.as_bytes()), ContractErrorKind::NonAscii);

    let oversized = vec![b' '; MAX_SYSTEMD_HARDENING_BYTES + 1];
    assert_eq!(kind(&oversized), ContractErrorKind::InputTooLarge);
}
