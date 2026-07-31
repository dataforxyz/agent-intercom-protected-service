use std::fs;
use std::path::PathBuf;

use agent_intercom_protected_service::{
    canonicalize_provisioning_request, validate_systemd_hardening, SYSTEMD_HARDENING_V1_JSON,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn text_file(path: &str) -> String {
    fs::read_to_string(root().join(path)).unwrap()
}

#[test]
fn schemas_are_closed_and_pin_the_same_literals_as_rust() {
    let provisioning = text_file("schemas/provisioning-request.v1.schema.json");
    assert_eq!(
        provisioning
            .matches("\"additionalProperties\": false")
            .count(),
        2
    );
    for literal in [
        "\"const\": \"provision\"",
        "\"const\": \"stable\"",
        "\"const\": \"linux-amd64\"",
        "\"pattern\": \"^[0-9a-f]{32}(?![\\\\s\\\\S])\"",
        "1844674407370955161[0-5]",
        "1844674407370955161[0-5])(?![\\\\s\\\\S])",
    ] {
        assert!(provisioning.contains(literal), "schema omitted {literal}");
    }
    assert!(!provisioning.contains("prerelease"));
    assert!(!provisioning.contains("buildMetadata"));
    assert!(provisioning.contains("Structural, non-authoritative"));
    assert!(provisioning.contains("Rust byte parser is mandatory"));

    let hardening = text_file("schemas/systemd-hardening.v1.schema.json");
    assert_eq!(
        hardening.matches("\"additionalProperties\": false").count(),
        1
    );
    for literal in [
        "\"AmbientCapabilities\": {\n      \"const\": []",
        "\"CapabilityBoundingSet\": {\n      \"const\": []",
        "\"NoNewPrivileges\": {\n      \"const\": \"yes\"",
        "\"PrivateTmp\": {\n      \"const\": \"yes\"",
        "\"ProtectHome\": {\n      \"const\": \"yes\"",
        "\"ProtectSystem\": {\n      \"const\": \"strict\"",
        "\"RestrictSUIDSGID\": {\n      \"const\": \"yes\"",
        "\"AF_UNIX\"",
    ] {
        assert!(hardening.contains(literal), "schema omitted {literal}");
    }
}

#[test]
fn shipped_hardening_data_is_the_validated_exact_object() {
    assert_eq!(
        fs::read(root().join("data/systemd-hardening.v1.json")).unwrap(),
        SYSTEMD_HARDENING_V1_JSON
    );
    assert!(validate_systemd_hardening(SYSTEMD_HARDENING_V1_JSON).is_ok());
}

#[test]
fn canonical_request_order_matches_the_declared_contract() {
    let input = br#"{
      "schema_version": 1,
      "request_id": "0123456789abcdef0123456789abcdef",
      "action": "provision",
      "release": {"version":"1.2.3","target":"linux-amd64","channel":"stable"}
    }"#;
    assert_eq!(
        canonicalize_provisioning_request(input).unwrap(),
        br#"{"action":"provision","release":{"channel":"stable","target":"linux-amd64","version":"1.2.3"},"request_id":"0123456789abcdef0123456789abcdef","schema_version":1}"#
    );
}
