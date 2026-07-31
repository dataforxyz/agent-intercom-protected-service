use std::panic;

use agent_intercom_protected_service::{
    canonicalize_untrusted_transparency_witness_claim, ContractErrorKind,
    UntrustedTransparencyWitnessClaimV1, MAX_UNTRUSTED_TRANSPARENCY_WITNESS_CLAIM_BYTES,
    MAX_UNTRUSTED_TRANSPARENCY_WITNESS_KEY_ID_BYTES,
    MAX_UNTRUSTED_TRANSPARENCY_WITNESS_LOG_ID_BYTES,
    MAX_UNTRUSTED_TRANSPARENCY_WITNESS_SIGNATURE_BYTES,
};

fn candidate(tree_size: &str, key_id: &str, log_id: &str, signature: &str) -> String {
    format!(
        "{{\"checkpoint\":{{\"root_digest\":{{\"algorithm\":\"root.alg\",\"value\":\"root value\"}},\"schema_version\":1,\"tree_size\":{tree_size}}},\"keyid\":\"{key_id}\",\"log_id\":\"{log_id}\",\"schema_version\":1,\"sig\":\"{signature}\"}}"
    )
}

fn kind(input: &[u8]) -> ContractErrorKind {
    canonicalize_untrusted_transparency_witness_claim(input)
        .expect_err("hostile witness claim must fail")
        .kind()
}

fn encode_padded(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in input.chunks(3) {
        let a = chunk[0];
        output.push(char::from(ALPHABET[usize::from(a >> 2)]));
        if chunk.len() == 1 {
            output.push(char::from(ALPHABET[usize::from((a & 3) << 4)]));
            output.push_str("==");
        } else {
            let b = chunk[1];
            output.push(char::from(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))]));
            output.push(char::from(
                ALPHABET[usize::from((b & 15) << 2 | chunk.get(2).copied().unwrap_or(0) >> 6)],
            ));
            if let Some(c) = chunk.get(2) {
                output.push(char::from(ALPHABET[usize::from(c & 63)]));
            } else {
                output.push('=');
            }
        }
    }
    output
}

#[test]
fn canonicalizes_permuted_singular_claim_idempotently() {
    let input = br#"{
      "sig":"AQI=",
      "schema_version":1,
      "log_id":"future.log_1",
      "keyid":"attacker \"key\"",
      "checkpoint":{"tree_size":9,"schema_version":1,"root_digest":{"value":"root value","algorithm":"root.alg"}}
    }"#;
    let parsed = UntrustedTransparencyWitnessClaimV1::parse(input).unwrap();
    assert_eq!(parsed.schema_version(), 1);
    assert_eq!(parsed.checkpoint().tree_size(), 9);
    assert_eq!(parsed.key_id(), "attacker \"key\"");
    assert_eq!(parsed.log_id(), "future.log_1");
    assert_eq!(parsed.signature_bytes(), &[1, 2]);

    let canonical = br#"{"checkpoint":{"root_digest":{"algorithm":"root.alg","value":"root value"},"schema_version":1,"tree_size":9},"keyid":"attacker \"key\"","log_id":"future.log_1","schema_version":1,"sig":"AQI="}"#;
    assert_eq!(parsed.canonical_bytes(), canonical);
    assert_eq!(
        canonicalize_untrusted_transparency_witness_claim(canonical).unwrap(),
        canonical
    );
}

#[test]
fn preserves_semantically_false_unknown_and_empty_identity_claims() {
    for case in [
        candidate("0", "", "unknown", "AA=="),
        candidate("18446744073709551615", "nobody", "not-a-real-log", "AQ=="),
        candidate("0", "duplicate-looking", "opaque.log", "////"),
    ] {
        let parsed = UntrustedTransparencyWitnessClaimV1::parse(case.as_bytes()).unwrap();
        assert_eq!(
            canonicalize_untrusted_transparency_witness_claim(&parsed.canonical_bytes()).unwrap(),
            parsed.canonical_bytes()
        );
    }
}

#[test]
fn enforces_closed_shapes_and_duplicate_safe_keys_at_every_level() {
    let baseline = candidate("7", "key", "log", "AQ==");
    for missing in [
        "\"checkpoint\":{\"root_digest\":{\"algorithm\":\"root.alg\",\"value\":\"root value\"},\"schema_version\":1,\"tree_size\":7},",
        "\"keyid\":\"key\",",
        "\"log_id\":\"log\",",
        ",\"schema_version\":1",
        ",\"sig\":\"AQ==\"",
    ] {
        assert_eq!(kind(baseline.replace(missing, "").as_bytes()), ContractErrorKind::MissingField);
    }
    for field in [
        "witness",
        "witnesses",
        "threshold",
        "quorum",
        "eligible",
        "independent",
        "endpoint",
        "algorithm",
        "signed_bytes",
        "verified",
        "trusted",
        "accepted",
        "manifest",
        "release",
        "timestamp",
        "fresh",
        "monotonic",
        "authority",
    ] {
        let hostile = baseline.replacen('{', &format!("{{\"{field}\":true,"), 1);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::UnknownField);
    }
    for (needle, duplicate) in [
        (
            "\"log_id\":\"log\"",
            "\"log_id\":\"log\",\"log_\\u0069d\":\"other\"",
        ),
        ("\"tree_size\":7", "\"tree_size\":7,\"tree_\\u0073ize\":8"),
        (
            "\"value\":\"root value\"",
            "\"value\":\"root value\",\"val\\u0075e\":\"other\"",
        ),
    ] {
        assert_eq!(
            kind(baseline.replacen(needle, duplicate, 1).as_bytes()),
            ContractErrorKind::DuplicateKey
        );
    }
}

#[test]
fn accepts_only_exact_schema_one_and_canonical_tree_size() {
    for size in ["0", "1", "10", "18446744073709551615"] {
        assert!(UntrustedTransparencyWitnessClaimV1::parse(
            candidate(size, "", "log", "AQ==").as_bytes()
        )
        .is_ok());
    }
    assert_eq!(
        kind(candidate("01", "", "log", "AQ==").as_bytes()),
        ContractErrorKind::InvalidJson
    );
    for hostile in [
        "-1",
        "1.0",
        "1e0",
        "18446744073709551616",
        "true",
        "null",
        "\"1\"",
    ] {
        assert_eq!(
            kind(candidate(hostile, "", "log", "AQ==").as_bytes()),
            ContractErrorKind::InvalidField
        );
    }
    for schema in ["0", "2", "1.0", "1e0", "-1", "true", "\"1\""] {
        for occurrence in [1, 2] {
            let mut hostile = candidate("1", "", "log", "AQ==");
            let mut start = 0;
            for index in 0..occurrence {
                let relative = hostile[start..].find("\"schema_version\":1").unwrap();
                start += relative;
                if index + 1 == occurrence {
                    hostile.replace_range(
                        start..start + "\"schema_version\":1".len(),
                        &format!("\"schema_version\":{schema}"),
                    );
                    break;
                }
                start += 1;
            }
            assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
        }
    }
}

#[test]
fn enforces_key_log_digest_and_signature_bounds() {
    assert_eq!(MAX_UNTRUSTED_TRANSPARENCY_WITNESS_KEY_ID_BYTES, 128);
    assert_eq!(MAX_UNTRUSTED_TRANSPARENCY_WITNESS_LOG_ID_BYTES, 128);
    assert_eq!(MAX_UNTRUSTED_TRANSPARENCY_WITNESS_SIGNATURE_BYTES, 4_096);
    let maximum_signature = encode_padded(&vec![0xa5; 4_096]);
    let maximum = candidate("1", &"k".repeat(128), &"l".repeat(128), &maximum_signature)
        .replace("root.alg", &"a".repeat(64))
        .replace("root value", &"v".repeat(512));
    assert!(UntrustedTransparencyWitnessClaimV1::parse(maximum.as_bytes()).is_ok());

    for (key, log) in [
        ("k".repeat(129), "log".into()),
        ("key".into(), String::new()),
        ("key".into(), "l".repeat(129)),
        ("key".into(), "https://log".into()),
        ("key".into(), "path/log".into()),
        ("key".into(), "log:1".into()),
    ] {
        assert_eq!(
            kind(candidate("1", &key, &log, "AQ==").as_bytes()),
            ContractErrorKind::InvalidField
        );
    }
    assert_eq!(
        kind(candidate("1", "line\\nbreak", "log", "AQ==").as_bytes()),
        ContractErrorKind::InvalidField
    );
    for (needle, replacement) in [
        ("root.alg", String::new()),
        ("root.alg", "a".repeat(65)),
        ("root value", String::new()),
        ("root value", "v".repeat(513)),
    ] {
        assert_eq!(
            kind(
                candidate("1", "", "log", "AQ==")
                    .replace(needle, &replacement)
                    .as_bytes()
            ),
            ContractErrorKind::InvalidField
        );
    }
    let too_large_signature = encode_padded(&vec![0; 4_097]);
    assert_eq!(
        kind(candidate("1", "", "log", &too_large_signature).as_bytes()),
        ContractErrorKind::InvalidField
    );
}

#[test]
fn rejects_noncanonical_or_empty_base64_without_inferring_algorithm() {
    for hostile in [
        "", "A", "AQ", "AQI", "AQI", "AQI-", "AQI_", "AQ I=", "AR==", "AQJ=", "AQ===", "=Q==",
    ] {
        assert!(matches!(
            kind(candidate("1", "", "log", hostile).as_bytes()),
            ContractErrorKind::InvalidBase64 | ContractErrorKind::InvalidField
        ));
    }
    for valid in ["AA==", "AQI=", "AQID", "////", "AAAA"] {
        assert!(UntrustedTransparencyWitnessClaimV1::parse(
            candidate("1", "", "log", valid).as_bytes()
        )
        .is_ok());
    }
}

#[test]
fn enforces_transport_boundaries_and_byte_limit_first() {
    let minimal = candidate("0", "", "l", "AA==");
    let mut exact = vec![b' '; MAX_UNTRUSTED_TRANSPARENCY_WITNESS_CLAIM_BYTES - minimal.len()];
    exact.extend_from_slice(minimal.as_bytes());
    assert!(UntrustedTransparencyWitnessClaimV1::parse(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(kind(&exact), ContractErrorKind::InputTooLarge);
    assert_eq!(
        kind(&vec![
            0xff;
            MAX_UNTRUSTED_TRANSPARENCY_WITNESS_CLAIM_BYTES + 1
        ]),
        ContractErrorKind::InputTooLarge
    );

    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(minimal.as_bytes());
    assert_eq!(kind(&bom), ContractErrorKind::ByteOrderMark);
    let mut nul = minimal.as_bytes().to_vec();
    nul.insert(1, 0);
    assert_eq!(kind(&nul), ContractErrorKind::NulByte);
    assert_eq!(kind(&[0xff]), ContractErrorKind::InvalidUtf8);
    assert_eq!(
        kind(minimal.replace("root value", "rootí").as_bytes()),
        ContractErrorKind::NonAscii
    );
}

#[test]
fn malformed_truncated_and_deep_corpus_never_panics() {
    let minimal = candidate("0", "", "l", "AA==");
    let mut corpus: Vec<Vec<u8>> = minimal
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(length, _)| minimal.as_bytes()[..length].to_vec())
        .collect();
    for depth in [63, 64, 65, 66] {
        corpus.push(format!("{}0{}", "[".repeat(depth), "]".repeat(depth)).into_bytes());
    }
    corpus.extend([
        Vec::new(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"{} trailing".to_vec(),
    ]);
    for hostile in corpus {
        let outcome =
            panic::catch_unwind(|| canonicalize_untrusted_transparency_witness_claim(&hostile));
        assert!(outcome.is_ok(), "parser panicked");
        assert!(outcome.unwrap().is_err(), "hostile corpus accepted");
    }
}
