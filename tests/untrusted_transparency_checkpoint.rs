use std::panic;

use agent_intercom_protected_service::{
    canonicalize_untrusted_transparency_checkpoint, ContractErrorKind,
    UntrustedTransparencyCheckpointV1, MAX_UNTRUSTED_TRANSPARENCY_CHECKPOINT_BYTES,
};

fn checkpoint(tree_size: &str) -> String {
    format!(
        "{{\"root_digest\":{{\"algorithm\":\"attacker.algorithm\",\"value\":\"opaque root claim\"}},\"schema_version\":1,\"tree_size\":{tree_size}}}"
    )
}

fn kind(input: &[u8]) -> ContractErrorKind {
    canonicalize_untrusted_transparency_checkpoint(input)
        .expect_err("hostile checkpoint must fail")
        .kind()
}

#[test]
fn parses_permuted_claim_and_emits_fixed_idempotent_canonical_json() {
    let input = br#"{
      "tree_size":18446744073709551615,
      "schema_version":1,
      "root_digest":{"value":"opaque \u0022root\u0022 \\ claim","algorithm":"unknown.algorithm_v999"}
    }"#;
    let parsed = UntrustedTransparencyCheckpointV1::parse(input).unwrap();
    assert_eq!(parsed.schema_version(), 1);
    assert_eq!(parsed.tree_size(), u64::MAX);
    assert_eq!(parsed.root_digest().algorithm(), "unknown.algorithm_v999");
    assert_eq!(parsed.root_digest().value(), "opaque \"root\" \\ claim");

    let canonical = br#"{"root_digest":{"algorithm":"unknown.algorithm_v999","value":"opaque \"root\" \\ claim"},"schema_version":1,"tree_size":18446744073709551615}"#;
    assert_eq!(parsed.canonical_bytes(), canonical);
    assert_eq!(
        canonicalize_untrusted_transparency_checkpoint(input).unwrap(),
        canonical
    );
    assert_eq!(
        canonicalize_untrusted_transparency_checkpoint(canonical).unwrap(),
        canonical
    );
}

#[test]
fn accepts_opaque_non_digest_claims_without_dispatch_or_length_inference() {
    for (algorithm, value) in [
        ("x", "?".to_owned()),
        ("not-a-hash", "three".to_owned()),
        (&"a".repeat(64), "~".repeat(512)),
    ] {
        let candidate = checkpoint("0")
            .replace("attacker.algorithm", algorithm)
            .replace("opaque root claim", &value);
        let parsed = UntrustedTransparencyCheckpointV1::parse(candidate.as_bytes()).unwrap();
        assert_eq!(parsed.root_digest().algorithm(), algorithm);
        assert_eq!(parsed.root_digest().value(), value);
    }
}

#[test]
fn enforces_closed_root_and_digest_shapes() {
    let baseline = checkpoint("42");
    for missing in [
        "\"root_digest\":{\"algorithm\":\"attacker.algorithm\",\"value\":\"opaque root claim\"},",
        "\"schema_version\":1,",
        ",\"tree_size\":42",
    ] {
        assert_eq!(
            kind(baseline.replace(missing, "").as_bytes()),
            ContractErrorKind::MissingField
        );
    }
    for field in [
        "log",
        "log_id",
        "witnesses",
        "signatures",
        "inclusion_proof",
        "consistency_proof",
        "endpoint",
        "keyid",
        "trusted",
        "accepted",
    ] {
        let hostile = baseline.replacen('{', &format!("{{\"{field}\":\"attacker\","), 1);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::UnknownField);
    }

    let duplicate = baseline.replacen(
        "\"tree_size\":42",
        "\"tree_size\":42,\"tree_\\u0073ize\":43",
        1,
    );
    assert_eq!(kind(duplicate.as_bytes()), ContractErrorKind::DuplicateKey);

    for (needle, replacement, expected) in [
        (
            "\"algorithm\":\"attacker.algorithm\",",
            "",
            ContractErrorKind::MissingField,
        ),
        (
            ",\"value\":\"opaque root claim\"",
            "",
            ContractErrorKind::MissingField,
        ),
        (
            "\"value\":\"opaque root claim\"",
            "\"value\":\"opaque root claim\",\"key\":\"attacker\"",
            ContractErrorKind::UnknownField,
        ),
        (
            "\"algorithm\":\"attacker.algorithm\"",
            "\"algorithm\":\"x\",\"algorith\\u006d\":\"y\"",
            ContractErrorKind::DuplicateKey,
        ),
    ] {
        assert_eq!(
            kind(baseline.replacen(needle, replacement, 1).as_bytes()),
            expected
        );
    }
    let non_object = baseline.replace(
        "{\"algorithm\":\"attacker.algorithm\",\"value\":\"opaque root claim\"}",
        "[]",
    );
    assert_eq!(kind(non_object.as_bytes()), ContractErrorKind::InvalidJson);
}

#[test]
fn accepts_only_exact_schema_one_and_canonical_u64_tree_size() {
    for valid in ["0", "1", "10", "18446744073709551615"] {
        let parsed =
            UntrustedTransparencyCheckpointV1::parse(checkpoint(valid).as_bytes()).unwrap();
        assert_eq!(parsed.tree_size().to_string(), valid);
    }
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
            kind(checkpoint(hostile).as_bytes()),
            ContractErrorKind::InvalidField
        );
    }
    for hostile in ["00", "01"] {
        assert_eq!(
            kind(checkpoint(hostile).as_bytes()),
            ContractErrorKind::InvalidJson
        );
    }
    for schema in ["0", "2", "1.0", "1e0", "-1", "true", "\"1\""] {
        let hostile = checkpoint("1").replace(
            "\"schema_version\":1",
            &format!("\"schema_version\":{schema}"),
        );
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }
}

#[test]
fn enforces_digest_claim_boundaries_and_transport_encoding() {
    let maximum = checkpoint("1")
        .replace("attacker.algorithm", &"a".repeat(64))
        .replace("opaque root claim", &"x".repeat(512));
    assert!(UntrustedTransparencyCheckpointV1::parse(maximum.as_bytes()).is_ok());

    for (needle, replacement) in [
        ("attacker.algorithm", String::new()),
        ("attacker.algorithm", "a".repeat(65)),
        ("opaque root claim", String::new()),
        ("opaque root claim", "x".repeat(513)),
    ] {
        assert_eq!(
            kind(checkpoint("1").replace(needle, &replacement).as_bytes()),
            ContractErrorKind::InvalidField
        );
    }
    for forbidden in ["/", ":", " ", "@", "+"] {
        assert_eq!(
            kind(
                checkpoint("1")
                    .replace("attacker.algorithm", &format!("bad{forbidden}label"))
                    .as_bytes()
            ),
            ContractErrorKind::InvalidField
        );
    }
    for hostile in ["line\\nbreak", "tab\\tvalue", "delete\\u007fvalue"] {
        assert_eq!(
            kind(
                checkpoint("1")
                    .replace("opaque root claim", hostile)
                    .as_bytes()
            ),
            ContractErrorKind::InvalidField
        );
    }

    let valid = checkpoint("1");
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(valid.as_bytes());
    assert_eq!(kind(&bom), ContractErrorKind::ByteOrderMark);
    let mut nul = valid.as_bytes().to_vec();
    nul.insert(1, 0);
    assert_eq!(kind(&nul), ContractErrorKind::NulByte);
    assert_eq!(kind(&[0xff]), ContractErrorKind::InvalidUtf8);
    assert_eq!(
        kind(valid.replace("opaque root claim", "rootí").as_bytes()),
        ContractErrorKind::NonAscii
    );
    assert_eq!(
        kind(valid.replace("opaque root claim", "root\\u0080").as_bytes()),
        ContractErrorKind::NonAscii
    );
}

#[test]
fn byte_limits_and_hostile_corpus_never_panic() {
    let minimal = checkpoint("0");
    let mut exact = vec![b' '; MAX_UNTRUSTED_TRANSPARENCY_CHECKPOINT_BYTES - minimal.len()];
    exact.extend_from_slice(minimal.as_bytes());
    assert!(UntrustedTransparencyCheckpointV1::parse(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(kind(&exact), ContractErrorKind::InputTooLarge);

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
        vec![0xff; MAX_UNTRUSTED_TRANSPARENCY_CHECKPOINT_BYTES + 1],
    ]);
    for hostile in corpus {
        let outcome =
            panic::catch_unwind(|| canonicalize_untrusted_transparency_checkpoint(&hostile));
        assert!(outcome.is_ok(), "parser panicked");
        assert!(outcome.unwrap().is_err(), "hostile corpus accepted");
    }
}
