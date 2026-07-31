use std::panic;

use agent_intercom_protected_service::{
    canonicalize_untrusted_transparency_consistency_proof, ContractErrorKind,
    UntrustedTransparencyConsistencyProofV1, MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_BYTES,
    MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_NODES,
};

fn candidate(from: &str, to: &str, proof: &str) -> String {
    format!(
        "{{\"from_checkpoint\":{{\"root_digest\":{{\"algorithm\":\"from.alg\",\"value\":\"from root\"}},\"schema_version\":1,\"tree_size\":{from}}},\"proof\":[{proof}],\"schema_version\":1,\"to_checkpoint\":{{\"root_digest\":{{\"algorithm\":\"to.alg\",\"value\":\"to root\"}},\"schema_version\":1,\"tree_size\":{to}}}}}"
    )
}

fn node(value: &str) -> String {
    format!("{{\"algorithm\":\"node.alg\",\"value\":\"{value}\"}}")
}

fn kind(input: &[u8]) -> ContractErrorKind {
    canonicalize_untrusted_transparency_consistency_proof(input)
        .expect_err("hostile consistency claim must fail")
        .kind()
}

#[test]
fn canonicalizes_permuted_self_contained_claim_idempotently() {
    let input = br#"{
      "to_checkpoint":{"tree_size":9,"schema_version":1,"root_digest":{"value":"to \"root\"","algorithm":"to.alg"}},
      "schema_version":1,
      "proof":[{"value":"node \\ one","algorithm":"node.alg"},{"algorithm":"node.alg","value":"node \\ one"}],
      "from_checkpoint":{"tree_size":7,"root_digest":{"value":"from root","algorithm":"from.alg"},"schema_version":1}
    }"#;
    let parsed = UntrustedTransparencyConsistencyProofV1::parse(input).unwrap();
    assert_eq!(parsed.schema_version(), 1);
    assert_eq!(parsed.from_checkpoint().tree_size(), 7);
    assert_eq!(parsed.to_checkpoint().tree_size(), 9);
    assert_eq!(parsed.proof().len(), 2);
    assert_eq!(parsed.proof()[0], parsed.proof()[1]);

    let canonical = br#"{"from_checkpoint":{"root_digest":{"algorithm":"from.alg","value":"from root"},"schema_version":1,"tree_size":7},"proof":[{"algorithm":"node.alg","value":"node \\ one"},{"algorithm":"node.alg","value":"node \\ one"}],"schema_version":1,"to_checkpoint":{"root_digest":{"algorithm":"to.alg","value":"to \"root\""},"schema_version":1,"tree_size":9}}"#;
    assert_eq!(parsed.canonical_bytes(), canonical);
    assert_eq!(
        canonicalize_untrusted_transparency_consistency_proof(canonical).unwrap(),
        canonical
    );
}

#[test]
fn preserves_semantically_hostile_claims_without_proof_or_ordering_checks() {
    let cases = [
        candidate("9", "7", ""),
        candidate("7", "7", &node("repeated")),
        candidate(
            "0",
            "18446744073709551615",
            &format!("{},{}", node("x"), node("x")),
        ),
    ];
    for case in cases {
        let parsed = UntrustedTransparencyConsistencyProofV1::parse(case.as_bytes()).unwrap();
        assert_eq!(
            canonicalize_untrusted_transparency_consistency_proof(&parsed.canonical_bytes())
                .unwrap(),
            parsed.canonical_bytes()
        );
    }

    let mixed = candidate("3", "4", &node("opaque"))
        .replace("node.alg", "unknown.algorithm_v999")
        .replace("from.alg", "different.from")
        .replace("to.alg", "different.to");
    assert!(UntrustedTransparencyConsistencyProofV1::parse(mixed.as_bytes()).is_ok());
}

#[test]
fn enforces_closed_shapes_and_duplicate_safe_keys_at_every_level() {
    let baseline = candidate("7", "9", &node("one"));
    for missing in [
        "\"from_checkpoint\":{\"root_digest\":{\"algorithm\":\"from.alg\",\"value\":\"from root\"},\"schema_version\":1,\"tree_size\":7},",
        "\"proof\":[{\"algorithm\":\"node.alg\",\"value\":\"one\"}],",
        "\"schema_version\":1,",
        ",\"to_checkpoint\":{\"root_digest\":{\"algorithm\":\"to.alg\",\"value\":\"to root\"},\"schema_version\":1,\"tree_size\":9}",
    ] {
        assert_eq!(kind(baseline.replace(missing, "").as_bytes()), ContractErrorKind::MissingField);
    }
    for field in [
        "log",
        "log_id",
        "active_log",
        "endpoint",
        "keyid",
        "signatures",
        "witnesses",
        "threshold",
        "manifest_digest",
        "release",
        "channel",
        "target",
        "version",
        "inclusion_proof",
        "timestamp",
        "fresh",
        "monotonic",
        "trusted",
        "verified",
        "accepted",
        "authorized",
        "policy",
    ] {
        let hostile = baseline.replacen('{', &format!("{{\"{field}\":\"attacker\","), 1);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::UnknownField);
    }
    let duplicate_root = baseline.replacen("\"proof\":[", "\"proof\":[],\"pr\\u006fof\":[", 1);
    assert_eq!(
        kind(duplicate_root.as_bytes()),
        ContractErrorKind::DuplicateKey
    );
    let duplicate_nested = baseline.replacen(
        "\"tree_size\":7",
        "\"tree_size\":7,\"tree_\\u0073ize\":8",
        1,
    );
    assert_eq!(
        kind(duplicate_nested.as_bytes()),
        ContractErrorKind::DuplicateKey
    );
    let duplicate_node = baseline.replacen(
        "\"value\":\"one\"",
        "\"value\":\"one\",\"val\\u0075e\":\"two\"",
        1,
    );
    assert_eq!(
        kind(duplicate_node.as_bytes()),
        ContractErrorKind::DuplicateKey
    );

    for hostile in [
        baseline
            .replace("\"proof\":[", "\"proof\":{")
            .replace("}],\"schema_version\"", "}},\"schema_version\""),
        baseline.replace(&node("one"), "[]"),
        baseline
            .replace("\"from_checkpoint\":{", "\"from_checkpoint\":[")
            .replacen("},\"proof\"", "],\"proof\"", 1),
    ] {
        assert!(matches!(
            kind(hostile.as_bytes()),
            ContractErrorKind::InvalidField | ContractErrorKind::InvalidJson
        ));
    }
}

#[test]
fn accepts_only_exact_schema_one_and_canonical_u64_tree_sizes() {
    for valid in ["0", "1", "10", "18446744073709551615"] {
        assert!(UntrustedTransparencyConsistencyProofV1::parse(
            candidate(valid, valid, "").as_bytes()
        )
        .is_ok());
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
            kind(candidate(hostile, "1", "").as_bytes()),
            ContractErrorKind::InvalidField
        );
        assert_eq!(
            kind(candidate("1", hostile, "").as_bytes()),
            ContractErrorKind::InvalidField
        );
    }
    for schema in ["0", "2", "1.0", "1e0", "-1", "true", "\"1\""] {
        for occurrence in [1, 2, 3] {
            let mut hostile = candidate("1", "2", "");
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
fn enforces_proof_count_and_preserves_order_and_duplicates() {
    let sixty_four = (0..MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_NODES)
        .map(|index| node(&format!("node-{index}")))
        .collect::<Vec<_>>()
        .join(",");
    let parsed =
        UntrustedTransparencyConsistencyProofV1::parse(candidate("1", "2", &sixty_four).as_bytes())
            .unwrap();
    assert_eq!(parsed.proof().len(), 64);
    assert_eq!(parsed.proof()[0].value(), "node-0");
    assert_eq!(parsed.proof()[63].value(), "node-63");

    let sixty_five = format!("{sixty_four},{}", node("overflow"));
    assert_eq!(
        kind(candidate("1", "2", &sixty_five).as_bytes()),
        ContractErrorKind::InvalidField
    );
}

#[test]
fn enforces_digest_claim_and_transport_boundaries() {
    let maximum = candidate("1", "2", &node("proof value"))
        .replace("from.alg", &"a".repeat(64))
        .replace("from root", &"x".repeat(512))
        .replace("to.alg", &"b".repeat(64))
        .replace("to root", &"y".repeat(512))
        .replace("node.alg", &"c".repeat(64))
        .replace("proof value", &"z".repeat(512));
    assert!(UntrustedTransparencyConsistencyProofV1::parse(maximum.as_bytes()).is_ok());

    for (needle, replacement) in [
        ("from.alg", String::new()),
        ("from.alg", "a".repeat(65)),
        ("from root", String::new()),
        ("from root", "x".repeat(513)),
        ("node.alg", "bad/label".into()),
        ("proof value", "line\\nbreak".into()),
    ] {
        let hostile = candidate("1", "2", &node("proof value")).replace(needle, &replacement);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }

    let valid = candidate("1", "2", "");
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(valid.as_bytes());
    assert_eq!(kind(&bom), ContractErrorKind::ByteOrderMark);
    let mut nul = valid.as_bytes().to_vec();
    nul.insert(1, 0);
    assert_eq!(kind(&nul), ContractErrorKind::NulByte);
    assert_eq!(kind(&[0xff]), ContractErrorKind::InvalidUtf8);
    assert_eq!(
        kind(valid.replace("from root", "rootí").as_bytes()),
        ContractErrorKind::NonAscii
    );
    assert_eq!(
        kind(valid.replace("from root", "root\\u0080").as_bytes()),
        ContractErrorKind::NonAscii
    );
}

#[test]
fn byte_limit_is_checked_first_and_hostile_corpus_never_panics() {
    let minimal = candidate("0", "0", "");
    let mut exact = vec![b' '; MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_BYTES - minimal.len()];
    exact.extend_from_slice(minimal.as_bytes());
    assert!(UntrustedTransparencyConsistencyProofV1::parse(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(kind(&exact), ContractErrorKind::InputTooLarge);
    assert_eq!(
        kind(&vec![
            0xff;
            MAX_UNTRUSTED_TRANSPARENCY_CONSISTENCY_PROOF_BYTES + 1
        ]),
        ContractErrorKind::InputTooLarge
    );

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
            panic::catch_unwind(|| canonicalize_untrusted_transparency_consistency_proof(&hostile));
        assert!(outcome.is_ok(), "parser panicked");
        assert!(outcome.unwrap().is_err(), "hostile corpus accepted");
    }
}
