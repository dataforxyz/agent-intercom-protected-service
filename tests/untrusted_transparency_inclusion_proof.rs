use std::panic;

use agent_intercom_protected_service::{
    canonicalize_untrusted_transparency_inclusion_proof, ContractErrorKind,
    UntrustedTransparencyInclusionProofV1, MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_BYTES,
    MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_NODES,
};

fn candidate(tree_size: &str, leaf_index: &str, proof: &str) -> String {
    format!(
        "{{\"checkpoint\":{{\"root_digest\":{{\"algorithm\":\"root.alg\",\"value\":\"root value\"}},\"schema_version\":1,\"tree_size\":{tree_size}}},\"leaf_digest\":{{\"algorithm\":\"leaf.alg\",\"value\":\"leaf value\"}},\"leaf_index\":{leaf_index},\"proof\":[{proof}],\"schema_version\":1}}"
    )
}

fn node(value: &str) -> String {
    format!("{{\"algorithm\":\"node.alg\",\"value\":\"{value}\"}}")
}

fn kind(input: &[u8]) -> ContractErrorKind {
    canonicalize_untrusted_transparency_inclusion_proof(input)
        .expect_err("hostile inclusion claim must fail")
        .kind()
}

#[test]
fn canonicalizes_permuted_self_contained_claim_idempotently() {
    let input = br#"{
      "schema_version":1,
      "proof":[{"value":"node \\ one","algorithm":"node.alg"},{"algorithm":"node.alg","value":"node \\ one"}],
      "leaf_index":8,
      "leaf_digest":{"value":"leaf \"value\"","algorithm":"leaf.alg"},
      "checkpoint":{"tree_size":9,"schema_version":1,"root_digest":{"value":"root value","algorithm":"root.alg"}}
    }"#;
    let parsed = UntrustedTransparencyInclusionProofV1::parse(input).unwrap();
    assert_eq!(parsed.schema_version(), 1);
    assert_eq!(parsed.checkpoint().tree_size(), 9);
    assert_eq!(parsed.leaf_index(), 8);
    assert_eq!(parsed.leaf_digest().value(), "leaf \"value\"");
    assert_eq!(parsed.proof().len(), 2);
    assert_eq!(parsed.proof()[0], parsed.proof()[1]);

    let canonical = br#"{"checkpoint":{"root_digest":{"algorithm":"root.alg","value":"root value"},"schema_version":1,"tree_size":9},"leaf_digest":{"algorithm":"leaf.alg","value":"leaf \"value\""},"leaf_index":8,"proof":[{"algorithm":"node.alg","value":"node \\ one"},{"algorithm":"node.alg","value":"node \\ one"}],"schema_version":1}"#;
    assert_eq!(parsed.canonical_bytes(), canonical);
    assert_eq!(
        canonicalize_untrusted_transparency_inclusion_proof(canonical).unwrap(),
        canonical
    );
}

#[test]
fn preserves_semantically_impossible_claims_without_inclusion_checks() {
    for case in [
        candidate("0", "0", ""),
        candidate("0", "18446744073709551615", &node("outside")),
        candidate("7", "7", &format!("{},{}", node("same"), node("same"))),
    ] {
        let parsed = UntrustedTransparencyInclusionProofV1::parse(case.as_bytes()).unwrap();
        assert_eq!(
            canonicalize_untrusted_transparency_inclusion_proof(&parsed.canonical_bytes()).unwrap(),
            parsed.canonical_bytes()
        );
    }
    let mixed = candidate("3", "99", &node("opaque"))
        .replace("root.alg", "different.root")
        .replace("leaf.alg", "unknown.leaf_v999")
        .replace("node.alg", "other.node");
    assert!(UntrustedTransparencyInclusionProofV1::parse(mixed.as_bytes()).is_ok());
}

#[test]
fn enforces_closed_shapes_and_duplicate_safe_keys_at_every_level() {
    let baseline = candidate("7", "3", &node("one"));
    for missing in [
        "\"checkpoint\":{\"root_digest\":{\"algorithm\":\"root.alg\",\"value\":\"root value\"},\"schema_version\":1,\"tree_size\":7},",
        "\"leaf_digest\":{\"algorithm\":\"leaf.alg\",\"value\":\"leaf value\"},",
        "\"leaf_index\":3,",
        "\"proof\":[{\"algorithm\":\"node.alg\",\"value\":\"one\"}],",
        ",\"schema_version\":1",
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
        "orientation",
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
    assert_eq!(
        kind(
            baseline
                .replacen(
                    "\"leaf_index\":3",
                    "\"leaf_index\":3,\"leaf_\\u0069ndex\":4",
                    1
                )
                .as_bytes()
        ),
        ContractErrorKind::DuplicateKey
    );
    assert_eq!(
        kind(
            baseline
                .replacen(
                    "\"tree_size\":7",
                    "\"tree_size\":7,\"tree_\\u0073ize\":8",
                    1
                )
                .as_bytes()
        ),
        ContractErrorKind::DuplicateKey
    );
    assert_eq!(
        kind(
            baseline
                .replacen(
                    "\"value\":\"one\"",
                    "\"value\":\"one\",\"val\\u0075e\":\"two\"",
                    1
                )
                .as_bytes()
        ),
        ContractErrorKind::DuplicateKey
    );
}

#[test]
fn accepts_only_exact_schema_one_and_canonical_u64_claims() {
    for valid in ["0", "1", "10", "18446744073709551615"] {
        assert!(UntrustedTransparencyInclusionProofV1::parse(
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
        for occurrence in [1, 2] {
            let mut hostile = candidate("1", "0", "");
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
    let sixty_four = (0..MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_NODES)
        .map(|index| node(&format!("node-{index}")))
        .collect::<Vec<_>>()
        .join(",");
    let parsed =
        UntrustedTransparencyInclusionProofV1::parse(candidate("1", "0", &sixty_four).as_bytes())
            .unwrap();
    assert_eq!(parsed.proof().len(), 64);
    assert_eq!(parsed.proof()[0].value(), "node-0");
    assert_eq!(parsed.proof()[63].value(), "node-63");
    let sixty_five = format!("{sixty_four},{}", node("overflow"));
    assert_eq!(
        kind(candidate("1", "0", &sixty_five).as_bytes()),
        ContractErrorKind::InvalidField
    );
}

#[test]
fn enforces_digest_claim_and_transport_boundaries() {
    let maximum = candidate("1", "0", &node("proof value"))
        .replace("root.alg", &"a".repeat(64))
        .replace("root value", &"x".repeat(512))
        .replace("leaf.alg", &"b".repeat(64))
        .replace("leaf value", &"y".repeat(512))
        .replace("node.alg", &"c".repeat(64))
        .replace("proof value", &"z".repeat(512));
    assert!(UntrustedTransparencyInclusionProofV1::parse(maximum.as_bytes()).is_ok());

    for (needle, replacement) in [
        ("leaf.alg", String::new()),
        ("leaf.alg", "a".repeat(65)),
        ("leaf value", String::new()),
        ("leaf value", "x".repeat(513)),
        ("node.alg", "bad/label".into()),
        ("proof value", "line\\nbreak".into()),
    ] {
        let hostile = candidate("1", "0", &node("proof value")).replace(needle, &replacement);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }

    let valid = candidate("1", "0", "");
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(valid.as_bytes());
    assert_eq!(kind(&bom), ContractErrorKind::ByteOrderMark);
    let mut nul = valid.as_bytes().to_vec();
    nul.insert(1, 0);
    assert_eq!(kind(&nul), ContractErrorKind::NulByte);
    assert_eq!(kind(&[0xff]), ContractErrorKind::InvalidUtf8);
    assert_eq!(
        kind(valid.replace("leaf value", "leafí").as_bytes()),
        ContractErrorKind::NonAscii
    );
    assert_eq!(
        kind(valid.replace("leaf value", "leaf\\u0080").as_bytes()),
        ContractErrorKind::NonAscii
    );
}

#[test]
fn byte_limit_is_checked_first_and_hostile_corpus_never_panics() {
    let minimal = candidate("0", "0", "");
    let mut exact = vec![b' '; MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_BYTES - minimal.len()];
    exact.extend_from_slice(minimal.as_bytes());
    assert!(UntrustedTransparencyInclusionProofV1::parse(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(kind(&exact), ContractErrorKind::InputTooLarge);
    assert_eq!(
        kind(&vec![
            0xff;
            MAX_UNTRUSTED_TRANSPARENCY_INCLUSION_PROOF_BYTES + 1
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
            panic::catch_unwind(|| canonicalize_untrusted_transparency_inclusion_proof(&hostile));
        assert!(outcome.is_ok(), "parser panicked");
        assert!(outcome.unwrap().is_err(), "hostile corpus accepted");
    }
}
