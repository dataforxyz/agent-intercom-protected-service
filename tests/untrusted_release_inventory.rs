use std::panic;

use agent_intercom_protected_service::{
    canonicalize_untrusted_release_inventory, ContractErrorKind, UntrustedEvidenceTag,
    UntrustedReleaseInventoryV1, MAX_UNTRUSTED_EVIDENCE_CLAIMS,
    MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES,
};

const SUBJECT_ALGORITHM: &str = "attacker.algorithm";
const SUBJECT_VALUE: &str = "opaque-subject-claim";

fn digest(algorithm: &str, value: &str) -> String {
    format!("{{\"algorithm\":\"{algorithm}\",\"value\":\"{value}\"}}")
}

fn evidence(tag: &str, algorithm: &str, value: &str, length: &str) -> String {
    format!(
        "{{\"digest\":{},\"length\":{length},\"subject_digest\":{},\"tag\":\"{tag}\"}}",
        digest(algorithm, value),
        digest(SUBJECT_ALGORITHM, SUBJECT_VALUE),
    )
}

fn inventory(evidence: &str) -> String {
    format!(
        "{{\"channel\":\"hostile-candidate\",\"evidence\":[{evidence}],\"installable\":{{\"digest\":{},\"length\":7}},\"schema_version\":1,\"target\":\"not-a-platform\",\"version\":\"0_untrusted\"}}",
        digest(SUBJECT_ALGORITHM, SUBJECT_VALUE),
    )
}

fn kind(input: &[u8]) -> ContractErrorKind {
    canonicalize_untrusted_release_inventory(input)
        .expect_err("hostile inventory must fail")
        .kind()
}

#[test]
fn parses_inline_hostile_sentinel_and_emits_fixed_escaped_canonical_json() {
    let input = br#"{
      "version":"0_untrusted",
      "target":"not-a-platform",
      "schema_version":1,
      "installable":{"length":18446744073709551615,"digest":{"value":"opaque\u0022\u005cclaim","algorithm":"made.up-algorithm"}},
      "evidence":[
        {"tag":"sbom","subject_digest":{"value":"opaque\u0022\u005cclaim","algorithm":"made.up-algorithm"},"length":0,"digest":{"value":"not a digest: []{}","algorithm":"claim_one"}},
        {"tag":"builder_record","subject_digest":{"algorithm":"made.up-algorithm","value":"opaque\"\\claim"},"length":9,"digest":{"algorithm":"claim_two","value":"?"}}
      ],
      "channel":"hostile-candidate"
    }"#;
    let parsed = UntrustedReleaseInventoryV1::parse(input).unwrap();

    assert_eq!(parsed.schema_version(), 1);
    assert_eq!(parsed.channel(), "hostile-candidate");
    assert_eq!(parsed.target(), "not-a-platform");
    assert_eq!(parsed.version(), "0_untrusted");
    assert_eq!(parsed.installable().length(), u64::MAX);
    assert_eq!(
        parsed.installable().digest().algorithm(),
        "made.up-algorithm"
    );
    assert_eq!(parsed.installable().digest().value(), "opaque\"\\claim");
    assert_eq!(parsed.evidence().len(), 2);
    assert_eq!(parsed.evidence()[0].tag(), UntrustedEvidenceTag::Sbom);
    assert_eq!(parsed.evidence()[0].length(), 0);
    assert_eq!(parsed.evidence()[0].digest().value(), "not a digest: []{}");
    assert_eq!(
        parsed.evidence()[1].tag(),
        UntrustedEvidenceTag::BuilderRecord
    );
    assert_eq!(
        parsed.evidence()[1].subject_digest(),
        parsed.installable().digest()
    );

    let canonical = br#"{"channel":"hostile-candidate","evidence":[{"digest":{"algorithm":"claim_one","value":"not a digest: []{}"},"length":0,"subject_digest":{"algorithm":"made.up-algorithm","value":"opaque\"\\claim"},"tag":"sbom"},{"digest":{"algorithm":"claim_two","value":"?"},"length":9,"subject_digest":{"algorithm":"made.up-algorithm","value":"opaque\"\\claim"},"tag":"builder_record"}],"installable":{"digest":{"algorithm":"made.up-algorithm","value":"opaque\"\\claim"},"length":18446744073709551615},"schema_version":1,"target":"not-a-platform","version":"0_untrusted"}"#;
    assert_eq!(parsed.canonical_bytes(), canonical);
    assert_eq!(
        canonicalize_untrusted_release_inventory(input).unwrap(),
        canonical
    );
    assert_eq!(
        canonicalize_untrusted_release_inventory(canonical).unwrap(),
        canonical
    );
}

#[test]
fn permits_empty_evidence_without_implying_sufficiency() {
    let parsed = UntrustedReleaseInventoryV1::parse(inventory("").as_bytes()).unwrap();
    assert!(parsed.evidence().is_empty());
    assert_eq!(
        parsed.canonical_bytes(),
        inventory("").as_bytes(),
        "an empty required array remains structurally representable"
    );
}

#[test]
fn accepts_only_the_six_closed_tags_and_preserves_evidence_order() {
    let tags = [
        ("sbom", UntrustedEvidenceTag::Sbom),
        ("provenance", UntrustedEvidenceTag::Provenance),
        ("attestation", UntrustedEvidenceTag::Attestation),
        ("build_recipe", UntrustedEvidenceTag::BuildRecipe),
        ("toolchain", UntrustedEvidenceTag::Toolchain),
        ("builder_record", UntrustedEvidenceTag::BuilderRecord),
    ];
    let entries = tags
        .iter()
        .enumerate()
        .map(|(index, (tag, _))| evidence(tag, "attacker", &format!("claim-{index}"), "0"))
        .collect::<Vec<_>>()
        .join(",");
    let parsed = UntrustedReleaseInventoryV1::parse(inventory(&entries).as_bytes()).unwrap();
    assert_eq!(
        parsed
            .evidence()
            .iter()
            .map(|claim| claim.tag())
            .collect::<Vec<_>>(),
        tags.iter().map(|(_, tag)| *tag).collect::<Vec<_>>()
    );
    assert_eq!(
        tags.iter().map(|(_, tag)| tag.as_str()).collect::<Vec<_>>(),
        tags.iter().map(|(name, _)| *name).collect::<Vec<_>>()
    );

    for hostile_tag in [
        "",
        "SBOM",
        "build-recipe",
        "builder",
        "signature",
        "authorization",
    ] {
        let hostile = inventory(&evidence(hostile_tag, "attacker", "claim", "0"));
        assert_eq!(
            kind(hostile.as_bytes()),
            ContractErrorKind::InvalidField,
            "tag accepted: {hostile_tag:?}"
        );
    }
}

#[test]
fn subject_binding_is_decoded_string_equality_only() {
    let escaped_equal = inventory(&evidence("sbom", "attacker", "evidence-claim", "1"))
        .replace(
            &format!(
                "\"subject_digest\":{}",
                digest(SUBJECT_ALGORITHM, SUBJECT_VALUE)
            ),
            "\"subject_digest\":{\"algorithm\":\"attacker\\u002ealgorithm\",\"value\":\"opaque-subject-\\u0063laim\"}",
        );
    assert!(UntrustedReleaseInventoryV1::parse(escaped_equal.as_bytes()).is_ok());

    for (algorithm, value) in [
        ("ATTACKER.algorithm", SUBJECT_VALUE),
        (SUBJECT_ALGORITHM, "opaque-subject-Claim"),
        (SUBJECT_ALGORITHM, "opaque-subject-claim "),
        ("other", SUBJECT_VALUE),
    ] {
        let hostile = inventory(&evidence("sbom", "attacker", "evidence-claim", "1")).replace(
            &format!(
                "\"subject_digest\":{}",
                digest(SUBJECT_ALGORITHM, SUBJECT_VALUE)
            ),
            &format!("\"subject_digest\":{}", digest(algorithm, value)),
        );
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }
}

#[test]
fn digest_claims_have_no_algorithm_dispatch_or_digest_length_inference() {
    for (algorithm, value) in [
        ("x", "?".to_owned()),
        ("unknown.algorithm_v999", "A".repeat(3)),
        (&"a".repeat(64), "~".repeat(511)),
        ("not-a-hash", "x".repeat(512)),
    ] {
        let mut candidate = inventory(&evidence("attestation", algorithm, &value, "1"));
        candidate = candidate.replace(SUBJECT_ALGORITHM, algorithm);
        candidate = candidate.replace(SUBJECT_VALUE, &value);
        let parsed = UntrustedReleaseInventoryV1::parse(candidate.as_bytes()).unwrap();
        assert_eq!(parsed.installable().digest().algorithm(), algorithm);
        assert_eq!(parsed.installable().digest().value(), value);
    }
}

#[test]
fn enforces_byte_and_evidence_count_limits_before_semantic_use() {
    let minimal = inventory("");
    let mut exact = vec![b' '; MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES - minimal.len()];
    exact.extend_from_slice(minimal.as_bytes());
    assert_eq!(exact.len(), MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES);
    assert!(UntrustedReleaseInventoryV1::parse(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(kind(&exact), ContractErrorKind::InputTooLarge);

    let oversized_invalid = vec![0xff; MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES + 1];
    assert_eq!(kind(&oversized_invalid), ContractErrorKind::InputTooLarge);

    let maximum = vec![evidence("sbom", "x", "?", "0"); MAX_UNTRUSTED_EVIDENCE_CLAIMS].join(",");
    assert_eq!(
        UntrustedReleaseInventoryV1::parse(inventory(&maximum).as_bytes())
            .unwrap()
            .evidence()
            .len(),
        MAX_UNTRUSTED_EVIDENCE_CLAIMS
    );
    let excessive =
        vec![evidence("sbom", "x", "?", "0"); MAX_UNTRUSTED_EVIDENCE_CLAIMS + 1].join(",");
    assert_eq!(
        kind(inventory(&excessive).as_bytes()),
        ContractErrorKind::InvalidField
    );
}

#[test]
fn enforces_identifier_and_digest_claim_string_boundaries() {
    let maximums = inventory("")
        .replace("hostile-candidate", &"c".repeat(64))
        .replace("not-a-platform", &"t".repeat(128))
        .replace("0_untrusted", &"v".repeat(128))
        .replace(SUBJECT_ALGORITHM, &"a".repeat(64))
        .replace(SUBJECT_VALUE, &"x".repeat(512));
    assert!(UntrustedReleaseInventoryV1::parse(maximums.as_bytes()).is_ok());

    for (needle, hostile) in [
        ("hostile-candidate", String::new()),
        ("hostile-candidate", "c".repeat(65)),
        ("not-a-platform", String::new()),
        ("not-a-platform", "t".repeat(129)),
        ("0_untrusted", String::new()),
        ("0_untrusted", "v".repeat(129)),
        (SUBJECT_ALGORITHM, String::new()),
        (SUBJECT_ALGORITHM, "a".repeat(65)),
        (SUBJECT_VALUE, String::new()),
        (SUBJECT_VALUE, "x".repeat(513)),
    ] {
        let candidate = inventory("").replace(needle, &hostile);
        assert_eq!(kind(candidate.as_bytes()), ContractErrorKind::InvalidField);
    }

    for forbidden in ["/", ":", "\\\\", " ", "\\t", "@", "+"] {
        for needle in ["hostile-candidate", "not-a-platform", "0_untrusted"] {
            let candidate = inventory("").replace(needle, &format!("bad{forbidden}text"));
            assert_eq!(kind(candidate.as_bytes()), ContractErrorKind::InvalidField);
        }
        let candidate =
            inventory("").replace(SUBJECT_ALGORITHM, &format!("bad{forbidden}algorithm"));
        assert_eq!(kind(candidate.as_bytes()), ContractErrorKind::InvalidField);
    }

    for hostile_value in ["line\\nbreak", "tab\\tvalue", "delete\\u007fvalue"] {
        let candidate = inventory("").replace(SUBJECT_VALUE, hostile_value);
        assert_eq!(kind(candidate.as_bytes()), ContractErrorKind::InvalidField);
    }
}

#[test]
fn accepts_only_canonical_unsigned_json_u64_lengths() {
    for valid in ["0", "1", "10", "18446744073709551615"] {
        let candidate = inventory(&evidence("sbom", "x", "?", valid))
            .replace("\"length\":7", &format!("\"length\":{valid}"));
        let parsed = UntrustedReleaseInventoryV1::parse(candidate.as_bytes()).unwrap();
        assert_eq!(parsed.installable().length().to_string(), valid);
        assert_eq!(parsed.evidence()[0].length().to_string(), valid);
    }

    for hostile in [
        "-1",
        "00",
        "01",
        "1.0",
        "1e0",
        "1E+0",
        "18446744073709551616",
        "true",
        "null",
        "\"1\"",
        "[]",
        "{}",
    ] {
        let installable = inventory("").replace("\"length\":7", &format!("\"length\":{hostile}"));
        let expected = if matches!(hostile, "00" | "01") {
            ContractErrorKind::InvalidJson
        } else {
            ContractErrorKind::InvalidField
        };
        assert_eq!(kind(installable.as_bytes()), expected);

        let evidence_length = inventory(&evidence("sbom", "x", "?", hostile));
        assert_eq!(kind(evidence_length.as_bytes()), expected);
    }
}

#[test]
fn requires_one_singular_installable_object_and_closed_shapes() {
    let baseline = inventory("");
    let two_descriptors = baseline.replace(
        "\"installable\":{\"digest\"",
        "\"installable\":[{\"digest\"",
    );
    let two_descriptors = two_descriptors.replace(
        "\"length\":7},\"schema_version\"",
        "\"length\":7},{\"digest\":{\"algorithm\":\"x\",\"value\":\"y\"},\"length\":1}],\"schema_version\"",
    );
    assert!(canonicalize_untrusted_release_inventory(two_descriptors.as_bytes()).is_err());

    let duplicate = baseline.replacen(
        "\"installable\":",
        "\"installable\":{\"digest\":{\"algorithm\":\"x\",\"value\":\"y\"},\"length\":1},\"installable\":",
        1,
    );
    assert_eq!(kind(duplicate.as_bytes()), ContractErrorKind::DuplicateKey);

    for missing in [
        "\"channel\":\"hostile-candidate\",",
        "\"evidence\":[],",
        "\"installable\":{\"digest\":{\"algorithm\":\"attacker.algorithm\",\"value\":\"opaque-subject-claim\"},\"length\":7},",
        "\"schema_version\":1,",
        "\"target\":\"not-a-platform\",",
        ",\"version\":\"0_untrusted\"",
    ] {
        assert_eq!(
            kind(baseline.replace(missing, "").as_bytes()),
            ContractErrorKind::MissingField
        );
    }

    for field in [
        "path",
        "url",
        "endpoint",
        "identity",
        "key",
        "root",
        "clock",
        "signature",
        "policy",
        "authorized",
        "selected",
        "__proto__",
    ] {
        let hostile = baseline.replacen("{", &format!("{{\"{field}\":\"attacker\","), 1);
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::UnknownField);
    }
}

#[test]
fn rejects_duplicates_unknowns_and_missing_fields_at_nested_depths() {
    let baseline = inventory(&evidence("sbom", "x", "?", "0"));
    for (needle, replacement) in [
        (
            "\"algorithm\":\"attacker.algorithm\"",
            "\"algorithm\":\"attacker.algorithm\",\"algorithm\":\"other\"",
        ),
        (
            "\"tag\":\"sbom\"",
            "\"tag\":\"sbom\",\"t\\u0061g\":\"sbom\"",
        ),
        ("\"length\":7", "\"length\":7,\"length\":8"),
    ] {
        assert_eq!(
            kind(baseline.replacen(needle, replacement, 1).as_bytes()),
            ContractErrorKind::DuplicateKey
        );
    }

    for (needle, replacement) in [
        (
            "\"digest\":{\"algorithm\":\"x\",\"value\":\"?\"}",
            "\"digest\":{\"algorithm\":\"x\",\"value\":\"?\",\"path\":\"attacker\"}",
        ),
        ("\"length\":7}", "\"length\":7,\"media_type\":\"attacker\"}"),
        (
            "\"tag\":\"sbom\"",
            "\"tag\":\"sbom\",\"signature\":\"attacker\"",
        ),
    ] {
        assert_eq!(
            kind(baseline.replacen(needle, replacement, 1).as_bytes()),
            ContractErrorKind::UnknownField
        );
    }

    for (needle, replacement) in [
        ("\"algorithm\":\"x\",", ""),
        (",\"value\":\"?\"", ""),
        ("\"length\":0,", ""),
        (
            &format!(
                "\"subject_digest\":{},",
                digest(SUBJECT_ALGORITHM, SUBJECT_VALUE)
            ),
            "",
        ),
        (",\"tag\":\"sbom\"", ""),
    ] {
        assert_eq!(
            kind(baseline.replacen(needle, replacement, 1).as_bytes()),
            ContractErrorKind::MissingField
        );
    }
}

#[test]
fn rejects_schema_transport_and_json_encoding_attacks() {
    for schema in ["0", "2", "1.0", "1e0", "-1", "true", "\"1\""] {
        let hostile = inventory("").replace(
            "\"schema_version\":1",
            &format!("\"schema_version\":{schema}"),
        );
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }

    let valid = inventory("");
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(valid.as_bytes());
    assert_eq!(kind(&bom), ContractErrorKind::ByteOrderMark);

    let mut nul = valid.as_bytes().to_vec();
    nul.insert(1, 0);
    assert_eq!(kind(&nul), ContractErrorKind::NulByte);
    assert_eq!(kind(&[0xff]), ContractErrorKind::InvalidUtf8);

    let raw_non_ascii = valid.replace("hostile-candidate", "hostíle");
    assert_eq!(kind(raw_non_ascii.as_bytes()), ContractErrorKind::NonAscii);
    let escaped_non_ascii = valid.replace("hostile-candidate", "host\\u0080ile");
    assert_eq!(
        kind(escaped_non_ascii.as_bytes()),
        ContractErrorKind::NonAscii
    );
    let escaped_nul = valid.replace("hostile-candidate", "host\\u0000ile");
    assert_eq!(kind(escaped_nul.as_bytes()), ContractErrorKind::NulByte);

    for malformed in [
        "",
        "null",
        "[]",
        "{",
        "{} trailing",
        "{\"channel\":}",
        "{\"x\":\"bad\\xescape\"}",
        "{\"x\":\"bad\\u12zz\"}",
        "{\"x\":1,}",
    ] {
        assert!(canonicalize_untrusted_release_inventory(malformed.as_bytes()).is_err());
    }
    let trailing = format!("{valid} {{}}");
    assert_eq!(kind(trailing.as_bytes()), ContractErrorKind::InvalidJson);
}

#[test]
fn hostile_truncation_length_count_and_depth_corpus_never_panics() {
    let valid = inventory(&evidence("sbom", "x", "?", "0"));
    let mut corpus: Vec<(String, Vec<u8>)> = valid
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(length, _)| {
            (
                format!("truncation-{length}"),
                valid.as_bytes()[..length].to_vec(),
            )
        })
        .collect();

    for length in [
        0,
        1,
        MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES - 1,
        MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES,
        MAX_UNTRUSTED_RELEASE_INVENTORY_BYTES + 1,
    ] {
        corpus.push((format!("raw-length-{length}"), vec![b' '; length]));
    }
    corpus.push((
        "evidence-count-over".to_owned(),
        inventory(
            &vec![evidence("sbom", "x", "?", "0"); MAX_UNTRUSTED_EVIDENCE_CLAIMS + 1].join(","),
        )
        .into_bytes(),
    ));
    for depth in [63, 64, 65, 66] {
        corpus.push((
            format!("depth-{depth}"),
            format!("{}0{}", "[".repeat(depth), "]".repeat(depth)).into_bytes(),
        ));
    }

    for (name, hostile) in corpus {
        let outcome = panic::catch_unwind(|| canonicalize_untrusted_release_inventory(&hostile));
        assert!(outcome.is_ok(), "parser panicked for {name}");
        assert!(outcome.unwrap().is_err(), "hostile corpus accepted {name}");
    }
}
