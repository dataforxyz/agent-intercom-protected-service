use std::panic;

use agent_intercom_protected_service::{
    canonicalize_untrusted_dsse_envelope, ContractErrorKind, UntrustedDsseEnvelopeV1,
    MAX_DSSE_ENVELOPE_BYTES, MAX_DSSE_PAYLOAD_BYTES, MAX_DSSE_SIGNATURES,
};

fn kind(input: &[u8]) -> ContractErrorKind {
    canonicalize_untrusted_dsse_envelope(input)
        .expect_err("hostile DSSE envelope must fail")
        .kind()
}

fn envelope(payload: &str, payload_type: &str, signatures: &str) -> String {
    format!(
        "{{\"payload\":\"{payload}\",\"payloadType\":\"{payload_type}\",\"signatures\":[{signatures}]}}"
    )
}

fn signature(key_id: &str, signature: &str) -> String {
    format!("{{\"keyid\":\"{key_id}\",\"sig\":\"{signature}\"}}")
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::new();
    for chunk in input.chunks(3) {
        output.push(char::from(ALPHABET[usize::from(chunk[0] >> 2)]));
        if chunk.len() == 1 {
            output.push(char::from(ALPHABET[usize::from((chunk[0] & 0x03) << 4)]));
            output.push_str("==");
            continue;
        }
        output.push(char::from(
            ALPHABET[usize::from(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4))],
        ));
        if chunk.len() == 2 {
            output.push(char::from(ALPHABET[usize::from((chunk[1] & 0x0f) << 2)]));
            output.push('=');
            continue;
        }
        output.push(char::from(
            ALPHABET[usize::from(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6))],
        ));
        output.push(char::from(ALPHABET[usize::from(chunk[2] & 0x3f)]));
    }
    output
}

#[test]
fn parses_untrusted_values_and_emits_fixed_escaped_canonical_json() {
    let input = br#"{
      "signatures": [
        {"sig":"3q2+7w==","keyid":"attacker\u0022\u005cid"},
        {"keyid":"","sig":"AA=="}
      ],
      "payloadType":"application/vnd.example+json\u0022\u005c",
      "payload":"AP8g"
    }"#;
    let envelope = UntrustedDsseEnvelopeV1::parse(input).unwrap();

    assert_eq!(envelope.payload_type(), "application/vnd.example+json\"\\");
    assert_eq!(envelope.payload_bytes(), &[0x00, 0xff, b' ']);
    assert_eq!(envelope.signatures().len(), 2);
    assert_eq!(envelope.signatures()[0].key_id(), "attacker\"\\id");
    assert_eq!(
        envelope.signatures()[0].signature_bytes(),
        &[0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(envelope.signatures()[1].key_id(), "");
    assert_eq!(envelope.signatures()[1].signature_bytes(), &[0]);

    let canonical = br#"{"payload":"AP8g","payloadType":"application/vnd.example+json\"\\","signatures":[{"keyid":"attacker\"\\id","sig":"3q2+7w=="},{"keyid":"","sig":"AA=="}]}"#;
    assert_eq!(envelope.canonical_bytes(), canonical);
    assert_eq!(
        canonicalize_untrusted_dsse_envelope(input).unwrap(),
        canonical
    );
}

#[test]
fn emits_exact_dsse_v1_pae_over_payload_bytes() {
    let input = envelope("AP8g", "x", &signature("untrusted", "AA=="));
    let parsed = UntrustedDsseEnvelopeV1::parse(input.as_bytes()).unwrap();
    assert_eq!(
        parsed.pre_authentication_encoding(),
        [b"DSSEv1 1 x 3 ".as_slice(), &[0x00, 0xff, b' ']].concat()
    );

    let text = envelope("YWJj", "text/plain", &signature("", "AQ=="));
    assert_eq!(
        UntrustedDsseEnvelopeV1::parse(text.as_bytes())
            .unwrap()
            .pre_authentication_encoding(),
        b"DSSEv1 10 text/plain 3 abc"
    );
}

#[test]
fn permits_dsse_empty_payload_and_required_but_empty_key_id() {
    let input = envelope("", "text/plain", &signature("", "AA=="));
    let parsed = UntrustedDsseEnvelopeV1::parse(input.as_bytes()).unwrap();
    assert!(parsed.payload_bytes().is_empty());
    assert_eq!(parsed.signatures()[0].key_id(), "");
    assert_eq!(parsed.signatures()[0].signature_bytes(), &[0]);
    assert_eq!(
        parsed.canonical_bytes(),
        br#"{"payload":"","payloadType":"text/plain","signatures":[{"keyid":"","sig":"AA=="}]}"#
    );
}

#[test]
fn treats_payload_key_ids_and_signature_bytes_as_attacker_chosen_data_only() {
    let payload = br#"{"command":"do-not-run","authorized":true,"policy":"attacker"}"#;
    let input = envelope(
        &base64(payload),
        "application/vnd.attacker.policy+json",
        &signature("attacker-selected-root", "AQIDBA=="),
    );
    let parsed = UntrustedDsseEnvelopeV1::parse(input.as_bytes()).unwrap();

    assert_eq!(parsed.payload_bytes(), payload);
    assert_eq!(parsed.signatures()[0].key_id(), "attacker-selected-root");
    assert_eq!(parsed.signatures()[0].signature_bytes(), &[1, 2, 3, 4]);
}

#[test]
fn preserves_signature_order_without_algorithm_or_length_inference() {
    let signatures = [
        signature("first", "AA=="),
        signature("second", "AQI="),
        signature("third", "AwQFBgcICQ=="),
    ]
    .join(",");
    let input = envelope("", "application/octet-stream", &signatures);
    let parsed = UntrustedDsseEnvelopeV1::parse(input.as_bytes()).unwrap();

    assert_eq!(
        parsed
            .signatures()
            .iter()
            .map(|entry| entry.key_id())
            .collect::<Vec<_>>(),
        ["first", "second", "third"]
    );
    assert_eq!(
        parsed
            .signatures()
            .iter()
            .map(|entry| entry.signature_bytes().len())
            .collect::<Vec<_>>(),
        [1, 2, 7]
    );
}

#[test]
fn accepts_exact_size_and_count_boundaries_and_rejects_the_next_value() {
    let minimal = envelope("", "x", &signature("", "AA=="));
    let mut exact_envelope = vec![b' '; MAX_DSSE_ENVELOPE_BYTES - minimal.len()];
    exact_envelope.extend_from_slice(minimal.as_bytes());
    assert!(UntrustedDsseEnvelopeV1::parse(&exact_envelope).is_ok());
    exact_envelope.push(b' ');
    assert_eq!(kind(&exact_envelope), ContractErrorKind::InputTooLarge);

    let maximum_payload = vec![0xa5; MAX_DSSE_PAYLOAD_BYTES];
    let maximum_payload_envelope = envelope(&base64(&maximum_payload), "x", &signature("", "AA=="));
    assert_eq!(
        UntrustedDsseEnvelopeV1::parse(maximum_payload_envelope.as_bytes())
            .unwrap()
            .payload_bytes()
            .len(),
        MAX_DSSE_PAYLOAD_BYTES
    );
    let excessive_payload = envelope(
        &base64(&vec![0xa5; MAX_DSSE_PAYLOAD_BYTES + 1]),
        "x",
        &signature("", "AA=="),
    );
    assert_eq!(
        kind(excessive_payload.as_bytes()),
        ContractErrorKind::InvalidField
    );

    let maximum_signature = base64(&vec![0x5a; 4_096]);
    let maximum_signature_envelope = envelope("", "x", &signature("", &maximum_signature));
    assert_eq!(
        UntrustedDsseEnvelopeV1::parse(maximum_signature_envelope.as_bytes())
            .unwrap()
            .signatures()[0]
            .signature_bytes()
            .len(),
        4_096
    );
    let excessive_signature = base64(&vec![0x5a; 4_097]);
    assert_eq!(
        kind(envelope("", "x", &signature("", &excessive_signature)).as_bytes()),
        ContractErrorKind::InvalidField
    );

    let maximum_signatures = vec![signature("", "AA=="); MAX_DSSE_SIGNATURES].join(",");
    assert_eq!(
        UntrustedDsseEnvelopeV1::parse(envelope("", "x", &maximum_signatures).as_bytes())
            .unwrap()
            .signatures()
            .len(),
        MAX_DSSE_SIGNATURES
    );
    let excessive_signatures = vec![signature("", "AA=="); MAX_DSSE_SIGNATURES + 1].join(",");
    assert_eq!(
        kind(envelope("", "x", &excessive_signatures).as_bytes()),
        ContractErrorKind::InvalidField
    );
}

#[test]
fn enforces_printable_ascii_payload_type_and_key_id_boundaries() {
    let payload_type_256 = "t".repeat(256);
    let key_id_128 = "k".repeat(128);
    assert!(UntrustedDsseEnvelopeV1::parse(
        envelope("", &payload_type_256, &signature(&key_id_128, "AA==")).as_bytes()
    )
    .is_ok());

    for hostile in [
        envelope("", "", &signature("", "AA==")),
        envelope("", &"t".repeat(257), &signature("", "AA==")),
        envelope("", "text\\nplain", &signature("", "AA==")),
        envelope("", "text\\u001fplain", &signature("", "AA==")),
        envelope("", "text\\u007fplain", &signature("", "AA==")),
        envelope("", "x", &signature(&"k".repeat(129), "AA==")),
        envelope("", "x", &signature("key\\tidentifier", "AA==")),
        envelope("", "x", &signature("key\\u001fidentifier", "AA==")),
        envelope("", "x", &signature("key\\u007fidentifier", "AA==")),
    ] {
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::InvalidField);
    }
}

#[test]
fn accepts_only_canonical_padded_rfc4648_standard_base64() {
    for (encoded, decoded) in [
        ("", b"".as_slice()),
        ("Zg==", b"f".as_slice()),
        ("Zm8=", b"fo".as_slice()),
        ("Zm9v", b"foo".as_slice()),
        ("/w==", &[0xff]),
    ] {
        let input = envelope(encoded, "x", &signature("", "AA=="));
        assert_eq!(
            UntrustedDsseEnvelopeV1::parse(input.as_bytes())
                .unwrap()
                .payload_bytes(),
            decoded
        );
    }

    let escaped_slash = envelope(r#"\/w=="#, "x", &signature("", "AA=="));
    assert_eq!(
        canonicalize_untrusted_dsse_envelope(escaped_slash.as_bytes()).unwrap(),
        br#"{"payload":"/w==","payloadType":"x","signatures":[{"keyid":"","sig":"AA=="}]}"#
    );

    for hostile_base64 in [
        "Y Q==",
        r#"Y\tQ=="#,
        r#"Y\nQ=="#,
        "YQ",
        "YQ=",
        "YQ===",
        "YQ======",
        "Y=Q=",
        "=YQ=",
        "YQ=A",
        "Y-Q=",
        "Y_Q=",
        "Y*==",
        "YR==",
        "YWJ=",
        "A===",
        "====",
        "AAA==",
        "AA=A",
    ] {
        let hostile_payload = envelope(hostile_base64, "x", &signature("", "AA=="));
        assert_eq!(
            kind(hostile_payload.as_bytes()),
            ContractErrorKind::InvalidBase64,
            "payload encoding accepted: {hostile_base64:?}"
        );

        let hostile_signature = envelope("", "x", &signature("", hostile_base64));
        let expected = if hostile_base64.is_empty() {
            ContractErrorKind::InvalidField
        } else {
            ContractErrorKind::InvalidBase64
        };
        assert_eq!(
            kind(hostile_signature.as_bytes()),
            expected,
            "signature encoding accepted: {hostile_base64:?}"
        );
    }

    assert_eq!(
        kind(envelope("", "x", &signature("", "")).as_bytes()),
        ContractErrorKind::InvalidField
    );
}

#[test]
fn rejects_non_closed_or_wrongly_shaped_envelopes() {
    let closed_hostiles = [
        r#"{"payloadType":"x","signatures":[{"keyid":"","sig":"AA=="}]}"#,
        r#"{"payload":"","signatures":[{"keyid":"","sig":"AA=="}]}"#,
        r#"{"payload":"","payloadType":"x"}"#,
        r#"{"payload":"","payloadType":"x","signatures":[{"sig":"AA=="}]}"#,
        r#"{"payload":"","payloadType":"x","signatures":[{"keyid":""}]}"#,
    ];
    for hostile in closed_hostiles {
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::MissingField);
    }

    for attacker_field in [
        "algorithm",
        "payloadDigest",
        "verified",
        "policy",
        "trustedReleaseKeys",
        "install",
        "authorization",
        "__proto__",
    ] {
        let hostile = format!(
            "{{\"payload\":\"\",\"payloadType\":\"x\",\"signatures\":[{{\"keyid\":\"\",\"sig\":\"AA==\"}}],\"{attacker_field}\":true}}"
        );
        assert_eq!(kind(hostile.as_bytes()), ContractErrorKind::UnknownField);
    }

    let signature_unknown = envelope(
        "",
        "x",
        r#"{"keyid":"","sig":"AA==","algorithm":"attacker"}"#,
    );
    assert_eq!(
        kind(signature_unknown.as_bytes()),
        ContractErrorKind::UnknownField
    );

    for hostile in [
        "null",
        "[]",
        r#"{"payload":null,"payloadType":"x","signatures":[{"keyid":"","sig":"AA=="}]}"#,
        r#"{"payload":"","payloadType":1,"signatures":[{"keyid":"","sig":"AA=="}]}"#,
        r#"{"payload":"","payloadType":"x","signatures":{}}"#,
        r#"{"payload":"","payloadType":"x","signatures":[null]}"#,
        r#"{"payload":"","payloadType":"x","signatures":[{"keyid":1,"sig":"AA=="}]}"#,
        r#"{"payload":"","payloadType":"x","signatures":[{"keyid":"","sig":false}]}"#,
    ] {
        assert!(canonicalize_untrusted_dsse_envelope(hostile.as_bytes()).is_err());
    }

    assert_eq!(
        kind(br#"{"payload":"","payload":"","payloadType":"x","signatures":[{"keyid":"","sig":"AA=="}]}"#),
        ContractErrorKind::DuplicateKey
    );
    assert_eq!(
        kind(br#"{"payload":"","payl\u006fad":"","payloadType":"x","signatures":[{"keyid":"","sig":"AA=="}]}"#),
        ContractErrorKind::DuplicateKey
    );
    assert_eq!(
        kind(br#"{"payload":"","payloadType":"x","signatures":[{"keyid":"","key\u0069d":"","sig":"AA=="}]}"#),
        ContractErrorKind::DuplicateKey
    );
}

#[test]
fn rejects_transport_and_decoded_string_encoding_attacks() {
    let valid = envelope("", "x", &signature("", "AA=="));
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(valid.as_bytes());
    assert_eq!(kind(&bom), ContractErrorKind::ByteOrderMark);

    let mut nul = valid.as_bytes().to_vec();
    nul.insert(1, 0);
    assert_eq!(kind(&nul), ContractErrorKind::NulByte);
    assert_eq!(kind(&[0xff]), ContractErrorKind::InvalidUtf8);

    let raw_non_ascii = envelope("", "týpe", &signature("", "AA=="));
    assert_eq!(kind(raw_non_ascii.as_bytes()), ContractErrorKind::NonAscii);
    let escaped_non_ascii = envelope("", "t\\u0080pe", &signature("", "AA=="));
    assert_eq!(
        kind(escaped_non_ascii.as_bytes()),
        ContractErrorKind::NonAscii
    );
    let escaped_nul = envelope("", "t\\u0000pe", &signature("", "AA=="));
    assert_eq!(kind(escaped_nul.as_bytes()), ContractErrorKind::NulByte);
}

#[test]
fn hostile_truncation_padding_length_and_depth_corpus_never_panics() {
    let valid = envelope("YWJj", "text/plain", &signature("attacker", "AQID"));
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

    for padding in [
        "A", "AA", "AAA", "A=", "AA=", "A===", "AA=A", "AA==AA==", "AB==", "ABC=",
    ] {
        corpus.push((
            format!("padding-{padding:?}"),
            envelope(padding, "x", &signature("", "AA==")).into_bytes(),
        ));
    }

    for length in [
        0,
        1,
        2,
        3,
        MAX_DSSE_ENVELOPE_BYTES - 1,
        MAX_DSSE_ENVELOPE_BYTES,
        MAX_DSSE_ENVELOPE_BYTES + 1,
    ] {
        corpus.push((format!("raw-length-{length}"), vec![b' '; length]));
    }
    corpus.push((
        "payload-length-over".to_owned(),
        envelope(
            &base64(&vec![0; MAX_DSSE_PAYLOAD_BYTES + 1]),
            "x",
            &signature("", "AA=="),
        )
        .into_bytes(),
    ));
    corpus.push((
        "signature-count-zero".to_owned(),
        envelope("", "x", "").into_bytes(),
    ));
    corpus.push((
        "signature-count-over".to_owned(),
        envelope(
            "",
            "x",
            &vec![signature("", "AA=="); MAX_DSSE_SIGNATURES + 1].join(","),
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
        let outcome = panic::catch_unwind(|| canonicalize_untrusted_dsse_envelope(&hostile));
        assert!(outcome.is_ok(), "parser panicked for {name}");
        assert!(outcome.unwrap().is_err(), "hostile corpus accepted {name}");
    }
}
