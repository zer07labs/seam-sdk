//! `seam-commitment-digest:v6` and the Gate block v1 against the runtime-emitted vectors (Flows W2, A18):
//!
//! * `commitment_digest_v6_vector.json` — every section: `cases` (digest-only re-cuts of every v5 case,
//!   and the env/Gate cases derived from their `trailers`), `digest_input_refusals`,
//!   `governing_trailer_refusals`, `v5_refusals`, `scheme_free` and `statement_selection`;
//! * `commitment_digest_v6_signed_vector.json` — real TCTs over v6 commitments, and the negatives;
//! * `gate_block_vector.json` — `cases`, `presence_states`, `body_refusals` and `sequences`.
//!   `outage_classification` and `writer_refusals` are WRITER-side rules (what the runtime may seal for an
//!   observed HTTP outcome): a reader cannot see the HTTP status, so they are not ported (plan A18 §3).
//!
//! These files are byte-pinned to the runtime's by its `sdk-digest-parity` job; they are not edited here.
//! Refusal rows assert the REFUSAL only. Rule names are advisory (spec §Refusal rules), so a different
//! applicable rule is not a failure.

use seam_verify::commitment::{
    commitment_digest_under, decode_commitment_trailers, encode_slot, explanation_digest,
    select_commitment_version, select_commitment_version_in_ext, served_commitment_trailers,
    tct_jti, verify_commitment_tct, verify_commitment_tct_sealed_at, Commitment,
    CommitmentDigestVersion as V, ExplanationEntry,
};
use seam_verify::gate::{decode_gate_body, gate_digest, GateResult};
use serde_json::Value;

fn load(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../conformance")
        .join(name);
    serde_json::from_str(
        &std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("{}: {e} — this test refuses to skip", p.display())),
    )
    .unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_owned()
}

fn bytes_arr(v: &Value) -> Vec<u8> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect()
}

fn opt_hex(v: &Value, k: &str) -> Option<Vec<u8>> {
    v.get(k).and_then(Value::as_str).map(unhex)
}

/// A vector `commitment` object as the digest reads it. Entries are parsed when present (signed vector);
/// the digest-only cases carry only `explanation_digest`.
fn commitment(c: &Value) -> Commitment {
    Commitment {
        id: text(c, "id"),
        action: text(c, "action"),
        authority: text(c, "authority"),
        supersedes: c
            .get("supersedes")
            .and_then(Value::as_str)
            .map(str::to_owned),
        auth_method: text(c, "auth_method"),
        trust_basis: text(c, "trust_basis"),
        committer: text(c, "committer"),
        explanation: c
            .get("explanation")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|e| {
                        assert!(e["voter_verification"].is_null());
                        ExplanationEntry {
                            kind: text(e, "kind"),
                            participant: text(e, "participant"),
                            proposal_id: text(e, "proposal_id"),
                            value: text(e, "value"),
                            reason: text(e, "reason"),
                            confidence: e.get("confidence").and_then(Value::as_f64),
                            rationale_ref: e
                                .get("rationale_ref")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            voter_verification: None,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        selection_digest: None,
        certificate_digest: None,
        governing_doc_sha256: c
            .get("governing_doc_sha256")
            .filter(|v| v.is_array())
            .map(bytes_arr),
        signed_artifact: text(c, "signed_artifact"),
    }
}

fn explanation(c: &Value) -> [u8; 32] {
    bytes_arr(&c["explanation_digest"]).try_into().unwrap()
}

fn case<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

fn rows<'a>(v: &'a Value, section: &str) -> &'a [Value] {
    let r = v[section]
        .as_array()
        .unwrap_or_else(|| panic!("missing section {section}"));
    assert!(!r.is_empty(), "{section} is empty");
    r
}

fn scheme(row: &Value) -> Option<V> {
    match row["scheme"].as_str() {
        Some("v5") => Some(V::V5),
        Some("v6") => Some(V::V6),
        None => None,
        Some(s) => panic!("unknown scheme {s}"),
    }
}

/// `cases`: digest-only rows replay through the digest function with the given field values (and must
/// NOT look for trailers, which are `null`); the others derive fields 10–12 from `trailers` and compare.
#[test]
fn every_v6_case_matches() {
    let v = load("commitment_digest_v6_vector.json");
    assert_eq!(v["commitment_digest_domain"], "seam-commitment-digest:v6");
    let cases = rows(&v, "cases");
    assert_eq!(cases.len(), 15);
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let mut c = commitment(&row["commitment"]);
        c.selection_digest = opt_hex(row, "selection_digest");
        c.governing_doc_sha256 = opt_hex(row, "governing_doc_sha256");
        let e = explanation(&row["commitment"]);
        assert_eq!(
            hex(&e),
            row["explanation_digest"].as_str().unwrap(),
            "{name}"
        );
        let (field_10, env) = if row["digest_only"] == true {
            assert!(
                row["trailers"].is_null(),
                "{name}: digest_only carries no trailers"
            );
            (
                opt_hex(row, "gate_digest"),
                row["env"].as_str().map(|s| s.as_bytes().to_vec()),
            )
        } else {
            let t = decode_commitment_trailers(
                &unhex(row["trailers"].as_str().expect("a hex string")),
                Some(V::V6),
            )
            .unwrap_or_else(|r| panic!("{name}: {r}"));
            assert_eq!(hex(&t.field_10()), row["field_10"], "{name}: field 10");
            assert_eq!(hex(&t.field_11()), row["field_11"], "{name}: field 11");
            assert_eq!(hex(&t.field_12()), row["field_12"], "{name}: field 12");
            assert_eq!(
                t.gate_digest.map(|d| hex(&d)),
                row["gate_digest"].as_str().map(str::to_owned),
                "{name}: gate digest recomputed over the 0x05 body"
            );
            assert_eq!(t.env(), row["env"].as_str(), "{name}: env");
            assert_eq!(
                t.governing_doc_sha256().map(|d| d.to_vec()),
                c.governing_doc_sha256,
                "{name}: field 11 from the trailer"
            );
            (
                t.gate_digest.map(|d| d.to_vec()),
                t.env().map(|s| s.as_bytes().to_vec()),
            )
        };
        assert_eq!(
            hex(&encode_slot(field_10.as_deref())),
            row["field_10"],
            "{name}"
        );
        assert_eq!(hex(&encode_slot(env.as_deref())), row["field_12"], "{name}");
        let d = commitment_digest_under(V::V6, &c, &e, field_10.as_deref(), env.as_deref())
            .unwrap_or_else(|r| panic!("{name}: {r}"));
        assert_eq!(
            hex(&d),
            row["commitment_digest"].as_str().unwrap(),
            "{name}"
        );
        // The re-cut rows carry the v5 digest of the same inputs: fields 0–11 frame exactly as v5.
        if let Some(v5) = row.get("v5_commitment_digest").and_then(Value::as_str) {
            let d5 = commitment_digest_under(V::V5, &c, &e, field_10.as_deref(), None).unwrap();
            assert_eq!(hex(&d5), v5, "{name}: v5 digest");
        }
    }
}

/// (commitment, explanation digest, field 10 value, env).
type RefusalInputs = (Commitment, [u8; 32], Option<Vec<u8>>, Option<Vec<u8>>);

/// The inputs of a refusal row: its `base_case`'s fields, then `override`, then `env`.
fn refusal_inputs(v: &Value, row: &Value) -> RefusalInputs {
    let base = case(v, row["base_case"].as_str().unwrap());
    let mut c = commitment(&base["commitment"]);
    c.selection_digest = opt_hex(base, "selection_digest");
    c.governing_doc_sha256 = opt_hex(base, "governing_doc_sha256");
    let mut gate = opt_hex(base, "gate_digest");
    let mut env = base["env"].as_str().map(|s| s.as_bytes().to_vec());
    if let Some(o) = row.get("override").and_then(Value::as_object) {
        for (k, val) in o {
            let b = val.as_str().map(unhex);
            match k.as_str() {
                "selection_digest" => c.selection_digest = b,
                "gate_digest" => gate = b,
                "governing_doc_sha256" => c.governing_doc_sha256 = b,
                other => panic!("unknown override {other}"),
            }
        }
    }
    if let Some(e) = row.get("env") {
        env = e.as_str().map(|s| s.as_bytes().to_vec());
    }
    (c, explanation(&base["commitment"]), gate, env)
}

#[test]
fn every_digest_input_refusal_is_refused_before_hashing() {
    let v = load("commitment_digest_v6_vector.json");
    for row in rows(&v, "digest_input_refusals") {
        let (c, e, gate, env) = refusal_inputs(&v, row);
        let s = scheme(row).expect("a scheme");
        assert!(
            commitment_digest_under(s, &c, &e, gate.as_deref(), env.as_deref()).is_err(),
            "{}: must refuse",
            row["name"]
        );
    }
}

#[test]
fn every_governing_trailer_and_v5_refusal_is_refused() {
    let v = load("commitment_digest_v6_vector.json");
    for section in ["governing_trailer_refusals", "v5_refusals"] {
        for row in rows(&v, section) {
            let name = row["name"].as_str().unwrap();
            assert!(
                row["expect"].as_str().unwrap().starts_with("refused"),
                "{name}"
            );
            let s = scheme(row);
            if let Some(t) = row.get("trailers").and_then(Value::as_str) {
                assert!(
                    decode_commitment_trailers(&unhex(t), s).is_err(),
                    "{section}/{name}: must refuse"
                );
            } else {
                // `env_under_v5_digest`: a v5 digest asked to frame an env.
                let (c, e, gate, env) = refusal_inputs(&v, row);
                assert!(
                    commitment_digest_under(s.unwrap(), &c, &e, gate.as_deref(), env.as_deref())
                        .is_err(),
                    "{section}/{name}: must refuse"
                );
            }
        }
    }
}

/// `scheme_free`: both body versions accepted and `governing_body_version` reported; every scheme-free
/// rule (here `gate_env_binding` and an unknown body version) still refuses.
#[test]
fn the_scheme_free_decode_matches() {
    let v = load("commitment_digest_v6_vector.json");
    for row in rows(&v, "scheme_free") {
        let name = row["name"].as_str().unwrap();
        assert!(row["scheme"].is_null());
        let got = decode_commitment_trailers(&unhex(row["trailers"].as_str().unwrap()), None);
        match &row["expect"] {
            Value::String(s) => {
                assert_eq!(s, "refused");
                assert!(got.is_err(), "{name}: must refuse");
            }
            Value::Object(o) => {
                let t = got.unwrap_or_else(|r| panic!("{name}: {r}"));
                assert_eq!(hex(&t.field_10()), o["field_10"], "{name}");
                assert_eq!(hex(&t.field_11()), o["field_11"], "{name}");
                if let Some(f12) = o.get("field_12") {
                    assert_eq!(hex(&t.field_12()), *f12, "{name}");
                }
                assert_eq!(
                    t.governing_body_version().map(u64::from),
                    o["governing_body_version"].as_u64(),
                    "{name}"
                );
            }
            other => panic!("{name}: unexpected expect {other}"),
        }
    }
}

#[test]
fn every_statement_selection_row_matches() {
    let v = load("commitment_digest_v6_vector.json");
    for row in rows(&v, "statement_selection") {
        let name = row["name"].as_str().unwrap();
        let got = match (row.get("statement"), row.get("ext")) {
            (Some(s), None) => select_commitment_version(s.as_str().unwrap().as_bytes()),
            (None, Some(e)) => select_commitment_version_in_ext(e.as_str().unwrap().as_bytes()),
            _ => panic!("{name}: neither statement nor ext"),
        };
        match row["expect"].as_str().unwrap() {
            "v5" => assert_eq!(got.map(|s| s.version), Ok(V::V5), "{name}"),
            "v6" => assert_eq!(got.map(|s| s.version), Ok(V::V6), "{name}"),
            "refused" => assert!(got.is_err(), "{name}: must refuse"),
            other => panic!("{name}: unexpected expect {other}"),
        }
    }
}

/// A clock inside every signed vector TCT's `[iat, exp]`.
const NOW: u64 = 1_800_000_000;

#[test]
fn the_signed_v6_tcts_verify_under_v6_only_and_every_negative_is_refused() {
    let v = load("commitment_digest_v6_signed_vector.json");
    let issuer = v["issuer_aid"].as_str().unwrap();
    for row in rows(&v, "cases") {
        let name = row["name"].as_str().unwrap();
        let mut c = commitment(&row["commitment"]);
        assert_eq!(
            explanation_digest(&c.explanation).unwrap(),
            explanation(&row["commitment"]),
            "{name}: entries bind the explanation digest"
        );
        c.signed_artifact = row["signed_artifact"].as_str().unwrap().into();
        let trailers = unhex(row["trailers"].as_str().unwrap());
        let t = decode_commitment_trailers(&trailers, Some(V::V6)).unwrap();
        assert_eq!(hex(&t.field_10()), row["field_10"], "{name}");
        assert_eq!(hex(&t.field_11()), row["field_11"], "{name}");
        assert_eq!(hex(&t.field_12()), row["field_12"], "{name}");
        assert_eq!(row["expect"], "v6");
        assert_eq!(
            verify_commitment_tct(issuer, &c, &trailers, NOW),
            Ok(V::V6),
            "{name}"
        );
        // An edited field moves the digest, and the TCT no longer binds it.
        let mut edited = c.clone();
        edited.id.push('x');
        assert!(
            verify_commitment_tct(issuer, &edited, &trailers, NOW).is_err(),
            "{name}"
        );
        // A wrong pinned issuer fails closed.
        let other = "aid:pubkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(
            verify_commitment_tct(other, &c, &trailers, NOW).is_err(),
            "{name}"
        );
    }
    for row in rows(&v, "negatives") {
        let name = row["name"].as_str().unwrap();
        assert_eq!(row["expect"], "refused");
        let over = case(&v, row["over"].as_str().unwrap());
        let mut c = commitment(&over["commitment"]);
        c.signed_artifact = row["signed_artifact"].as_str().unwrap().into();
        let trailers = unhex(over["trailers"].as_str().unwrap());
        assert!(
            verify_commitment_tct(issuer, &c, &trailers, NOW).is_err(),
            "{name}: must refuse"
        );
    }
}

fn be64_dec(b: &Value, k: &str) -> u64 {
    b[k].as_str().unwrap().parse().unwrap()
}

#[test]
fn every_gate_case_decodes_and_digests() {
    let v = load("gate_block_vector.json");
    assert_eq!(v["gate_digest_domain"], "seam-gate-digest:v1");
    for row in rows(&v, "cases") {
        let name = row["name"].as_str().unwrap();
        let body = unhex(row["gate_body"].as_str().unwrap());
        let g = decode_gate_body(&body).unwrap_or_else(|r| panic!("{name}: {r}"));
        let b = &row["block"];
        assert_eq!(g.attempt_id, text(b, "attempt_id"), "{name}");
        assert_eq!(g.domain, text(b, "domain"), "{name}");
        assert_eq!(g.flow_id, text(b, "flow_id"), "{name}");
        assert_eq!(g.env, text(b, "env"), "{name}");
        assert_eq!(g.timeout_ms, be64_dec(b, "timeout_ms"), "{name}");
        assert_eq!(g.requested_at_ms, be64_dec(b, "requested_at_ms"), "{name}");
        let on_outage = match g.on_outage {
            1 => "refuse_seal",
            2 => "seal_gate_unavailable",
            _ => unreachable!(),
        };
        assert_eq!(on_outage, text(b, "on_outage"), "{name}");
        match &g.result {
            GateResult::Answered {
                receipt_jcs,
                key_id,
                signature,
                certificate_jcs,
            } => {
                assert_eq!(text(b, "status"), "answered");
                assert_eq!(*receipt_jcs, text(b, "receipt_jcs"));
                assert_eq!(*key_id, text(b, "key_id"));
                assert_eq!(hex(signature), text(b, "signature"));
                assert_eq!(
                    certificate_jcs.as_deref(),
                    b["certificate_jcs"].as_str(),
                    "{name}"
                );
            }
            GateResult::Unavailable {
                reason,
                given_up_at_ms,
            } => {
                assert_eq!(text(b, "status"), "unavailable");
                let r = match reason {
                    1 => "timeout",
                    2 => "connect",
                    3 => "http_5xx",
                    5 => "circuit_open",
                    6 => "token_mint",
                    _ => unreachable!(),
                };
                assert_eq!(r, text(b, "reason"), "{name}");
                assert_eq!(*given_up_at_ms, be64_dec(b, "given_up_at_ms"), "{name}");
            }
        }
        let d = gate_digest(&body);
        assert_eq!(hex(&d), row["gate_digest"].as_str().unwrap(), "{name}");
        assert_eq!(hex(&encode_slot(Some(&d))), row["field_10"], "{name}");
        let mut trailer = vec![0x05];
        trailer.extend_from_slice(&(body.len() as u32).to_le_bytes());
        trailer.extend_from_slice(&body);
        assert_eq!(hex(&trailer), row["trailer"], "{name}");
        let mut prefix = 19u64.to_be_bytes().to_vec();
        prefix.extend_from_slice(b"seam-gate-digest:v1");
        assert_eq!(hex(&prefix), row["gate_digest_preimage_prefix"], "{name}");
    }
}

#[test]
fn the_three_presence_states_match() {
    let v = load("gate_block_vector.json");
    let states = rows(&v, "presence_states");
    assert_eq!(states.len(), 3);
    for row in states {
        let name = row["name"].as_str().unwrap();
        let field_10 = match row["trailer"].as_str() {
            None => encode_slot(None),
            Some(t) => {
                let t = unhex(t);
                assert_eq!(t[0], 0x05, "{name}");
                let body = &t[5..];
                assert_eq!(
                    u32::from_le_bytes(t[1..5].try_into().unwrap()) as usize,
                    body.len()
                );
                decode_gate_body(body).unwrap();
                encode_slot(Some(&gate_digest(body)))
            }
        };
        assert_eq!(hex(&field_10), row["field_10"], "{name}");
    }
}

#[test]
fn every_gate_body_refusal_is_refused() {
    let v = load("gate_block_vector.json");
    for row in rows(&v, "body_refusals") {
        assert_eq!(row["expect"], "refused");
        assert!(
            decode_gate_body(&unhex(row["gate_body"].as_str().unwrap())).is_err(),
            "{}: must refuse",
            row["name"]
        );
    }
}

#[test]
fn every_gate_sequence_matches() {
    let v = load("gate_block_vector.json");
    for row in rows(&v, "sequences") {
        let name = row["name"].as_str().unwrap();
        let got =
            decode_commitment_trailers(&unhex(row["trailers"].as_str().unwrap()), scheme(row));
        match &row["expect"] {
            Value::String(s) => {
                assert_eq!(s, "refused");
                assert!(got.is_err(), "{name}: must refuse");
            }
            Value::Object(o) => {
                let t = got.unwrap_or_else(|r| panic!("{name}: {r}"));
                assert_eq!(hex(&t.field_10()), o["field_10"], "{name}");
                assert_eq!(hex(&t.field_11()), o["field_11"], "{name}");
                assert_eq!(hex(&t.field_12()), o["field_12"], "{name}");
            }
            other => panic!("{name}: unexpected expect {other}"),
        }
    }
}

/// `outage_classification` and `writer_refusals` pin what the WRITER may seal for an observed HTTP
/// outcome (B3: a 4xx is never `unavailable`). A Gate body cannot carry the HTTP status, so no reader can
/// check them: they are deliberately not ported (plan A18 §3). Asserted present so a change to the file's
/// shape is still noticed here.
#[test]
fn the_writer_side_sections_are_present_and_not_ported() {
    let v = load("gate_block_vector.json");
    assert!(!rows(&v, "outage_classification").is_empty());
    assert!(!rows(&v, "writer_refusals").is_empty());
}

/// seam-sdk#420: a served `Commitment` carries no raw trailers, only the projection (`gate.body`,
/// `governing_doc_sha256`, `env`). It is lossless under v6: it rebuilds each signed case's trailer run byte
/// for byte, so a served record verifies; a wrong projected value fails the TCT.
#[test]
fn a_served_projection_rebuilds_the_trailers_and_verifies() {
    let v = load("commitment_digest_v6_signed_vector.json");
    let issuer = v["issuer_aid"].as_str().unwrap();
    for row in rows(&v, "cases") {
        let name = row["name"].as_str().unwrap();
        let mut c = commitment(&row["commitment"]);
        c.signed_artifact = row["signed_artifact"].as_str().unwrap().into();
        let raw = unhex(row["trailers"].as_str().unwrap());
        let gate = (raw.first() == Some(&0x05)).then(|| {
            let n = u32::from_le_bytes(raw[1..5].try_into().unwrap()) as usize;
            raw[5..5 + n].to_vec()
        });
        let t = decode_commitment_trailers(&raw, Some(V::V6)).unwrap();
        let doc = t.governing_doc_sha256().copied();
        let env = t.env().map(str::to_owned);
        let rebuilt =
            served_commitment_trailers(gate.as_deref(), doc.as_ref(), env.as_deref()).unwrap();
        assert_eq!(hex(&rebuilt), hex(&raw), "{name}: rebuild");
        assert_eq!(
            verify_commitment_tct(issuer, &c, &rebuilt, NOW),
            Ok(V::V6),
            "{name}"
        );
        if let Some(d) = doc {
            let flipped = if env.as_deref() == Some("live") {
                "sandbox"
            } else {
                "live"
            };
            let wrong = served_commitment_trailers(gate.as_deref(), Some(&d), Some(flipped));
            if let Ok(w) = wrong {
                assert!(
                    verify_commitment_tct(issuer, &c, &w, NOW).is_err(),
                    "{name}: flipped env"
                );
            }
        }
    }
    for (gate, doc, env, rule) in [
        (None, None, Some("live"), "env_without_governing_doc"),
        (None, Some([1u8; 32]), Some(""), "env_not_sandbox_or_live"),
        (
            None,
            Some([1u8; 32]),
            Some("Live"),
            "env_not_sandbox_or_live",
        ),
    ] {
        let r = served_commitment_trailers(gate, doc.as_ref(), env).unwrap_err();
        assert_eq!(r.rule, rule);
    }
}

/// S-4 evidence grade, pinned by `conformance/tct_sealed_at_vector.json` (emitted by
/// `scripts/emit_tct_sealed_at_vector.py` over this file's signed vector), the vector the Python, TS, Go,
/// Java and Kotlin verifiers answer too: `sealed_at_ms <= i64::MAX` and `iat == floor(sealed_at_ms / 1000)`,
/// the runtime's `verify_commitment_sealed_at` (seam-runtime #2031).
#[test]
fn the_sealed_at_vector_binds_iat_to_the_chained_seal_second() {
    let sv = load("tct_sealed_at_vector.json");
    assert_eq!(
        sv["source"],
        "conformance/commitment_digest_v6_signed_vector.json"
    );
    let v = load("commitment_digest_v6_signed_vector.json");
    let issuer = v["issuer_aid"].as_str().unwrap();
    let row = case(&v, sv["over"].as_str().unwrap());
    let mut c = commitment(&row["commitment"]);
    c.signed_artifact = row["signed_artifact"].as_str().unwrap().into();
    let trailers = unhex(row["trailers"].as_str().unwrap());
    assert_eq!(
        verify_commitment_tct(issuer, &c, &trailers, NOW),
        Ok(V::V6),
        "control"
    );
    let cases = rows(&sv, "cases");
    for n in [
        "exact_second_boundary",
        "last_ms_of_the_second",
        "iat_plus_1s_at_boundary",
        "iat_minus_1s_at_boundary",
        "replayed_onto_another_record",
        "commitment_id_is_not_the_record_id",
    ] {
        assert!(cases.iter().any(|r| r["name"] == n), "vector lacks {n}");
    }
    for r in cases {
        let name = r["name"].as_str().unwrap();
        let id = r["decision_id"].as_str().unwrap();
        let ms: u64 = r["sealed_at_ms"].as_str().unwrap().parse().unwrap();
        let got = verify_commitment_tct_sealed_at(issuer, &c, &trailers, NOW, id, ms);
        assert_eq!(
            got.is_ok(),
            r["expect"] == "verified",
            "{name}: decision_id {id:?}, sealed_at_ms {ms}: {got:?}"
        );
        if let Err(e) = got {
            assert!(e.contains("seals a different record"), "{name}: {e}");
        }
    }
    let id = sv["decision_id"].as_str().unwrap();
    assert!(verify_commitment_tct_sealed_at(issuer, &c, &trailers, NOW, id, u64::MAX).is_err());
}

/// The `seam-tct-jti-v1` derivation answers the runtime's own known answer and the token's `jti`.
#[test]
fn the_tct_jti_derivation_matches_the_runtime_known_answer() {
    let sv = load("tct_sealed_at_vector.json");
    let kat = &sv["jti_kat"];
    let ms: i64 = kat["sealed_at_ms"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        tct_jti(kat["decision_id"].as_str().unwrap(), ms).unwrap(),
        kat["jti"].as_str().unwrap()
    );
    let v = load("commitment_digest_v6_signed_vector.json");
    let seal_ms = v["seal_ms"].as_i64().unwrap();
    assert_eq!(
        tct_jti(sv["decision_id"].as_str().unwrap(), seal_ms).unwrap(),
        sv["jti"].as_str().unwrap()
    );
}
