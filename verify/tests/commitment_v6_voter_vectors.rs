//! `seam-commitment-digest:v6` with sealed voter records: every row of
//! `conformance/commitment_digest_v6_voter_vector.json` (seam-runtime
//! `crates/seam-trust-aitp/tests/fixtures/`, seamd 0.113.0, byte-pinned by its `sdk-digest-parity`).
//! Specs: seam-runtime `docs/specs/seam-commitment-digest.v6.md` and `docs/specs/voter-verification.v1.md`.
//!
//! Unlike the plain v6 signed vector, its vote and objection entries carry real `seam-voter-pop-v1`
//! records, so the TCT is checked over the full commitment (entries and trailers), and the
//! commitment-level voter check runs against the vector's `decision`. A case passes under v6 AND
//! `verify_commitment_voters(entries, issuer_aid, decision)` with `voters_verified` records. A negative
//! is refused by at least one of the two. `rule` is advisory (the vector's note says so), so it is never
//! compared: `accepted_outside_window` carries `record_malformed`, for one.
//!
//! The records are read by the bundle's own public reader (`bundle::parse_voter_verification`), since the
//! vector's projection is the bundle's: byte fields as JSON number arrays.
//!
//! Excluded from the published package (see `Cargo.toml`), for the reason `tests/conformance.rs` is: it
//! reads the ONE copy of the vector rather than vendoring a second one.

use seam_verify::bundle::parse_voter_verification;
use seam_verify::commitment::{
    commitment_digest_v6, decode_commitment_trailers, explanation_digest,
    select_commitment_version_in_ext, verify_commitment_tct, Commitment,
    CommitmentDigestVersion as V, ExplanationEntry,
};
use seam_verify::voter::verify_commitment_voters;
use serde_json::Value;

fn load() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../conformance/commitment_digest_v6_voter_vector.json");
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
        .map(|b| u8::try_from(b.as_u64().unwrap()).unwrap())
        .collect()
}

/// A row as the verifier reads it: the full commitment WITH its entries (records included), its TCT, and
/// the raw `0x05`/`0x06` trailers.
fn commitment(row: &Value) -> (Commitment, Vec<u8>) {
    let c = &row["commitment"];
    let explanation = c["explanation"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| ExplanationEntry {
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
            voter_verification: match &e["voter_verification"] {
                Value::Null => None,
                v => Some(parse_voter_verification(v).unwrap()),
            },
        })
        .collect();
    let commitment = Commitment {
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
        explanation,
        selection_digest: None,
        certificate_digest: None,
        governing_doc_sha256: c
            .get("governing_doc_sha256")
            .filter(|v| v.is_array())
            .map(bytes_arr),
        signed_artifact: text(row, "signed_artifact"),
    };
    (commitment, unhex(row["trailers"].as_str().unwrap()))
}

fn records(c: &Commitment) -> usize {
    c.explanation
        .iter()
        .filter(|e| e.voter_verification.is_some())
        .count()
}

fn rows<'a>(v: &'a Value, section: &str) -> &'a [Value] {
    v[section].as_array().unwrap()
}

fn named<'a>(v: &'a Value, name: &str) -> &'a Value {
    rows(v, "negatives")
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("no negative {name}"))
}

fn decision(v: &Value) -> (String, String) {
    let d = v["decision"].as_array().unwrap();
    assert_eq!(d.len(), 2);
    (d[0].as_str().unwrap().into(), d[1].as_str().unwrap().into())
}

/// A clock inside every vector TCT's `[iat, exp]` (1767225600, 4920825600).
const NOW: u64 = 1_800_000_000;

#[test]
fn the_vector_file_is_the_v6_voter_spec() {
    let v = load();
    assert_eq!(v["commitment_digest_domain"], "seam-commitment-digest:v6");
    assert_eq!(v["explanation_digest_domain"], "seam-explanation-digest:v2");
    assert_eq!(v["gate_digest_domain"], "seam-gate-digest:v1");
    decision(&v);
    let lists: std::collections::BTreeSet<&str> = v
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, x)| x.is_array())
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(
        lists,
        ["cases", "decision", "negatives"].into_iter().collect()
    );
    assert_eq!(rows(&v, "cases").len(), 2);
    assert_eq!(rows(&v, "negatives").len(), 8);
}

#[test]
fn every_case_verifies_with_its_voter_records() {
    let v = load();
    let issuer = v["issuer_aid"].as_str().unwrap();
    let (tenant, session) = decision(&v);
    let want = v["voters_verified"].as_u64().unwrap() as usize;
    for row in rows(&v, "cases") {
        let name = row["name"].as_str().unwrap();
        let (c, trailers) = commitment(row);
        assert_eq!(row["expect"], "v6", "{name}");
        assert_eq!(
            select_commitment_version_in_ext(row["ext"].as_str().unwrap().as_bytes())
                .map(|s| s.version),
            Ok(V::V6),
            "{name}: version selected from ext"
        );
        assert_eq!(
            explanation_digest(&c.explanation).unwrap().to_vec(),
            bytes_arr(&row["commitment"]["explanation_digest"]),
            "{name}: entries (records included) bind the explanation digest"
        );
        let t = decode_commitment_trailers(&trailers, Some(V::V6))
            .unwrap_or_else(|r| panic!("{name}: {r}"));
        assert_eq!(
            t.governing_doc_sha256().map(|d| d.to_vec()),
            c.governing_doc_sha256,
            "{name}: the stated doc is the 0x06 trailer's"
        );
        let d = commitment_digest_v6(
            &c,
            t.gate_digest.as_ref().map(|d| d.as_slice()),
            t.env().map(str::as_bytes),
        )
        .unwrap_or_else(|r| panic!("{name}: {r}"));
        assert_eq!(hex(&d), row["commitment_digest"], "{name}: v6 digest");
        assert_eq!(
            verify_commitment_tct(issuer, &c, &trailers, NOW),
            Ok(V::V6),
            "{name}"
        );
        assert_eq!(
            verify_commitment_voters(&c.explanation, issuer, Some((&tenant, &session))),
            Ok(want),
            "{name}"
        );
        assert_eq!(records(&c), want, "{name}: every record verified");
    }
}

#[test]
fn every_negative_is_refused() {
    let v = load();
    let issuer = v["issuer_aid"].as_str().unwrap();
    let (tenant, session) = decision(&v);
    let cases: Vec<&Value> = rows(&v, "cases").iter().map(|c| &c["name"]).collect();
    for row in rows(&v, "negatives") {
        let name = row["name"].as_str().unwrap();
        assert_eq!(row["expect"], "refused", "{name}");
        assert!(cases.contains(&&row["over"]), "{name}: over a known case");
        let (c, trailers) = commitment(row);
        let tct_ok = verify_commitment_tct(issuer, &c, &trailers, NOW).is_ok();
        let voters_ok =
            verify_commitment_voters(&c.explanation, issuer, Some((&tenant, &session))).is_ok();
        assert!(!(tct_ok && voters_ok), "{name}: must be refused");
    }
}

/// `wrong_decision` is a well-signed TCT whose records name another decision: only the decision the
/// verifier knows can refuse it, so dropping that argument must let it through.
#[test]
fn the_decision_binding_is_what_refuses_wrong_decision() {
    let v = load();
    let issuer = v["issuer_aid"].as_str().unwrap();
    let (tenant, session) = decision(&v);
    let (c, trailers) = commitment(named(&v, "wrong_decision"));
    assert_eq!(verify_commitment_tct(issuer, &c, &trailers, NOW), Ok(V::V6));
    assert!(verify_commitment_voters(&c.explanation, issuer, None).is_ok());
    assert!(verify_commitment_voters(&c.explanation, issuer, Some((&tenant, &session))).is_err());
}

/// The entries and their digest were rewritten together and the old TCT kept: the records still re-check,
/// so it is the commitment digest under the signature that refuses it.
#[test]
fn a_tampered_published_entry_breaks_the_signed_digest() {
    let v = load();
    let issuer = v["issuer_aid"].as_str().unwrap();
    let (tenant, session) = decision(&v);
    let (c, trailers) = commitment(named(&v, "tampered_published_entry"));
    assert!(verify_commitment_voters(&c.explanation, issuer, Some((&tenant, &session))).is_ok());
    assert!(verify_commitment_tct(issuer, &c, &trailers, NOW).is_err());
}
