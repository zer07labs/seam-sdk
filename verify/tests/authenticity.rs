//! `chain --issuer <AID>` — AUTHENTICITY, driven against the runtime's committed golden streams.
//!
//! The goldens in `tests/goldens/` are copied verbatim from the runtime
//! (`seam-runtime/crates/seam-verify/tests/goldens/`, pinned at commit fd633c9); they are the SAME
//! fixtures the runtime's own verifier is tested against, so agreement here is the independent verifier
//! reaching parity on authenticity. Nothing of Seam's is linked (the whole point) — see Cargo.toml.
//!
//! The distinction Phase 3 (design-b) proves: integrity-only PASSES a self-consistent forged chain, but
//! `--issuer` REFUSES it, because a forger cannot mint the issuer-signed head.

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;

// The KAT / golden issuer (ed25519 key from seed 07×32) — the AID a consumer pins out of band.
const ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";

fn golden(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/goldens/");
    std::fs::read_to_string(format!("{path}{name}")).expect("golden must exist")
}

fn run(name: &str, body: &str, args: &[&str]) -> (i32, String) {
    let path = std::env::temp_dir().join(format!("auth-{name}-{}.jsonl", std::process::id()));
    std::fs::write(&path, body).unwrap();
    let mut a: Vec<&str> = vec!["chain", path.to_str().unwrap()];
    a.extend_from_slice(args);
    let out = Command::new(env!("CARGO_BIN_EXE_seam-verify"))
        .args(&a)
        .output()
        .expect("run seam-verify");
    let _ = std::fs::remove_file(&path);
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap(), s)
}

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}
fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Apply `f` to the `payload` object of the FIRST DECISION_SEALED in a JSONL stream; return the new stream.
/// The chain triple (prev_checksum/digest/checksum) is untouched, so integrity stays intact by construction
/// — only the payload column the mutation targets changes, which is exactly a payload-rewrite / strip shape.
fn mutate_first_sealed(jsonl: &str, f: impl Fn(&mut serde_json::Value)) -> String {
    let mut done = false;
    jsonl
        .lines()
        .map(|l| {
            let mut e: serde_json::Value = serde_json::from_str(l).unwrap();
            if !done && e["kind"] == "DECISION_SEALED" {
                if let Some(p) = e.get_mut("payload") {
                    f(p);
                    done = true;
                }
            }
            serde_json::to_string(&e).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ── The golden trio ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn attested_chain_authenticates_under_issuer() {
    let (code, out) = run(
        "attested",
        &golden("attested_chain.jsonl"),
        &["--issuer", ISSUER],
    );
    assert_eq!(
        code, VERIFIED,
        "a genuine attested chain must authenticate:\n{out}"
    );
    assert!(out.contains("CHAIN AUTHENTICATED"), "{out}");
    assert!(
        out.contains("attestations      : 1"),
        "one issuer-signed head:\n{out}"
    );
    assert!(
        out.contains("covered prefix    : 3"),
        "the covered reach is reported:\n{out}"
    );
}

#[test]
fn attested_chain_still_passes_integrity_without_issuer() {
    // --issuer is the strictly-stronger gate: the same stream verifies integrity-only without it.
    let (code, out) = run("attested-int", &golden("attested_chain.jsonl"), &[]);
    assert_eq!(code, VERIFIED, "integrity-only must still pass:\n{out}");
    assert!(out.contains("CHAIN VERIFIED"), "{out}");
    assert!(
        !out.contains("AUTHENTICATED"),
        "no --issuer ⇒ no authenticity claim:\n{out}"
    );
}

#[test]
fn fabricated_chain_passes_integrity_but_is_refused_under_issuer() {
    let fab = golden("fabricated_chain.jsonl");
    // A self-consistent forged chain PASSES integrity — that is exactly the gap design-b closes.
    let (code, out) = run("fab-int", &fab, &[]);
    assert_eq!(
        code, VERIFIED,
        "a self-consistent chain passes integrity:\n{out}"
    );
    // Under --issuer it is REFUSED: a forger cannot mint the issuer-signed head, so its absence is the tell.
    let (code, out) = run("fab-auth", &fab, &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "a chain with no attestation must be REFUSED under --issuer:\n{out}"
    );
    assert!(out.contains("NO chain-head attestation"), "{out}");
}

// ── Spliced: an authentic issuer-signed head relinked onto a different chain dies on position ──────────

#[test]
fn an_authentic_attestation_spliced_onto_another_chain_is_refused() {
    // Take the genuine attestation event (a valid issuer signature over the REAL chain's head at len 3)
    // and relink it as the 3rd link of the fabricated 2-link chain, so integrity passes. Its signature
    // still verifies — but it attests the REAL chain's head at len 3, while this chain's head at len 3 (the
    // relinked attestation's own checksum) differs, so the head-at-position check refuses it on the
    // head-MISMATCH branch. The sharpest case: a valid issuer signature is not enough.
    let attested: Vec<String> = golden("attested_chain.jsonl")
        .lines()
        .map(String::from)
        .collect();
    let fab: Vec<String> = golden("fabricated_chain.jsonl")
        .lines()
        .map(String::from)
        .collect();

    // The fabricated head after its links (ask the binary — no need to re-derive the chain here).
    let (code, out) = run("splice-head", &fab.join("\n"), &["--json"]);
    assert_eq!(code, VERIFIED, "{out}");
    let fab_head_hex = out
        .split("\"head\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("head in json");
    let fab_head: Vec<u8> = (0..fab_head_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&fab_head_hex[i..i + 2], 16).unwrap())
        .collect();

    // The attestation is the last line of the attested golden. Relink it: prev_checksum = fabricated head,
    // checksum = H(prev ‖ digest). The attestation PAYLOAD (attested_len/head/signature) is untouched.
    let mut att: serde_json::Value = serde_json::from_str(attested.last().unwrap()).unwrap();
    let digest = b64d(att["digest"].as_str().unwrap());
    let new_checksum = {
        let mut h = Sha256::new();
        h.update(&fab_head);
        h.update(&digest);
        h.finalize().to_vec()
    };
    att["prev_checksum"] = serde_json::Value::String(b64e(&fab_head));
    att["checksum"] = serde_json::Value::String(b64e(&new_checksum));
    att["seq"] = serde_json::json!(9999);

    let mut spliced = fab.clone();
    spliced.push(serde_json::to_string(&att).unwrap());
    let body = spliced.join("\n");

    // Integrity alone accepts the relink (the chain links cleanly).
    let (code, _out) = run("splice-int", &body, &[]);
    assert_eq!(
        code, VERIFIED,
        "the relinked splice passes integrity by construction"
    );
    // Authenticity refuses it on the position check, despite the valid signature.
    let (code, out) = run("splice-auth", &body, &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "a spliced authentic attestation must be refused:\n{out}"
    );
    // Specifically the head-MISMATCH branch: the attestation is itself the 3rd link, so len 3 IS reached —
    // the head there just differs from what the authentic signature attests.
    assert!(
        out.contains("SPLICED"),
        "the refusal must be the head-at-position splice failure, not out-of-range:\n{out}"
    );
}

// ── design-a: digest-v2 recomputation (Phase 4) ───────────────────────────────────────────────────────

#[test]
fn a_payload_rewrite_is_caught_under_issuer_but_not_by_integrity() {
    let rw = golden("payload_rewrite.jsonl");
    // Integrity PASSES a payload rewrite: the (prev,digest,checksum) triple stays consistent — only the
    // payload column changed. This is exactly the gap design-a closes (design-b's attestation covers the
    // prefix, but the head still matches the copied tag-19 digest).
    let (code, out) = run("rewrite-int", &rw, &[]);
    assert_eq!(
        code, VERIFIED,
        "integrity alone does not catch a rewrite:\n{out}"
    );
    // Under --issuer the recomputed digest-v2 no longer matches the wire digest → REFUSE.
    let (code, out) = run("rewrite-auth", &rw, &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "a payload rewrite must be refused under --issuer:\n{out}"
    );
    assert!(out.contains("does NOT match its own digest"), "{out}");
}

#[test]
fn a_v2_record_with_a_stripped_ciphertext_digest_is_refused() {
    // Strip tag 10 from a v2 DECISION_SEALED but leave the chain triple intact (a strip/downgrade attack:
    // the signed head still matches because tag 19 is copied unchanged). design-a refuses it rather than
    // treating "can't recompute" as a pass.
    let stripped = mutate_first_sealed(&golden("attested_chain.jsonl"), |p| {
        p.as_object_mut().unwrap().remove("ciphertext_digest");
    });
    // Integrity still passes (the triple is untouched).
    let (code, _out) = run("strip-int", &stripped, &[]);
    assert_eq!(
        code, VERIFIED,
        "the strip leaves the chain intact by construction"
    );
    let (code, out) = run("strip-auth", &stripped, &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "a v2 record missing ciphertext_digest must be refused:\n{out}"
    );
    assert!(out.contains("NO ciphertext_digest"), "{out}");
}

#[test]
fn a_v1_record_is_link_verified_but_not_recomputed() {
    // A v1 record (schema_version=1, no ciphertext_digest) is not stream-recomputable; design-a SKIPS it —
    // it must NOT trigger the strip refusal (that is v2-only) nor a false digest mismatch. Downgrade the
    // first sealed record to v1 and drop its ciphertext_digest; the chain + attestation are untouched, so
    // --issuer still passes, with one fewer record recomputed.
    let v1 = mutate_first_sealed(&golden("attested_chain.jsonl"), |p| {
        let o = p.as_object_mut().unwrap();
        o.insert("schema_version".into(), serde_json::json!(1));
        o.remove("ciphertext_digest");
    });
    let (code, out) = run("v1-skip", &v1, &["--issuer", ISSUER]);
    assert_eq!(
        code, VERIFIED,
        "a v1 record must be link-only, never a false failure:\n{out}"
    );
    // 3 v2 records → 2 after one is downgraded to v1.
    assert!(
        out.contains("records recomputed: 2"),
        "the v1 record is skipped, not recomputed:\n{out}"
    );
}

// ── AUTHORIZE_EVALUATED is advisory (P1 regression) ───────────────────────────────────────────────────

#[test]
fn an_authorize_evaluated_event_does_not_break_strict_issuer_verification() {
    // REGRESSION: AUTHORIZE_EVALUATED (spec §AUTHORIZE_EVALUATED, tag 23) is ADVISORY — the authorize
    // path seals nothing, so the event carries no digest/checksum BY DESIGN. Before the fix it was
    // missing from the advisory set, filed as UNVERIFIABLE, and `--strict --issuer` over a healthy
    // attested stream containing a single one exited 2. The runtime emits an event for EVERY ESCALATE
    // verdict unconditionally, so this false refusal hit any real delivered stream.
    let mut stream = golden("attested_chain.jsonl");
    stream.push_str(
        "\n{\"schema_version\":\"seam-event.v1\",\"event_id\":\"az01#az#9\",\"seq\":9,\
         \"occurred_at\":1701,\"tenant\":\"acme\",\"namespace\":\"fraud\",\
         \"kind\":\"AUTHORIZE_EVALUATED\",\"prev_checksum\":\"\",\
         \"authorize_evaluated\":{\"authorize_id\":\"az01\",\"agent_aid\":\"aid:pubkey:agent\",\
         \"agent_id\":\"agent-1\",\"tool_name\":\"payments.transfer\",\
         \"tool_input_digest\":\"sha256:00\",\"verdict\":\"ESCALATE\",\
         \"reason\":\"amount_over_floor\",\"policy_version\":\"p1\"}}",
    );
    let (code, out) = run("az-strict", &stream, &["--strict", "--issuer", ISSUER]);
    assert_eq!(
        code, VERIFIED,
        "a healthy attested stream + one AUTHORIZE_EVALUATED must PASS under --strict --issuer \
         (it used to exit 2, filed as unverifiable):\n{out}"
    );
    assert!(out.contains("CHAIN AUTHENTICATED"), "{out}");
    assert!(
        out.contains("advisory (skipped): 1"),
        "the event must be classified advisory, not unverifiable:\n{out}"
    );
}

// ── Key rotation: --issuer is repeatable ──────────────────────────────────────────────────────────────

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The `seam.audit.chain-head-attestation.v1` signed digest, reimplemented from the spec — built from
/// the published framing alone, like every other fixture here (that a third party CAN is the point).
fn att_digest(len: u64, head: &[u8], at: u64, schema: u32, issuer_aid: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut frame = |part: &[u8]| {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    };
    frame(b"seam.audit.chain-head-attestation.v1");
    frame(&len.to_le_bytes());
    frame(head);
    frame(&at.to_le_bytes());
    frame(&schema.to_le_bytes());
    frame(issuer_aid.as_bytes());
    h.finalize().into()
}

/// A chained CHAIN_HEAD_ATTESTATION event over `(len, head)`, signed by `sk` naming `aid`.
fn attestation_event(
    seq: u64,
    prev: &[u8],
    len: u64,
    attested_head: &[u8],
    sk: &ed25519_dalek::SigningKey,
    aid: &str,
) -> (String, Vec<u8>) {
    use ed25519_dalek::Signer;
    let at = 1_700 + seq;
    let sig = sk
        .sign(&att_digest(len, attested_head, at, 2, aid))
        .to_bytes();
    let digest = Sha256::digest(format!("att-{seq}").as_bytes()).to_vec();
    let checksum = {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(&digest);
        h.finalize().to_vec()
    };
    let line = format!(
        "{{\"schema_version\":\"seam-event.v1\",\"event_id\":\"att#{seq}\",\"seq\":{seq},\
         \"occurred_at\":{at},\"kind\":\"CHAIN_HEAD_ATTESTATION\",\
         \"prev_checksum\":\"{}\",\"digest\":\"{}\",\"checksum\":\"{}\",\
         \"chain_head_attestation\":{{\"attested_len\":{len},\"attested_head\":\"{}\",\
         \"attested_at\":{at},\"issuer_aid\":\"{aid}\",\"digest_schema\":2,\"signature\":\"{}\"}}}}",
        b64e(prev),
        b64e(&digest),
        b64e(&checksum),
        b64e(attested_head),
        b64e(&sig),
    );
    (line, checksum)
}

/// A chain spanning an issuer-key ROTATION: attestations signed by the retired key, then the new one.
/// Pinning BOTH (`--issuer` once per AID) authenticates the whole chain; pinning only the new key must
/// FAIL — the old attestation names an issuer outside the pinned set, same as any single-pin mismatch.
#[test]
fn a_key_rotation_chain_passes_with_both_issuers_pinned_and_fails_with_one() {
    use ed25519_dalek::SigningKey;

    // OLD = the golden issuer (ed25519 seed 07×32); NEW = a fresh key minted here from seed 42×32.
    let old_sk = SigningKey::from_bytes(&[0x07; 32]);
    let old_aid = format!("aid:pubkey:{}", b64u(old_sk.verifying_key().as_bytes()));
    assert_eq!(
        old_aid, ISSUER,
        "seed 07×32 must derive the golden issuer AID"
    );
    let new_sk = SigningKey::from_bytes(&[0x42; 32]);
    let new_aid = format!(
        "aid:pubkey:ed25519:{}",
        b64u(new_sk.verifying_key().as_bytes())
    );

    // Two plain links, then an OLD-signed attestation (itself link 3), then a NEW-signed one (link 4).
    let mut head = vec![0u8; 32];
    let mut lines = Vec::new();
    for seq in 0..2u64 {
        let digest = Sha256::digest(format!("r{seq}").as_bytes()).to_vec();
        let checksum = {
            let mut h = Sha256::new();
            h.update(&head);
            h.update(&digest);
            h.finalize().to_vec()
        };
        lines.push(format!(
            "{{\"schema_version\":\"seam-event.v1\",\"event_id\":\"d{seq}#{seq}\",\"seq\":{seq},\
             \"kind\":\"DECISION_SEALED\",\"prev_checksum\":\"{}\",\"digest\":\"{}\",\
             \"checksum\":\"{}\"}}",
            b64e(&head),
            b64e(&digest),
            b64e(&checksum),
        ));
        head = checksum;
    }
    let (old_att, head3) = attestation_event(2, &head, 2, &head, &old_sk, &old_aid);
    lines.push(old_att);
    let (new_att, _) = attestation_event(3, &head3, 3, &head3, &new_sk, &new_aid);
    lines.push(new_att);
    let body = lines.join("\n");

    // Both keys pinned → the rotation authenticates end-to-end.
    let (code, out) = run(
        "rotation-both",
        &body,
        &["--issuer", &old_aid, "--issuer", &new_aid],
    );
    assert_eq!(
        code, VERIFIED,
        "pin OLD + NEW must PASS across a rotation:\n{out}"
    );
    assert!(out.contains("attestations      : 2"), "{out}");

    // Only the new key pinned → the old attestation names an unpinned issuer: FAIL.
    let (code, out) = run("rotation-new-only", &body, &["--issuer", &new_aid]);
    assert_eq!(
        code, FAILED,
        "an attestation naming an issuer outside the pinned set must FAIL:\n{out}"
    );
    assert!(out.contains("but you pinned"), "{out}");
}

// ── The pin is load-bearing ───────────────────────────────────────────────────────────────────────────

#[test]
fn a_wrong_pinned_issuer_is_refused() {
    // A different pinned AID than the attestation names is refused before any signature work — deriving the
    // key from the attestation's own issuer would make verification tautological.
    let other = "aid:pubkey:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let (code, out) = run(
        "wrong-issuer",
        &golden("attested_chain.jsonl"),
        &["--issuer", other],
    );
    assert_eq!(
        code, FAILED,
        "a mismatched pinned issuer must be refused:\n{out}"
    );
}

// ── v3 record digest (B3) ─────────────────────────────────────────────────────────────────────────
//
// `tests/conformance.rs` proves the v3 formula matches the committed cross-repo vectors. This section
// proves the BEHAVIOUR around it, which no vector can express: that a stripped field is refused and
// reported distinctly from a rewritten one, that an unknown schema_version is refused rather than
// misreported, and that the three new columns are part of an event's identity.
//
// The digest here is transcribed from `seam-event.v1.md` a SECOND time, independently of
// `src/verify.rs` and sharing no code with it. Two transcriptions that agree are evidence; one
// compared against itself is not. (Python and TypeScript carry the same second-transcription check —
// it is what caught a frame/opt confusion during the Python phase.)

fn sha(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

/// A fully-populated v3 payload. Every optional is present, so a mutation test can move any of them,
/// and `context_digest != participation_digest` so a slot or tag swap cannot cancel out.
fn v3_payload() -> serde_json::Value {
    serde_json::json!({
        "decision_id": "dec:v3",
        "tenant": "acme",
        "namespace": "fraud",
        "mode": "decision.v1",
        "policy_version": "policy-7",
        "outcome": "Resolved",
        "supersedes": "dec:prior",
        "sealed_at": 1_700_000_000_000u64,
        "schema_version": 3,
        "ciphertext_digest": b64e(&sha("ciphertext")),
        "context_digest": b64e(&sha("context")),
        "participation_digest": b64e(&sha("participation")),
        "policy_rules_digest": b64e(&sha("policy-rules")),
    })
}

/// `seam.audit.record-digest.v3`, transcribed from the spec independently of `src/verify.rs`.
/// Panics on a payload missing a mandatory field — this helper builds HONEST records; the dishonest
/// ones in the tests below are made by mutating a payload AFTER its digest is computed, which is
/// exactly the shape of a strip or a rewrite.
fn v3_record_digest(p: &serde_json::Value) -> Vec<u8> {
    let mut pre: Vec<u8> = Vec::new();
    let f = |b: &mut Vec<u8>, x: &[u8]| {
        b.extend_from_slice(&(x.len() as u32).to_le_bytes());
        b.extend_from_slice(x);
    };
    let o = |b: &mut Vec<u8>, x: Option<&str>| match x {
        None => b.push(0x00),
        Some(s) => {
            b.push(0x01);
            b.extend_from_slice(&(s.len() as u32).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
        }
    };
    let ob = |b: &mut Vec<u8>, x: Option<Vec<u8>>| match x {
        None => b.push(0x00),
        Some(v) => {
            b.push(0x01);
            b.extend_from_slice(&(v.len() as u32).to_le_bytes());
            b.extend_from_slice(&v);
        }
    };
    let text = |k: &str| p[k].as_str().expect("mandatory text field").to_string();
    let opt_text = |k: &str| p.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let bytes = |k: &str| b64d(p[k].as_str().expect("mandatory bytes field"));
    let opt_bytes = |k: &str| p.get(k).and_then(|v| v.as_str()).map(b64d);

    f(&mut pre, b"seam.audit.record-digest.v3");
    f(&mut pre, text("decision_id").as_bytes());
    f(&mut pre, text("tenant").as_bytes());
    f(&mut pre, text("namespace").as_bytes());
    f(&mut pre, &bytes("ciphertext_digest"));
    f(&mut pre, &p["sealed_at"].as_u64().unwrap().to_le_bytes());
    f(&mut pre, text("outcome").as_bytes());
    o(&mut pre, opt_text("mode").as_deref());
    o(&mut pre, opt_text("policy_version").as_deref());
    o(&mut pre, opt_text("supersedes").as_deref());
    f(&mut pre, &bytes("context_digest"));
    f(&mut pre, &bytes("participation_digest"));
    ob(&mut pre, opt_bytes("policy_rules_digest"));
    f(
        &mut pre,
        &(p["schema_version"].as_u64().unwrap() as u32).to_le_bytes(),
    );
    Sha256::digest(&pre).to_vec()
}

/// A chain of `DECISION_SEALED` events plus a signed head, from `(payload, digest)` pairs. Passing a
/// digest computed from a DIFFERENT payload is how a strip or rewrite is staged: the chain triple
/// stays internally consistent, so integrity still passes and only the recompute can catch it.
fn v3_stream(records: &[(serde_json::Value, Vec<u8>)]) -> String {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let mut head = vec![0u8; 32];
    let mut lines = Vec::new();
    for (seq, (payload, digest)) in records.iter().enumerate() {
        let checksum = {
            let mut h = Sha256::new();
            h.update(&head);
            h.update(digest);
            h.finalize().to_vec()
        };
        lines.push(
            serde_json::json!({
                "schema_version": "seam-event.v1",
                "event_id": format!("v3#{seq}"),
                "seq": seq,
                "occurred_at": 1_700u64 + seq as u64,
                "kind": "DECISION_SEALED",
                "prev_checksum": b64e(&head),
                "digest": b64e(digest),
                "checksum": b64e(&checksum),
                "payload": payload,
            })
            .to_string(),
        );
        head = checksum;
    }
    let n = records.len() as u64;
    let (att, _) = attestation_event(n, &head, n, &head, &sk, ISSUER);
    lines.push(att);
    lines.join("\n")
}

/// One honest v3 record, then `f` applied to its payload WITHOUT recomputing the digest.
fn v3_tampered(f: impl Fn(&mut serde_json::Value)) -> String {
    let honest = v3_payload();
    let digest = v3_record_digest(&honest);
    let mut tampered = honest;
    f(&mut tampered);
    v3_stream(&[(tampered, digest)])
}

/// A strip must be reported in the vocabulary of a strip, and NOT in the vocabulary of a mismatch.
/// Asserting both directions is the point: "refuses somehow" is not the requirement — the spec asks
/// that an operator be able to tell "someone removed a field" from "someone rewrote one", because the
/// two have different responses.
fn assert_strip_not_mismatch(out: &str, field: &str, tag: u32) {
    assert!(
        out.contains(field),
        "the refusal must NAME the field:\n{out}"
    );
    assert!(
        out.contains(&format!("wire tag {tag}")),
        "the refusal must name the wire tag:\n{out}"
    );
    assert!(
        out.contains("STRIP"),
        "the refusal must say it is a strip:\n{out}"
    );
    assert!(
        !out.contains("does NOT match its own digest"),
        "a STRIP is being reported in the vocabulary of a MISMATCH:\n{out}"
    );
}

#[test]
fn an_honest_v3_chain_authenticates_and_is_counted() {
    let p = v3_payload();
    let d = v3_record_digest(&p);
    let (code, out) = run("v3-honest", &v3_stream(&[(p, d)]), &["--issuer", ISSUER]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.contains("records recomputed: 1"),
        "the v3 record must be RECOMPUTED, not merely not-refused — a record skipped by the version \
         dispatch would also produce exit 0:\n{out}"
    );
}

#[test]
fn stripping_a_mandatory_v3_digest_is_refused_as_a_strip() {
    for (field, tag) in [("context_digest", 11u32), ("participation_digest", 12)] {
        let body = v3_tampered(|p| {
            p.as_object_mut().unwrap().remove(field);
        });
        let (code, out) = run("v3-strip", &body, &["--issuer", ISSUER]);
        assert_eq!(code, FAILED, "stripping {field} must fail:\n{out}");
        assert_strip_not_mismatch(&out, field, tag);
    }
}

#[test]
fn a_present_but_empty_v3_digest_is_refused_as_a_strip() {
    // `"context_digest": ""` in the JSON projection means ABSENT, exactly as a zero-length field does
    // on the wire. This test asserted the opposite — that `""` is a distinct present-but-empty state
    // and must be reported MALFORMED — until seam-runtime#435 pinned the rule
    // (`seam-event.v1.md` §"Presence on the wire"): `len == 0` is absence *however the bytes arose*,
    // and the JSON projection "serializes omitted-when-empty and parses missing-as-empty, so
    // missing/`\"\"` ⇔ absent there too".
    //
    // The VERDICT is unchanged — the record still fails, and still fails as a strip rather than a
    // rewrite, which is the property that actually protects an operator. Only the diagnostic moves,
    // from MALFORMED to STRIP, and the spec explicitly sanctions that: telling "omitted" from
    // "explicitly-encoded-empty" requires parsing raw wire bytes rather than a decoded message, and
    // "both inputs verify identically either way; only the diagnostic differs."
    for (field, tag) in [("context_digest", 11u32), ("participation_digest", 12)] {
        let body = v3_tampered(|p| p[field] = serde_json::json!(""));
        let (code, out) = run("v3-empty", &body, &["--issuer", ISSUER]);
        assert_eq!(code, FAILED, "an empty {field} must fail:\n{out}");
        assert_strip_not_mismatch(&out, field, tag);
    }
}

#[test]
fn an_empty_policy_rules_digest_verifies_green_because_absent_is_legitimate() {
    // The counterpart, and the case that motivated the whole correction. Tag 13 absent means no
    // policy was bound — today's common case — so a record SEALED with no policy must still verify
    // when the field arrives as `""` rather than omitted, because `""` and missing are one state.
    //
    // Note the record is sealed WITHOUT tag 13 (`opt(None)`, one byte) and then presented WITH `""`.
    // That is the whole test: if the verifier read `""` as `opt(Some(b""))` — five bytes — it would
    // recompute a different digest and report a rewrite that never happened. This verifier instead
    // refused it outright as MALFORMED until the `len == 0` mapping landed, rejecting a record the
    // contract calls valid and disagreeing with the Python and TS twins on identical bytes.
    let mut honest = v3_payload();
    honest.as_object_mut().unwrap().remove("policy_rules_digest");
    let digest = v3_record_digest(&honest);

    let mut presented = honest;
    presented["policy_rules_digest"] = serde_json::json!("");

    let (code, out) = run("v3-empty-13", &v3_stream(&[(presented, digest)]), &["--issuer", ISSUER]);
    assert_eq!(
        code, VERIFIED,
        "an empty policy_rules_digest is ABSENT, and absent is legitimate:\n{out}"
    );
    assert!(
        out.contains("records recomputed: 1"),
        "it must be RECOMPUTED, not skipped — a skipped record also exits 0:\n{out}"
    );
}

#[test]
fn rewriting_a_v3_column_is_reported_as_a_mismatch_not_a_strip() {
    // The other direction of the same requirement. Without this, "always say STRIP" would pass the
    // strip tests above.
    let body = v3_tampered(|p| p["outcome"] = serde_json::json!("Denied"));
    let (code, out) = run("v3-rewrite", &body, &["--issuer", ISSUER]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("does NOT match its own digest"), "{out}");
    assert!(out.contains("v3 DECISION_SEALED"), "{out}");
    assert!(
        !out.contains("STRIP"),
        "a REWRITE is being reported in the vocabulary of a STRIP:\n{out}"
    );
}

#[test]
fn an_absent_policy_rules_digest_is_legitimate() {
    // Tag 13 absent means no policy was bound — today's common case. A verifier that refused it
    // would reject almost every real record, so this is the mirror of the strip tests.
    let mut p = v3_payload();
    p.as_object_mut().unwrap().remove("policy_rules_digest");
    let d = v3_record_digest(&p);
    let (code, out) = run("v3-no-policy", &v3_stream(&[(p, d)]), &["--issuer", ISSUER]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(out.contains("records recomputed: 1"), "{out}");
}

#[test]
fn an_unknown_schema_version_is_refused_and_no_longer_misreported() {
    // The regression this FIXES: before the version dispatch existed, a record newer than the
    // verifier fell through to the v2 formula, mismatched (v3 binds three more slots), and was
    // reported as "a structural column was rewritten after sealing" — a false accusation of tampering
    // that would send an operator looking for an attack that never happened. Both halves are pinned:
    // it refuses, AND it refuses with the right words.
    let mut p = v3_payload();
    p["schema_version"] = serde_json::json!(4);
    let d = v3_record_digest(&p);
    let (code, out) = run("v3-future", &v3_stream(&[(p, d)]), &["--issuer", ISSUER]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("NEWER THAN THIS VERIFIER"), "{out}");
    assert!(
        !out.contains("does NOT match its own digest"),
        "an unknown version is still being misreported as a payload rewrite:\n{out}"
    );
}

#[test]
fn a_mixed_v2_and_v3_chain_verifies_end_to_end() {
    // Real streams span a version cutover: there is no dual-emit, so a chain simply contains v2
    // records before the switch and v3 records after. Both must recompute under their OWN formula in
    // one pass.
    let v3 = v3_payload();
    let v3_digest = v3_record_digest(&v3);

    let mut v2 = v3_payload();
    {
        let o = v2.as_object_mut().unwrap();
        o.insert("schema_version".into(), serde_json::json!(2));
        o.insert("decision_id".into(), serde_json::json!("dec:v2"));
        for k in [
            "context_digest",
            "participation_digest",
            "policy_rules_digest",
        ] {
            o.remove(k);
        }
    }
    // v2's digest, transcribed here too — same framing, v2 domain, and no B3 slots.
    let v2_digest = {
        let mut pre: Vec<u8> = Vec::new();
        let f = |b: &mut Vec<u8>, x: &[u8]| {
            b.extend_from_slice(&(x.len() as u32).to_le_bytes());
            b.extend_from_slice(x);
        };
        let o = |b: &mut Vec<u8>, x: Option<&str>| match x {
            None => b.push(0x00),
            Some(s) => {
                b.push(0x01);
                b.extend_from_slice(&(s.len() as u32).to_le_bytes());
                b.extend_from_slice(s.as_bytes());
            }
        };
        f(&mut pre, b"seam.audit.record-digest.v2");
        f(&mut pre, b"dec:v2");
        f(&mut pre, b"acme");
        f(&mut pre, b"fraud");
        f(&mut pre, &b64d(v2["ciphertext_digest"].as_str().unwrap()));
        f(&mut pre, &1_700_000_000_000u64.to_le_bytes());
        f(&mut pre, b"Resolved");
        o(&mut pre, Some("decision.v1"));
        o(&mut pre, Some("policy-7"));
        o(&mut pre, Some("dec:prior"));
        f(&mut pre, &2u32.to_le_bytes());
        Sha256::digest(&pre).to_vec()
    };

    let body = v3_stream(&[(v2, v2_digest), (v3, v3_digest)]);
    let (code, out) = run("v3-mixed", &body, &["--issuer", ISSUER]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.contains("records recomputed: 2"),
        "both the v2 and the v3 record must recompute:\n{out}"
    );
}

#[test]
fn integrity_only_still_passes_a_stripped_v3_stream() {
    // The strip refusal is design-a work, scoped to `--issuer`, exactly as the tag-10 strip is. A
    // stream with no pinned issuer is internally consistent and must still verify — "no issuer key
    // therefore integrity-only" is a property of running without `--issuer`, not something a
    // stripped field is allowed to trigger.
    let body = v3_tampered(|p| {
        p.as_object_mut().unwrap().remove("context_digest");
    });
    let (code, out) = run("v3-strip-integrity", &body, &[]);
    assert_eq!(
        code, VERIFIED,
        "integrity-only must not have learned to refuse a strip:\n{out}"
    );
}

#[test]
fn two_v3_records_differing_only_in_a_new_column_are_not_one_event() {
    // The one v3 wire omission that fails SILENTLY. Event identity is the RE-ENCODED event — that is
    // what lets the same event arriving as JSON on a webhook and as protobuf on a relay collapse into
    // one chain link instead of looking like a forgery. If `with_identity` did not carry tags
    // 11/12/13, two records differing ONLY in `participation_digest` would re-encode to identical
    // bytes, and the second would be swallowed as an at-least-once duplicate.
    //
    // Isolating that required care, and two earlier versions of this test were VACUOUS — worth
    // recording, because the trap is the same one the code has:
    //   * chaining the two events normally made `seq` and `prev_checksum` differ, so the identities
    //     differed no matter what the payload carried;
    //   * giving them their own honest digests made `digest`/`checksum` differ — and those ARE in the
    //     identity projection (`wire.rs`, `with_identity`), so again the payload column was never the
    //     discriminator.
    // Both stayed green with the columns dropped. The two lines below are therefore identical in
    // EVERY identity-bearing field, including the chain triple; `participation_digest` is the only
    // thing that can tell them apart.
    //
    // That is also the realistic shape: substitute a payload column, leave (prev, digest, checksum)
    // intact so the chain still hashes. With the columns in the identity, this is refused LOUDLY as an
    // impostor pair. Without them, the substituted record is deduped away, the honest one verifies,
    // and the stream comes back GREEN with the evidence quietly gone.
    let honest = v3_payload();
    let mut substituted = v3_payload();
    substituted["participation_digest"] =
        serde_json::json!(b64e(&sha("a different participation")));

    let prev = vec![0u8; 32];
    let digest = v3_record_digest(&honest);
    let checksum = {
        let mut h = Sha256::new();
        h.update(&prev);
        h.update(&digest);
        h.finalize().to_vec()
    };
    let line = |payload: &serde_json::Value| {
        serde_json::json!({
            "schema_version": "seam-event.v1",
            "event_id": "v3#0",
            "seq": 0,
            "occurred_at": 1_700,
            "kind": "DECISION_SEALED",
            "prev_checksum": b64e(&prev),
            "digest": b64e(&digest),
            "checksum": b64e(&checksum),
            "payload": payload,
        })
        .to_string()
    };

    // An attestation over the one-link head, so that if the substituted record IS deduped away the
    // remaining stream is perfectly valid and verifies GREEN — which is what makes exit 2 below
    // evidence of the identity check rather than of some unrelated refusal.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let (att, _) = attestation_event(1, &checksum, 1, &checksum, &sk, ISSUER);
    let body = format!("{}\n{}\n{}", line(&honest), line(&substituted), att);

    let (code, out) = run("v3-identity", &body, &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "two v3 records differing only in participation_digest collapsed into one event — the new \
         columns are missing from the re-encoded identity, so a substituted record is deduped away \
         and the stream reports GREEN with the evidence gone:\n{out}"
    );
    assert!(
        out.contains("appears TWICE with DIFFERENT content"),
        "the pair must be refused as impostors, which is the LOUD outcome; any other refusal means \
         the payload difference was not visible to the identity projection:\n{out}"
    );
}

#[test]
fn a_covered_record_relabelled_as_v1_is_refused_as_a_downgrade() {
    // The one downgrade direction the recompute cannot catch by construction. Every other
    // schema_version is dispatched to a formula, so a rewritten column fails the comparison. But v1 is
    // SKIPPED — link-only, because its historical digest is not stream-recomputable — so an attacker
    // who rewrites a column and relabels the version lands in the exemption and no recompute ever
    // runs. Before this guard, every case below verified GREEN.
    //
    // What closes it is the one thing a genuine v1 record cannot fake: v1 payloads carry none of the
    // covered columns. Tag 10 arrived with v2 ("absent... only on schema_version = 1 payloads", per
    // the spec) and tags 11/12/13 with v3.
    //
    // Each column is tested ALONE, with the other three removed. Testing them together would let the
    // tag-10 check alone satisfy the whole test — proven: a decoy that guarded only on tag 10 passed
    // an earlier version of this test, leaving the three v3 columns unchecked with a green suite.
    const COLUMNS: [&str; 4] = [
        "ciphertext_digest",
        "context_digest",
        "participation_digest",
        "policy_rules_digest",
    ];
    for kept in COLUMNS {
        let body = v3_tampered(move |p| {
            p["outcome"] = serde_json::json!("Denied"); // the rewrite...
            p["schema_version"] = serde_json::json!(1); // ...and the relabel that hides it
            let o = p.as_object_mut().unwrap();
            for c in COLUMNS {
                if c != kept {
                    o.remove(c);
                }
            }
        });
        let (code, out) = run("v3-downgrade", &body, &["--issuer", ISSUER]);
        assert_eq!(
            code, FAILED,
            "a rewritten record relabelled as v1, carrying only {kept}, was waved through the v1 \
             skip:\n{out}"
        );
        assert!(
            out.contains("DOWNGRADE"),
            "the refusal must name what this is (carrying {kept}):\n{out}"
        );
        assert!(
            out.contains(kept),
            "the refusal must name the column that gave it away ({kept}):\n{out}"
        );
    }
}

#[test]
fn a_genuine_v1_record_is_still_skipped_not_refused() {
    // The mirror, and the reason the guard keys on the COLUMNS rather than on the version alone. Real
    // pre-A14 records exist in real chains; refusing them would break every historical stream and turn
    // a verifier into something nobody can run over their archive.
    let mut p = v3_payload();
    {
        let o = p.as_object_mut().unwrap();
        o.insert("schema_version".into(), serde_json::json!(1));
        for k in [
            "ciphertext_digest",
            "context_digest",
            "participation_digest",
            "policy_rules_digest",
        ] {
            o.remove(k);
        }
    }
    let digest = Sha256::digest(b"historical-v1-digest").to_vec();
    let (code, out) = run(
        "v1-genuine",
        &v3_stream(&[(p, digest)]),
        &["--issuer", ISSUER],
    );
    assert_eq!(
        code, VERIFIED,
        "a genuine v1 record must still verify:\n{out}"
    );
    assert!(
        out.contains("records recomputed: 0"),
        "a v1 record is link-only — it must be SKIPPED, not counted as recomputed:\n{out}"
    );
}
