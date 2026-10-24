//! `chain --issuer <AID>` — AUTHENTICITY, driven against the runtime's committed golden streams.
//!
//! The goldens in `tests/goldens/` are copied verbatim from the runtime
//! (`seam-runtime/crates/seam-verify/tests/goldens/`, re-vendored at the runtime 0.57.0 train pin ae40c52 (k8s P7: `dev/` ids and `stream_id`), matching the
//! `seam-event.v1` spec pin in `docs/seam-event.v1.md`); they are the SAME fixtures the runtime's own
//! verifier is tested against, so agreement here is the independent verifier reaching parity on
//! authenticity. Nothing of Seam's is linked (the whole point) — see Cargo.toml.
//!
//! `attested_chain.jsonl` and `payload_rewrite.jsonl` carry the post-U-RT-3 shape: the
//! `CHAIN_HEAD_ATTESTATION` event's envelope `tenant` agrees with the chain it continues, and its
//! `chain_head_attestation` payload carries its own `tenant`, signed under the v2 framing (#835).
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

// ── design-a: record-digest-v4 recomputation (P7) ─────────────────────────────────────────────────────

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
    // Under --issuer the recomputed digest-v4 no longer matches the wire digest → REFUSE.
    let (code, out) = run("rewrite-auth", &rw, &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "a payload rewrite must be refused under --issuer:\n{out}"
    );
    assert!(out.contains("does NOT match its own digest"), "{out}");
}

#[test]
fn a_record_with_a_stripped_ciphertext_digest_is_refused() {
    // Strip tag 10 from a v4 DECISION_SEALED but leave the chain triple intact (a strip/downgrade attack:
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
        "a v4 record missing ciphertext_digest must be refused:\n{out}"
    );
    assert!(out.contains("NO ciphertext_digest"), "{out}");
}

#[test]
fn a_v1_record_is_refused_as_retired_not_link_verified() {
    // Before P7 a v1 record (schema_version=1, no ciphertext_digest) was SKIPPED as link-only. P7
    // retired v1-v3 with no dual-verify, so the same record is now a cannot-verify refusal: never a
    // pass, and never misreported as a strip or a rewrite. The chain + attestation are untouched, so
    // integrity-only still passes.
    let v1 = mutate_first_sealed(&golden("attested_chain.jsonl"), |p| {
        let o = p.as_object_mut().unwrap();
        o.insert("schema_version".into(), serde_json::json!(1));
        o.remove("ciphertext_digest");
    });
    let (code, _out) = run("v1-int", &v1, &[]);
    assert_eq!(code, VERIFIED, "integrity is untouched by the relabel");
    let (code, out) = run("v1-retired", &v1, &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "a v1 record must be refused, not skipped:\n{out}"
    );
    assert!(
        out.contains("CANNOT VERIFY") && out.contains("RETIRED"),
        "the refusal must say the version is retired:\n{out}"
    );
    assert!(
        !out.contains("NO ciphertext_digest") && !out.contains("does NOT match its own digest"),
        "a retired version must not be reported as a strip or a rewrite:\n{out}"
    );
}

// ── POLICY_DENIED is advisory (the same regression, one kind later) ──────────────────────────────────

#[test]
fn a_policy_denied_event_does_not_break_strict_issuer_verification() {
    // POLICY_DENIED (spec §POLICY_DENIED, tag 24) is ADVISORY for the same reason its neighbour below
    // is: a refused commitment errors before the seal, so nothing is sealed, nothing is appended, and
    // the row carries no digest/checksum BY DESIGN. This is the end-to-end shape of the regression
    // the unit test pins — a healthy attested stream carrying one must still authenticate.
    //
    // Worth having BOTH: the unit test proves the kind classifies advisory, this proves the whole
    // pipeline agrees, and it was the pipeline that reported UNVERIFIABLE and exited 2 last time. The
    // blast radius is also wider here than it was for tag 23 — a bound policy emits one of these per
    // REFUSED COMMITMENT, so a stream under a strict policy carries many, not one.
    let mut stream = golden("attested_chain.jsonl");
    stream.push_str(
        "\n{\"schema_version\":\"seam-event.v1\",\"event_id\":\"sess01#pd#9\",\"seq\":9,\
         \"occurred_at\":1701,\"tenant\":\"acme\",\"namespace\":\"fraud\",\
         \"kind\":\"POLICY_DENIED\",\"prev_checksum\":\"\",\
         \"policy_denied\":{\"policy_version\":\"p1\",\"mode\":\"macp.mode.decision.v1\",\
         \"reason\":\"capability_not_granted\"}}",
    );
    let (code, out) = run("pd-strict", &stream, &["--strict", "--issuer", ISSUER]);
    assert_eq!(
        code, VERIFIED,
        "a healthy attested stream + one POLICY_DENIED must PASS under --strict --issuer:\n{out}"
    );
    assert!(out.contains("CHAIN AUTHENTICATED"), "{out}");
    assert!(
        out.contains("advisory (skipped): 1"),
        "the event must be classified advisory, not unverifiable:\n{out}"
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
///
/// `digest_schema` is a PARAMETER, not a constant, because spec clause (e) makes it load-bearing: it
/// must be >= the highest `schema_version` in the attested prefix. It was hard-coded to `2` until
/// 2026-08-26, which meant every attested-V3 fixture here was signing a false ceiling — four tests
/// asserted GREEN on streams the spec says must be FAILED, and they went red the moment clause (e)
/// was implemented. That is the fixture landmine `seam-runtime` hit in the same change; the value is
/// threaded through so a future v4 cannot silently reintroduce it.
///
/// It is fed to BOTH the signed payload and the JSON field deliberately. Letting them diverge would
/// produce an attestation whose signature covers a different ceiling than the one it advertises —
/// which fails the signature check, masking whatever the test meant to prove.
fn attestation_event(
    seq: u64,
    prev: &[u8],
    len: u64,
    attested_head: &[u8],
    sk: &ed25519_dalek::SigningKey,
    aid: &str,
    digest_schema: u32,
) -> (String, Vec<u8>) {
    use ed25519_dalek::Signer;
    let at = 1_700 + seq;
    let sig = sk
        .sign(&att_digest(len, attested_head, at, digest_schema, aid))
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
         \"attested_at\":{at},\"issuer_aid\":\"{aid}\",\"digest_schema\":{digest_schema},\"signature\":\"{}\"}}}}",
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
    let (old_att, head3) = attestation_event(2, &head, 2, &head, &old_sk, &old_aid, 2);
    lines.push(old_att);
    let (new_att, _) = attestation_event(3, &head3, 3, &head3, &new_sk, &new_aid, 2);
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

// ── v4 record digest (P7) ─────────────────────────────────────────────────────────────────────────
//
// `tests/conformance.rs` proves the v4 formula matches the committed cross-repo vectors. This section
// proves the BEHAVIOUR around it, which no vector can express: that a stripped field is refused and
// reported distinctly from a rewritten one, that every schema_version other than 4 is refused rather
// than skipped or misreported, and that the digest columns are part of an event's identity.
//
// The digest here is transcribed from `seam-event.v1.md` a SECOND time, independently of
// `src/verify.rs` and sharing no code with it. Two transcriptions that agree are evidence; one
// compared against itself is not. (Python and TypeScript carry the same second-transcription check —
// it is what caught a frame/opt confusion during the Python phase.)

fn sha(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

/// A fully-populated v4 payload. Every optional is present, so a mutation test can move any of them,
/// and every 32-byte column holds a distinct value so a slot or tag swap cannot cancel out.
fn v4_payload() -> serde_json::Value {
    serde_json::json!({
        "decision_id": "dec:v4",
        "tenant": "acme",
        "namespace": "fraud",
        "mode": "decision.v1",
        "policy_version": "policy-7",
        "outcome": "Resolved",
        "supersedes": "dec:prior",
        "sealed_at": 1_700_000_000_000u64,
        "schema_version": 4,
        "ciphertext_digest": b64e(&sha("ciphertext")),
        "context_digest": b64e(&sha("context")),
        "participation_digest": b64e(&sha("participation")),
        "policy_rules_digest": b64e(&sha("policy-rules")),
        "classification": "Internal",
        "participants_digest": b64e(&sha("participants")),
        "trust_basis_commitment": format!("hmac-sha256:k1:{}", "cd".repeat(32)),
        "auth_method": "aitp-pinned-handshake",
    })
}

/// `seam.audit.record-digest.v4`, transcribed from the spec independently of `src/verify.rs`.
/// Panics on a payload missing a mandatory field — this helper builds HONEST records; the dishonest
/// ones in the tests below are made by mutating a payload AFTER its digest is computed, which is
/// exactly the shape of a strip or a rewrite.
fn v4_record_digest(p: &serde_json::Value) -> Vec<u8> {
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

    f(&mut pre, b"seam.audit.record-digest.v4");
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
    f(&mut pre, text("classification").as_bytes());
    f(&mut pre, &bytes("participants_digest"));
    f(&mut pre, text("trust_basis_commitment").as_bytes());
    f(&mut pre, text("auth_method").as_bytes());
    f(
        &mut pre,
        &(p["schema_version"].as_u64().unwrap() as u32).to_le_bytes(),
    );
    Sha256::digest(&pre).to_vec()
}

/// A chain of `DECISION_SEALED` events plus a signed head, from `(payload, digest)` pairs. Passing a
/// digest computed from a DIFFERENT payload is how a strip or rewrite is staged: the chain triple
/// stays internally consistent, so integrity still passes and only the recompute can catch it.
///
/// The attestation's ceiling is 4 — the only `schema_version` this build accepts, and what an honest
/// producer stamps. Streams carrying a deliberately bogus `schema_version` are refused for THAT reason
/// by the record loop; a ceiling inflated to cover the bogus value would only change which refusal
/// fires.
fn v4_stream(records: &[(serde_json::Value, Vec<u8>)]) -> String {
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
                "event_id": format!("v4#{seq}"),
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
    let ceiling = records
        .iter()
        .filter_map(|(p, _)| p["schema_version"].as_u64())
        .filter(|v| *v == 4)
        .max()
        .unwrap_or(4) as u32;
    let (att, _) = attestation_event(n, &head, n, &head, &sk, ISSUER, ceiling);
    lines.push(att);
    lines.join("\n")
}

/// One honest v4 record, then `f` applied to its payload WITHOUT recomputing the digest.
fn v4_tampered(f: impl Fn(&mut serde_json::Value)) -> String {
    let honest = v4_payload();
    let digest = v4_record_digest(&honest);
    let mut tampered = honest;
    f(&mut tampered);
    v4_stream(&[(tampered, digest)])
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

/// The mandatory v4 columns a strip can remove, with their wire tags (tag 10 has its own wording and
/// its own test above; tag 13 is legitimately absent).
const MANDATORY_V4: [(&str, u32); 6] = [
    ("context_digest", 11),
    ("participation_digest", 12),
    ("classification", 14),
    ("participants_digest", 15),
    ("trust_basis_commitment", 16),
    ("auth_method", 17),
];

#[test]
fn an_honest_v4_chain_authenticates_and_is_counted() {
    let p = v4_payload();
    let d = v4_record_digest(&p);
    let (code, out) = run("v4-honest", &v4_stream(&[(p, d)]), &["--issuer", ISSUER]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.contains("records recomputed: 1"),
        "the v4 record must be RECOMPUTED, not merely not-refused — a record skipped by the version \
         dispatch would also produce exit 0:\n{out}"
    );
}

#[test]
fn stripping_a_mandatory_v4_column_is_refused_as_a_strip() {
    for (field, tag) in MANDATORY_V4 {
        let body = v4_tampered(|p| {
            p.as_object_mut().unwrap().remove(field);
        });
        let (code, out) = run("v4-strip", &body, &["--issuer", ISSUER]);
        assert_eq!(code, FAILED, "stripping {field} must fail:\n{out}");
        assert_strip_not_mismatch(&out, field, tag);
    }
}

#[test]
fn a_present_but_empty_v4_column_is_refused_as_a_strip() {
    // `"context_digest": ""` in the JSON projection means ABSENT, exactly as a zero-length field does
    // on the wire (`seam-event.v1.md` §"Presence on the wire"): `len == 0` is absence *however the
    // bytes arose*, and the JSON projection serializes omitted-when-empty and parses
    // missing-as-empty. The string columns (14, 16, 17) follow the same rule.
    for (field, tag) in MANDATORY_V4 {
        let body = v4_tampered(|p| p[field] = serde_json::json!(""));
        let (code, out) = run("v4-empty", &body, &["--issuer", ISSUER]);
        assert_eq!(code, FAILED, "an empty {field} must fail:\n{out}");
        assert_strip_not_mismatch(&out, field, tag);
    }
}

#[test]
fn an_empty_policy_rules_digest_verifies_green_because_absent_is_legitimate() {
    // Tag 13 absent means no policy was bound — today's common case — so a record SEALED with no
    // policy must still verify when the field arrives as `""` rather than omitted, because `""` and
    // missing are one state.
    //
    // The record is sealed WITHOUT tag 13 (`opt(None)`, one byte) and then presented WITH `""`. If
    // the verifier read `""` as `opt(Some(b""))` — five bytes — it would recompute a different digest
    // and report a rewrite that never happened.
    let mut honest = v4_payload();
    honest
        .as_object_mut()
        .unwrap()
        .remove("policy_rules_digest");
    let digest = v4_record_digest(&honest);

    let mut presented = honest;
    presented["policy_rules_digest"] = serde_json::json!("");

    let (code, out) = run(
        "v4-empty-13",
        &v4_stream(&[(presented, digest)]),
        &["--issuer", ISSUER],
    );
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
fn rewriting_a_v4_column_is_reported_as_a_mismatch_not_a_strip() {
    // The other direction of the same requirement. Without this, "always say STRIP" would pass the
    // strip tests above. The four P7 columns are each rewritten too: a verifier that hashed them in
    // the wrong slot, or not at all, would pass a rewrite of one of them.
    let rewrites: [(&str, serde_json::Value); 5] = [
        ("outcome", serde_json::json!("Denied")),
        ("classification", serde_json::json!("Financial")),
        (
            "participants_digest",
            serde_json::json!(b64e(&sha("another roster"))),
        ),
        (
            "trust_basis_commitment",
            serde_json::json!(format!("hmac-sha256:k1:{}", "ab".repeat(32))),
        ),
        ("auth_method", serde_json::json!("aitp-tct")),
    ];
    for (field, value) in rewrites {
        let body = v4_tampered(|p| p[field] = value.clone());
        let (code, out) = run("v4-rewrite", &body, &["--issuer", ISSUER]);
        assert_eq!(code, FAILED, "rewriting {field}:\n{out}");
        assert!(
            out.contains("does NOT match its own digest"),
            "{field}: {out}"
        );
        assert!(out.contains("v4 DECISION_SEALED"), "{field}: {out}");
        assert!(
            !out.contains("STRIP"),
            "a REWRITE of {field} is being reported in the vocabulary of a STRIP:\n{out}"
        );
    }
}

#[test]
fn an_absent_policy_rules_digest_is_legitimate() {
    // Tag 13 absent means no policy was bound — today's common case. A verifier that refused it
    // would reject almost every real record, so this is the mirror of the strip tests.
    let mut p = v4_payload();
    p.as_object_mut().unwrap().remove("policy_rules_digest");
    let d = v4_record_digest(&p);
    let (code, out) = run("v4-no-policy", &v4_stream(&[(p, d)]), &["--issuer", ISSUER]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(out.contains("records recomputed: 1"), "{out}");
}

#[test]
fn a_newer_schema_version_is_refused_and_not_misreported() {
    // A record newer than the verifier must refuse as cannot-verify, never fall through to the v4
    // formula and be reported as "a structural column was rewritten after sealing" — a false
    // accusation of tampering that would send an operator looking for an attack that never happened.
    let mut p = v4_payload();
    p["schema_version"] = serde_json::json!(5);
    let d = v4_record_digest(&p);
    let (code, out) = run("v4-future", &v4_stream(&[(p, d)]), &["--issuer", ISSUER]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("CANNOT VERIFY"), "{out}");
    assert!(out.contains("NEWER THAN THIS VERIFIER"), "{out}");
    assert!(
        !out.contains("does NOT match its own digest"),
        "an unknown version is being misreported as a payload rewrite:\n{out}"
    );
}

#[test]
fn every_retired_schema_version_is_refused_never_skipped() {
    // P7 retired v1-v3 with no dual-verify. Before it, v1 was SKIPPED as link-only, which made a
    // relabel-to-v1 the one downgrade the recompute could not see and needed a guard of its own. With
    // a single formula there is nothing to downgrade INTO: a genuine old record and a rewritten,
    // relabelled one both land on the same refusal. Both shapes are driven per version, columns
    // present (the relabel) and columns absent (a genuine pre-v4 record).
    for version in [0u64, 1, 2, 3] {
        for strip_columns in [false, true] {
            let body = v4_tampered(move |p| {
                p["outcome"] = serde_json::json!("Denied");
                p["schema_version"] = serde_json::json!(version);
                if strip_columns {
                    let o = p.as_object_mut().unwrap();
                    for (c, _) in MANDATORY_V4 {
                        o.remove(c);
                    }
                    o.remove("ciphertext_digest");
                    o.remove("policy_rules_digest");
                }
            });
            let (code, out) = run("v4-retired", &body, &["--issuer", ISSUER]);
            assert_eq!(
                code, FAILED,
                "a schema_version {version} record (columns stripped: {strip_columns}) must be \
                 refused:\n{out}"
            );
            assert!(
                out.contains("CANNOT VERIFY") && out.contains("RETIRED"),
                "version {version} must be refused as retired, not as a strip or rewrite:\n{out}"
            );
            assert!(
                out.contains("records recomputed") || !out.contains("CHAIN AUTHENTICATED"),
                "{out}"
            );
        }
    }
}

#[test]
fn integrity_only_still_passes_a_stripped_v4_stream() {
    // The strip refusal is design-a work, scoped to `--issuer`, exactly as the tag-10 strip is. A
    // stream with no pinned issuer is internally consistent and must still verify — "no issuer key
    // therefore integrity-only" is a property of running without `--issuer`, not something a
    // stripped field is allowed to trigger.
    let body = v4_tampered(|p| {
        p.as_object_mut().unwrap().remove("context_digest");
    });
    let (code, out) = run("v4-strip-integrity", &body, &[]);
    assert_eq!(
        code, VERIFIED,
        "integrity-only must not have learned to refuse a strip:\n{out}"
    );
}

#[test]
fn two_v4_records_differing_only_in_a_digest_column_are_not_one_event() {
    // The one wire omission that fails SILENTLY. Event identity is the RE-ENCODED event — that is what
    // lets the same event arriving as JSON on a webhook and as protobuf on a relay collapse into one
    // chain link instead of looking like a forgery. If `with_identity` did not carry tags 11-17, two
    // records differing ONLY in one of them would re-encode to identical bytes, and the second would
    // be swallowed as an at-least-once duplicate.
    //
    // The two lines below are identical in EVERY identity-bearing field, including the chain triple
    // (seq, prev_checksum, digest, checksum); the substituted column is the only thing that can tell
    // them apart. Two earlier versions of this test were vacuous because seq/prev or digest/checksum
    // differed, so the payload column was never the discriminator.
    //
    // That is also the realistic shape: substitute a payload column, leave (prev, digest, checksum)
    // intact so the chain still hashes. With the columns in the identity, this is refused LOUDLY as an
    // impostor pair. Without them, the substituted record is deduped away, the honest one verifies,
    // and the stream comes back GREEN with the evidence quietly gone.
    let substitutions: [(&str, serde_json::Value); 5] = [
        (
            "participation_digest",
            serde_json::json!(b64e(&sha("a different participation"))),
        ),
        ("classification", serde_json::json!("Financial")),
        (
            "participants_digest",
            serde_json::json!(b64e(&sha("a different roster"))),
        ),
        (
            "trust_basis_commitment",
            serde_json::json!(format!("hmac-sha256:k1:{}", "ef".repeat(32))),
        ),
        ("auth_method", serde_json::json!("aitp-tct")),
    ];
    for (field, value) in substitutions {
        let honest = v4_payload();
        let mut substituted = v4_payload();
        substituted[field] = value;

        let prev = vec![0u8; 32];
        let digest = v4_record_digest(&honest);
        let checksum = {
            let mut h = Sha256::new();
            h.update(&prev);
            h.update(&digest);
            h.finalize().to_vec()
        };
        let line = |payload: &serde_json::Value| {
            serde_json::json!({
                "schema_version": "seam-event.v1",
                "event_id": "v4#0",
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

        // An attestation over the one-link head, so that if the substituted record IS deduped away
        // the remaining stream is perfectly valid and verifies GREEN — which is what makes exit 2
        // below evidence of the identity check rather than of some unrelated refusal.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
        let (att, _) = attestation_event(1, &checksum, 1, &checksum, &sk, ISSUER, 4);
        let body = format!("{}\n{}\n{}", line(&honest), line(&substituted), att);

        let (code, out) = run("v4-identity", &body, &["--issuer", ISSUER]);
        assert_eq!(
            code, FAILED,
            "two v4 records differing only in {field} collapsed into one event — the column is \
             missing from the re-encoded identity, so a substituted record is deduped away and the \
             stream reports GREEN with the evidence gone:\n{out}"
        );
        assert!(
            out.contains("appears TWICE with DIFFERENT content"),
            "the pair must be refused as impostors ({field}); any other refusal means the payload \
             difference was not visible to the identity projection:\n{out}"
        );
    }
}

/// One `DECISION_SEALED` line chained after `prev`, and its checksum.
fn sealed_line(seq: u64, prev: &[u8], payload: &serde_json::Value) -> (String, Vec<u8>) {
    let d = v4_record_digest(payload);
    let checksum = {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(&d);
        h.finalize().to_vec()
    };
    let line = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": format!("dec#{seq}"), "seq": seq,
        "occurred_at": 1_700 + seq, "kind": "DECISION_SEALED", "prev_checksum": b64e(prev),
        "digest": b64e(&d), "checksum": b64e(&checksum), "payload": payload,
    })
    .to_string();
    (line, checksum)
}

// ── spec clause (e): the attestation ceiling ─────────────────────────────────────────────────────
//
// `digest_schema` asserts that every record in the attested prefix has `schema_version <=
// digest_schema`. seam-runtime#441. These four tests pin the rule AND its three boundaries — a
// ceiling check that only refuses is half-tested, and the passing directions are the ones that
// would quietly invalidate real production history if implemented wrong.

/// The refusal itself: a V4 record under a signed ceiling of 3.
///
/// Every link hashes, every digest recomputes, and the signature is authentic — so nothing else in
/// the verifier can catch this. That is the whole point of the clause: the only reachable violation
/// is an issuer honestly signing a false statement about the regime, which is what a rolled-back
/// producer does.
#[test]
fn an_attestation_below_the_prefix_ceiling_is_refused() {
    let p = v4_payload();
    let d = v4_record_digest(&p);
    // Build the stream by hand so the ceiling can be forced to 3 over a V4 record — `v4_stream`
    // derives an honest ceiling and cannot express this.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let head0 = vec![0u8; 32];
    let checksum = {
        let mut h = Sha256::new();
        h.update(&head0);
        h.update(&d);
        h.finalize().to_vec()
    };
    let sealed = serde_json::json!({
        "schema_version": "seam-event.v1",
        "event_id": "dec#0",
        "seq": 0,
        "occurred_at": 1_700,
        "kind": "DECISION_SEALED",
        "prev_checksum": b64e(&head0),
        "digest": b64e(&d),
        "checksum": b64e(&checksum),
        "payload": p,
    })
    .to_string();
    let (att, _) = attestation_event(1, &checksum, 1, &checksum, &sk, ISSUER, 3);
    let (code, out) = run(
        "ceiling-below-max",
        &format!("{sealed}\n{att}"),
        &["--issuer", ISSUER],
    );
    assert_eq!(code, FAILED, "a signed downgrade claim must REFUSE:\n{out}");
    assert!(
        out.contains("digest_schema 3") && out.contains("schema_version 4"),
        "the refusal must name BOTH the claimed ceiling and the record that exceeds it, or an \
         operator cannot tell which record forced it:\n{out}"
    );
    // Clause (e) requires this be reported DISTINCTLY from the other two refusals over the same
    // events. Asserting the absence of their vocabulary is what makes "distinctly" checkable.
    assert!(
        out.contains("SIGNED DOWNGRADE"),
        "the ceiling refusal must be self-identifying:\n{out}"
    );
    assert!(
        !out.contains("does not match the running head") && !out.contains("SPLICED"),
        "a ceiling violation must not be reported as a rewrite or a splice — the records are \
         intact and the attestation covers this very chain:\n{out}"
    );
}

/// ANTI-REGRESSION, and the reason the check indexes by `attested_len` rather than a running max.
///
/// A stale attestation covers a SHORTER prefix than the chain's current length: the head is read,
/// signed and appended without a lock, so the chain advances underneath it. Here a ceiling-3
/// attestation covers a prefix holding no V4 record (one AUDIT_ENTRY), and a V4 record is sealed
/// AFTER it. The attestation is still true about what it covers and must PASS.
///
/// An encounter-time running max would compare it against the later V4 record and refuse — turning
/// a race the design explicitly permits into a verification failure, and invalidating attestations
/// that are correct.
#[test]
fn a_stale_attestation_over_an_earlier_prefix_still_passes() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let head0 = vec![0u8; 32];
    let d0 = Sha256::digest(b"audit-0").to_vec();
    let c1 = {
        let mut h = Sha256::new();
        h.update(&head0);
        h.update(&d0);
        h.finalize().to_vec()
    };
    let entry = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": "aud#0", "seq": 0, "occurred_at": 1_700,
        "kind": "AUDIT_ENTRY", "prev_checksum": b64e(&head0), "digest": b64e(&d0),
        "checksum": b64e(&c1),
    })
    .to_string();
    // Ceiling 3 over the 1-link prefix — honest at the moment it was signed: nothing in it exceeds 3.
    let (att, c2) = attestation_event(1, &c1, 1, &c1, &sk, ISSUER, 3);
    // ...and only THEN does a V4 record arrive.
    let (sealed_v4, _) = sealed_line(2, &c2, &v4_payload());
    let (code, out) = run(
        "ceiling-stale-ok",
        &format!("{entry}\n{att}\n{sealed_v4}"),
        &["--issuer", ISSUER],
    );
    assert_eq!(
        code, VERIFIED,
        "a ceiling-3 attestation over a prefix with no V4 record is TRUE about what it covers and \
         must pass, even though a V4 record was sealed after it:\n{out}"
    );
}

/// `>=`, not `==`: a ceiling that OVERSTATES is legitimate. A later build may attest a V4-only
/// prefix at 5 — true, and refusing it would break that deployment during its quiet period.
#[test]
fn a_ceiling_above_the_prefix_maximum_is_legitimate() {
    let v4 = v4_payload();
    let d = v4_record_digest(&v4);
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let head0 = vec![0u8; 32];
    let checksum = {
        let mut h = Sha256::new();
        h.update(&head0);
        h.update(&d);
        h.finalize().to_vec()
    };
    let sealed = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": "dec#0", "seq": 0, "occurred_at": 1_700,
        "kind": "DECISION_SEALED", "prev_checksum": b64e(&head0), "digest": b64e(&d),
        "checksum": b64e(&checksum), "payload": v4,
    })
    .to_string();
    let (att, _) = attestation_event(1, &checksum, 1, &checksum, &sk, ISSUER, 5);
    let (code, out) = run(
        "ceiling-above-ok",
        &format!("{sealed}\n{att}"),
        &["--issuer", ISSUER],
    );
    assert_eq!(
        code, VERIFIED,
        "digest_schema is a CEILING, not a description — 5 over a v4-only prefix is true:\n{out}"
    );
}

/// The empty-witness case the spec calls out explicitly: a NON-EMPTY prefix carrying no
/// `DECISION_SEALED` at all has no record to exceed any ceiling, so (e) cannot fire. Guards the
/// off-by-one too — indexing `max_schema_by_link` at a real length must not panic or read garbage.
#[test]
fn a_prefix_with_no_sealed_records_cannot_violate_the_ceiling() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let head0 = vec![0u8; 32];
    // A chained AUDIT_ENTRY: a real link that carries no decision.
    let d = Sha256::digest(b"audit-0").to_vec();
    let checksum = {
        let mut h = Sha256::new();
        h.update(&head0);
        h.update(&d);
        h.finalize().to_vec()
    };
    let entry = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": "aud#0", "seq": 0, "occurred_at": 1_700,
        "kind": "AUDIT_ENTRY", "prev_checksum": b64e(&head0), "digest": b64e(&d),
        "checksum": b64e(&checksum),
    })
    .to_string();
    let (att, _) = attestation_event(1, &checksum, 1, &checksum, &sk, ISSUER, 2);
    let (code, out) = run(
        "ceiling-no-records",
        &format!("{entry}\n{att}"),
        &["--issuer", ISSUER],
    );
    assert_eq!(
        code, VERIFIED,
        "the rule is existential over covered RECORDS, not a claim about the prefix's length:\n{out}"
    );
}

/// `attested_len == 0` — the VACUOUS attestation, REFUSED outright (spec clause (d), second
/// sentence; seam-runtime#458). It makes no claim: a conforming producer never signs the empty
/// chain (spec §Triggers), so its presence on the wire is itself the non-conforming-producer tell.
/// Until #458 this test pinned the OLD behaviour — CHAIN AUTHENTICATED with `covered prefix: 0
/// links`, a green verdict whose only warrant was a signature over nothing — and its NOTE promised
/// the flip would be a visible, deliberate assertion change. This is that change.
///
/// Still pinned alongside the refusal: the diagnosis must be the vacuity, never the ceiling — a
/// verifier that indexed the chain's full length instead of `attested_len` would see ceiling 3
/// against the v4 record this stream seals and misreport a SIGNED DOWNGRADE.
#[test]
fn a_vacuous_attestation_is_refused_outright() {
    let p = v4_payload();
    let d = v4_record_digest(&p);
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let head0 = vec![0u8; 32];
    let checksum = {
        let mut h = Sha256::new();
        h.update(&head0);
        h.update(&d);
        h.finalize().to_vec()
    };
    let sealed = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": "dec#0", "seq": 0, "occurred_at": 1_700,
        "kind": "DECISION_SEALED", "prev_checksum": b64e(&head0), "digest": b64e(&d),
        "checksum": b64e(&checksum), "payload": p,
    })
    .to_string();
    // len 0 over GENESIS: vacuous but structurally well-formed and correctly signed.
    let (att, _) = attestation_event(1, &checksum, 0, &head0, &sk, ISSUER, 3);
    let (code, out) = run(
        "vacuous-attestation",
        &format!("{sealed}\n{att}"),
        &["--issuer", ISSUER],
    );
    assert!(
        !out.contains("SIGNED DOWNGRADE"),
        "the refusal must be the vacuity, never a misindexed ceiling:\n{out}"
    );
    assert_eq!(
        code, FAILED,
        "an attestation over the empty prefix claims nothing and must be REFUSED outright — a \
         CHAIN AUTHENTICATED warranted by a signature over nothing is the coverage hole clause (d) \
         exists to close:\n{out}"
    );
    assert!(
        out.contains("VACUOUS"),
        "the refusal must be self-identifying:\n{out}"
    );
}

/// The verdict's sharp edge: the vacuous attestation is refused as an ARTIFACT — not merely
/// "streams whose only attestations are vacuous". A perfectly valid attestation over the real head
/// sits right beside it and does not save the stream: a trusted issuer that signed the empty chain
/// is a non-conforming or rolled-back producer regardless of what else it signed correctly. A
/// verifier that only required "at least one valid attestation" (clause (d)'s first sentence alone)
/// passes this stream; the second sentence is what refuses it.
#[test]
fn a_vacuous_attestation_is_refused_even_beside_a_valid_one() {
    let p = v4_payload();
    let d = v4_record_digest(&p);
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let head0 = vec![0u8; 32];
    let checksum = {
        let mut h = Sha256::new();
        h.update(&head0);
        h.update(&d);
        h.finalize().to_vec()
    };
    let sealed = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": "dec#0", "seq": 0, "occurred_at": 1_700,
        "kind": "DECISION_SEALED", "prev_checksum": b64e(&head0), "digest": b64e(&d),
        "checksum": b64e(&checksum), "payload": p,
    })
    .to_string();
    // A GENUINE attestation over the real head first (len 1; ceiling 4 — the record is v4) …
    let (good, c2) = attestation_event(1, &checksum, 1, &checksum, &sk, ISSUER, 4);
    // … then the vacuous one, chained after it: len 0 over GENESIS, correctly signed by the SAME
    // trusted issuer.
    let (vac, _) = attestation_event(2, &c2, 0, &head0, &sk, ISSUER, 4);
    let (code, out) = run(
        "vacuous-beside-valid",
        &format!("{sealed}\n{good}\n{vac}"),
        &["--issuer", ISSUER],
    );
    assert_eq!(
        code, FAILED,
        "a valid attestation beside it must NOT save the stream — the vacuous artifact itself is \
         refused:\n{out}"
    );
    assert!(
        out.contains("VACUOUS"),
        "the refusal must name the vacuity, not the neighbour:\n{out}"
    );
}

/// The fail-closed arm, exercised rather than merely reasoned about.
///
/// It is unreachable through the CLI — `chain()` builds `heads` and `max_schema_by_link` together,
/// so they are always the same length, and the position check errors first anyway. It is reachable
/// by an EMBEDDER, because `verify_authenticity` is a public API. Under the `unwrap_or(0)` this
/// replaced, a caller passing a mismatched slice got the ceiling check SILENTLY DISABLED while
/// every other check kept running — a green report with one refusal quietly switched off.
///
/// Driven at the library level deliberately: no CLI invocation can produce this state, so a
/// process-level test would prove nothing.
#[test]
fn a_mismatched_prefix_max_slice_refuses_instead_of_skipping_the_check() {
    let p = v4_payload();
    let d = v4_record_digest(&p);
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let head0 = vec![0u8; 32];
    let checksum = {
        let mut h = Sha256::new();
        h.update(&head0);
        h.update(&d);
        h.finalize().to_vec()
    };
    let sealed = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": "dec#0", "seq": 0, "occurred_at": 1_700,
        "kind": "DECISION_SEALED", "prev_checksum": b64e(&head0), "digest": b64e(&d),
        "checksum": b64e(&checksum), "payload": p,
    })
    .to_string();
    let (att, _) = attestation_event(1, &checksum, 1, &checksum, &sk, ISSUER, 4);
    let body = format!("{sealed}\n{att}");

    let events: Vec<seam_verify::wire::Event> = body
        .lines()
        .map(|l| seam_verify::wire::Event::parse(l).expect("parse"))
        .collect();
    let report = seam_verify::chain(&events).expect("chain");
    let issuers = vec![ISSUER.to_string()];

    // Honest slices: this stream is legitimate (ceiling 4 over a v4 record) and must pass.
    assert!(
        seam_verify::verify_authenticity(
            &events,
            &report.heads,
            &report.max_schema_by_link,
            &issuers
        )
        .is_ok(),
        "an honest stream with matching slices must authenticate — otherwise the refusal below \
         proves nothing about the slice length"
    );

    // Truncated prefix-max: the ceiling can no longer be evaluated for this attestation.
    let err = match seam_verify::verify_authenticity(
        &events,
        &report.heads,
        &report.max_schema_by_link[..1],
        &issuers,
    ) {
        Err(e) => e,
        Ok(_) => panic!(
            "a short max_schema_by_link must REFUSE. Silently treating the missing entry as 0 \
             would pass every ceiling check — fail-open, in the one crate whose job is refusing."
        ),
    };
    assert!(
        err.contains("max_schema_by_link"),
        "the error must name the slice that was wrong, so an embedder can fix the call:\n{err}"
    );
}
