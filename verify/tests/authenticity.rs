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
