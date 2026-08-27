//! `chain --issuer <AID> --from-anchor <FILE>` — the ANCHORED START (spec clause (f)), clean-room
//! from `verify/docs/seam-event.v1.md`'s clause (f) alone. Nothing of Seam's is linked (the whole
//! point) — see `Cargo.toml` — and nothing under `seam-runtime/crates/` was read to write this file.
//!
//! An anchored start relocates the trust root from the public genesis constant to an issuer-signed
//! `CHAIN_HEAD_ATTESTATION` artifact (the anchor), supplied out of band (e.g. one element of the
//! public `GET /v1/anchors` feed). What this file proves, one clause at a time:
//!
//! * (f1) the anchor is validated against a PINNED issuer before it seeds anything — an unsigned,
//!   forged, or unpinned-issuer anchor is refused, never silently seeded;
//! * (f2) a vacuous anchor (`attested_len == 0`) is refused outright;
//! * (f3) window positions are anchor-relative, and a signature-valid but BELOW-window attestation is
//!   skipped and reported rather than refused or silently dropped — the read→sign→append race the
//!   spec permits can legitimately place one there;
//! * (f4) the anchor itself never satisfies coverage — at least one attestation strictly past the
//!   anchor's position is required;
//! * genesis-mode output/behaviour is untouched by any of this.

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;
const USAGE: i32 = 1;

// The golden issuer (ed25519 seed 07×32) — the AID a consumer pins out of band. Same key
// `tests/authenticity.rs` uses; duplicated here rather than shared, in the spirit of this crate's
// deliberate second-transcription discipline (see `record_digest_v3`'s doc comment).
const ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}
fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn write_tmp(name: &str, ext: &str, body: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "anchored-{name}-{}-{}.{ext}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, body).unwrap();
    path
}

fn run(name: &str, cmd: &str, body: &str, args: &[&str]) -> (i32, String) {
    let path = write_tmp(name, "jsonl", body);
    let mut a: Vec<&str> = vec![cmd, path.to_str().unwrap()];
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

/// `seam.audit.chain-head-attestation.v1`, transcribed from the spec independently of `src/verify.rs`
/// (same transcription `tests/authenticity.rs` uses).
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

/// A bare six-field anchor object — byte-for-byte one element of `GET /v1/anchors`' `anchors` array.
fn anchor_json(
    len: u64,
    head: &[u8],
    at: u64,
    issuer_aid: &str,
    schema: u32,
    sk: &ed25519_dalek::SigningKey,
) -> String {
    use ed25519_dalek::Signer;
    let sig = sk
        .sign(&att_digest(len, head, at, schema, issuer_aid))
        .to_bytes();
    serde_json::json!({
        "attested_len": len,
        "attested_head": b64e(head),
        "attested_at": at,
        "issuer_aid": issuer_aid,
        "digest_schema": schema,
        "signature": b64e(&sig),
    })
    .to_string()
}

/// A chained `CHAIN_HEAD_ATTESTATION` event line: chains like ANY link (its OWN prev/digest/checksum
/// triple), while its payload attests a `(len, head)` that may be anywhere — in this window, at its
/// anchor's own position, or below the window entirely. Exactly this shape is how a read→sign→append
/// race can legitimately land a below-window attestation inside a later window (spec clause (f3)).
fn attestation_event(
    seq: u64,
    prev: &[u8],
    attested_len: u64,
    attested_head: &[u8],
    sk: &ed25519_dalek::SigningKey,
    issuer_aid: &str,
    digest_schema: u32,
) -> (String, Vec<u8>) {
    use ed25519_dalek::Signer;
    let at = 1_700 + seq;
    let sig = sk
        .sign(&att_digest(
            attested_len,
            attested_head,
            at,
            digest_schema,
            issuer_aid,
        ))
        .to_bytes();
    let digest = Sha256::digest(format!("att-{seq}").as_bytes()).to_vec();
    let checksum = {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(&digest);
        h.finalize().to_vec()
    };
    let line = serde_json::json!({
        "schema_version": "seam-event.v1",
        "event_id": format!("att#{seq}"),
        "seq": seq,
        "occurred_at": at,
        "kind": "CHAIN_HEAD_ATTESTATION",
        "prev_checksum": b64e(prev),
        "digest": b64e(&digest),
        "checksum": b64e(&checksum),
        "chain_head_attestation": {
            "attested_len": attested_len,
            "attested_head": b64e(attested_head),
            "attested_at": at,
            "issuer_aid": issuer_aid,
            "digest_schema": digest_schema,
            "signature": b64e(&sig),
        },
    })
    .to_string();
    (line, checksum)
}

/// A plain `DECISION_SEALED` link (no payload — the sealed-record digest is orthogonal to what this
/// file is proving).
fn sealed_link(seq: u64, prev: &[u8]) -> (String, Vec<u8>) {
    let digest = Sha256::digest(format!("r{seq}").as_bytes()).to_vec();
    let checksum = {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(&digest);
        h.finalize().to_vec()
    };
    let line = serde_json::json!({
        "schema_version": "seam-event.v1",
        "event_id": format!("d{seq}#{seq}"),
        "seq": seq,
        "kind": "DECISION_SEALED",
        "prev_checksum": b64e(prev),
        "digest": b64e(&digest),
        "checksum": b64e(&checksum),
    })
    .to_string();
    (line, checksum)
}

/// The standard fixture: an anchor at `base_len = 5` over an invented head (no prior stream needed —
/// the whole point of an anchored start is that the verifier trusts the anchor's signature, not a
/// prefix it never sees), plus a two-link window `[link1, link2]` reaching `head2`, and a covering
/// attestation over the full window (`attested_len = base_len + 2`).
struct Fixture {
    sk: ed25519_dalek::SigningKey,
    base_len: u64,
    base_head: Vec<u8>,
    link1: String,
    link2: String,
    head2: Vec<u8>,
    covering_len: u64,
}

fn fixture() -> Fixture {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let base_len = 5u64;
    let base_head = Sha256::digest(b"anchor-head-seed").to_vec();
    let (link1, head1) = sealed_link(5, &base_head);
    let (link2, head2) = sealed_link(6, &head1);
    Fixture {
        sk,
        base_len,
        base_head,
        link1,
        link2,
        head2,
        covering_len: base_len + 2,
    }
}

fn covering_attestation(f: &Fixture) -> String {
    attestation_event(7, &f.head2, f.covering_len, &f.head2, &f.sk, ISSUER, 2).0
}

fn anchor_file(f: &Fixture) -> std::path::PathBuf {
    let json = anchor_json(f.base_len, &f.base_head, 1_700, ISSUER, 2, &f.sk);
    write_tmp("anchor", "json", &json)
}

// ── (f1)/(f4) — the happy path ────────────────────────────────────────────────────────────────────

#[test]
fn anchored_window_authenticates() {
    let f = fixture();
    let body = format!("{}\n{}\n{}", f.link1, f.link2, covering_attestation(&f));
    let anchor = anchor_file(&f);
    let (code, out) = run(
        "happy",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, VERIFIED,
        "a genuine anchored window must authenticate:\n{out}"
    );
    assert!(out.contains("WINDOW AUTHENTICATED"), "{out}");
    assert!(
        out.contains("covering (len > base_len): 1"),
        "one covering (in-window) attestation:\n{out}"
    );
}

#[test]
fn anchored_json_reports_base_len_head_and_coverage() {
    let f = fixture();
    let body = format!("{}\n{}\n{}", f.link1, f.link2, covering_attestation(&f));
    let anchor = anchor_file(&f);
    let (code, out) = run(
        "json",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
            "--json",
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(out.contains("\"anchored\":true"), "{out}");
    assert!(
        out.contains(&format!("\"base_len\":{}", f.base_len)),
        "{out}"
    );
    assert!(out.contains("\"covering_attestations\":1"), "{out}");
    assert!(out.contains("\"below_window\":0"), "{out}");
}

// ── genesis mode is untouched ─────────────────────────────────────────────────────────────────────

#[test]
fn genesis_behaviour_unchanged() {
    // The SAME two-link-plus-attestation shape, but from genesis (no --from-anchor): the classic
    // `CHAIN AUTHENTICATED` banner, and NONE of the anchored-only fields appear anywhere.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let genesis = [0u8; 32];
    let (link1, head1) = sealed_link(0, &genesis);
    let (link2, head2) = sealed_link(1, &head1);
    let (att, _) = attestation_event(2, &head2, 2, &head2, &sk, ISSUER, 2);
    let body = format!("{link1}\n{link2}\n{att}");

    let (code, out) = run("genesis-text", "chain", &body, &["--issuer", ISSUER]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.contains("CHAIN AUTHENTICATED (integrity + issuer-signed head)"),
        "{out}"
    );
    assert!(
        !out.contains("WINDOW"),
        "genesis mode must never say WINDOW:\n{out}"
    );
    assert!(!out.contains("anchored start"), "{out}");

    let (code, out) = run(
        "genesis-json",
        "chain",
        &body,
        &["--issuer", ISSUER, "--json"],
    );
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        !out.contains("\"anchored\""),
        "genesis JSON must carry no anchored keys:\n{out}"
    );
    assert!(!out.contains("\"base_len\""), "{out}");
    assert!(!out.contains("\"covering_attestations\""), "{out}");
}

// ── (f1) — the anchor is validated before it is trusted ──────────────────────────────────────────

#[test]
fn forged_anchor_signature_is_rejected() {
    let f = fixture();
    let body = format!("{}\n{}\n{}", f.link1, f.link2, covering_attestation(&f));
    let json = anchor_json(f.base_len, &f.base_head, 1_700, ISSUER, 2, &f.sk);
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    // Flip one byte of the signature — same shape as `attestation_payload_is_tamper_sensitive`.
    let mut sig = b64d(v["signature"].as_str().unwrap());
    sig[0] ^= 0xff;
    v["signature"] = serde_json::Value::String(b64e(&sig));
    let anchor = write_tmp("forged-anchor", "json", &v.to_string());

    let (code, out) = run(
        "forged-anchor",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(code, FAILED, "a forged anchor must be REJECTED:\n{out}");
    assert!(out.contains("ANCHOR REJECTED"), "{out}");
}

#[test]
fn anchor_from_unpinned_issuer_is_rejected() {
    let f = fixture();
    let body = format!("{}\n{}\n{}", f.link1, f.link2, covering_attestation(&f));
    // Signed by a DIFFERENT key than the one pinned below.
    let other_sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let other_aid = format!(
        "aid:pubkey:ed25519:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(other_sk.verifying_key().as_bytes())
    );
    let json = anchor_json(f.base_len, &f.base_head, 1_700, &other_aid, 2, &other_sk);
    let anchor = write_tmp("wrong-issuer-anchor", "json", &json);

    let (code, out) = run(
        "wrong-issuer-anchor",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, FAILED,
        "an anchor from an unpinned issuer must be REJECTED:\n{out}"
    );
    assert!(out.contains("ANCHOR REJECTED"), "{out}");
    assert!(out.contains("you pinned"), "{out}");
}

// ── (f2) — a vacuous anchor is refused ────────────────────────────────────────────────────────────

#[test]
fn vacuous_anchor_is_refused() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let genesis = [0u8; 32];
    let json = anchor_json(0, &genesis, 1_700, ISSUER, 2, &sk);
    let anchor = write_tmp("vacuous-anchor", "json", &json);
    let (link1, _) = sealed_link(0, &genesis);

    let (code, out) = run(
        "vacuous-anchor",
        "chain",
        &link1,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(code, FAILED, "a vacuous anchor must be REFUSED:\n{out}");
    assert!(out.contains("VACUOUS ANCHOR"), "{out}");
}

// ── usage errors ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn from_anchor_without_issuer_is_usage_error() {
    let f = fixture();
    let body = format!("{}\n{}", f.link1, f.link2);
    let anchor = anchor_file(&f);
    let (code, out) = run(
        "no-issuer",
        "chain",
        &body,
        &["--from-anchor", anchor.to_str().unwrap()],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, USAGE,
        "--from-anchor without --issuer must be a usage error:\n{out}"
    );
    assert!(
        out.contains("--from-anchor requires --issuer"),
        "must name the specific reason, not just any mention of --issuer in the general usage text:\n{out}"
    );
}

#[test]
fn from_anchor_on_erasure_cert_is_usage_error() {
    let f = fixture();
    let anchor = anchor_file(&f);
    // erasure-cert requires a FILE too; content is irrelevant, the flag check fires first.
    let (code, out) = run(
        "erasure-anchor",
        "erasure-cert",
        "{}",
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, USAGE,
        "--from-anchor on erasure-cert must be a usage error:\n{out}"
    );
    assert!(out.contains("chain-only"), "{out}");
}

// ── (f4) — the anchor itself never satisfies coverage ─────────────────────────────────────────────

#[test]
fn window_with_no_covering_attestation_is_refused() {
    let f = fixture();
    let body = format!("{}\n{}", f.link1, f.link2); // no attestation at all
    let anchor = anchor_file(&f);
    let (code, out) = run(
        "no-covering",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, FAILED,
        "a window with no covering attestation must be REFUSED:\n{out}"
    );
    assert!(out.contains("AUTHENTICITY VERIFICATION FAILED"), "{out}");
    assert!(out.contains("covering it"), "{out}");
}

#[test]
fn attestation_at_exactly_anchor_position_does_not_count_as_covering() {
    let f = fixture();
    // An attestation landing EXACTLY on the anchor's own position (attested_len == base_len,
    // attested_head == the anchor's head) — verifies, but must not satisfy (f4) by itself.
    let (at_anchor, head_a) =
        attestation_event(5, &f.base_head, f.base_len, &f.base_head, &f.sk, ISSUER, 2);
    let (link1, head1) = sealed_link(6, &head_a);
    let (link2, head2) = sealed_link(7, &head1);
    let body_alone = format!("{at_anchor}\n{link1}\n{link2}");
    let anchor = anchor_file(&f);

    let (code, out) = run(
        "at-anchor-alone",
        "chain",
        &body_alone,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, FAILED,
        "an at-anchor-position attestation ALONE must not satisfy coverage:\n{out}"
    );
    assert!(out.contains("covering it"), "{out}");

    // Add a genuine covering attestation: NOW it passes, and covering_attestations counts only the
    // real one — the at-anchor attestation still does not count.
    let (covering, _) = attestation_event(8, &head2, f.base_len + 3, &head2, &f.sk, ISSUER, 2);
    let body_both = format!("{body_alone}\n{covering}");
    let (code, out) = run(
        "at-anchor-plus-covering",
        "chain",
        &body_both,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
            "--json",
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.contains("\"covering_attestations\":1"),
        "only the genuine in-window attestation counts, not the at-anchor one:\n{out}"
    );
}

// ── (f3) — window positions are anchor-relative ───────────────────────────────────────────────────

#[test]
fn attestation_beyond_window_is_out_of_range() {
    let f = fixture();
    // The attestation event chains too (it is a link like any other), so once it is appended the
    // window holds THREE links (link1, link2, beyond) — positions base_len..=base_len+3. Attesting
    // base_len + 5 is genuinely past the window's extent, not merely past its own append point.
    let (beyond, _) = attestation_event(7, &f.head2, f.base_len + 5, &f.head2, &f.sk, ISSUER, 2);
    let body = format!("{}\n{}\n{beyond}", f.link1, f.link2);
    let anchor = anchor_file(&f);
    let (code, out) = run(
        "beyond-window",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, FAILED,
        "an out-of-range attestation must be REFUSED:\n{out}"
    );
    assert!(out.contains("cannot be covering this window"), "{out}");
}

#[test]
fn below_window_attestation_is_skipped_and_reported() {
    let f = fixture();
    // A below-window attestation is a GENUINE, validly-signed artifact — its payload just attests a
    // position the window does not contain. It still chains normally as the first window event.
    let stale_head = Sha256::digest(b"stale-head-4").to_vec();
    let (below, head_b) = attestation_event(
        5,
        &f.base_head,
        f.base_len - 1,
        &stale_head,
        &f.sk,
        ISSUER,
        2,
    );
    let (link1, head1) = sealed_link(6, &head_b);
    let (link2, head2) = sealed_link(7, &head1);
    // Covering attestation over the full (now three-link) window.
    let (covering, _) = attestation_event(8, &head2, f.base_len + 3, &head2, &f.sk, ISSUER, 2);
    let body = format!("{below}\n{link1}\n{link2}\n{covering}");
    let anchor = anchor_file(&f);

    let (code, out) = run(
        "below-window",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        code, VERIFIED,
        "a below-window straggler beside a genuine covering attestation must still PASS:\n{out}"
    );
    assert!(out.contains("\"below_window\":1"), "{out}");
    assert!(out.contains("\"covering_attestations\":1"), "{out}");

    // Remove the covering attestation: the below-window one alone cannot satisfy (f4) — it never
    // counts toward coverage, however green its own signature is.
    let body_alone = format!("{below}\n{link1}\n{link2}");
    let (code, out) = run(
        "below-window-alone",
        "chain",
        &body_alone,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, FAILED,
        "a below-window attestation ALONE must not satisfy coverage:\n{out}"
    );
}

#[test]
fn below_window_forged_attestation_still_fails() {
    let f = fixture();
    let stale_head = Sha256::digest(b"stale-head-4").to_vec();
    let (below, head_b) = attestation_event(
        5,
        &f.base_head,
        f.base_len - 1,
        &stale_head,
        &f.sk,
        ISSUER,
        2,
    );
    // Forge the below-window attestation's signature by corrupting its chain_head_attestation.
    let mut v: serde_json::Value = serde_json::from_str(&below).unwrap();
    let mut sig = b64d(v["chain_head_attestation"]["signature"].as_str().unwrap());
    sig[0] ^= 0xff;
    v["chain_head_attestation"]["signature"] = serde_json::Value::String(b64e(&sig));
    let below_forged = v.to_string();

    let (link1, head1) = sealed_link(6, &head_b);
    let (link2, head2) = sealed_link(7, &head1);
    let (covering, _) = attestation_event(8, &head2, f.base_len + 3, &head2, &f.sk, ISSUER, 2);
    let body = format!("{below_forged}\n{link1}\n{link2}\n{covering}");
    let anchor = anchor_file(&f);

    let (code, out) = run(
        "below-window-forged",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, FAILED,
        "a forged attestation ANYWHERE must fail the whole chain, even beside a valid covering one \
         and even though its position would only ever have been skipped, never checked:\n{out}"
    );
    assert!(
        !out.contains("does NOT match its own digest"),
        "must be reported as a signature failure, not a digest mismatch:\n{out}"
    );
}

// ── anchor-file shapes (spec clause (f), "supplied out of band") ─────────────────────────────────

#[test]
fn anchor_as_full_event_line_is_accepted() {
    let f = fixture();
    let body = format!("{}\n{}\n{}", f.link1, f.link2, covering_attestation(&f));
    // The anchor supplied as a FULL seam-event.v1 event line (what an outbox consumer already holds),
    // not the bare six-field object `GET /v1/anchors` returns.
    let (event_line, _) =
        attestation_event(4, &[0u8; 32], f.base_len, &f.base_head, &f.sk, ISSUER, 2);
    let anchor = write_tmp("event-anchor", "jsonl", &event_line);

    let (code, out) = run(
        "event-anchor",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, VERIFIED,
        "a full-event-line anchor must be accepted:\n{out}"
    );
    assert!(out.contains("WINDOW AUTHENTICATED"), "{out}");
}

#[test]
fn whole_anchors_feed_is_refused() {
    let f = fixture();
    let body = format!("{}\n{}\n{}", f.link1, f.link2, covering_attestation(&f));
    let one = anchor_json(f.base_len, &f.base_head, 1_700, ISSUER, 2, &f.sk);
    let feed = format!("{{\"anchors\":[{one}]}}");
    let anchor = write_tmp("feed", "json", &feed);

    let (code, out) = run(
        "whole-feed",
        "chain",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, USAGE,
        "the whole feed must be refused, not silently picked from:\n{out}"
    );
    assert!(out.contains("pick ONE element"), "{out}");
}
