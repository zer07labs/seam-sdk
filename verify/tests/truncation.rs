//! `chain --issuer <AID> --expect-anchor <FILE>` — the truncation check (seam-sdk#140), unblocked
//! by `seam-runtime`'s `GET /v1/anchors` feed (seam-runtime#422, live since 2026-08-26). Nothing of
//! Seam's is linked (the whole point) — see `Cargo.toml`.
//!
//! The property under test is exactly the one `COMPATIBILITY.md` used to disclaim outright: a
//! stream cut at the tail is internally consistent and verifies green **on its own** — every test
//! below first confirms the truncated window DOES verify green without `--expect-anchor`, then
//! shows that supplying an anchor the operator holds independently (never present in the stream
//! itself) is what actually catches it.

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;
const USAGE: i32 = 1;

// The golden issuer (ed25519 seed 07×32) — same key every other `tests/*.rs` file in this crate
// uses; duplicated here rather than shared, in the spirit of this crate's deliberate
// second-transcription discipline (see `record_digest_v3`'s doc comment).
const ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";

fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Tests in this file run as threads of one process, so pid + nanos alone can collide on a coarse
/// clock: a parallel test's length-3 anchor once overwrote another's length-5 one under the same
/// name, and the run read the wrong anchor. The counter makes every name unique within the process.
static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_tmp(name: &str, ext: &str, body: &str) -> std::path::PathBuf {
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "truncation-{name}-{}-{seq}-{}.{ext}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, body).unwrap();
    path
}

fn run(name: &str, body: &str, args: &[&str]) -> (i32, String) {
    let path = write_tmp(name, "jsonl", body);
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

/// `seam.audit.chain-head-attestation.v1`, transcribed from the spec independently of
/// `src/verify.rs` (same transcription every other `tests/*.rs` attestation helper uses).
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

/// A bare six-field anchor object — byte-for-byte one element of `GET /v1/anchors`' `anchors`
/// array, and exactly the shape `--expect-anchor` takes (same parser as `--from-anchor`).
/// Untenanted on purpose for most tests here: the fallback this crate attributes to the window's
/// sole chained tenant, mirroring `chain_anchored`'s own spec clause (f0) fallback.
fn anchor_json(len: u64, head: &[u8], sk: &ed25519_dalek::SigningKey) -> String {
    use ed25519_dalek::Signer;
    let sig = sk.sign(&att_digest(len, head, 1_700, 2, ISSUER)).to_bytes();
    serde_json::json!({
        "attested_len": len,
        "attested_head": b64e(head),
        "attested_at": 1_700,
        "issuer_aid": ISSUER,
        "digest_schema": 2,
        "signature": b64e(&sig),
    })
    .to_string()
}

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

fn attestation_event(
    seq: u64,
    prev: &[u8],
    attested_len: u64,
    attested_head: &[u8],
    sk: &ed25519_dalek::SigningKey,
) -> (String, Vec<u8>) {
    use ed25519_dalek::Signer;
    let at = 1_700 + seq;
    let sig = sk
        .sign(&att_digest(attested_len, attested_head, at, 2, ISSUER))
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
            "issuer_aid": ISSUER,
            "digest_schema": 2,
            "signature": b64e(&sig),
        },
    })
    .to_string();
    (line, checksum)
}

/// A genuine five-link genesis chain, with heads recorded at every prefix length so a test can
/// build an anchor for ANY position (`heads[0]` is genesis, `heads[k]` is the head after `k`
/// links) — exactly the real chain, never a fabricated one.
struct Chain {
    sk: ed25519_dalek::SigningKey,
    lines: Vec<String>,
    heads: Vec<Vec<u8>>,
}

fn five_link_chain() -> Chain {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let mut heads = vec![vec![0u8; 32]]; // genesis
    let mut lines = Vec::new();
    let mut prev = heads[0].clone();
    for seq in 0..5u64 {
        let (line, head) = sealed_link(seq, &prev);
        lines.push(line);
        heads.push(head.clone());
        prev = head;
    }
    Chain { sk, lines, heads }
}

/// The first `n` links of the chain, PLUS this prefix's own covering attestation — a window that
/// is, taken alone, a completely legitimate and fully-authenticated stream. This is the whole
/// point: nothing about the window itself reveals it is a truncated prefix of a longer chain.
fn prefix_with_covering_attestation(c: &Chain, n: usize) -> String {
    let (att, _) = attestation_event(n as u64, &c.heads[n], n as u64, &c.heads[n], &c.sk);
    format!("{}\n{att}", c.lines[..n].join("\n"))
}

// ── The window alone, before any anchor is involved ───────────────────────────────────────────

#[test]
fn a_truncated_prefix_verifies_green_on_its_own() {
    let c = five_link_chain();
    let body = prefix_with_covering_attestation(&c, 3);
    let (code, out) = run("alone", &body, &["--issuer", ISSUER]);
    assert_eq!(
        code, VERIFIED,
        "a truncated prefix must verify green by itself — that is the whole reason the \
         truncation check has to be a separate, independently-anchored step:\n{out}"
    );
}

// ── `--expect-anchor` actually catches it ─────────────────────────────────────────────────────

#[test]
fn expect_anchor_catches_a_genuine_truncation() {
    let c = five_link_chain();
    // The window: only the first 3 links, self-consistently attested — see the test above.
    let body = prefix_with_covering_attestation(&c, 3);
    // The independently-held anchor: the REAL chain's head at length 5, which this window never
    // reaches. Never appears in `body` above — fetched separately is the whole scenario.
    let anchor = write_tmp("expect", "json", &anchor_json(5, &c.heads[5], &c.sk));

    let (code, out) = run(
        "truncated",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--expect-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, FAILED,
        "a stream verifiably shorter than an independently-held anchor must be refused:\n{out}"
    );
    assert!(out.contains("TRUNCATED STREAM"), "{out}");
    // The window covers 4 (3 sealed links PLUS the covering attestation's own link — a
    // CHAIN_HEAD_ATTESTATION chains too), strictly less than the anchor's attested length of 5.
    assert!(out.contains("attests length 5"), "{out}");
    assert!(out.contains("only reaches 4"), "{out}");
}

#[test]
fn expect_anchor_passes_when_the_window_reaches_it() {
    let c = five_link_chain();
    let body = prefix_with_covering_attestation(&c, 5);
    let anchor = write_tmp("expect", "json", &anchor_json(5, &c.heads[5], &c.sk));

    let (code, out) = run(
        "full",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--expect-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, VERIFIED,
        "the window genuinely reaches the anchor:\n{out}"
    );
    assert!(
        out.contains("not truncated thru: 5"),
        "the report must say what it checked against:\n{out}"
    );
}

#[test]
fn an_anchor_older_than_the_window_is_not_an_error() {
    let c = five_link_chain();
    let body = prefix_with_covering_attestation(&c, 5);
    // An OLDER, genuinely-valid anchor (len 3, the real head at that position) — reaching further
    // than an anchor asked for is not truncation.
    let anchor = write_tmp("expect", "json", &anchor_json(3, &c.heads[3], &c.sk));

    let (code, out) = run(
        "older-anchor",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--expect-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, VERIFIED,
        "an anchor older than the window's own reach must not be refused:\n{out}"
    );
}

// ── Reaching far enough is not the whole claim — the head must agree too ─────────────────────

#[test]
fn a_spliced_tail_as_long_as_the_anchor_is_still_caught() {
    let c = five_link_chain();
    // A window that reaches length 5 — but NOT the real chain's length-5 head: link seq=3 is
    // re-derived under a DIFFERENT payload than the real chain used, forking the tail from there
    // on (a hash chain propagates the fork into every head after it) while staying exactly as
    // long as the real chain.
    let (diverged_line, diverged_head) = {
        let digest = Sha256::digest(b"a-different-record-entirely").to_vec();
        let checksum = {
            let mut h = Sha256::new();
            h.update(&c.heads[3]);
            h.update(&digest);
            h.finalize().to_vec()
        };
        let line = serde_json::json!({
            "schema_version": "seam-event.v1",
            "event_id": "d3#3",
            "seq": 3,
            "kind": "DECISION_SEALED",
            "prev_checksum": b64e(&c.heads[3]),
            "digest": b64e(&digest),
            "checksum": b64e(&checksum),
        })
        .to_string();
        (line, checksum)
    };
    let (link5, head5) = sealed_link(4, &diverged_head);
    let (att, _) = attestation_event(5, &head5, 5, &head5, &c.sk);
    let body = format!(
        "{}\n{diverged_line}\n{link5}\n{att}",
        c.lines[..3].join("\n")
    );

    // The independently-held anchor: the REAL chain's length-5 head — different from this
    // window's own (forked) length-5 head, even though both are length 5.
    let anchor = write_tmp("expect", "json", &anchor_json(5, &c.heads[5], &c.sk));
    let (code, out) = run(
        "spliced",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--expect-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(
        code, FAILED,
        "a same-length forked tail must not pass just because the length matches:\n{out}"
    );
    assert!(out.contains("ANCHOR DIVERGENCE"), "{out}");
}

// ── Usage error: an untenanted anchor over an ambiguous window ───────────────────────────────

#[test]
fn expect_anchor_over_a_multi_tenant_window_is_a_usage_error() {
    let base_head = vec![0u8; 32];
    let mk_tenant_link = |seq: u64, tenant: &str| {
        let digest = Sha256::digest(format!("r{seq}").as_bytes()).to_vec();
        let checksum = {
            let mut h = Sha256::new();
            h.update(&base_head);
            h.update(&digest);
            h.finalize().to_vec()
        };
        serde_json::json!({
            "schema_version": "seam-event.v1",
            "event_id": format!("d{seq}#{seq}"),
            "seq": seq,
            "tenant": tenant,
            "kind": "DECISION_SEALED",
            "prev_checksum": b64e(&base_head),
            "digest": b64e(&digest),
            "checksum": b64e(&checksum),
        })
        .to_string()
    };
    let body = format!(
        "{}\n{}",
        mk_tenant_link(0, "acme"),
        mk_tenant_link(1, "globex")
    );

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let anchor = write_tmp("expect-multi", "json", &anchor_json(5, &base_head, &sk));
    let (code, out) = run(
        "multi-usage",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--expect-anchor",
            anchor.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(code, USAGE, "{out}");
    assert!(out.contains("USAGE ERROR"), "{out}");
}

#[test]
fn expect_anchor_requires_issuer() {
    let c = five_link_chain();
    let body = prefix_with_covering_attestation(&c, 5);
    let anchor = write_tmp("expect", "json", &anchor_json(5, &c.heads[5], &c.sk));
    let (code, out) = run(
        "no-issuer",
        &body,
        &["--expect-anchor", anchor.to_str().unwrap()],
    );
    let _ = std::fs::remove_file(&anchor);
    assert_eq!(code, USAGE, "{out}");
    assert!(out.contains("--expect-anchor requires --issuer"), "{out}");
}
