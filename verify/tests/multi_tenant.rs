//! Per-tenant chain verification (U-RT-1/U-RT-3) — `chain_by_tenant` and
//! `verify_authenticity_by_tenant`, driven mostly through the CLI (`chain [--issuer] [--strict]
//! [--json]`), and through the library directly where the CLI's own single-file `--from-anchor` cannot
//! reach a scenario (see the `chain_by_tenant_*` test below). Nothing of Seam's is linked — see
//! `Cargo.toml`.
//!
//! `tests/goldens/two_tenant_chain.jsonl` is copied verbatim from the runtime
//! (`seam-runtime/crates/seam-verify/tests/goldens/`, pinned at commit 2ea9f93, matching
//! `docs/seam-event.v1.md`'s own pin): two tenants (`acme`, `globex`) interleaved, two
//! `DECISION_SEALED` links and one issuer-signed `CHAIN_HEAD_ATTESTATION` each, both attestations
//! agreeing with their own envelope tenant (the post-U-RT-3 Phase 2/3 shape).

use std::collections::BTreeMap;
use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;
const USAGE: i32 = 1;

// The golden issuer (ed25519 seed 07×32) — same key `tests/authenticity.rs` and `tests/anchored.rs`
// use; duplicated here rather than shared, in the spirit of this crate's deliberate
// second-transcription discipline (see `record_digest_v3`'s doc comment).
const ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}
fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn golden(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/goldens/");
    std::fs::read_to_string(format!("{path}{name}")).expect("golden must exist")
}

fn write_tmp(name: &str, ext: &str, body: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "multi-tenant-{name}-{}-{}.{ext}",
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

/// Apply `f` to the first event line satisfying `matches`; return the new stream.
fn mutate_line(
    jsonl: &str,
    matches: impl Fn(&serde_json::Value) -> bool,
    f: impl Fn(&mut serde_json::Value),
) -> String {
    let mut done = false;
    jsonl
        .lines()
        .map(|l| {
            let mut e: serde_json::Value = serde_json::from_str(l).unwrap();
            if !done && matches(&e) {
                f(&mut e);
                done = true;
            }
            serde_json::to_string(&e).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ── (1) two-tenant interleaved independence ──────────────────────────────────────────────────────

#[test]
fn two_tenants_verify_independently() {
    let body = golden("two_tenant_chain.jsonl");
    let (code, out) = run("two-tenant", &body, &["--issuer", ISSUER, "--json"]);
    assert_eq!(code, VERIFIED, "{out}");
    let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    let tenants = v["tenants"]
        .as_array()
        .expect("multi-tenant JSON carries a tenants array");
    assert_eq!(tenants.len(), 2, "{out}");
    let names: Vec<&str> = tenants
        .iter()
        .map(|t| t["tenant"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"acme") && names.contains(&"globex"),
        "{out}"
    );
    for t in tenants {
        // 2 DECISION_SEALED + 1 CHAIN_HEAD_ATTESTATION — the attestation is itself a link (it carries
        // digest/checksum), so it advances the chain too.
        assert_eq!(t["links"], 3, "{out}");
        assert_eq!(t["attestations"], 1, "{out}");
        assert_eq!(t["tenant_unbound"], 0, "{out}");
    }
}

// ── (2) isolated tamper detection ─────────────────────────────────────────────────────────────────

#[test]
fn a_tampered_tenant_is_isolated_from_the_other() {
    let body = golden("two_tenant_chain.jsonl");
    // Flip a bit in globex's second link's own checksum: a FORGED LINK at that event, named by tenant.
    let tampered = mutate_line(
        &body,
        |e| e["decision_id"] == "g1",
        |e| {
            let mut cs = b64d(e["checksum"].as_str().unwrap());
            let last = cs.len() - 1;
            cs[last] ^= 0x01;
            e["checksum"] = serde_json::Value::String(b64e(&cs));
        },
    );
    let (code, out) = run("tamper", &tampered, &[]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("FORGED LINK"), "{out}");
    assert!(
        out.contains("\"globex\""),
        "tampered tenant must be named:\n{out}"
    );
}

// ── (3) mismatched payload tenant is refused under --issuer ──────────────────────────────────────

#[test]
fn a_mismatched_payload_tenant_is_refused_under_issuer() {
    let body = golden("two_tenant_chain.jsonl");
    // `tenant` inside `chain_head_attestation` is UNSIGNED — mutating it alone cannot break the
    // signature, so this exercises the agreement check specifically, not authenticity itself.
    let mutated = mutate_line(
        &body,
        |e| e["kind"] == "CHAIN_HEAD_ATTESTATION" && e["tenant"] == "acme",
        |e| {
            e["chain_head_attestation"]["tenant"] = serde_json::Value::String("globex".into());
        },
    );
    let (code, out) = run("mismatch", &mutated, &["--issuer", ISSUER]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("ATTESTATION TENANT MISMATCH"), "{out}");
}

// ── (4) legacy (pre-Phase-2) attestation: accepted, counted, --strict refuses ─────────────────────

#[test]
fn a_legacy_attestation_with_no_payload_tenant_is_accepted_and_counted() {
    let body = golden("two_tenant_chain.jsonl");
    let mutated = mutate_line(
        &body,
        |e| e["kind"] == "CHAIN_HEAD_ATTESTATION" && e["tenant"] == "acme",
        |e| {
            e["chain_head_attestation"]["tenant"] = serde_json::Value::String(String::new());
        },
    );

    let (code, out) = run("unbound", &mutated, &["--issuer", ISSUER, "--json"]);
    assert_eq!(code, VERIFIED, "accepted on the envelope alone:\n{out}");
    let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    let acme = v["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tenant"] == "acme")
        .unwrap();
    assert_eq!(acme["tenant_unbound"], 1, "{out}");

    let (code, out) = run(
        "unbound-strict",
        &mutated,
        &["--issuer", ISSUER, "--strict"],
    );
    assert_eq!(
        code, FAILED,
        "--strict must refuse an unbound attestation:\n{out}"
    );
    assert!(out.contains("REFUSED"), "{out}");
}

// ── (5) a cutover-spanning tenant reports NON-GENESIS FIRST LINK, not BROKEN CHAIN ───────────────

#[test]
fn a_cutover_spanning_tenant_reports_non_genesis_first_link() {
    let body = golden("two_tenant_chain.jsonl");
    // Drop globex's FIRST event (g0): globex's remaining first-OBSERVED event (g1) legitimately
    // continues a prior head this window never shows — exactly the cutover-backfill ambiguity, not
    // tampering. acme is untouched.
    let trimmed: String = body
        .lines()
        .filter(|l| {
            let e: serde_json::Value = serde_json::from_str(l).unwrap();
            e["decision_id"] != "g0"
        })
        .collect::<Vec<_>>()
        .join("\n");
    let (code, out) = run("cutover", &trimmed, &[]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("NON-GENESIS FIRST LINK"), "{out}");
    assert!(out.contains("\"globex\""), "{out}");
}

// ── (6) an anchor naming a tenant absent from the window ──────────────────────────────────────────
//
// Not reachable through the CLI's own single-file `--from-anchor` today (its `chain_anchored` wrapper
// only ever attributes the anchor to a tenant proven present in the window — see that function's own
// doc comment). Tests the actual, documented contract instead: `chain_by_tenant` itself does not
// refuse on this — `ChainReport::unconsumed_anchors`'s doc comment says the caller decides (and
// `main.rs::cmd_chain` does, for when the CLI grows multi-anchor input).

#[test]
fn chain_by_tenant_reports_an_anchor_for_a_tenant_absent_from_the_window() {
    let body = golden("two_tenant_chain.jsonl");
    let mut events: Vec<seam_verify::wire::Event> = body
        .lines()
        .map(|l| seam_verify::wire::Event::parse(l).unwrap())
        .collect();
    events.sort_by_key(|e| e.seq);

    let mut anchors: BTreeMap<String, (u64, Vec<u8>)> = BTreeMap::new();
    anchors.insert("nobody".to_string(), (3, vec![0xab; 32]));

    let r = seam_verify::chain_by_tenant(&events, &anchors)
        .expect("chain_by_tenant itself does not refuse — its caller decides");
    assert_eq!(r.unconsumed_anchors.get("nobody"), Some(&3));
    assert!(!r.tenants.contains_key("nobody"));
    // The two REAL tenants still walk normally — an anchor for an absent tenant does not disturb them.
    assert_eq!(r.tenants.len(), 2);
}

// ── (7) untenanted anchor fallback: correct for single-tenant, usage-error for multi-tenant ──────

/// `seam.audit.chain-head-attestation.v1`, transcribed from the spec independently of `src/verify.rs`
/// (same transcription `tests/authenticity.rs` / `tests/anchored.rs` use).
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
/// Untenanted on purpose: this is spec clause (f0)'s fallback shape, which `chain_anchored` attributes
/// by inferring the window's sole chained tenant, never by reading a tenant off the anchor itself.
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

fn sealed_link(seq: u64, prev: &[u8], tenant: &str) -> (String, Vec<u8>) {
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
        "tenant": tenant,
        "kind": "DECISION_SEALED",
        "prev_checksum": b64e(prev),
        "digest": b64e(&digest),
        "checksum": b64e(&checksum),
    })
    .to_string();
    (line, checksum)
}

#[allow(clippy::too_many_arguments)]
fn attestation_event(
    seq: u64,
    prev: &[u8],
    attested_len: u64,
    attested_head: &[u8],
    sk: &ed25519_dalek::SigningKey,
    issuer_aid: &str,
    digest_schema: u32,
    tenant: &str,
) -> String {
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
    serde_json::json!({
        "schema_version": "seam-event.v1",
        "event_id": format!("att#{seq}"),
        "seq": seq,
        "tenant": tenant,
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
            "tenant": tenant,
        },
    })
    .to_string()
}

#[test]
fn from_anchor_over_a_single_real_tenant_authenticates() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let base_len = 5u64;
    let base_head = Sha256::digest(b"anchor-head-seed").to_vec();
    let (link1, head1) = sealed_link(5, &base_head, "acme");
    let (link2, head2) = sealed_link(6, &head1, "acme");
    let covering_len = base_len + 2;
    let att = attestation_event(7, &head2, covering_len, &head2, &sk, ISSUER, 2, "acme");
    let body = format!("{link1}\n{link2}\n{att}");

    let anchor_body = anchor_json(base_len, &base_head, 1_700, ISSUER, 2, &sk);
    let anchor_path = write_tmp("anchor-single", "json", &anchor_body);
    let (code, out) = run(
        "anchor-single-tenant",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor_path.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor_path);
    assert_eq!(
        code, VERIFIED,
        "an untenanted anchor over a real single tenant must work:\n{out}"
    );
}

#[test]
fn from_anchor_over_a_multi_tenant_window_is_a_usage_error() {
    let base_head = Sha256::digest(b"anchor-head-seed").to_vec();
    // Two events, two distinct tenants, no need for either to chain validly: `chain_anchored`'s
    // tenant-attribution check runs over `is_link()` events before any chain walk happens at all.
    let (l1, _) = sealed_link(0, &base_head, "acme");
    let (l2, _) = sealed_link(1, &base_head, "globex");
    let body = format!("{l1}\n{l2}");

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let anchor_body = anchor_json(5, &base_head, 1_700, ISSUER, 2, &sk);
    let anchor_path = write_tmp("anchor-multi", "json", &anchor_body);
    let (code, out) = run(
        "multi-anchor-usage",
        &body,
        &[
            "--issuer",
            ISSUER,
            "--from-anchor",
            anchor_path.to_str().unwrap(),
        ],
    );
    let _ = std::fs::remove_file(&anchor_path);
    assert_eq!(code, USAGE, "{out}");
    assert!(out.contains("USAGE ERROR"), "{out}");
    assert!(out.contains("acme") && out.contains("globex"), "{out}");
}
