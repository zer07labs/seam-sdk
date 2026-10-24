//! Per-tenant chain verification (U-RT-1/U-RT-3) — `chain_by_tenant` and
//! `verify_authenticity_by_tenant`, driven mostly through the CLI (`chain [--issuer] [--strict]
//! [--json]`), and through the library directly where the CLI's own single-file `--from-anchor` cannot
//! reach a scenario (see the `chain_by_tenant_*` test below). Nothing of Seam's is linked — see
//! `Cargo.toml`.
//!
//! `tests/goldens/two_tenant_chain.jsonl` is copied verbatim from the runtime
//! (`seam-runtime/crates/seam-verify/tests/goldens/`, re-vendored at the runtime 0.57.0 train pin ae40c52 (k8s P7: `dev/` ids and `stream_id`), matching
//! `docs/seam-event.v1.md`'s own pin): two tenants (`acme`, `globex`) interleaved, two
//! `DECISION_SEALED` links and one issuer-signed `CHAIN_HEAD_ATTESTATION` each, both attestations
//! agreeing with their own envelope tenant (the post-U-RT-3 Phase 2/3 shape).

use std::collections::BTreeMap;
use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;

// The golden issuer (ed25519 seed 07×32) — same key `tests/authenticity.rs` and `tests/anchored.rs`
// use; duplicated here rather than shared, in the spirit of this crate's deliberate
// second-transcription discipline (see `record_digest_v4`'s doc comment).
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

/// Unique per process as well as per instant: these tests run as parallel threads, and a coarse clock
/// can hand two of them the same pid + nanos name (see the matching note in truncation.rs).
static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_tmp(name: &str, ext: &str, body: &str) -> std::path::PathBuf {
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "multi-tenant-{name}-{}-{seq}-{}.{ext}",
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
        assert!(
            t.get("tenant_unbound").is_none(),
            "tenant_unbound is gone (#835 step 4):\n{out}"
        );
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
    // Since #835 step 4 the payload `tenant` is inside the v2 signature, so this relabel would also
    // break it — but the agreement check runs first (as in seam-runtime's seam-verify), so the refusal
    // names the actual defect: the attestation disagrees with its own envelope.
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

// ── (4) legacy (pre-Phase-2) attestation: refused, with or without --strict (#835 step 4) ────────

/// The pre-U-RT-3-Phase-2 shape — a genuine v1 attestation, no payload tenant, envelope naming a
/// tenant — used to be accepted on the envelope's word, counted as `tenant_unbound`, and refused only
/// under `--strict`. Since #835 step 4 there is no back-compat: it is ATTESTATION TENANT MISMATCH either
/// way, and relabelling its payload to the envelope's tenant does not help, because v1 never signs one.
#[test]
fn a_legacy_tenant_unbound_attestation_is_refused() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let genesis = vec![0u8; 32];
    let (l0, h0) = sealed_link(0, &genesis, "acme");
    let (l1, h1) = sealed_link(1, &h0, "acme");
    let v1 = attestation_event_v1(2, &h1, 2, &h1, &sk, ISSUER, 2, "acme");

    let mut legacy: serde_json::Value = serde_json::from_str(&v1).unwrap();
    legacy["chain_head_attestation"]["tenant"] = serde_json::Value::String(String::new());
    let legacy = format!("{l0}\n{l1}\n{legacy}");
    for (name, args) in [
        ("legacy-unbound", &["--issuer", ISSUER][..]),
        (
            "legacy-unbound-strict",
            &["--issuer", ISSUER, "--strict"][..],
        ),
    ] {
        let (code, out) = run(name, &legacy, args);
        assert_eq!(
            code, FAILED,
            "a legacy tenant-unbound attestation must be refused ({name}):\n{out}"
        );
        assert!(out.contains("ATTESTATION TENANT MISMATCH"), "{out}");
    }

    // The same v1 signature with its payload relabelled to `acme`: the two tenant fields now agree,
    // so it reaches the signature — and is refused there, because a named tenant is v2 only.
    let relabelled = format!("{l0}\n{l1}\n{v1}");
    let (code, out) = run("v1-relabelled", &relabelled, &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "a v1 attestation over a tenant chain must be refused:\n{out}"
    );
    assert!(
        out.contains("does not verify against the pinned issuer's key"),
        "{out}"
    );
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

// ── (7) an anchor seeds exactly the tenant it names (#835 step 4) ─────────────────────────────────

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

/// What a step-3+ runtime signs for `tenant`: v2 over a named tenant, v1 for the system partition.
fn att_digest_for(
    len: u64,
    head: &[u8],
    at: u64,
    schema: u32,
    issuer_aid: &str,
    tenant: &str,
) -> [u8; 32] {
    if tenant.is_empty() {
        att_digest(len, head, at, schema, issuer_aid)
    } else {
        att_digest_v2(len, head, at, schema, issuer_aid, tenant)
    }
}

/// A bare anchor object — byte-for-byte one element of `GET /v1/anchors`' `anchors` array — signed
/// the way the runtime signs `tenant` (v2 for a named tenant, v1 for `""`). An empty tenant omits the
/// key entirely: the six-field shape an anchor minted before U-RT-3 Phase 2 has.
fn anchor_json(
    len: u64,
    head: &[u8],
    at: u64,
    issuer_aid: &str,
    schema: u32,
    sk: &ed25519_dalek::SigningKey,
    tenant: &str,
) -> String {
    use ed25519_dalek::Signer;
    let sig = sk
        .sign(&att_digest_for(len, head, at, schema, issuer_aid, tenant))
        .to_bytes();
    let mut v = serde_json::json!({
        "attested_len": len,
        "attested_head": b64e(head),
        "attested_at": at,
        "issuer_aid": issuer_aid,
        "digest_schema": schema,
        "signature": b64e(&sig),
    });
    if !tenant.is_empty() {
        v["tenant"] = serde_json::Value::String(tenant.to_string());
    }
    v.to_string()
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

/// An in-stream attestation for `tenant`, signed as a step-3+ runtime signs it (v2 for a named
/// tenant, v1 for `""`), envelope and payload both `tenant`.
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
    let at = 1_700 + seq;
    let digest = att_digest_for(
        attested_len,
        attested_head,
        at,
        digest_schema,
        issuer_aid,
        tenant,
    );
    attestation_event_signed(
        seq,
        prev,
        attested_len,
        attested_head,
        sk,
        issuer_aid,
        digest_schema,
        tenant,
        &digest,
    )
}

/// As [`attestation_event`], but v1-signed whatever `tenant` is — what the runtime minted for every
/// tenant before #835 step 3.
#[allow(clippy::too_many_arguments)]
fn attestation_event_v1(
    seq: u64,
    prev: &[u8],
    attested_len: u64,
    attested_head: &[u8],
    sk: &ed25519_dalek::SigningKey,
    issuer_aid: &str,
    digest_schema: u32,
    tenant: &str,
) -> String {
    let at = 1_700 + seq;
    let digest = att_digest(attested_len, attested_head, at, digest_schema, issuer_aid);
    attestation_event_signed(
        seq,
        prev,
        attested_len,
        attested_head,
        sk,
        issuer_aid,
        digest_schema,
        tenant,
        &digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn attestation_event_signed(
    seq: u64,
    prev: &[u8],
    attested_len: u64,
    attested_head: &[u8],
    sk: &ed25519_dalek::SigningKey,
    issuer_aid: &str,
    digest_schema: u32,
    tenant: &str,
    signed_digest: &[u8; 32],
) -> String {
    use ed25519_dalek::Signer;
    let at = 1_700 + seq;
    let sig = sk.sign(signed_digest).to_bytes();
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

fn run_anchored(name: &str, body: &str, anchor_body: &str, extra: &[&str]) -> (i32, String) {
    let anchor_path = write_tmp(name, "json", anchor_body);
    let mut args = vec![
        "--issuer",
        ISSUER,
        "--from-anchor",
        anchor_path.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let res = run(name, body, &args);
    let _ = std::fs::remove_file(&anchor_path);
    res
}

/// `acme`'s window from an anchor at `base_len` 5: two links and a covering attestation.
fn anchored_acme_window(sk: &ed25519_dalek::SigningKey) -> (String, u64, Vec<u8>) {
    let base_len = 5u64;
    let base_head = Sha256::digest(b"anchor-head-seed").to_vec();
    let (link1, head1) = sealed_link(5, &base_head, "acme");
    let (link2, head2) = sealed_link(6, &head1, "acme");
    let att = attestation_event(7, &head2, base_len + 2, &head2, sk, ISSUER, 2, "acme");
    (format!("{link1}\n{link2}\n{att}"), base_len, base_head)
}

#[test]
fn from_anchor_over_a_single_real_tenant_authenticates() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let (body, base_len, base_head) = anchored_acme_window(&sk);
    let anchor = anchor_json(base_len, &base_head, 1_700, ISSUER, 2, &sk, "acme");
    let (code, out) = run_anchored("anchor-single-tenant", &body, &anchor, &[]);
    assert_eq!(
        code, VERIFIED,
        "a v2 anchor naming the window's tenant must seed it:\n{out}"
    );
    assert!(out.contains("WINDOW AUTHENTICATED"), "{out}");
}

/// #835 step 4: an untenanted anchor is a v1 signature, which never binds a tenant, so it seeds only
/// the `""` system partition. The pre-#835 fallback to the window's sole tenant is gone: over a cut
/// `acme` window the tenant is walked from genesis and cannot link, and over a genesis `acme` window
/// the anchor is left unconsumed and fails closed — exit 2 either way, as in seam-runtime's own
/// seam-verify (`an_untenanted_anchor_never_seeds_a_tenant_chain`).
#[test]
fn an_untenanted_anchor_never_seeds_a_tenant_chain() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);

    let (cut, base_len, base_head) = anchored_acme_window(&sk);
    let untenanted = anchor_json(base_len, &base_head, 1_700, ISSUER, 2, &sk, "");
    let (code, out) = run_anchored("untenanted-cut", &cut, &untenanted, &[]);
    assert_eq!(
        code, FAILED,
        "an untenanted anchor must not seed acme's window:\n{out}"
    );
    assert!(
        out.contains("NON-GENESIS FIRST LINK") && out.contains("\"acme\""),
        "{out}"
    );

    // The same v1 signature with `"tenant":"acme"` added: the tenant is not in a v1 signature, so
    // this is refused at the anchor itself, before it can seed anything.
    let mut relabelled: serde_json::Value = serde_json::from_str(&untenanted).unwrap();
    relabelled["tenant"] = serde_json::Value::String("acme".into());
    let (code, out) = run_anchored("v1-relabelled-anchor", &cut, &relabelled.to_string(), &[]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("ANCHOR REJECTED"), "{out}");

    let genesis = vec![0u8; 32];
    let (l0, h0) = sealed_link(0, &genesis, "acme");
    let (l1, h1) = sealed_link(1, &h0, "acme");
    let att = attestation_event(2, &h1, 2, &h1, &sk, ISSUER, 2, "acme");
    let whole = format!("{l0}\n{l1}\n{att}");
    let anchor = anchor_json(2, &h1, 1_700, ISSUER, 2, &sk, "");
    let (code, out) = run_anchored("untenanted-genesis", &whole, &anchor, &[]);
    assert_eq!(code, FAILED, "{out}");
    assert!(
        out.contains("tenant \"\"") && out.contains("NO VALID ATTESTATION"),
        "{out}"
    );
}

/// An anchor seeds exactly the tenant it names, so a window spanning more than one tenant is no
/// longer ambiguous: the named tenant starts at its anchor and every other tenant at genesis — the
/// shape of seam-runtime's own `a_tenant_with_no_anchor_verifies_from_genesis_while_another_is_anchored`.
#[test]
fn from_anchor_over_a_multi_tenant_window_seeds_only_the_named_tenant() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let (acme, base_len, base_head) = anchored_acme_window(&sk);
    let genesis = vec![0u8; 32];
    let (g0, gh0) = sealed_link(10, &genesis, "globex");
    let (g1, gh1) = sealed_link(11, &gh0, "globex");
    let gatt = attestation_event(12, &gh1, 2, &gh1, &sk, ISSUER, 2, "globex");
    let body = format!("{acme}\n{g0}\n{g1}\n{gatt}");

    let anchor = anchor_json(base_len, &base_head, 1_700, ISSUER, 2, &sk, "acme");
    let (code, out) = run_anchored("anchor-multi", &body, &anchor, &[]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.contains("WINDOW AUTHENTICATED (issuer-anchored start, per tenant)"),
        "{out}"
    );

    let (code, out) = run_anchored("anchor-multi-json", &body, &anchor, &["--json"]);
    assert_eq!(code, VERIFIED, "{out}");
    let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    let base = |t: &str| {
        v["tenants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["tenant"] == t)
            .unwrap()["base_len"]
            .clone()
    };
    assert_eq!(base("acme"), 5, "{out}");
    assert_eq!(base("globex"), 0, "{out}");
}

/// A full-event anchor follows the same payload==envelope equality rule as an in-stream attestation
/// (#835 step 4): an empty payload tenant under a named envelope is refused as a defect in the anchor
/// itself — exit 2, before it can seed anything — not accepted on the envelope's word.
#[test]
fn a_full_event_anchor_whose_payload_tenant_differs_from_its_envelope_is_refused() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let (body, base_len, base_head) = anchored_acme_window(&sk);
    let full = attestation_event(4, &[0u8; 32], base_len, &base_head, &sk, ISSUER, 2, "acme");

    let (code, out) = run_anchored("full-event-anchor", &body, &full, &[]);
    assert_eq!(
        code, VERIFIED,
        "an agreeing full-event anchor seeds its tenant:\n{out}"
    );

    for payload_tenant in ["", "globex"] {
        let mut e: serde_json::Value = serde_json::from_str(&full).unwrap();
        e["chain_head_attestation"]["tenant"] = serde_json::Value::String(payload_tenant.into());
        let (code, out) = run_anchored("full-event-mismatch", &body, &e.to_string(), &[]);
        assert_eq!(code, FAILED, "payload {payload_tenant:?}: {out}");
        assert!(out.contains("ANCHOR SELF-CONTRADICTS"), "{out}");
    }
}

// ── (6) the system partition is attested like any tenant (seam-runtime#1196/#1205) ────────────────

/// The system partition (wire `tenant == ""`) gets its own `CHAIN_HEAD_ATTESTATION`, with envelope AND
/// payload `tenant` both `""`, signed v1. Spec §CHAIN_HEAD_ATTESTATION *Per partition*: `""` agreeing
/// with `""` is agreement, NOT the refused empty-payload case, and it verifies under v1. And `--issuer`
/// requires a covering attestation for every partition, `""` included.
///
/// Built from the two-tenant golden by moving `acme`'s envelope and its attestation's payload tenant to
/// `""`, and RE-SIGNING that attestation under v1 (the golden's is v2 over `acme`, which an empty tenant
/// no longer verifies under, #835 step 4) with the golden's own issuer seed. The records' own payload
/// `tenant` is left alone, because it is sealed into their digests. The verifier does not police which
/// kinds may be tenant-less (the producer does, invariant 10), so this exercises the attestation path
/// exactly.
#[test]
fn the_system_partition_is_attested_like_any_tenant() {
    let body = golden("two_tenant_chain.jsonl");
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let to_system = |e: &mut serde_json::Value| {
        use ed25519_dalek::Signer;
        e["tenant"] = serde_json::Value::String(String::new());
        if e["kind"] == "CHAIN_HEAD_ATTESTATION" {
            let a = &mut e["chain_head_attestation"];
            a["tenant"] = serde_json::Value::String(String::new());
            let sig = sk.sign(&att_digest(
                a["attested_len"].as_u64().unwrap(),
                &b64d(a["attested_head"].as_str().unwrap()),
                a["attested_at"].as_u64().unwrap(),
                a["digest_schema"].as_u64().unwrap() as u32,
                a["issuer_aid"].as_str().unwrap(),
            ));
            a["signature"] = serde_json::Value::String(b64e(&sig.to_bytes()));
        }
    };
    let system: String = body
        .lines()
        .map(|l| {
            let mut e: serde_json::Value = serde_json::from_str(l).unwrap();
            if e["tenant"] == "acme" {
                to_system(&mut e);
            }
            e.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");

    let (code, out) = run(
        "system",
        &system,
        &["--issuer", ISSUER, "--strict", "--json"],
    );
    assert_eq!(
        code, VERIFIED,
        "a system-partition attestation must authenticate under --strict:\n{out}"
    );
    let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    let sys = v["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tenant"] == "")
        .expect("the system partition is reported");
    assert_eq!(sys["authenticated"], true, "{out}");

    // Without its attestation, the system partition is uncovered, and --issuer refuses the whole stream.
    let unattested: String = system
        .lines()
        .filter(|l| {
            let e: serde_json::Value = serde_json::from_str(l).unwrap();
            !(e["kind"] == "CHAIN_HEAD_ATTESTATION" && e["tenant"] == "")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let (code, out) = run("system-unattested", &unattested, &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "an unattested system partition must be refused under --issuer:\n{out}"
    );
    assert!(
        out.contains("tenant \"\""),
        "the refusal names the system partition:\n{out}"
    );
}

// ── (8) the v2 signed framing binds the tenant (seam-runtime #835) ────────────────────────────────

/// `seam.audit.chain-head-attestation.v2` — the v1 frames under the v2 domain tag, then `frame(tenant)`.
/// Transcribed from the spec independently of `src/verify.rs`, like `att_digest` above.
fn att_digest_v2(
    len: u64,
    head: &[u8],
    at: u64,
    schema: u32,
    issuer_aid: &str,
    tenant: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut frame = |part: &[u8]| {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    };
    frame(b"seam.audit.chain-head-attestation.v2");
    frame(&len.to_le_bytes());
    frame(head);
    frame(&at.to_le_bytes());
    frame(&schema.to_le_bytes());
    frame(issuer_aid.as_bytes());
    frame(tenant.as_bytes());
    h.finalize().into()
}

/// A single-tenant `acme` stream whose attestation is v2-signed over `signed_tenant` but labelled
/// `acme` on the wire (envelope and payload).
fn v2_stream(signed_tenant: &str) -> String {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
    let genesis = vec![0u8; 32];
    let (l0, h0) = sealed_link(0, &genesis, "acme");
    let (l1, h1) = sealed_link(1, &h0, "acme");
    let mut att: serde_json::Value =
        serde_json::from_str(&attestation_event(2, &h1, 2, &h1, &sk, ISSUER, 2, "acme")).unwrap();
    let at = att["chain_head_attestation"]["attested_at"]
        .as_u64()
        .unwrap();
    let sig = sk
        .sign(&att_digest_v2(2, &h1, at, 2, ISSUER, signed_tenant))
        .to_bytes();
    att["chain_head_attestation"]["signature"] = serde_json::Value::String(b64e(&sig));
    format!("{l0}\n{l1}\n{att}")
}

#[test]
fn a_v2_attestation_authenticates_its_own_tenant() {
    let (code, out) = run(
        "v2-own-tenant",
        &v2_stream("acme"),
        &["--issuer", ISSUER, "--strict"],
    );
    assert_eq!(
        code, VERIFIED,
        "a v2 attestation over its own tenant must authenticate:\n{out}"
    );
}

/// The point of v2: an attestation signed for `globex` and relabelled `acme` — consistently, envelope
/// and payload, so the tenant-agreement check cannot catch it — fails on the signature itself. Under v1
/// the tenant was outside the signature and this relabel was invisible.
#[test]
fn a_v2_attestation_relabelled_to_another_tenant_is_refused() {
    let (code, out) = run("v2-relabelled", &v2_stream("globex"), &["--issuer", ISSUER]);
    assert_eq!(
        code, FAILED,
        "a relabelled v2 attestation must be refused:\n{out}"
    );
    assert!(
        out.contains("does not verify against the pinned issuer's key"),
        "{out}"
    );
    assert!(
        out.contains("newer than this verifier"),
        "the refusal must leave room for a framing newer than this build, never assert forgery alone:\n{out}"
    );
}
