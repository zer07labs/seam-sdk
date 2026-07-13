//! The public verifier, driven as a **subprocess** — the shipped artifact and its exit code.
//!
//! Every stream here is built by hand from the published spec, using nothing of Seam's. That is the point:
//! if these fixtures can be constructed from the spec alone, then so can a third party's, and the claim
//! *"verify it yourself"* is real rather than decorative.
//!
//! The load-bearing cases are the **negative** ones. A verifier that can only say "verified" is worthless;
//! what makes it worth anything is that it is capable of saying "forged" — and that it does not say it
//! about a healthy stream.

use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const USAGE: i32 = 1;
const FAILED: i32 = 2;

fn link(prev: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(digest);
    h.finalize().to_vec()
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// One event of the JSON projection. `digest`/`checksum` are omitted entirely when absent (per the spec's
/// `skip_serializing_if` rule), which is exactly what makes a pre-cutover event indistinguishable from an
/// advisory one.
fn event(seq: u64, kind: &str, prev: &[u8], digest: Option<&[u8]>, extra: &str) -> String {
    let mut s = format!(
        r#"{{"schema_version":"seam-event.v1","event_id":"e{seq}","seq":{seq},"kind":"{kind}","prev_checksum":"{}""#,
        b64(prev)
    );
    if let Some(d) = digest {
        s.push_str(&format!(
            r#","digest":"{}","checksum":"{}""#,
            b64(d),
            b64(&link(prev, d))
        ));
    }
    s.push_str(extra);
    s.push('}');
    s
}

/// A genuine chain of `n` DECISION_SEALED events, built straight from the spec's rule.
fn chain(n: u64) -> Vec<String> {
    let mut head = vec![0u8; 32]; // genesis
    let mut out = Vec::new();
    for seq in 0..n {
        let digest = Sha256::digest(format!("record-{seq}").as_bytes()).to_vec();
        out.push(event(seq, "DECISION_SEALED", &head, Some(&digest), ""));
        head = link(&head, &digest);
    }
    out
}

fn run(name: &str, lines: &[String], args: &[&str]) -> (i32, String) {
    let path = std::env::temp_dir().join(format!("pubverify-{name}-{}.jsonl", std::process::id()));
    std::fs::write(&path, lines.join("\n")).unwrap();
    let mut argv: Vec<&str> = vec!["chain", path.to_str().unwrap()];
    argv.extend_from_slice(args);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_seam-verify"))
        .args(&argv)
        .output()
        .expect("run seam-verify");
    let _ = std::fs::remove_file(&path);
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap(), s)
}

#[test]
fn a_genuine_chain_verifies() {
    let (code, out) = run("genuine", &chain(6), &[]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(out.contains("links checked     : 6"), "{out}");
}

#[test]
fn a_rewritten_event_is_caught() {
    // The tamper the product claim is really about: a sealed decision is altered after the fact, so its
    // digest no longer produces the head it claims.
    let mut c = chain(5);
    c[2] = c[2].replace("\"digest\":\"", "\"digest\":\"AAAA");
    let (code, out) = run("rewritten", &c, &[]);
    assert_eq!(code, FAILED, "a rewritten event MUST fail:\n{out}");
}

#[test]
fn a_dropped_event_breaks_the_chain() {
    // Quietly removing a decision that should not have happened. The next link's prev_checksum no longer
    // matches the running head.
    let mut c = chain(6);
    c.remove(3);
    let (code, out) = run("dropped", &c, &[]);
    assert_eq!(code, FAILED, "a dropped event MUST break the chain:\n{out}");
    assert!(out.contains("BROKEN CHAIN"), "{out}");
}

#[test]
fn an_at_least_once_duplicate_is_not_a_forgery() {
    // Delivery is at-least-once. A single retry means the consumer holds two identical copies of one
    // event. A verifier that calls that "forged" is crying wolf on a healthy stream — the one failure a
    // verifier cannot afford, and the one this project has now made twice.
    let mut c = chain(5);
    c.push(c[2].clone());
    c.push(c[0].clone());
    let (code, out) = run("dupes", &c, &[]);
    assert_eq!(
        code, VERIFIED,
        "a retried event MUST NOT read as a forgery:\n{out}"
    );
    assert!(
        out.contains("duplicates        : 2"),
        "and it must say it dropped them:\n{out}"
    );
}

#[test]
fn two_chain_anchors_over_a_quiet_stream_are_not_a_forgery() {
    // The chain anchor is an AUDIT_ENTRY that is emitted OFF-chain (spec §AUDIT_ENTRY): it records a head
    // for an out-of-band notary without perturbing the chain it anchors. Two anchors emitted while nothing
    // was sealed between them share every field but the timestamp — and, in Seam, their event_id too.
    //
    // Keying dedup on `event_id` therefore refuses a perfectly healthy stream. That is precisely the bug
    // the runtime's verifier shipped with, and this implementation must not repeat it.
    let mut c = chain(3);
    for occurred in ["100", "200"] {
        c.push(format!(
            r#"{{"schema_version":"seam-event.v1","event_id":"chain-anchor:3#3","seq":3,"kind":"AUDIT_ENTRY","prev_checksum":"","occurred_at":{occurred},"audit_entry":{{"action":"chain_anchor","subject":"audit-chain","reason":"len=3"}}}}"#
        ));
    }
    let (code, out) = run("anchors", &c, &[]);
    assert_eq!(code, VERIFIED, "periodic anchors are NOT a forgery:\n{out}");
    assert!(out.contains("advisory (skipped): 2"), "{out}");
}

#[test]
fn an_advisory_event_does_not_advance_the_head() {
    // Chained-ness is by field PRESENCE, never by kind. A verifier keyed on `kind` trips over the first
    // LEARNING_DECISION in an unfiltered stream.
    let mut c = chain(3);
    c.insert(
        1,
        r#"{"schema_version":"seam-event.v1","event_id":"ld1","seq":1,"kind":"LEARNING_DECISION","prev_checksum":""}"#.to_string(),
    );
    let (code, out) = run("advisory", &c, &[]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(out.contains("advisory (skipped): 1"), "{out}");
    assert!(out.contains("links checked     : 3"), "{out}");
}

#[test]
fn pre_cutover_events_are_disclosed_and_strict_refuses_them() {
    // The spec's MUST: an event with no digest/checksum that is NOT advisory predates the chain fields,
    // and cannot be verified. Skipping it silently would report a green chain over history never checked.
    let mut c = chain(3);
    c.push(
        r#"{"schema_version":"seam-event.v1","event_id":"old","seq":99,"kind":"DECISION_SEALED","prev_checksum":""}"#
            .to_string(),
    );

    let (code, out) = run("lenient", &c, &[]);
    assert_eq!(code, VERIFIED, "default: skip — but SAY so:\n{out}");
    assert!(
        out.contains("UNVERIFIABLE"),
        "the skip must be disclosed:\n{out}"
    );

    let (code, out) = run("strict", &c, &["--strict"]);
    assert_eq!(code, FAILED, "--strict must refuse:\n{out}");
    assert!(out.contains("REFUSED"), "{out}");
}

#[test]
fn an_empty_stream_is_not_a_green_chain() {
    // The most dangerous pass of all: point it at the wrong file and conclude the chain is intact.
    let (code, _) = run("empty", &[], &[]);
    assert_eq!(
        code, USAGE,
        "an empty stream must NOT report a verified chain"
    );
}

#[test]
fn garbage_is_a_parse_error_not_a_green_chain() {
    for junk in ["A", "!!!!", "{\"seq\":1"] {
        let mut c = chain(3);
        c.push(junk.to_string());
        let (code, out) = run("junk", &c, &[]);
        assert_eq!(
            code, USAGE,
            "junk line {junk:?} must be a parse error, never a skipped event under a green verdict:\n{out}"
        );
    }
}

#[test]
fn out_of_order_delivery_is_fine_but_a_real_reorder_is_not() {
    // Delivery is unordered (retries, replays, merged shards), so the LINE order must not matter...
    let mut c = chain(5);
    c.swap(1, 4);
    let (code, out) = run("shuffled", &c, &[]);
    assert_eq!(
        code, VERIFIED,
        "out-of-order delivery is legitimate:\n{out}"
    );

    // ...but rewriting the sequence numbers so events genuinely change places is a rewrite of history.
    let mut c = chain(5);
    c[1] = c[1].replace("\"seq\":1", "\"seq\":3");
    c[3] = c[3].replace("\"seq\":3", "\"seq\":1");
    let (code, out) = run("reordered", &c, &[]);
    assert_eq!(code, FAILED, "a genuine reorder MUST fail:\n{out}");
}
