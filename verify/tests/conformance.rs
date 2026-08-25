//! `record_digest_v3` against the committed conformance vectors — through the REAL wire path.
//!
//! These vectors are machine-emitted by `scripts/emit_record_digest_v3_vectors.py` and byte-diffed by
//! seam-runtime's `sdk-digest-parity` job, so they are a cross-repo contract rather than a local
//! fixture. Four independent implementations of `seam.audit.record-digest.v3` exist (Python,
//! TypeScript, this verifier, and the runtime's own); the vectors are what stops them drifting.
//!
//! **Deliberately end-to-end, not a unit test of the digest function.** Each case is assembled into a
//! chained `DECISION_SEALED` JSON event and run through the shipped CLI. That covers three things a
//! direct call could not:
//!
//! * the **wire mapping** — tags 11/12/13 landing in the right `Decision` fields. The vectors keep
//!   `context_digest != participation_digest` in every case precisely so a swapped tag-11/tag-12
//!   mapping in `wire.rs` cannot cancel out against a swapped preimage slot;
//! * **base64 decode and presence** — `None` (key absent) vs `Some("")` vs a real 32-byte value;
//! * the **version dispatch** — that a `schema_version = 3` record actually reaches the v3 formula
//!   rather than the v2 one.
//!
//! It also means this file needs no access to the crate's private digest functions, so proving the
//! contract does not require widening the published API surface to do it.

use std::process::Command;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;

/// The golden issuer (ed25519 seed 07×32) — the same AID `tests/authenticity.rs` pins.
const ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";

fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string of odd length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// A conformance file, read from the repo rather than vendored.
///
/// Vendoring a copy here would defeat the purpose: the runtime's parity job byte-diffs the ONE file,
/// and a second copy is a second thing to drift. Loading it from `../conformance/` is also why this
/// test is in `Cargo.toml`'s package `exclude` — the published crate is a standalone tarball with no
/// parent directory, so a test that reads one has to be left out of it rather than ship broken.
fn conformance_file(name: &str) -> Value {
    let path = format!("{}/../conformance/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "conformance/{name} is unreadable ({e}).\n  \
             This is a FAILURE, not a reason to skip: the whole point of a conformance test is that \
             it cannot quietly stop testing anything."
        )
    });
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("conformance/{name} must be valid JSON: {e}"))
}

fn vectors() -> Value {
    conformance_file("vectors.json")
}

fn extended() -> Value {
    conformance_file("record_digest_v3_extended.json")
}

/// seam-runtime's own v3 blocks in `vectors.json`, and the name each takes once normalised.
///
/// These two are the CROSS-REPO contract: `sdk-digest-parity` byte-diffs the whole of `vectors.json`
/// against seam-runtime's emitter, so agreeing on them is what "independent implementations agree"
/// actually means here.
const RUNTIME_V3_BLOCKS: [(&str, &str); 2] = [
    ("record_digest_v3", "runtime_bound_policy"),
    ("record_digest_v3_absent_policy", "runtime_absent_policy"),
];

/// The v3 cases from both files, or a loud failure.
///
/// A conformance test that SKIPS when its fixtures go missing is worse than no test at all: it
/// reports green while proving nothing, and the day someone renames the block is the day the
/// cross-repo contract stops being checked without anyone noticing. So this panics, and
/// `the_case_loader_fails_loudly_when_the_block_is_missing` proves it panics.
fn v3_cases(v: &Value, ext: &Value) -> Vec<Value> {
    let mut cases: Vec<Value> = Vec::new();
    for (block, name) in RUNTIME_V3_BLOCKS {
        let b = v.get(block).unwrap_or_else(|| {
            panic!(
                "conformance/vectors.json has no `{block}` block.\n  \
                 Refusing to pass: that file is byte-diffed by seam-runtime's sdk-digest-parity \
                 gate, so a missing block means this repo and the runtime have stopped agreeing on \
                 the vector set — not that a case was tidied away."
            )
        });
        cases.push(json!({
            "name": name,
            "inputs": b.get("inputs").unwrap_or_else(|| panic!("`{block}` must carry `inputs`")),
            "digest_hex": b.get("digest_hex").unwrap_or_else(|| panic!("`{block}` must carry `digest_hex`")),
        }));
    }
    let extra = ext
        .get("cases")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("record_digest_v3_extended.json must carry a `cases` array"));
    assert!(
        !extra.is_empty(),
        "record_digest_v3_extended.json carries zero cases — nothing below would assert anything"
    );
    cases.extend(extra.iter().cloned());
    cases
}

/// The JSON payload object for one vector case.
///
/// The three string optionals follow the spec's `None` / `Some("")` distinction exactly: a `null` in
/// the vector means the key is ABSENT from the object (which deserializes to `None`), while an empty
/// string means the key is PRESENT and empty. Emitting `"mode": null` for the absent case would work
/// here by accident — serde maps it to `None` too — but it would stop this test covering the shape a
/// real producer emits, so absence is spelled as absence.
fn payload_of(inputs: &Value) -> Value {
    let mut p = Map::new();
    for key in ["decision_id", "tenant", "namespace", "outcome"] {
        p.insert(key.into(), inputs[key].clone());
    }
    p.insert("sealed_at".into(), inputs["sealed_at"].clone());
    p.insert("schema_version".into(), inputs["schema_version"].clone());
    for key in ["mode", "policy_version", "supersedes"] {
        if let Some(s) = inputs[key].as_str() {
            p.insert(key.into(), json!(s));
        }
    }
    for (key, hex_key) in [
        ("ciphertext_digest", "ciphertext_digest_hex"),
        ("context_digest", "context_digest_hex"),
        ("participation_digest", "participation_digest_hex"),
        ("policy_rules_digest", "policy_rules_digest_hex"),
    ] {
        if let Some(h) = inputs[hex_key].as_str() {
            p.insert(key.into(), json!(b64e(&unhex(h))));
        }
    }
    Value::Object(p)
}

/// A chained `DECISION_SEALED` line carrying `payload`, committing to `digest`. Returns the new head.
fn sealed_line(seq: u64, prev: &[u8], digest: &[u8], payload: &Value) -> (String, Vec<u8>) {
    let checksum = {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(digest);
        h.finalize().to_vec()
    };
    let ev = json!({
        "schema_version": "seam-event.v1",
        "event_id": format!("v3#{seq}"),
        "seq": seq,
        "occurred_at": 1_700_000_000_000u64 + seq,
        "kind": "DECISION_SEALED",
        "prev_checksum": b64e(prev),
        "digest": b64e(digest),
        "checksum": b64e(&checksum),
        "payload": payload,
    });
    (ev.to_string(), checksum)
}

/// The signed head that turns integrity-only verification into authenticity (design-b). Without one,
/// `--issuer` has nothing to check and the digest recompute never runs.
fn attestation_line(seq: u64, prev: &[u8], len: u64, head: &[u8], sk: &SigningKey) -> String {
    let at = 1_700 + seq;
    let mut pre: Vec<u8> = Vec::new();
    let frame = |b: &mut Vec<u8>, part: &[u8]| {
        b.extend_from_slice(&(part.len() as u32).to_le_bytes());
        b.extend_from_slice(part);
    };
    frame(&mut pre, b"seam.audit.chain-head-attestation.v1");
    frame(&mut pre, &len.to_le_bytes());
    frame(&mut pre, head);
    frame(&mut pre, &at.to_le_bytes());
    frame(&mut pre, &2u32.to_le_bytes());
    frame(&mut pre, ISSUER.as_bytes());
    let sig = sk.sign(&Sha256::digest(&pre)).to_bytes();

    let digest = Sha256::digest(b"att").to_vec();
    let checksum = {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(&digest);
        h.finalize().to_vec()
    };
    json!({
        "schema_version": "seam-event.v1",
        "event_id": format!("att#{seq}"),
        "seq": seq,
        "occurred_at": at,
        "kind": "CHAIN_HEAD_ATTESTATION",
        "prev_checksum": b64e(prev),
        "digest": b64e(&digest),
        "checksum": b64e(&checksum),
        "chain_head_attestation": {
            "attested_len": len,
            "attested_head": b64e(head),
            "attested_at": at,
            "issuer_aid": ISSUER,
            "digest_schema": 2,
            "signature": b64e(&sig),
        }
    })
    .to_string()
}

/// Build a stream from `(payload, digest)` pairs and run `chain --issuer` over it.
fn run_stream(name: &str, records: &[(Value, Vec<u8>)]) -> (i32, String) {
    let sk = SigningKey::from_bytes(&[0x07; 32]);
    assert_eq!(
        format!("aid:pubkey:{}", b64u(sk.verifying_key().as_bytes())),
        ISSUER,
        "seed 07×32 must derive the golden issuer AID"
    );

    let mut head = vec![0u8; 32];
    let mut lines = Vec::new();
    for (seq, (payload, digest)) in records.iter().enumerate() {
        let (line, next) = sealed_line(seq as u64, &head, digest, payload);
        lines.push(line);
        head = next;
    }
    let n = records.len() as u64;
    lines.push(attestation_line(n, &head, n, &head, &sk));

    let path = std::env::temp_dir().join(format!("v3-conf-{name}-{}.jsonl", std::process::id()));
    std::fs::write(&path, lines.join("\n")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_seam-verify"))
        .args(["chain", path.to_str().unwrap(), "--issuer", ISSUER])
        .output()
        .expect("run seam-verify");
    let _ = std::fs::remove_file(&path);
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap(), s)
}

fn records() -> Vec<(Value, Vec<u8>)> {
    v3_cases(&vectors(), &extended())
        .iter()
        .map(|c| {
            (
                payload_of(&c["inputs"]),
                unhex(c["digest_hex"].as_str().expect("digest_hex")),
            )
        })
        .collect()
}

// ── the contract ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn every_v3_conformance_case_recomputes_through_the_wire() {
    let recs = records();
    let (code, out) = run_stream("all", &recs);
    assert_eq!(
        code, VERIFIED,
        "the committed v3 vectors must verify:\n{out}"
    );
    assert!(
        out.contains(&format!("records recomputed: {}", recs.len())),
        "every case must be COUNTED, not merely not-refused — a case silently skipped would look \
         identical to a case that passed:\n{out}"
    );
}

#[test]
fn the_conformance_loop_is_falsifiable() {
    // Guard the guard. If the v3 arm were wired to skip, or to compare something to itself, the test
    // above would pass with the formula arbitrarily wrong. Perturbing one input byte must break it.
    let mut recs = records();
    let p = &mut recs[0].0;
    let mut ctx = base64::engine::general_purpose::STANDARD
        .decode(p["context_digest"].as_str().unwrap())
        .unwrap();
    ctx[0] ^= 0xff;
    p["context_digest"] = json!(b64e(&ctx));

    let (code, out) = run_stream("perturbed", &recs);
    assert_eq!(code, FAILED, "a perturbed context_digest must fail:\n{out}");
    assert!(out.contains("does NOT match its own digest"), "{out}");
}

#[test]
fn a_swapped_tag_11_12_mapping_cannot_cancel() {
    // The decoy that catches a wire-layer swap. Reading tag 12 into slot 10 and tag 11 into slot 11
    // produces a perfectly well-formed preimage, so it is invisible UNLESS the two values differ —
    // which is why the emitter keeps them distinct in every case, asserted here rather than assumed.
    let mut recs = records();
    for (p, _) in recs.iter_mut() {
        assert_ne!(
            p["context_digest"], p["participation_digest"],
            "a vector case sets context_digest == participation_digest, so a slot swap would cancel"
        );
        let (c, q) = (
            p["context_digest"].clone(),
            p["participation_digest"].clone(),
        );
        p["context_digest"] = q;
        p["participation_digest"] = c;
    }
    let (code, out) = run_stream("swapped", &recs);
    assert_eq!(code, FAILED, "swapping tags 11 and 12 must fail:\n{out}");
}

#[test]
fn the_case_loader_fails_loudly_when_the_block_is_missing() {
    // The property this file's value rests on: it cannot quietly stop testing anything. Proven by
    // running the loader against a doctored document rather than by reading the code.
    // Every runtime block, one at a time — a guard that only covers the first would let the second
    // disappear silently, which is exactly the class of hole this file exists to close.
    for (block, _) in RUNTIME_V3_BLOCKS {
        let mut doctored = vectors();
        doctored.as_object_mut().unwrap().remove(block);
        let missing = std::panic::catch_unwind(|| v3_cases(&doctored, &extended()));
        assert!(
            missing.is_err(),
            "a vectors file with no `{block}` block was accepted — this test would then pass while \
             proving nothing"
        );
    }

    let mut emptied = extended();
    emptied["cases"] = json!([]);
    let empty = std::panic::catch_unwind(|| v3_cases(&vectors(), &emptied));
    assert!(empty.is_err(), "an EMPTY extended cases array was accepted");
}
