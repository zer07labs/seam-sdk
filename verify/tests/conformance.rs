//! `record_digest_v4` against the committed conformance vectors — through the REAL wire path.
//!
//! `vectors.json` is byte-diffed by seam-runtime's `sdk-digest-parity` job, and `vectors_extended.json`
//! is the runtime's `conformance_vectors_extended.json` vendored byte-identical, so both are a
//! cross-repo contract rather than a local fixture. Several independent implementations of
//! `seam.audit.record-digest.v4` exist (the SDKs, this verifier, and the runtime's own); the vectors
//! are what stops them drifting.
//!
//! **Deliberately end-to-end, not a unit test of the digest function.** Each case is assembled into a
//! chained `DECISION_SEALED` JSON event and run through the shipped CLI. That covers three things a
//! direct call could not:
//!
//! * the **wire mapping** — tags 11-17 landing in the right `Decision` fields. The vectors keep
//!   `context_digest`, `participation_digest` and `participants_digest` pairwise distinct in every
//!   case precisely so a swapped tag mapping in `wire.rs` cannot cancel out against a swapped
//!   preimage slot;
//! * **base64 decode and presence** — `None` (key absent) vs `Some("")` vs a real 32-byte value;
//! * the **version dispatch** — that a `schema_version = 4` record actually reaches the v4 formula
//!   and is counted as recomputed, rather than refused or skipped.
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
    conformance_file("vectors_extended.json")
}

/// seam-runtime's own v4 blocks in `vectors.json`, and the name each takes once normalised.
///
/// These two are the CROSS-REPO contract: `sdk-digest-parity` byte-diffs the whole of `vectors.json`
/// against seam-runtime's emitter, so agreeing on them is what "independent implementations agree"
/// actually means here.
const RUNTIME_V4_BLOCKS: [(&str, &str); 2] = [
    ("record_digest_v4", "runtime_bound_policy"),
    ("record_digest_v4_absent_policy", "runtime_absent_policy"),
];

/// The `record_digest_v4` cases in `vectors_extended.json`. Each is a top-level block there, beside
/// the `chain_head_attestation_v2` block this file does not read.
const EXTENDED_V4_BLOCKS: [&str; 3] = [
    "all_optionals_present",
    "optionals_none",
    "mode_empty_string",
];

/// The v4 cases from both files, or a loud failure.
///
/// A conformance test that SKIPS when its fixtures go missing is worse than no test at all: it
/// reports green while proving nothing, and the day someone renames the block is the day the
/// cross-repo contract stops being checked without anyone noticing. So this panics, and
/// `the_case_loader_fails_loudly_when_the_block_is_missing` proves it panics.
fn v4_cases(v: &Value, ext: &Value) -> Vec<Value> {
    let mut cases: Vec<Value> = Vec::new();
    let blocks = RUNTIME_V4_BLOCKS
        .iter()
        .map(|(b, n)| (v, "vectors.json", *b, *n))
        .chain(
            EXTENDED_V4_BLOCKS
                .iter()
                .map(|b| (ext, "vectors_extended.json", *b, *b)),
        );
    for (doc, file, block, name) in blocks {
        let b = doc.get(block).unwrap_or_else(|| {
            panic!(
                "conformance/{file} has no `{block}` block.\n  \
                 Refusing to pass: that file is byte-identical with seam-runtime's own vectors, so a \
                 missing block means this repo and the runtime have stopped agreeing on the vector \
                 set — not that a case was tidied away."
            )
        });
        let inputs = b
            .get("inputs")
            .unwrap_or_else(|| panic!("`{block}` must carry `inputs`"));
        assert_eq!(
            inputs["domain"], "seam.audit.record-digest.v4",
            "`{block}` is not a v4 case"
        );
        cases.push(json!({
            "name": name,
            "inputs": inputs,
            "digest_hex": b.get("digest_hex").unwrap_or_else(|| panic!("`{block}` must carry `digest_hex`")),
        }));
    }
    cases
}

/// `participants_digest` from the roster, transcribed from the spec independently of the vector's
/// own `participants_digest_hex`: SHA-256 over `frame("seam.audit.participants.v4") ‖ le32(count) ‖
/// frame(id)...` in stored order.
fn participants_digest(ids: &[Value]) -> Vec<u8> {
    let mut pre: Vec<u8> = Vec::new();
    let frame = |b: &mut Vec<u8>, x: &[u8]| {
        b.extend_from_slice(&(x.len() as u32).to_le_bytes());
        b.extend_from_slice(x);
    };
    frame(&mut pre, b"seam.audit.participants.v4");
    pre.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for id in ids {
        frame(&mut pre, id.as_str().expect("participant id").as_bytes());
    }
    Sha256::digest(&pre).to_vec()
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
    for key in [
        "decision_id",
        "tenant",
        "namespace",
        "outcome",
        "classification",
        "trust_basis_commitment",
        "auth_method",
    ] {
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
        ("participants_digest", "participants_digest_hex"),
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
        "event_id": format!("v4#{seq}"),
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
///
/// `digest_schema` is a PARAMETER because spec clause (e) makes it load-bearing — it must be >= the
/// highest `schema_version` in the attested prefix. Hard-coded to `2`, this helper signed a false
/// ceiling over every conformance case above the ceiling, and the whole suite asserted GREEN on streams the spec
/// says must be REFUSED.
fn attestation_line(
    seq: u64,
    prev: &[u8],
    len: u64,
    head: &[u8],
    sk: &SigningKey,
    digest_schema: u32,
) -> String {
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
    frame(&mut pre, &digest_schema.to_le_bytes());
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
            "digest_schema": digest_schema,
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
    // Derived from what the stream actually seals, as an honest producer derives it — never a
    // constant. Only 4 is accepted, so a fabricated `schema_version` cannot inflate the ceiling and
    // change which refusal fires.
    let ceiling = records
        .iter()
        .filter_map(|(p, _)| p["schema_version"].as_u64())
        .filter(|v| *v == 4)
        .max()
        .unwrap_or(4) as u32;
    lines.push(attestation_line(n, &head, n, &head, &sk, ceiling));

    let path = std::env::temp_dir().join(format!("v4-conf-{name}-{}.jsonl", std::process::id()));
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
    v4_cases(&vectors(), &extended())
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
fn every_v4_conformance_case_recomputes_through_the_wire() {
    let recs = records();
    assert_eq!(
        recs.len(),
        5,
        "two runtime blocks plus three extended cases"
    );
    let (code, out) = run_stream("all", &recs);
    assert_eq!(
        code, VERIFIED,
        "the committed v4 vectors must verify:\n{out}"
    );
    assert!(
        out.contains(&format!("records recomputed: {}", recs.len())),
        "every case must be COUNTED, not merely not-refused — a case silently skipped would look \
         identical to a case that passed:\n{out}"
    );
}

#[test]
fn every_participants_digest_follows_from_its_roster() {
    // Tag 15 is opaque on the wire, so the verifier never recomputes it — but the vector's value must
    // still be the spec formula over the roster, or every case above is hashing an unrelated blob.
    for c in v4_cases(&vectors(), &extended()) {
        let i = &c["inputs"];
        assert_eq!(
            participants_digest(i["participants"].as_array().expect("participants")),
            unhex(i["participants_digest_hex"].as_str().unwrap()),
            "{}: participants_digest_hex is not the v4 roster digest",
            c["name"]
        );
    }
}

#[test]
fn the_conformance_loop_is_falsifiable() {
    // Guard the guard. If the v4 arm were wired to skip, or to compare something to itself, the test
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
fn a_swapped_digest_mapping_cannot_cancel() {
    // The decoy that catches a wire-layer swap. Reading tag 12 into slot 11 and tag 11 into slot 12
    // produces a perfectly well-formed preimage, so it is invisible UNLESS the two values differ —
    // which is why the emitter keeps them distinct in every case, asserted here rather than assumed.
    // The same holds for the v4 opaque digest at tag 15 and for the two v4 strings at tags 16/17.
    for (a, b) in [
        ("context_digest", "participation_digest"),
        ("participation_digest", "participants_digest"),
        ("context_digest", "participants_digest"),
        ("trust_basis_commitment", "auth_method"),
    ] {
        let mut recs = records();
        for (p, _) in recs.iter_mut() {
            assert_ne!(
                p[a], p[b],
                "a vector case sets {a} == {b}, so a slot swap would cancel"
            );
            let (x, y) = (p[a].clone(), p[b].clone());
            p[a] = y;
            p[b] = x;
        }
        let (code, out) = run_stream("swapped", &recs);
        assert_eq!(code, FAILED, "swapping {a} and {b} must fail:\n{out}");
    }
}

#[test]
fn the_case_loader_fails_loudly_when_the_block_is_missing() {
    // The property this file's value rests on: it cannot quietly stop testing anything. Proven by
    // running the loader against a doctored document rather than by reading the code.
    // Every runtime block, one at a time — a guard that only covers the first would let the second
    // disappear silently, which is exactly the class of hole this file exists to close.
    for (block, _) in RUNTIME_V4_BLOCKS {
        let mut doctored = vectors();
        doctored.as_object_mut().unwrap().remove(block);
        let missing = std::panic::catch_unwind(|| v4_cases(&doctored, &extended()));
        assert!(
            missing.is_err(),
            "a vectors file with no `{block}` block was accepted — this test would then pass while \
             proving nothing"
        );
    }
    for block in EXTENDED_V4_BLOCKS {
        let mut doctored = extended();
        doctored.as_object_mut().unwrap().remove(block);
        let missing = std::panic::catch_unwind(|| v4_cases(&vectors(), &doctored));
        assert!(
            missing.is_err(),
            "an extended file with no `{block}` block was accepted"
        );
    }
}

// ── #835 step 4: the chain-head attestation framing is strict per tenant ─────────────────────────

/// The shared v1 chain-head vector (`conformance/vectors.json`), as the public verifier's
/// [`seam_verify::wire::Attestation`], under `tenant`.
fn v1_chain_head_vector(tenant: &str) -> seam_verify::wire::Attestation {
    let v = &vectors()["chain_head_attestation"];
    let i = &v["inputs"];
    seam_verify::wire::Attestation {
        attested_len: i["attested_len"].as_u64().unwrap(),
        attested_head: unhex(i["attested_head_hex"].as_str().unwrap()),
        attested_at: i["attested_at"].as_u64().unwrap(),
        issuer_aid: v["issuer_aid"].as_str().unwrap().to_owned(),
        digest_schema: i["digest_schema"].as_u64().unwrap() as u32,
        signature: unhex(v["signature_hex"].as_str().unwrap()),
        tenant: tenant.to_owned(),
    }
}

/// Mirrors seam-runtime's `conformance_drift::the_v1_chain_head_vector_is_refused_under_a_non_empty_tenant`
/// (#1303): the shared v1 vector verifies with its EMPTY tenant, and relabelled to a non-empty tenant it
/// is REFUSED — a tenant's attestation must be v2. The vector itself is untouched. Checked through
/// `verify_anchor`, the public entry point that runs the pin + signature check on one attestation.
#[test]
fn the_v1_chain_head_vector_is_refused_under_a_non_empty_tenant() {
    let pins = [ISSUER.to_owned()];
    let v1 = v1_chain_head_vector("");
    assert_eq!(v1.issuer_aid, ISSUER, "the vector's issuer is seed 07×32");
    seam_verify::verify_anchor(&v1, &pins).expect("the v1 vector verifies with its empty tenant");
    let err = seam_verify::verify_anchor(&v1_chain_head_vector("acme"), &pins)
        .expect_err("a v1 vector carrying a non-empty tenant must be refused (#835 step 4)");
    assert!(err.contains("does not verify"), "{err}");
}

/// The other half of the strict rule: a v2 signature over the EMPTY tenant (never minted; hand-rolled
/// with the vector's own seed, 07×32) is refused, because an empty tenant selects v1 only. The v2
/// framing here is transcribed from the spec, independently of `src/verify.rs`; a v2 signature over
/// `acme` from the same transcription verifies, so the refusal is the rule, not a framing typo.
#[test]
fn a_v2_chain_head_signature_over_the_empty_tenant_is_refused() {
    let sk = SigningKey::from_bytes(&[0x07; 32]);
    let pins = [ISSUER.to_owned()];
    let v2_sign = |a: &seam_verify::wire::Attestation, tenant: &str| -> Vec<u8> {
        let mut pre: Vec<u8> = Vec::new();
        let mut frame = |part: &[u8]| {
            pre.extend_from_slice(&(part.len() as u32).to_le_bytes());
            pre.extend_from_slice(part);
        };
        frame(b"seam.audit.chain-head-attestation.v2");
        frame(&a.attested_len.to_le_bytes());
        frame(&a.attested_head);
        frame(&a.attested_at.to_le_bytes());
        frame(&a.digest_schema.to_le_bytes());
        frame(a.issuer_aid.as_bytes());
        frame(tenant.as_bytes());
        sk.sign(&Sha256::digest(&pre)).to_bytes().to_vec()
    };

    let mut over_empty = v1_chain_head_vector("");
    over_empty.signature = v2_sign(&over_empty, "");
    assert!(
        seam_verify::verify_anchor(&over_empty, &pins).is_err(),
        "a v2 signature over the empty tenant must be refused (#835 step 4)"
    );

    let mut over_acme = v1_chain_head_vector("acme");
    over_acme.signature = v2_sign(&over_acme, "acme");
    seam_verify::verify_anchor(&over_acme, &pins)
        .expect("a v2 signature over its own tenant verifies");
}
