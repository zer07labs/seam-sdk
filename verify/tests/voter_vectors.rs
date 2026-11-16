//! `seam-voter-pop-v1` / `seam-vote-content-v1` against the runtime's own cross-language vector
//! (`conformance/voter_pop_v1_payload_vector.json`, byte-identical to seam-runtime#1713's
//! `crates/seam-api/tests/fixtures/voter_pop_v1_payload_vector.json`): for every case, the content digest,
//! the frozen entry bytes, the signed input and the deterministic Ed25519 signature, and that the
//! signature verifies under the voter AID.
//!
//! Excluded from the published package (see `Cargo.toml`), for the reason `tests/conformance.rs` is: it
//! reads the ONE copy of the vector rather than vendoring a second one.

use seam_verify::commitment::ExplanationEntry;
use seam_verify::voter::{
    entry_bytes, signed_input, vote_content_digest, ContentContext, Target, VotePolicy,
};
use serde_json::Value;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect()
}

#[test]
fn every_voter_pop_case_reproduces_byte_for_byte() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../conformance/voter_pop_v1_payload_vector.json");
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("{}: {e} — this test refuses to skip", p.display())),
    )
    .unwrap();
    assert_eq!(v["domain"], "seam-voter-pop-v1");
    assert_eq!(v["content_domain"], "seam-vote-content-v1");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 18, "the vector lost cases");
    let mut payloads = std::collections::HashSet::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let c = &case["content"];
        let context: Vec<ContentContext> = c["context"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| ContentContext {
                ctx_ref: x["ctx_ref"].as_str().unwrap().into(),
                content_hash: x["content_hash"].as_str().unwrap().into(),
            })
            .collect();
        let features: Vec<(&str, &str)> = c["features"]
            .as_array()
            .unwrap()
            .iter()
            .map(|kv| (kv[0].as_str().unwrap(), kv[1].as_str().unwrap()))
            .collect();
        let rules: Option<[u8; 32]> = c["policy"]
            .get("rules_digest_hex")
            .map(|h| unhex(h.as_str().unwrap()).try_into().unwrap());
        let policy = rules.as_ref().map(|r| VotePolicy {
            policy_version: c["policy"]["policy_version"].as_str().unwrap(),
            rules_digest: r,
        });
        let digest = vote_content_digest(
            c["mode"].as_str().unwrap(),
            c["proposal_id"].as_str().unwrap(),
            c["content"].as_str().unwrap(),
            &strs(&c["participants"]),
            &strs(&c["on_behalf_of"]),
            &context,
            &features,
            policy,
        )
        .unwrap();
        assert_eq!(
            hex(&digest),
            case["content_digest_hex"].as_str().unwrap(),
            "{name}: content digest"
        );
        let e = &case["entry"];
        let entry = ExplanationEntry {
            kind: e["kind"].as_str().unwrap().into(),
            participant: e["participant"].as_str().unwrap().into(),
            proposal_id: e["proposal_id"].as_str().unwrap().into(),
            value: e["value"].as_str().unwrap().into(),
            reason: e["reason"].as_str().unwrap().into(),
            confidence: e["confidence"].as_f64(),
            rationale_ref: e["rationale_ref"].as_str().map(str::to_owned),
            voter_verification: None,
        };
        let eb = entry_bytes(&entry);
        assert_eq!(
            hex(&eb),
            case["entry_bytes_hex"].as_str().unwrap(),
            "{name}: entry bytes"
        );
        let t = &case["target"];
        let target = Target {
            issuer: t["issuer"].as_str().unwrap(),
            audience: t["audience"].as_str().unwrap(),
            tenant: t["tenant"].as_str().unwrap(),
            namespace: t["namespace"].as_str().unwrap(),
            session_id: t["session_id"].as_str().unwrap(),
            opened_at_millis: t["opened_at_millis"].as_u64().unwrap(),
        };
        let aid = case["voter_aid"].as_str().unwrap();
        let msg = signed_input(
            &target,
            aid,
            &digest,
            case["issued_at_ms"].as_u64().unwrap(),
            case["expires_at_ms"].as_u64().unwrap(),
            &eb,
        );
        assert_eq!(
            hex(&msg),
            case["payload_hex"].as_str().unwrap(),
            "{name}: signed input"
        );
        if name != "features-order-b" {
            assert!(payloads.insert(msg.clone()), "{name}: a duplicate payload");
        }

        // The signature is deterministic (Ed25519), and verifies under the AID the seed derives.
        use ed25519_dalek::{Signer, SigningKey};
        let seed: [u8; 32] = unhex(case["seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let sk = SigningKey::from_bytes(&seed);
        assert_eq!(
            hex(&sk.sign(&msg).to_bytes()),
            case["signature_hex"].as_str().unwrap(),
            "{name}: signature"
        );
        let key = seam_verify::verify::aid_to_key(aid).unwrap();
        assert_eq!(key, sk.verifying_key().to_bytes(), "{name}: voter_aid");
    }
}
