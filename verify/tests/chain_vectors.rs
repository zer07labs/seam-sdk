//! `chain_bundle` v1 (RTC C4) against the runtime's chain vectors, copied byte for byte from seam-runtime
//! `fixtures/chain/` into `conformance/chain/`:
//!
//! * `chain_genesis_vectors.json` — every `genesis` row (preimage and digest), every `key_refusal` row, and
//!   the `genesis_mismatch` row (a claimed zero genesis is not `genesis(K)`);
//! * `chain_link_vectors.json` — every `chain` row decoded from BOTH projections (JSON and pb must give the
//!   same event), walked by the verifier from `genesis(K)` to `head_hex`, each `DECISION_SEALED` digest
//!   recomputed as record digest v4 (the `AUDIT_ENTRY` digests are opaque stand-ins, linked only, as the
//!   file's `rule` says); and every `chain_refusal` row refused at its `fails_at` entry.
//!
//! Reader scope is decode, keying and genesis (W2). The V-checks beyond that are W5 (see `src/chain_key.rs`).

use seam_verify::chain_key::ChainKey;
use seam_verify::verify::{chain, hex, record_digest_v4};
use seam_verify::wire::Event;
use serde_json::Value;

fn load(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../conformance/chain")
        .join(name);
    serde_json::from_str(
        &std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("{}: {e} — this test refuses to skip", p.display())),
    )
    .unwrap()
}

fn key(k: &Value) -> Result<ChainKey, &'static str> {
    ChainKey::new(
        k["kind"].as_u64().unwrap() as u32,
        k["stream_id"].as_str().unwrap(),
        k["tenant"].as_str().unwrap(),
        k["flow_id"].as_str().unwrap(),
        k["env"].as_str().unwrap(),
    )
}

#[test]
fn every_genesis_row_matches() {
    let v = load("chain_genesis_vectors.json");
    assert_eq!(v["bundle_version"], 1);
    let cases = v["cases"].as_array().unwrap();
    let (mut genesis, mut refusals, mut mismatch) = (0, 0, 0);
    for row in cases {
        let name = row["name"].as_str().unwrap();
        match row["type"].as_str().unwrap() {
            "genesis" => {
                genesis += 1;
                let k = key(&row["key"]).unwrap_or_else(|r| panic!("{name}: {r}"));
                assert_eq!(hex(&k.genesis_preimage()), row["preimage_hex"], "{name}");
                assert_eq!(hex(&k.genesis()), row["genesis_hex"], "{name}");
            }
            "key_refusal" => {
                refusals += 1;
                assert!(key(&row["key"]).is_err(), "{name}: must refuse");
            }
            "genesis_mismatch" => {
                mismatch += 1;
                let k = key(&row["key"]).unwrap_or_else(|r| panic!("{name}: {r}"));
                assert_ne!(
                    hex(&k.genesis()),
                    row["claimed_genesis_hex"].as_str().unwrap(),
                    "{name}: the claimed genesis must not be accepted"
                );
            }
            other => panic!("{name}: unknown type {other}"),
        }
    }
    assert_eq!((genesis, mismatch), (4, 1));
    assert!(refusals > 0);
}

/// Decode one entry from both projections and require the same canonical event.
fn entry(e: &Value, name: &str) -> Event {
    let j = Event::parse(e["json"].as_str().unwrap()).unwrap_or_else(|r| panic!("{name}: {r}"));
    let p =
        Event::parse(e["pb_b64"].as_str().unwrap()).unwrap_or_else(|r| panic!("{name}: pb: {r}"));
    assert_eq!(
        j.bytes, p.bytes,
        "{name}: JSON and pb decode to the same event"
    );
    assert_eq!(j.chain, p.chain, "{name}: tag 29 in both projections");
    assert!(
        j.chain.is_some(),
        "{name}: every vector entry carries tag 29"
    );
    assert_eq!(j.kind, e["kind"].as_str().unwrap(), "{name}");
    j
}

#[test]
fn every_chain_row_walks_from_genesis_to_its_head() {
    let v = load("chain_link_vectors.json");
    let mut walked = 0;
    for row in v["cases"].as_array().unwrap() {
        if row["type"] != "chain" {
            continue;
        }
        walked += 1;
        let name = row["name"].as_str().unwrap();
        let events: Vec<Event> = row["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| entry(e, name))
            .collect();
        for e in &events {
            if let Some(d) = &e.decision {
                assert_eq!(
                    record_digest_v4(d).unwrap().to_vec(),
                    *e.digest.as_ref().unwrap(),
                    "{name}: seq {} digest recomputes as record digest v4",
                    e.seq
                );
            }
        }
        let r = chain(&events).unwrap_or_else(|err| panic!("{name}: {err}"));
        let k = key(&row["key"]).unwrap();
        assert!(r.tenants.is_empty(), "{name}: no legacy tenant chain");
        assert_eq!(r.chains.len(), 1, "{name}");
        let c = &r.chains[&k];
        assert_eq!(hex(&k.genesis()), row["genesis_hex"], "{name}");
        assert_eq!(hex(&c.heads[0]), row["genesis_hex"], "{name}");
        assert_eq!(hex(&c.head), row["head_hex"], "{name}");
        assert_eq!(c.links, 3, "{name}");
        // The sole-chain mirror reports the same head at the top level.
        assert_eq!(hex(&r.head), row["head_hex"], "{name}");
    }
    assert_eq!(walked, 4);
}

#[test]
fn every_chain_refusal_fails_at_its_entry() {
    let v = load("chain_link_vectors.json");
    let mut refused = 0;
    for row in v["cases"].as_array().unwrap() {
        if row["type"] != "chain_refusal" {
            continue;
        }
        refused += 1;
        let name = row["name"].as_str().unwrap();
        let events: Vec<Event> = row["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| entry(e, name))
            .collect();
        let at = row["fails_at"].as_u64().unwrap() as usize;
        let err = chain(&events)
            .err()
            .unwrap_or_else(|| panic!("{name}: must refuse"));
        assert!(
            err.starts_with(&format!("seq {}:", events[at].seq)),
            "{name}: must fail at entry {at}: {err}"
        );
        assert!(
            err.contains("NOT GENESIS"),
            "{name}: genesis_mismatch: {err}"
        );
        // The prefix before the failing entry still walks.
        assert!(chain(&events[..at]).is_ok(), "{name}");
    }
    assert_eq!(refused, 2);
}

fn flow_live_lines() -> Vec<Value> {
    let v = load("chain_link_vectors.json");
    let row = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "flow_live")
        .unwrap()
        .clone();
    row["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| serde_json::from_str(e["json"].as_str().unwrap()).unwrap())
        .collect()
}

/// The spec's consistency rule: a `flow_ref` naming another flow/env than the event's flow-kind chain is a
/// `FLOW_REF_CONFLICT` warning (flow_ref is unsealed); a matching one is silent. The chain still verifies.
#[test]
fn a_flow_ref_disagreeing_with_its_flow_chain_warns() {
    use seam_verify::verify::{dedup_with_warnings, FLOW_REF_CONFLICT};
    let mut lines = flow_live_lines();
    lines[0]["flow_ref"] = serde_json::json!({"flow_id": "flow-fraud", "rev": 3, "env": "live"});
    lines[1]["flow_ref"] = serde_json::json!({"flow_id": "flow-fraud", "rev": 3, "env": "sandbox"});
    let events: Vec<Event> = lines
        .iter()
        .map(|l| Event::parse(&l.to_string()).unwrap())
        .collect();
    let d = dedup_with_warnings(events).unwrap();
    assert_eq!(d.warnings.len(), 1, "{:?}", d.warnings);
    assert!(d.warnings[0].starts_with(FLOW_REF_CONFLICT));
    assert!(chain(&d.events).is_ok());
}

/// Authenticity over a chain-keyed chain needs attestation v3 (chain_bundle v2, W5): `--issuer` fails
/// closed instead of vouching for a chain it cannot authenticate. Without `--issuer` the integrity
/// walk verifies.
#[test]
fn issuer_over_a_chain_keyed_window_fails_closed() {
    let lines = flow_live_lines();
    let path = std::env::temp_dir().join(format!("chain-keyed-{}.jsonl", std::process::id()));
    let body: Vec<String> = lines.iter().map(Value::to_string).collect();
    std::fs::write(&path, body.join("\n") + "\n").unwrap();
    let run = |extra: &[&str]| {
        let mut a = vec!["chain", path.to_str().unwrap(), "--json"];
        a.extend_from_slice(extra);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_seam-verify"))
            .args(&a)
            .output()
            .unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        (out.status.code().unwrap(), v)
    };
    let (code, v) = run(&[]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["chains"][0]["kind"], 2);
    assert_eq!(v["chains"][0]["links"], 3);
    let (code, v) = run(&[
        "--issuer",
        "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_ne!(code, 0, "{v}");
    assert_eq!(v["verified"], false);
}
