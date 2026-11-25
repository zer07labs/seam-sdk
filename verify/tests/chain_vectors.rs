//! `chain_bundle` v2 (W4 train 1, seam#264) against the runtime's chain vectors, copied byte for byte from seam-runtime
//! `fixtures/chain/` into `conformance/chain/`:
//!
//! * `chain_genesis_vectors.json` — every `genesis` row (preimage and digest), every `key_refusal` row, and
//!   the `genesis_mismatch` row (a claimed zero genesis is not `genesis(K)`); each refusal by its rule name;
//! * `chain_link_vectors.json` — every `chain` row decoded from BOTH projections (JSON and pb must give the
//!   same event), walked by the verifier from `genesis(K)` to `head_hex`, each `DECISION_SEALED` digest
//!   recomputed as record digest v4 (the `AUDIT_ENTRY` digests are opaque stand-ins, linked only, as the
//!   file's `rule` says); and every `chain_refusal` row refused at its `fails_at` entry, by its rule —
//!   S-3 (seam-runtime#2039 @ `64ec782c4`): the Merkle batch rows, the chain that crosses the history
//!   boundary, and the boundary refusals (a row's `batch_boundary` is the boundary a signed artifact states;
//!   the walk must switch to batches exactly there, [`boundary_agrees`]);
//! * `../conformance/flow_ref_unsealed_vectors.json` case f — the FlowRef version rule.
//!
//! Reader scope is decode, keying and genesis (W2). The V-checks beyond that are W5 (see `src/chain_key.rs`).

use seam_verify::chain_key::ChainKey;
use seam_verify::verify::{boundary_agrees, chain, hex, record_digest_v4, ChainReport};
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
        k["version"].as_u64().unwrap() as u32,
    )
}

#[test]
fn every_genesis_row_matches() {
    let v = load("chain_genesis_vectors.json");
    assert_eq!(v["bundle_version"], 2);
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
                assert_eq!(
                    key(&row["key"]),
                    Err(row["rule"].as_str().unwrap()),
                    "{name}"
                );
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
    assert_eq!((genesis, refusals, mismatch), (5, 18, 1));
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
        assert_eq!(c.links, events.len(), "{name}");
        // A stated boundary agrees with where the walk switched to batches.
        if let Some(b) = row.get("batch_boundary") {
            assert!(
                boundary_agrees(c.first_batch, b.as_u64(), c.links as u64),
                "{name}: boundary {b} vs walked {:?}",
                c.first_batch
            );
        }
        // The sole-chain mirror reports the same head at the top level.
        assert_eq!(hex(&r.head), row["head_hex"], "{name}");
    }
    assert_eq!(walked, 7);
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
        let rule = row["rule"].as_str().unwrap();
        // A stated boundary the walk disagrees with: the links verify, the claim does not. The first
        // entry on the wrong side of it is where the walk and the claim part.
        if let Some(claim) = row.get("batch_boundary") {
            let r: ChainReport = chain(&events).unwrap_or_else(|e| panic!("{name}: {e}"));
            let c = r.chains.values().next().unwrap();
            let len = c.links as u64;
            assert!(
                !boundary_agrees(c.first_batch, claim.as_u64(), len),
                "{name}"
            );
            let walked = c.first_batch.expect("the crossing chain has a batch");
            let parted = claim.as_u64().map_or(walked, |b| b.min(walked));
            assert_eq!(parted, at as u64, "{name}: {rule}");
            assert!(
                (rule == "batch_below_boundary") == claim.as_u64().is_none_or(|b| b > walked),
                "{name}: {rule}"
            );
            continue;
        }
        let err = chain(&events)
            .err()
            .unwrap_or_else(|| panic!("{name}: must refuse"));
        assert!(
            err.starts_with(&format!("seq {}:", events[at].seq)),
            "{name}: must fail at entry {at}: {err}"
        );
        match rule {
            "genesis_mismatch" => assert!(err.contains("NOT GENESIS"), "{name}: {err}"),
            "checksum_mismatch" => assert!(
                [
                    "FORGED LINK",
                    "BAD INCLUSION PROOF",
                    "BATCH MEMBER MISMATCH"
                ]
                .iter()
                .any(|m| err.contains(m)),
                "{name}: {err}"
            ),
            // Rule names are advisory: a moved index can also stop the path folding.
            "batch_member_mismatch" => assert!(
                [
                    "BATCH MEMBER MISMATCH",
                    "BATCH MEMBER MISSING",
                    "BAD INCLUSION PROOF"
                ]
                .iter()
                .any(|m| err.contains(m)),
                "{name}: {err}"
            ),
            "pre_s3_at_or_above_boundary" => {
                assert!(err.contains("PRE_S3_ABOVE_BOUNDARY"), "{name}: {err}")
            }
            _ => assert!(
                err.contains("INVALID CHAIN KEY") && err.contains(&format!("({rule})")),
                "{name}: {rule}: {err}"
            ),
        }
        // The prefix before the failing entry still walks (unless it stops inside a batch).
        let mid_batch = at > 0 && events[at - 1].leaf_index + 1 < events[at - 1].leaf_count;
        assert_eq!(chain(&events[..at]).is_ok(), !mid_batch, "{name}");
    }
    assert_eq!(refused, 12);
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
/// On live the version is not compared (a promoted live ref carries one, the live key never does).
#[test]
fn a_flow_ref_disagreeing_with_its_flow_chain_warns() {
    use seam_verify::verify::{dedup_with_warnings, FLOW_REF_CONFLICT};
    let mut lines = flow_live_lines();
    lines[0]["flow_ref"] =
        serde_json::json!({"flow_id": "flow-fraud", "rev": 3, "env": "live", "version": 5});
    lines[1]["flow_ref"] =
        serde_json::json!({"flow_id": "flow-fraud", "rev": 3, "env": "sandbox", "version": 1});
    let events: Vec<Event> = lines
        .iter()
        .map(|l| Event::parse(&l.to_string()).unwrap())
        .collect();
    let d = dedup_with_warnings(events).unwrap();
    assert_eq!(d.warnings.len(), 1, "{:?}", d.warnings);
    assert!(d.warnings[0].starts_with(FLOW_REF_CONFLICT));
    assert!(chain(&d.events).is_ok());
}

/// On sandbox the version is compared: a ref naming sibling version 1 on the version-2 chain warns.
#[test]
fn a_sandbox_flow_ref_naming_another_version_warns() {
    use seam_verify::verify::{dedup_with_warnings, FLOW_REF_CONFLICT};
    let v = load("chain_link_vectors.json");
    let row = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "flow_sandbox_v2")
        .unwrap();
    let ref_of = |version: u32| serde_json::json!({"flow_id": "flow-fraud", "rev": 3, "env": "sandbox", "version": version});
    let events: Vec<Event> = row["entries"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let mut l: Value = serde_json::from_str(e["json"].as_str().unwrap()).unwrap();
            l["flow_ref"] = ref_of(if i == 0 { 1 } else { 2 });
            Event::parse(&l.to_string()).unwrap()
        })
        .collect();
    let d = dedup_with_warnings(events).unwrap();
    assert_eq!(d.warnings.len(), 1, "{:?}", d.warnings);
    assert!(d.warnings[0].starts_with(FLOW_REF_CONFLICT));
    assert!(chain(&d.events).is_ok());
}

/// `flow_ref_unsealed_vectors.json` case f: `FlowRef.version ≥ 1` exactly when env = sandbox; live may
/// carry 0 or a promoted version. Each ref stamped on a real event and decoded through the JSON reader.
#[test]
fn the_flow_ref_version_rule_matches_case_f() {
    use seam_verify::wire::FLOW_REF_SANDBOX_VERSION_MISSING;
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../conformance/flow_ref_unsealed_vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let f = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == "flow_ref_version_rule")
        .unwrap();
    let base = flow_live_lines().remove(0);
    let mut n = 0;
    for r in f["refs"].as_array().unwrap() {
        n += 1;
        let mut l = base.clone();
        l["flow_ref"] = r["flow_ref"].clone();
        let got = Event::parse(&l.to_string());
        match r["refusal"].as_str() {
            None => assert_eq!(
                got.unwrap().flow_ref.unwrap().version as u64,
                r["flow_ref"]["version"].as_u64().unwrap()
            ),
            Some(rule) => {
                assert_eq!(rule, FLOW_REF_SANDBOX_VERSION_MISSING);
                assert!(got.err().unwrap().starts_with(rule));
            }
        }
    }
    assert_eq!(n, 4);
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
    assert_eq!(v["chains"][0]["version"], 0);
    assert_eq!(v["chains"][0]["links"], 3);
    let (code, v) = run(&[
        "--issuer",
        "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",
    ]);
    let _ = std::fs::remove_file(&path);
    assert_ne!(code, 0, "{v}");
    assert_eq!(v["verified"], false);
}

fn case_lines(name: &str) -> Vec<Value> {
    let v = load("chain_link_vectors.json");
    let row = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
        .clone();
    row["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| serde_json::from_str(e["json"].as_str().unwrap()).unwrap())
        .collect()
}

fn run_cli(lines: &[Value], tag: &str, extra: &[&str]) -> (i32, Value) {
    let path = std::env::temp_dir().join(format!("multi-{tag}-{}.jsonl", std::process::id()));
    let body: Vec<String> = lines.iter().map(Value::to_string).collect();
    std::fs::write(&path, body.join("\n") + "\n").unwrap();
    let mut a = vec!["chain", path.to_str().unwrap(), "--json"];
    a.extend_from_slice(extra);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_seam-verify"))
        .args(&a)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap(), v)
}

/// Flows W5 (D5, replan §9.7 CK3): one stream holding a flow's Live chain and its Sandbox version chains
/// (plus the tenant and cell chains, interleaved by seq) verifies every chain from its own genesis, and
/// `--chain` verifies the Live chain and a Sandbox version chain each ALONE. A tamper on one chain fails
/// that chain only: the other still verifies alone.
#[test]
fn a_live_and_a_sandbox_version_chain_of_one_flow_each_verify_alone() {
    let mut all: Vec<Value> = [
        "cell",
        "tenant",
        "flow_sandbox_v1",
        "flow_sandbox_v2",
        "flow_live",
    ]
    .iter()
    .flat_map(|n| case_lines(n))
    .collect();
    all.reverse(); // delivery is unordered; the verifier sorts
    let (code, v) = run_cli(&all, "all", &[]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["chains"].as_array().unwrap().len(), 5, "{v}");
    assert!(v.get("selected_chain").is_none());

    let live = case_lines("flow_live");
    let sb1 = case_lines("flow_sandbox_v1");
    for (sel, want, env, version) in [
        ("flow:acme:flow-fraud:live", &live, "live", 0),
        ("flow:acme:flow-fraud:sandbox:1", &sb1, "sandbox", 1),
    ] {
        let (code, v) = run_cli(&all, "sel", &["--chain", sel]);
        assert_eq!(code, 0, "{sel}: {v}");
        assert_eq!(v["selected_chain"], sel);
        assert_eq!(v["skipped_other_chains"], all.len() - want.len(), "{sel}");
        let chains = v["chains"].as_array().unwrap();
        assert_eq!(chains.len(), 1, "{sel}: {v}");
        assert_eq!(chains[0]["flow_id"], "flow-fraud");
        assert_eq!(chains[0]["env"], env);
        assert_eq!(chains[0]["version"], version);
        assert_eq!(chains[0]["links"], want.len());
        // The selection is the same verdict as a stream holding only that chain.
        let (code_alone, alone) = run_cli(want, "alone", &[]);
        assert_eq!(code_alone, 0, "{alone}");
        assert_eq!(alone["chains"][0]["head"], chains[0]["head"], "{sel}");
    }

    // Tamper the Live chain's middle link: the whole stream and the Live selection fail; the Sandbox
    // version chain still verifies alone.
    let mut tampered = all.clone();
    let mid = tampered
        .iter_mut()
        .find(|e| e["seq"] == 41)
        .expect("live seq 41");
    let cs = mid["checksum"].as_str().unwrap().to_owned();
    let flipped = if cs.starts_with('0') { "1" } else { "0" };
    mid["checksum"] = Value::String(format!("{flipped}{}", &cs[1..]));
    let (code, v) = run_cli(&tampered, "t-all", &[]);
    assert_ne!(code, 0, "{v}");
    let (code, v) = run_cli(
        &tampered,
        "t-live",
        &["--chain", "flow:acme:flow-fraud:live"],
    );
    assert_ne!(code, 0, "{v}");
    let (code, v) = run_cli(
        &tampered,
        "t-sb",
        &["--chain", "flow:acme:flow-fraud:sandbox:1"],
    );
    assert_eq!(code, 0, "{v}");

    // A selector naming no chain in the stream is an error, never a green over nothing.
    let (code, _) = run_cli(&all, "none", &["--chain", "flow:acme:flow-fraud:sandbox:9"]);
    assert_eq!(
        code, 1,
        "no event of the selected chain is an IO error (exit 1)"
    );
    // An entry relabelled onto the selected chain is kept and refused by the walk, not dropped.
    let mut relabel = live.clone();
    relabel.extend(case_lines("refuse_relabel_sandbox_into_live"));
    let (code, v) = run_cli(
        &relabel,
        "relabel",
        &["--chain", "flow:acme:flow-fraud:live"],
    );
    assert_eq!(code, 2, "{v}");

    // An entry whose tag-29 key the chain-key table refuses fails the run under ANY selection, as it
    // would without `--chain`: a selection never hides an invalid key (here a live key with version 3,
    // beside a sandbox:1 selection it does not name).
    let mut invalid = sb1.clone();
    invalid.extend(case_lines("refuse_live_entry_with_version"));
    let (code, v) = run_cli(&invalid, "invalid", &[]);
    assert_eq!(code, 2, "{v}");
    let (code, v) = run_cli(
        &invalid,
        "invalid-sel",
        &["--chain", "flow:acme:flow-fraud:sandbox:1"],
    );
    assert_eq!(code, 2, "{v}");

    // A selection spanning two delivery streams is refused (exit 1), never walked as one chain.
    let mut two = live.clone();
    two.extend(case_lines("refuse_wrong_stream_id"));
    let (code, v) = run_cli(&two, "two", &["--chain", "flow:acme:flow-fraud:live"]);
    assert_eq!(code, 1, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap_or("")
            .contains("delivery streams"),
        "{v}"
    );

    // Usage refusals (exit 1): given twice, paired with an anchor, a bad selector, a non-chain verb.
    let (code, _) = run_cli(
        &live,
        "twice",
        &["--chain", "flow:acme:flow-fraud:live", "--chain", "cell"],
    );
    assert_eq!(code, 1);
    let (code, _) = run_cli(
        &live,
        "anchor",
        &[
            "--chain",
            "flow:acme:flow-fraud:live",
            "--from-anchor",
            "/nonexistent",
        ],
    );
    assert_eq!(code, 1);
    let (code, _) = run_cli(&live, "bad", &["--chain", "flow:acme:flow-fraud:sandbox:0"]);
    assert_eq!(code, 1);
    for verb in ["erasure-cert", "bundle"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_seam-verify"))
            .args([verb, "/nonexistent", "--chain", "cell"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{verb}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("chain-only"),
            "{verb}"
        );
    }
}
