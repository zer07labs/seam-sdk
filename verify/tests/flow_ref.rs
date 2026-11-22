//! Flow attribution (`seam.event.v1` tag 28 `flow_ref`) at the reader — client-surfaces S5 / A9.
//!
//! `flow_ref` is UNSEALED attribution and sits outside the event's canonical identity. Over the vendored
//! `goldens/attested_chain.jsonl` window (a real attested chain, so `--issuer` recomputes every record
//! digest):
//!
//! * (i)   chained copies differing ONLY in `flow_ref` → `FLOW_REF_CONFLICT` warning, exit 0, counted once;
//! * (ii)  identical stamps → no warning;
//! * (iii) a copy differing in `stream_id` stays the hard forgery error (regression);
//! * (iv)  stamping `flow_ref` on every event leaves every recomputed digest and the head unchanged.
//!
//! (v) `flow_ref.env` against the v6-sealed env is DEFERRED (S13/S16): the event stream does not carry the
//! record's env, so a reader of this stream has nothing to compare it with.

use std::process::Command;

use seam_verify::verify::{dedup_with_warnings, FLOW_REF_CONFLICT};
use seam_verify::wire::Event;
use serde_json::{json, Value};

const ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
const HEAD: &str = "f2bc8d903e098caef377406a1fe5198ebdd5454051ee2467ecbbb3946c67052d";

static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn golden() -> Vec<Value> {
    let p =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens/attested_chain.jsonl");
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn stamp(v: &Value, flow_id: &str, rev: u64, env: &str) -> Value {
    let mut v = v.clone();
    v["flow_ref"] = json!({"flow_id": flow_id, "rev": rev, "env": env});
    v
}

fn run(lines: &[Value], args: &[&str]) -> (i32, Value) {
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("flow-ref-{}-{seq}.jsonl", std::process::id()));
    let body: Vec<String> = lines.iter().map(Value::to_string).collect();
    std::fs::write(&path, body.join("\n") + "\n").unwrap();
    let mut a = vec!["chain", path.to_str().unwrap(), "--json"];
    a.extend_from_slice(args);
    let out = Command::new(env!("CARGO_BIN_EXE_seam-verify"))
        .args(&a)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    (out.status.code().unwrap(), v)
}

fn warnings(v: &Value) -> Vec<String> {
    v.get("warnings")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|w| w.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

#[test]
fn i_copies_differing_only_in_flow_ref_warn_and_count_once() {
    let g = golden();
    let mut lines = g.clone();
    // A redrive restamped after a flow revision: same event, a different attribution.
    lines.insert(2, stamp(&g[1], "flow-fraud", 7, "live"));
    let (code, v) = run(&lines, &["--issuer", ISSUER]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["verified"], true);
    assert_eq!(v["events"], 4, "events counts distinct events, after dedup");
    assert_eq!(v["links"], 4, "the copy is not a second link");
    assert_eq!(v["duplicates"], 1, "counted once");
    assert_eq!(v["head"], HEAD);
    let w = warnings(&v);
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(w[0].starts_with(FLOW_REF_CONFLICT), "{w:?}");

    // Two different stamps (neither absent) warn the same way.
    let mut lines = g.clone();
    lines[1] = stamp(&g[1], "flow-fraud", 6, "live");
    lines.insert(2, stamp(&g[1], "flow-fraud", 7, "live"));
    let (code, v) = run(&lines, &[]);
    assert_eq!((code, v["duplicates"].clone()), (0, json!(1)), "{v}");
    assert_eq!(warnings(&v).len(), 1);
}

#[test]
fn ii_identical_stamps_warn_nothing() {
    let g = golden();
    for stamped in [false, true] {
        let mut lines: Vec<Value> = if stamped {
            g.iter()
                .map(|l| stamp(l, "flow-fraud", 7, "live"))
                .collect()
        } else {
            g.clone()
        };
        lines.insert(2, lines[1].clone());
        let (code, v) = run(&lines, &[]);
        assert_eq!(code, 0, "{v}");
        assert_eq!(v["duplicates"], 1);
        assert!(v.get("warnings").is_none(), "stamped={stamped}: {v}");
    }
}

#[test]
fn iii_a_stream_id_difference_stays_the_hard_forgery_error() {
    let g = golden();
    let mut lines = g.clone();
    let mut copy = g[1].clone();
    copy["stream_id"] = json!("other");
    lines.insert(2, copy);
    let (code, v) = run(&lines, &[]);
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["verified"], false);

    // ...even when the flow_ref stamps also differ: the warning path never swallows an identity change.
    let mut lines = g.clone();
    let mut copy = stamp(&g[1], "flow-fraud", 7, "live");
    copy["stream_id"] = json!("other");
    lines.insert(2, copy);
    assert_eq!(run(&lines, &[]).0, 2);
}

#[test]
fn iv_flow_ref_moves_no_digest_and_no_head() {
    let lines: Vec<Value> = golden()
        .iter()
        .map(|l| stamp(l, "flow-fraud", 7, "sandbox"))
        .collect();
    let (code, v) = run(&lines, &["--issuer", ISSUER]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["authenticated"], true);
    assert_eq!(
        v["records_recomputed"], 3,
        "every record digest recomputed, unchanged"
    );
    assert_eq!(v["head"], HEAD);
    assert!(v.get("warnings").is_none());
}

#[test]
fn flow_ref_decodes_from_both_projections_and_json_requires_every_member() {
    let g = golden();
    let e = Event::parse(&stamp(&g[0], "flow-fraud", 7, "live").to_string()).unwrap();
    let f = e.flow_ref.as_ref().unwrap();
    assert_eq!(
        (f.flow_id.as_str(), f.rev, f.env.as_str()),
        ("flow-fraud", 7, "live")
    );
    // Unstamped identity: tag 28 is not part of it.
    assert_eq!(e.bytes, Event::parse(&g[0].to_string()).unwrap().bytes);
    assert!(e.chain.is_none(), "no tag 29 → legacy tenant rule");

    for missing in ["flow_id", "rev", "env"] {
        let mut v = stamp(&g[0], "flow-fraud", 7, "live");
        v["flow_ref"].as_object_mut().unwrap().remove(missing);
        assert!(
            Event::parse(&v.to_string()).is_err(),
            "missing {missing} must refuse"
        );
    }
    // Unknown members are tolerated; an absent key is an absent stamp.
    let mut v = stamp(&g[0], "flow-fraud", 7, "live");
    v["flow_ref"]["future"] = json!(1);
    assert!(Event::parse(&v.to_string()).unwrap().flow_ref.is_some());
    assert!(Event::parse(&g[0].to_string()).unwrap().flow_ref.is_none());

    // pb: a hand-framed tag 28 appended to the event's own canonical encoding.
    use base64::Engine;
    let mut raw = e.bytes.clone();
    let inner = [
        &[0x0a, 10][..],
        b"flow-fraud",
        &[0x10, 7],
        &[0x1a, 4],
        b"live",
    ]
    .concat();
    raw.extend_from_slice(&[0xe2, 0x01, inner.len() as u8]);
    raw.extend_from_slice(&inner);
    let p = Event::parse(&base64::engine::general_purpose::STANDARD.encode(&raw)).unwrap();
    assert_eq!(p.flow_ref, e.flow_ref);
    assert_eq!(p.bytes, e.bytes);
}

#[test]
fn an_empty_tag_29_is_a_cell_chain_ref_not_absent() {
    use base64::Engine;
    let g = golden();
    let mut raw = Event::parse(&g[0].to_string()).unwrap().bytes;
    raw.extend_from_slice(&[0xea, 0x01, 0x00]);
    let p = Event::parse(&base64::engine::general_purpose::STANDARD.encode(&raw)).unwrap();
    let c = p.chain.expect("present-but-empty is present");
    assert_eq!(
        (c.kind, c.seq, c.flow_id.as_str(), c.env.as_str()),
        (0, 0, "", "")
    );
    // JSON: every member is required, `kind` included, so a missing one cannot alias the cell chain.
    let mut v = g[0].clone();
    v["chain"] = json!({"flow_id": "", "env": "", "seq": 0});
    assert!(Event::parse(&v.to_string()).is_err());
}

#[test]
fn dedup_reports_the_conflict_as_data() {
    let g = golden();
    let events = vec![
        Event::parse(&g[0].to_string()).unwrap(),
        Event::parse(&stamp(&g[0], "f", 1, "live").to_string()).unwrap(),
    ];
    let d = dedup_with_warnings(events).unwrap();
    assert_eq!((d.events.len(), d.duplicates, d.warnings.len()), (1, 1, 1));
}
