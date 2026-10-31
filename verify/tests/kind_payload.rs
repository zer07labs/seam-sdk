//! **Payload binds to kind** (spec §Ordering & integrity, code-health A4): *"each payload field belongs to
//! exactly one kind, so an event carries only its own kind's payload, and a known kind carries it. A known
//! advisory kind (or the chain anchor) that carries `digest`/`checksum` is refused, not linked."*
//!
//! Two layers:
//!
//! 1. **The eleven-row table, at the library.** For every payload slot: the slot grafted onto another kind
//!    is refused, and its own kind without it is refused — each on BOTH transports. The protobuf rows
//!    hand-encode the payload field, so the presence decode of the five slots this crate does not model
//!    (tags 14, 15, 17, 21, 26) is itself under test rather than assumed.
//! 2. **The shipped binary.** The refusals a third party actually sees, in every mode: no flags,
//!    `--strict`, `--issuer` — plus the cross-transport dedup of an event carrying an unmodelled payload.
//!
//! Every stream is built from the spec alone, like the rest of `tests/`.

use std::process::Command;

use base64::Engine;
use prost::Message;
use sha2::{Digest, Sha256};

use seam_verify::wire::{Event, SeamEventPb};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;

/// The golden issuer (ed25519 seed 07×32), as in `tests/authenticity.rs`.
const ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";

fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn link(prev: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(digest);
    h.finalize().to_vec()
}

// ── the table ─────────────────────────────────────────────────────────────────────────────────────

/// One payload slot: its owner kind, its JSON key, its envelope tag, the runtime's field label, and a
/// JSON value that parses as that payload. The JSON values carry content (where the shape allows) so a
/// presence-only decode is shown to ignore it.
struct Slot {
    kind: &'static str,
    key: &'static str,
    tag: u32,
    label: &'static str,
    json: &'static str,
}

const SLOTS: [Slot; 11] = [
    Slot {
        kind: "DECISION_SEALED",
        key: "payload",
        tag: 13,
        label: "payload (tag 13)",
        json: r#"{"decision_id":"d"}"#,
    },
    Slot {
        kind: "LEARNING_DECISION",
        key: "learning_decision",
        tag: 14,
        label: "learning_decision (tag 14)",
        json: r#"{"arm":"a","posterior":0.5}"#,
    },
    Slot {
        kind: "LEARNING_OUTCOME",
        key: "learning_outcome",
        tag: 15,
        label: "learning_outcome (tag 15)",
        json: r#"{"reward":1}"#,
    },
    Slot {
        kind: "AUDIT_ENTRY",
        key: "audit_entry",
        tag: 16,
        label: "audit_entry (tag 16)",
        json: r#"{"action":"party_registered","subject":"s","reason":"r"}"#,
    },
    Slot {
        kind: "BUDGET_BREACH",
        key: "budget_breach",
        tag: 17,
        label: "budget_breach (tag 17)",
        json: r#"{"limit":10,"spent":11}"#,
    },
    Slot {
        kind: "ERASURE_CERTIFICATE",
        key: "erasure_certificate",
        tag: 18,
        label: "erasure_certificate (tag 18)",
        json: r#"{"subject":"s","erased":[],"held":[],"erased_at":0,"chain_head":"","issuer_aid":"","signature":""}"#,
    },
    Slot {
        kind: "SESSION_LIFECYCLE",
        key: "session_lifecycle",
        tag: 21,
        label: "session_lifecycle (tag 21)",
        json: r#"{"phase":"opened"}"#,
    },
    Slot {
        kind: "CHAIN_HEAD_ATTESTATION",
        key: "chain_head_attestation",
        tag: 22,
        label: "chain_head_attestation (tag 22)",
        json: r#"{"attested_len":0,"attested_head":"","attested_at":0,"issuer_aid":"","digest_schema":0,"signature":""}"#,
    },
    Slot {
        kind: "AUTHORIZE_EVALUATED",
        key: "authorize_evaluated",
        tag: 23,
        label: "authorize_evaluated (tag 23)",
        json: r#"{"authorize_id":"a"}"#,
    },
    Slot {
        kind: "POLICY_DENIED",
        key: "policy_denied",
        tag: 24,
        label: "policy_denied (tag 24)",
        json: r#"{"reason":"r"}"#,
    },
    Slot {
        kind: "EVENT_REDRIVEN",
        key: "event_redriven",
        tag: 26,
        label: "event_redriven (tag 26)",
        json: r#"{"event":"AAEC"}"#,
    },
];

/// One unchained event of `kind` carrying the payloads of `slots`, as the JSON projection.
fn json_event(kind: &str, slots: &[&Slot]) -> String {
    let mut s = format!(
        r#"{{"schema_version":"seam-event.v1","event_id":"e1","seq":1,"tenant":"acme","kind":"{kind}","prev_checksum":"""#
    );
    for slot in slots {
        s.push_str(&format!(r#","{}":{}"#, slot.key, slot.json));
    }
    s.push('}');
    s
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// The same event as base64 protobuf. The envelope is encoded through the crate's own message; each
/// payload field is then **hand-appended** as a length-delimited field (wire type 2) with a few bytes of
/// opaque content, so the decode under test reads presence off raw wire bytes. The content is a valid
/// embedded field (`tag 1, string "x"`), so the modelled messages decode it too.
fn pb_event(kind: &str, slots: &[&Slot]) -> String {
    let mut raw = SeamEventPb {
        schema_version: "seam-event.v1".into(),
        event_id: "e1".into(),
        seq: 1,
        tenant: "acme".into(),
        kind: kind.into(),
        ..Default::default()
    }
    .encode_to_vec();
    for slot in slots {
        varint(u64::from(slot.tag << 3 | 2), &mut raw);
        // Tag 1 is a string in every modelled payload but the attestation (`attested_len`, a varint),
        // whose body is therefore left empty: an empty sub-message is still a present one.
        let body: &[u8] = if slot.tag == 22 {
            &[]
        } else {
            &[0x0a, 0x01, b'x']
        };
        varint(body.len() as u64, &mut raw);
        raw.extend_from_slice(body);
    }
    b64e(&raw)
}

/// Both transports of one event.
fn both(kind: &str, slots: &[&Slot]) -> [(&'static str, String); 2] {
    [
        ("json", json_event(kind, slots)),
        ("protobuf", pb_event(kind, slots)),
    ]
}

fn chain_err(line: &str) -> String {
    let e = Event::parse(line).unwrap_or_else(|err| panic!("must parse: {err}\n{line}"));
    match seam_verify::chain(&[e]) {
        Err(msg) => msg,
        Ok(_) => panic!("must be refused by the kind/payload binding:\n{line}"),
    }
}

/// A different known kind to host a foreign payload on — one whose own payload sits elsewhere in the
/// table, so the host is otherwise well-formed.
fn host_for(slot: &Slot) -> &'static Slot {
    SLOTS
        .iter()
        .find(|s| s.kind != slot.kind && !matches!(s.tag, 18 | 22))
        .expect("eleven slots")
}

/// Rule 1, all eleven rows: a payload grafted onto another (well-formed) kind is refused, naming the
/// slot and its owner — on both transports.
#[test]
fn every_payload_grafted_onto_another_kind_is_refused() {
    for slot in &SLOTS {
        let host = host_for(slot);
        for (transport, line) in both(host.kind, &[host, slot]) {
            let err = chain_err(&line);
            assert!(
                err.contains("KIND/PAYLOAD MISMATCH"),
                "{} on {} ({transport}):\n{err}",
                slot.label,
                host.kind
            );
            assert!(
                err.contains(&format!(
                    "a {} event carries {}, which only a {} carries",
                    host.kind, slot.label, slot.kind
                )),
                "{} on {} ({transport}):\n{err}",
                slot.label,
                host.kind
            );
        }
    }
}

/// Rule 2, all eleven rows: a known kind without its own payload is refused — on both transports.
#[test]
fn every_known_kind_without_its_own_payload_is_refused() {
    for slot in &SLOTS {
        for (transport, line) in both(slot.kind, &[]) {
            let err = chain_err(&line);
            assert!(
                err.contains(&format!(
                    "KIND/PAYLOAD MISMATCH — a {} event carries no {} payload.",
                    slot.kind, slot.kind
                )),
                "{} ({transport}):\n{err}",
                slot.kind
            );
        }
    }
}

/// The well-formed control for both tables above: each kind carrying exactly its own payload passes the
/// binding (unchained, so the walk skips it as advisory or unverifiable — never refuses it).
#[test]
fn every_known_kind_carrying_its_own_payload_passes_the_binding() {
    for slot in &SLOTS {
        for (transport, line) in both(slot.kind, &[slot]) {
            let e = Event::parse(&line).unwrap_or_else(|err| panic!("{err}\n{line}"));
            assert!(
                seam_verify::check_kind_payload(&e).is_ok(),
                "{} ({transport}) carrying only its own payload must pass",
                slot.kind
            );
        }
    }
}

/// An unknown, future kind may carry none of the known payloads — but carrying nothing is fine, and so is
/// a payload slot this build has never heard of.
#[test]
fn an_unknown_kind_may_carry_no_known_payload() {
    for (transport, line) in both("RETENTION_HOLD", &[]) {
        let e = Event::parse(&line).unwrap();
        assert!(
            seam_verify::check_kind_payload(&e).is_ok(),
            "an unknown kind with no known payload is not a mismatch ({transport})"
        );
    }
    let audit = &SLOTS[3];
    for (transport, line) in both("RETENTION_HOLD", &[audit]) {
        let err = chain_err(&line);
        assert!(
            err.contains(
                "a RETENTION_HOLD event carries audit_entry (tag 16), which only a AUDIT_ENTRY"
            ),
            "{transport}:\n{err}"
        );
    }
}

/// `"payload": null` is absent, as serde's `Option` reads it on the runtime side — so a seal whose
/// payload was nulled is refused like a stripped one, not treated as carrying an empty payload.
#[test]
fn a_null_payload_reads_as_absent() {
    let line = r#"{"schema_version":"seam-event.v1","event_id":"e1","seq":1,"tenant":"acme","kind":"DECISION_SEALED","prev_checksum":"","payload":null}"#;
    let err = chain_err(line);
    assert!(err.contains("carries no DECISION_SEALED payload"), "{err}");
    // ...and likewise for an unmodelled slot: null is not presence.
    let line = r#"{"schema_version":"seam-event.v1","event_id":"e1","seq":1,"tenant":"acme","kind":"SESSION_LIFECYCLE","prev_checksum":"","session_lifecycle":null}"#;
    let err = chain_err(line);
    assert!(
        err.contains("carries no SESSION_LIFECYCLE payload"),
        "{err}"
    );
}

// ── the shipped binary ────────────────────────────────────────────────────────────────────────────

fn run(name: &str, body: &str, args: &[&str]) -> (i32, String) {
    let path =
        std::env::temp_dir().join(format!("kindpayload-{name}-{}.jsonl", std::process::id()));
    std::fs::write(&path, body).unwrap();
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

/// The runtime-produced attested chain (`tests/goldens/attested_chain.jsonl`): two real v4 seals and an
/// issuer-signed attestation, so every mutation below is applied to a stream that passes in every mode.
fn golden() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/goldens/attested_chain.jsonl"
    ))
    .expect("golden must exist")
}

/// `golden()` with `f` applied to its first `DECISION_SEALED` line. The chain triple is untouched.
fn mutate_first_seal(f: impl Fn(&mut serde_json::Value)) -> String {
    let mut done = false;
    golden()
        .lines()
        .map(|l| {
            let mut e: serde_json::Value = serde_json::from_str(l).unwrap();
            if !done && e["kind"] == "DECISION_SEALED" {
                f(&mut e);
                done = true;
            }
            serde_json::to_string(&e).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

const MODES: [&[&str]; 3] = [&[], &["--strict"], &["--issuer", ISSUER]];

#[test]
fn the_golden_stream_verifies_in_every_mode() {
    for mode in MODES {
        let (code, out) = run("golden", &golden(), mode);
        assert_eq!(code, VERIFIED, "{mode:?}:\n{out}");
    }
}

/// Acceptance 2, and the hole the spec names: a sealed decision relabelled as an advisory kind would
/// otherwise still count as a link — and under `--issuer` as a recomputed seal. Refused in EVERY mode, as
/// the runtime refuses it (`a_sealed_decision_dressed_as_an_advisory_kind_fails`).
#[test]
fn a_seal_relabelled_as_learning_decision_is_refused_in_every_mode() {
    let body = mutate_first_seal(|e| e["kind"] = "LEARNING_DECISION".into());
    for mode in MODES {
        let (code, out) = run("relabel", &body, mode);
        assert_eq!(code, FAILED, "{mode:?}:\n{out}");
        assert!(out.contains("KIND/PAYLOAD MISMATCH"), "{mode:?}:\n{out}");
        assert!(out.contains("carries payload (tag 13)"), "{mode:?}:\n{out}");
    }
}

/// Acceptance 3: an `audit_entry` grafted onto a seal.
#[test]
fn an_audit_entry_grafted_onto_a_seal_is_refused() {
    let body = mutate_first_seal(|e| {
        e["audit_entry"] =
            serde_json::json!({"action": "party_registered", "subject": "s", "reason": "r"})
    });
    for mode in MODES {
        let (code, out) = run("graft", &body, mode);
        assert_eq!(code, FAILED, "{mode:?}:\n{out}");
        assert!(out.contains("which only a AUDIT_ENTRY"), "{mode:?}:\n{out}");
    }
}

/// Acceptance 4: a seal with its payload stripped. Rule 2 is the only thing that catches this one in
/// integrity mode — the link still hashes.
#[test]
fn a_seal_with_its_payload_stripped_is_refused() {
    let body = mutate_first_seal(|e| {
        e.as_object_mut().unwrap().remove("payload");
    });
    for mode in MODES {
        let (code, out) = run("strip", &body, mode);
        assert_eq!(code, FAILED, "{mode:?}:\n{out}");
        assert!(
            out.contains("carries no DECISION_SEALED payload"),
            "{mode:?}:\n{out}"
        );
    }
}

/// Edge case: stripped of its payload AND its chain fields, a seal reports the binding — never the
/// downstream `unverifiable` count — because the binding runs first, as in the runtime.
#[test]
fn a_seal_stripped_of_payload_and_chain_fields_reports_the_binding_first() {
    let body = mutate_first_seal(|e| {
        let o = e.as_object_mut().unwrap();
        o.remove("payload");
        o.remove("digest");
        o.remove("checksum");
    });
    for mode in MODES {
        let (code, out) = run("strip-all", &body, mode);
        assert_eq!(code, FAILED, "{mode:?}:\n{out}");
        assert!(
            out.contains("carries no DECISION_SEALED payload"),
            "{mode:?}:\n{out}"
        );
        assert!(!out.contains("UNVERIFIABLE"), "{mode:?}:\n{out}");
    }
}

/// A two-link genesis chain: a seal, then a CHAINED `chain_anchor` audit entry. Every link hashes.
fn chained_anchor_stream() -> String {
    let genesis = vec![0u8; 32];
    let d0 = Sha256::digest(b"record-0").to_vec();
    let h0 = link(&genesis, &d0);
    let d1 = Sha256::digest(b"anchor").to_vec();
    let h1 = link(&h0, &d1);
    let seal = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": "d0#0", "seq": 0, "kind": "DECISION_SEALED",
        "prev_checksum": b64e(&genesis), "digest": b64e(&d0), "checksum": b64e(&h0),
        "payload": {"decision_id": "d0"},
    });
    let anchor = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": "chain-anchor:1#1", "seq": 1,
        "kind": "AUDIT_ENTRY", "prev_checksum": b64e(&h0), "digest": b64e(&d1),
        "checksum": b64e(&h1),
        "audit_entry": {"action": "chain_anchor", "subject": "audit-chain", "reason": "len=1"},
    });
    format!("{seal}\n{anchor}")
}

/// Acceptance 5: the chain anchor is off-chain by design (spec §AUDIT_ENTRY); one carrying chain fields
/// is refused, where it used to link.
#[test]
fn a_chained_chain_anchor_is_refused() {
    let (code, out) = run("anchor", &chained_anchor_stream(), &[]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("ADVISORY EVENT WITH CHAIN FIELDS"), "{out}");

    // Either chain field alone is enough.
    let half: String = chained_anchor_stream()
        .lines()
        .map(|l| {
            let mut e: serde_json::Value = serde_json::from_str(l).unwrap();
            if e["kind"] == "AUDIT_ENTRY" {
                e.as_object_mut().unwrap().remove("checksum");
            }
            serde_json::to_string(&e).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n");
    let (code, out) = run("anchor-half", &half, &[]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("ADVISORY EVENT WITH CHAIN FIELDS"), "{out}");
}

/// A known advisory KIND with chain fields: same refusal as the anchor.
#[test]
fn a_chained_advisory_kind_is_refused() {
    let genesis = vec![0u8; 32];
    let d = Sha256::digest(b"x").to_vec();
    let line = serde_json::json!({
        "schema_version": "seam-event.v1", "event_id": "ld#0", "seq": 0, "kind": "LEARNING_DECISION",
        "prev_checksum": b64e(&genesis), "digest": b64e(&d), "checksum": b64e(&link(&genesis, &d)),
        "learning_decision": {"arm": "a"},
    })
    .to_string();
    let (code, out) = run("advisory-chained", &line, &[]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("ADVISORY EVENT WITH CHAIN FIELDS"), "{out}");
}

/// Acceptance 8: presence is identity, on both transports. One `SESSION_LIFECYCLE` event — its tag-21
/// payload unmodelled here — delivered once as JSON and once as base64 protobuf collapses to ONE event.
/// The two carry different payload CONTENT on the wire (a JSON object vs. raw protobuf bytes); the
/// identity re-encodes each present slot as an empty sub-message, so neither content nor transport splits
/// it.
#[test]
fn an_unmodelled_payload_event_dedups_across_transports() {
    let slot = &SLOTS[6];
    assert_eq!(slot.tag, 21);
    let json = json_event(slot.kind, &[slot]);
    let pb = pb_event(slot.kind, &[slot]);
    let (from_json, from_pb) = (Event::parse(&json).unwrap(), Event::parse(&pb).unwrap());
    assert!(from_json.presence.session_lifecycle && from_pb.presence.session_lifecycle);
    assert_eq!(
        from_json.bytes, from_pb.bytes,
        "one event, two transports — the canonical identity must collapse them"
    );

    // ...and the same event WITHOUT the slot is a different identity: presence is part of it.
    let bare = Event::parse(&json_event(slot.kind, &[])).unwrap();
    assert_ne!(
        bare.bytes, from_json.bytes,
        "a copy without the payload must not dedup into the copy with it"
    );

    // Through the binary: in one stream beside a genuine chain, it is one advisory event and one
    // duplicate — no impostor refusal, no second advisory row.
    let body = format!("{}\n{json}\n{pb}", golden());
    let (code, out) = run("xtransport", &body, &[]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(out.contains("advisory (skipped): 1"), "{out}");
    assert!(out.contains("duplicates        : 1"), "{out}");
}

/// An unmodelled slot must hold a payload object. A scalar or an array there is malformed, as the
/// runtime's typed decoder reads it; it is never "present". `null` stays absent.
#[test]
fn an_unmodelled_slot_holding_a_non_object_is_malformed() {
    let slot = &SLOTS[6];
    let base = json_event(slot.kind, &[]);
    for bad in ["1", "\"x\"", "true", "[]"] {
        let line = format!("{},\"{}\":{bad}}}", &base[..base.len() - 1], slot.key);
        assert!(Event::parse(&line).is_err(), "{bad} must not parse: {line}");
    }
    let null = format!("{},\"{}\":null}}", &base[..base.len() - 1], slot.key);
    let ev = Event::parse(&null).expect("null is absent, not malformed");
    assert!(!ev.presence.session_lifecycle);
}

/// The refusal reaches `--json` as a structured failure with exit 2, not a green document.
#[test]
fn the_refusal_reaches_json_output() {
    let body = mutate_first_seal(|e| e["kind"] = "LEARNING_DECISION".into());
    let (code, out) = run("relabel-json", &body, &["--json"]);
    assert_eq!(code, FAILED, "{out}");
    let doc: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).expect("JSON");
    assert_eq!(doc["verified"], false, "{out}");
    assert!(
        doc["error"]
            .as_str()
            .unwrap()
            .contains("KIND/PAYLOAD MISMATCH"),
        "{out}"
    );
}
