//! `CHAIN_MANIFEST` domain v3 (S-3 history boundary, seam-runtime#2039) and v2 (Flows W5, D-163,
//! seam-runtime#1910) against the runtime's `conformance/chain/chain_manifest_vectors.json`, copied byte for
//! byte from seam-runtime `fixtures/chain/` at `64ec782c4`:
//!
//! * each `manifest` row (v3 `manifest_every_state`, v2 `manifest_v2_before_the_boundary`) decoded from BOTH projections (same event), its signed preimage, signed digest,
//!   entry digest and Ed25519 signature under the vector's TEST issuer;
//! * every `manifest_refusal` row refused by its rule name (structure before signature);
//! * end to end: the manifest appended to the runtime's own tenant chain (`chain_link_vectors.json` row
//!   `tenant`, whose head is the manifest's `tenant_head`) beside the flow chains it lists — D-163, the
//!   entry-digest recompute and V7 against real runtime bytes.

use base64::Engine;
use seam_verify::manifest::{
    check_structure, entry_digest, signed_digest, signed_preimage, verify_signature,
};
use seam_verify::verify::{chain, chain_selected, hex, link};
use seam_verify::wire::{ChainManifestEntryPb, ChainManifestPb, Event};
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A manifest from a vector row's `fields` (heads in the JSON projection's base64) and `signature_hex`.
fn from_fields(f: &Value, signature_hex: &str) -> ChainManifestPb {
    ChainManifestPb {
        stream_id: f["stream_id"].as_str().unwrap().into(),
        tenant: f["tenant"].as_str().unwrap().into(),
        governing_doc_sha256: unhex(f["governing_doc_sha256_hex"].as_str().unwrap()),
        governing_generated_at: f["governing_generated_at"].as_u64().unwrap(),
        manifest_at: f["manifest_at"].as_u64().unwrap(),
        chains: f["chains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| ChainManifestEntryPb {
                flow_id: c["flow_id"].as_str().unwrap().into(),
                env: c["env"].as_str().unwrap().into(),
                len: c["len"].as_u64().unwrap(),
                head: unhex(c["head_hex"].as_str().unwrap()),
                state: c["state"].as_u64().unwrap() as u32,
                version: c["version"].as_u64().unwrap() as u32,
                batch_boundary: c["batch_boundary"].as_u64(),
            })
            .collect(),
        issuer_aid: f["issuer_aid"].as_str().unwrap().into(),
        digest_schema: f["digest_schema"].as_u64().unwrap() as u32,
        signature: unhex(signature_hex),
        tenant_len: f["tenant_len"].as_u64().unwrap(),
        tenant_head: unhex(f["tenant_head_hex"].as_str().unwrap()),
        manifest_version: f["manifest_version"].as_u64().unwrap_or(0) as u32,
        tenant_batch_boundary: f["tenant_batch_boundary"].as_u64(),
    }
}

fn manifest_row<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == "manifest" && c["name"] == name)
        .unwrap_or_else(|| panic!("the vectors carry manifest row {name}"))
}

/// The v3 manifest row (the runtime writes v3 only).
fn the_manifest_row(v: &Value) -> &Value {
    manifest_row(v, "manifest_every_state")
}

/// The vector's v3 manifest event, decoded from both projections.
fn manifest_event(v: &Value) -> Event {
    event_of(the_manifest_row(v))
}

fn event_of(row: &Value) -> Event {
    let j = Event::parse(row["event"]["json"].as_str().unwrap()).unwrap();
    let p = Event::parse(row["event"]["pb_b64"].as_str().unwrap()).unwrap();
    assert_eq!(j.bytes, p.bytes, "JSON and pb decode to the same event");
    assert_eq!(j.manifest, p.manifest, "tag 30 in both projections");
    j
}

#[test]
fn the_manifest_row_matches_byte_for_byte() {
    let v = load("chain_manifest_vectors.json");
    assert_eq!(v["bundle_version"], 2);
    for (name, domain) in [
        ("manifest_every_state", "seam.audit.chain-manifest.v3"),
        (
            "manifest_v2_before_the_boundary",
            "seam.audit.chain-manifest.v2",
        ),
    ] {
        manifest_row_matches(&v, name, domain);
    }
}

fn manifest_row_matches(v: &Value, name: &str, domain: &str) {
    let row = manifest_row(v, name);
    let out = &row["out"];
    let e = event_of(row);
    assert_eq!(e.kind, "CHAIN_MANIFEST");
    let m = e.manifest.as_ref().expect("the event carries tag 30");

    // The decoded payload is the row's `fields`, fields 10/11 included.
    let f = &row["fields"];
    assert_eq!(*m, from_fields(f, out["signature_hex"].as_str().unwrap()));
    assert_eq!(m.tenant_len, 3);

    assert_eq!(hex(&signed_preimage(m)), out["preimage_hex"]);
    let mut framed = (domain.len() as u32).to_le_bytes().to_vec();
    framed.extend_from_slice(domain.as_bytes());
    assert!(signed_preimage(m).starts_with(&framed), "{name}");
    assert_eq!(hex(&signed_digest(m)), out["signed_digest_hex"]);
    assert_eq!(hex(&entry_digest(m)), out["entry_digest_hex"]);
    assert_eq!(e.digest.as_deref(), Some(&entry_digest(m)[..]));
    check_structure(m).unwrap();
    verify_signature(v["issuer"]["aid"].as_str().unwrap(), m).unwrap();
}

/// Fields 10 and 11 are signed: moving either one, or verifying under another pin, fails.
#[test]
fn the_tenant_head_is_signed() {
    let v = load("chain_manifest_vectors.json");
    let e = manifest_event(&v);
    let aid = v["issuer"]["aid"].as_str().unwrap();
    let m = e.manifest.unwrap();

    let mut moved = m.clone();
    moved.tenant_len += 1;
    assert!(verify_signature(aid, &moved)
        .unwrap_err()
        .contains("signature_invalid"));
    let mut other = m.clone();
    other.tenant_head[0] ^= 1;
    assert!(verify_signature(aid, &other)
        .unwrap_err()
        .contains("signature_invalid"));
    assert_ne!(entry_digest(&moved), entry_digest(&m));

    let other_pin = "aid:pubkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(verify_signature(other_pin, &m)
        .unwrap_err()
        .contains("you pinned"));
}

#[test]
fn every_refusal_row_refuses_by_its_rule() {
    let v = load("chain_manifest_vectors.json");
    let aid = v["issuer"]["aid"].as_str().unwrap();
    let mut n = 0;
    for row in v["cases"].as_array().unwrap() {
        if row["type"] != "manifest_refusal" {
            continue;
        }
        n += 1;
        let name = row["name"].as_str().unwrap();
        let rule = row["rule"].as_str().unwrap();
        let m = from_fields(&row["fields"], row["signature_hex"].as_str().unwrap());
        if rule == "signature_invalid" {
            check_structure(&m).unwrap_or_else(|r| panic!("{name}: {r}"));
            let err = verify_signature(aid, &m).unwrap_err();
            assert!(err.contains("signature_invalid"), "{name}: {err}");
        } else {
            assert_eq!(check_structure(&m), Err(rule), "{name}");
            let err = verify_signature(aid, &m).unwrap_err();
            assert!(err.contains(rule), "{name}: {err}");
        }
    }
    assert_eq!(n, 8);
}

/// The runtime's tenant chain (row `tenant`) and the flow chains (rows `flow_*`) the manifest lists,
/// plus the manifest event at tenant position 3, in stream order.
fn stream() -> Vec<Event> {
    let links = load("chain_link_vectors.json");
    let mut events: Vec<Event> = Vec::new();
    for row in links["cases"].as_array().unwrap() {
        // The chains the manifest lists (the batch and boundary rows reuse flow_live's key).
        if row["type"] != "chain"
            || !["tenant", "flow_sandbox_v1", "flow_sandbox_v2", "flow_live"]
                .contains(&row["name"].as_str().unwrap())
        {
            continue;
        }
        for e in row["entries"].as_array().unwrap() {
            events.push(Event::parse(e["json"].as_str().unwrap()).unwrap());
        }
    }
    events.push(manifest_event(&load("chain_manifest_vectors.json")));
    events.sort_by_key(|e| e.seq);
    events
}

/// The selected walk checks every manifest rule but V7, and passes on the runtime's bytes.
#[test]
fn the_manifest_sits_at_its_signed_tenant_head() {
    let r = chain_selected(&stream()).unwrap();
    assert_eq!(r.manifests.len(), 1);
    assert!(
        r.unmodelled.is_empty(),
        "CHAIN_MANIFEST is modelled, not disclosed"
    );
}

/// V7: the manifest also lists `flow-b` (live, length 7; sandbox v1, length 2), which these vectors carry
/// no link of, so the full walk refuses `CHAIN_MISSING`. (`MANIFEST_HEAD_MISMATCH` is unit-tested in
/// `src/verify.rs`, since every runtime vector lists `flow-b` first.)
#[test]
fn a_listed_chain_the_stream_lacks_is_missing() {
    let err = chain(&stream()).err().unwrap();
    assert!(
        err.contains("CHAIN_MISSING") && err.contains("flow-b"),
        "{err}"
    );
}

/// D-163: the same manifest one tenant link earlier — the link itself re-made valid over the shorter
/// chain, its entry digest untouched — sits after another head than the one it signs.
#[test]
fn a_manifest_off_its_signed_tenant_head_fails() {
    let mut events: Vec<Event> = stream()
        .into_iter()
        .filter(|e| e.chain.as_ref().unwrap().kind == 1)
        .collect();
    let mut m = events.pop().unwrap();
    assert_eq!(m.kind, "CHAIN_MANIFEST");
    let dropped = events.pop().unwrap();
    m.prev_checksum = dropped.prev_checksum.clone();
    let entry = seam_verify::merkle::entry_digest(
        m.digest.as_ref().unwrap(),
        m.leaf_index,
        m.leaf_count,
        &m.inclusion_path,
    )
    .expect("a batch of one");
    m.checksum = Some(link(&m.prev_checksum, &entry));
    m.chain.as_mut().unwrap().seq -= 1;
    m.seq = dropped.seq;
    events.push(m);
    let err = chain_selected(&events).err().unwrap();
    assert!(err.contains("MANIFEST_TENANT_HEAD_MISMATCH"), "{err}");
}

/// A manifest whose fields were rewritten with its digest left in place is an entry rewrite, not a
/// manifest the walk trusts.
#[test]
fn a_rewritten_manifest_is_refused() {
    let mut events = stream();
    let m = events
        .iter_mut()
        .find(|e| e.kind == "CHAIN_MANIFEST")
        .unwrap();
    m.manifest.as_mut().unwrap().chains[0].state = 1;
    let err = chain_selected(&events).err().unwrap();
    assert!(err.contains("ENTRY REWRITE"), "{err}");
}

/// A CHAIN_MANIFEST payload on another kind, or off a ChainRef, is refused.
#[test]
fn the_payload_binds_to_its_kind_and_its_chain() {
    let v = load("chain_manifest_vectors.json");
    let mut e = manifest_event(&v);
    e.kind = "AUDIT_ENTRY".into();
    let err = chain(&[e]).err().unwrap();
    assert!(err.contains("KIND/PAYLOAD MISMATCH"), "{err}");

    let mut e = manifest_event(&v);
    e.chain = None;
    let err = chain(&[e]).err().unwrap();
    assert!(err.contains("MANIFEST_TENANT_HEAD_MISMATCH"), "{err}");
}

/// A manifest event moved onto the tenant chain right after the last one, as a batch of one, with its
/// digest recomputed from its (edited) fields — the walk checks the fields, `--issuer` the signature.
fn appended(events: &mut Vec<Event>, row: &Value, edit: impl Fn(&mut Value)) {
    let last = events
        .iter()
        .rfind(|e| e.chain.as_ref().unwrap().kind == 1)
        .unwrap()
        .clone();
    let mut j: Value = serde_json::from_str(row["event"]["json"].as_str().unwrap()).unwrap();
    edit(&mut j);
    let m = Event::parse(&j.to_string()).unwrap().manifest.unwrap();
    let digest = entry_digest(&m);
    let entry =
        seam_verify::merkle::entry_digest(&digest, 0, 1, &[] as &[Vec<u8>]).expect("batch of one");
    let prev = last.checksum.clone().unwrap();
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    j["seq"] = (last.seq + 1).into();
    j["chain"]["seq"] = (last.chain.as_ref().unwrap().seq + 1).into();
    j["prev_checksum"] = b64(&prev).into();
    j["digest"] = b64(&digest).into();
    j["checksum"] = b64(&link(&prev, &entry)).into();
    j["leaf_index"] = 0.into();
    j["leaf_count"] = 1.into();
    events.push(Event::parse(&j.to_string()).unwrap());
}

/// v2 is verify-only (its row is checked byte for byte above), and a v2 manifest after a v3 one on the
/// same tenant chain is `MANIFEST_DOWNGRADE`.
#[test]
fn a_v2_manifest_after_a_v3_one_is_a_downgrade() {
    let v = load("chain_manifest_vectors.json");
    let v2 = manifest_row(&v, "manifest_v2_before_the_boundary");
    let mut events = stream();
    appended(&mut events, v2, |j| {
        j["chain_manifest"]["tenant_len"] = 4.into();
    });
    let err = chain_selected(&events).err().unwrap();
    assert!(err.contains("MANIFEST_DOWNGRADE"), "{err}");
}

/// A v3 manifest signs the tenant chain's S-3 boundary: a claim the walk does not agree with is
/// `MANIFEST_BOUNDARY_MISMATCH` (the vectors' tenant chain is batched from genesis, boundary 0).
#[test]
fn a_tenant_boundary_the_walk_disagrees_with_is_refused() {
    let v = load("chain_manifest_vectors.json");
    for claim in [Value::Null, 2.into()] {
        let mut events: Vec<Event> = stream()
            .into_iter()
            .filter(|e| e.kind != "CHAIN_MANIFEST")
            .collect();
        let row = the_manifest_row(&v);
        appended(&mut events, row, |j| {
            j["chain_manifest"]["tenant_batch_boundary"] = claim.clone();
            j["chain_manifest"]["tenant_len"] = 3.into();
        });
        // `appended` puts it after the last tenant entry at position 3, where the original sat.
        let err = chain_selected(&events).err().unwrap();
        assert!(err.contains("MANIFEST_BOUNDARY_MISMATCH"), "{claim}: {err}");
    }
}
