//! `CHAIN_MANIFEST` domain v2 (Flows W5, D-163, seam-runtime#1910) against the runtime's
//! `conformance/chain/chain_manifest_vectors.json`, copied byte for byte from seam-runtime `fixtures/chain/`
//! at `a196a6c1`:
//!
//! * the `manifest` row decoded from BOTH projections (same event), its signed preimage, signed digest,
//!   entry digest and Ed25519 signature under the vector's TEST issuer;
//! * every `manifest_refusal` row refused by its rule name (structure before signature);
//! * end to end: the manifest appended to the runtime's own tenant chain (`chain_link_vectors.json` row
//!   `tenant`, whose head is the manifest's `tenant_head`) beside the flow chains it lists — D-163, the
//!   entry-digest recompute and V7 against real runtime bytes.

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
            })
            .collect(),
        issuer_aid: f["issuer_aid"].as_str().unwrap().into(),
        digest_schema: f["digest_schema"].as_u64().unwrap() as u32,
        signature: unhex(signature_hex),
        tenant_len: f["tenant_len"].as_u64().unwrap(),
        tenant_head: unhex(f["tenant_head_hex"].as_str().unwrap()),
    }
}

fn the_manifest_row(v: &Value) -> &Value {
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == "manifest")
        .expect("the vectors carry a manifest row")
}

/// The vector's manifest event, decoded from both projections.
fn manifest_event(v: &Value) -> Event {
    let row = the_manifest_row(v);
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
    let row = the_manifest_row(&v);
    let out = &row["out"];
    let e = manifest_event(&v);
    assert_eq!(e.kind, "CHAIN_MANIFEST");
    let m = e.manifest.as_ref().expect("the event carries tag 30");

    // The decoded payload is the row's `fields`, fields 10/11 included.
    let f = &row["fields"];
    assert_eq!(*m, from_fields(f, out["signature_hex"].as_str().unwrap()));
    assert_eq!(m.tenant_len, 3);

    assert_eq!(hex(&signed_preimage(m)), out["preimage_hex"]);
    assert!(signed_preimage(m).starts_with(b"\x1c\0\0\0seam.audit.chain-manifest.v2"));
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
    assert_eq!(n, 5);
}

/// The runtime's tenant chain (row `tenant`) and the flow chains (rows `flow_*`) the manifest lists,
/// plus the manifest event at tenant position 3, in stream order.
fn stream() -> Vec<Event> {
    let links = load("chain_link_vectors.json");
    let mut events: Vec<Event> = Vec::new();
    for row in links["cases"].as_array().unwrap() {
        if row["type"] != "chain" || row["name"] == "cell" {
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
    m.checksum = Some(link(&m.prev_checksum, m.digest.as_ref().unwrap()));
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
