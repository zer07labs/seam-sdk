//! Pre-D-163 `CHAIN_MANIFEST` history (seam-runtime#1921, 0.118.0). Runtime 0.115-0.116 sealed manifests
//! under `seam.audit.chain-manifest.v1` (fields 1-8, no `tenant_len`/`tenant_head`); 0.117.0 (D-163) signs
//! the tenant head each manifest follows. A live stream holds both, in that order, and must verify as it
//! was sealed: a v1 manifest recomputes under the v1 preimage and gets no tenant-head check, a v2 one gets
//! the full check, and a v1 manifest after a v2 one on the same tenant chain is `MANIFEST_DOWNGRADE`.
//!
//! `conformance/chain/chain_manifest_v1_event.json` is copied byte for byte from seam-runtime
//! `crates/seam-verify/tests/fixtures/chain_manifest_v1_event.json` @ `253f4995`: the 0.115.0 vector's
//! manifest, signed under the v1 domain, as a 0.117+ export renders it (`tenant_len` 0, `tenant_head` "").

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use seam_verify::chain_key::ChainKey;
use seam_verify::manifest::{
    entry_digest, is_v1, signed_digest, signed_preimage, verify_signature, CHAIN_MANIFEST_DOMAIN,
};
use seam_verify::verify::{chain, link};
use seam_verify::wire::{ChainRefPb, Event};
use sha2::{Digest, Sha256};

const STREAM: &str = "cell-a";
const TENANT: &str = "acme";

fn fixture() -> Event {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../conformance/chain/chain_manifest_v1_event.json");
    let raw = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("{}: {e} — this test refuses to skip", p.display()));
    Event::parse(raw.trim()).unwrap()
}

/// The runtime's real v1 manifest: its entry digest and signature recompute under the v1 preimage, and
/// under the v2 preimage they do not (why seam-verify 0.7.0 refused it as ENTRY REWRITE).
#[test]
fn a_real_v1_manifest_recomputes_as_it_was_sealed() {
    let e = fixture();
    let m = e.manifest.as_ref().unwrap();
    assert!(is_v1(m));
    assert!(signed_preimage(m).starts_with(&{
        let d = b"seam.audit.chain-manifest.v1";
        let mut v = (d.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(d);
        v
    }));
    assert_eq!(entry_digest(m).as_slice(), e.digest.as_deref().unwrap());
    verify_signature(&m.issuer_aid, m).unwrap();

    // Forced through the v2 framing (domain v2, `P(le64 0) ‖ P("")` appended) — what seam-verify 0.7.0
    // did to every manifest — the entry digest no longer matches the one the chain links.
    let pre = signed_preimage(m);
    let body = &pre[4 + b"seam.audit.chain-manifest.v1".len()..];
    let mut v2 = (CHAIN_MANIFEST_DOMAIN.len() as u32).to_le_bytes().to_vec();
    v2.extend_from_slice(CHAIN_MANIFEST_DOMAIN);
    v2.extend_from_slice(body);
    v2.extend_from_slice(&8u32.to_le_bytes());
    v2.extend_from_slice(&0u64.to_le_bytes());
    v2.extend_from_slice(&0u32.to_le_bytes());
    let mut h = Sha256::new();
    for part in [
        b"seam.audit.chain-manifest-entry.v1".as_slice(),
        v2.as_slice(),
        m.signature.as_slice(),
    ] {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    }
    assert_ne!(h.finalize().as_slice(), e.digest.as_deref().unwrap());
}

/// A tenant chain (`kind = 1`) of signed manifests, built the way the runtime appends them.
struct TenantChain {
    sk: SigningKey,
    aid: String,
    events: Vec<Event>,
}

impl TenantChain {
    fn new() -> Self {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let aid = format!(
            "aid:pubkey:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes())
        );
        Self {
            sk,
            aid,
            events: Vec::new(),
        }
    }

    fn head(&self) -> Vec<u8> {
        self.events.last().map_or_else(
            || {
                ChainKey::new(1, STREAM, TENANT, "", "", 0)
                    .unwrap()
                    .genesis()
                    .to_vec()
            },
            |e| e.checksum.clone().unwrap(),
        )
    }

    /// Append one manifest: `v2` signs the tenant head it follows (D-163), v1 signs none.
    fn manifest(&mut self, v2: bool) {
        let (prev, len) = (self.head(), self.events.len() as u64);
        let mut e = fixture();
        e.stream_id = STREAM.into();
        e.tenant = TENANT.into();
        e.seq = 100 + len;
        e.chain = Some(ChainRefPb {
            kind: 1,
            seq: len,
            ..Default::default()
        });
        let m = e.manifest.as_mut().unwrap();
        m.stream_id = STREAM.into();
        m.tenant = TENANT.into();
        m.chains.clear();
        m.manifest_at = 1_000 + len;
        m.issuer_aid = self.aid.clone();
        (m.tenant_len, m.tenant_head) = if v2 {
            (len, prev.clone())
        } else {
            (0, Vec::new())
        };
        m.signature = self.sk.sign(&signed_digest(m)).to_bytes().to_vec();
        let digest = entry_digest(m).to_vec();
        e.prev_checksum = prev.clone();
        e.checksum = Some(link(&prev, &digest));
        e.digest = Some(digest);
        self.events.push(e);
    }
}

/// v1, v1, v2, v2 on one tenant chain: every manifest verifies (walk and signature); then a v1 after the
/// v2 ones is a downgrade.
#[test]
fn v1_then_v2_manifests_verify_and_a_downgrade_fails() {
    let mut s = TenantChain::new();
    for v2 in [false, false, true, true] {
        s.manifest(v2);
    }
    let r = chain(&s.events).unwrap();
    assert_eq!(r.manifests.len(), 4);
    for e in &s.events {
        verify_signature(&s.aid, e.manifest.as_ref().unwrap()).unwrap();
    }

    s.manifest(false);
    verify_signature(&s.aid, s.events.last().unwrap().manifest.as_ref().unwrap()).unwrap();
    let err = chain(&s.events).err().unwrap();
    assert!(err.contains("MANIFEST_DOWNGRADE"), "{err}");
}

/// The version is signed, not trusted: a v2 manifest stripped to the v1 shape no longer recomputes its
/// digest (ENTRY REWRITE), and its signature no longer verifies.
#[test]
fn a_v2_manifest_stripped_to_v1_is_refused() {
    let mut s = TenantChain::new();
    s.manifest(false);
    s.manifest(true);
    let m = s.events[1].manifest.as_mut().unwrap();
    // `tenant_len` 1 here, so stripping both fields is what makes it read as v1.
    (m.tenant_len, m.tenant_head) = (0, Vec::new());
    assert!(is_v1(m));
    let err = verify_signature(&s.aid, m).err().unwrap();
    assert!(err.contains("signature_invalid"), "{err}");
    let err = chain(&s.events).err().unwrap();
    assert!(err.contains("ENTRY REWRITE"), "{err}");
}

/// A manifest whose signed tenant is not its envelope's is an entry rewrite (the runtime's
/// `CHAIN_MANIFEST's tenant`): for a v1 manifest it is the only tenant binding there is.
#[test]
fn a_manifest_on_another_tenants_envelope_is_refused() {
    let mut s = TenantChain::new();
    s.manifest(false);
    s.events[0].manifest.as_mut().unwrap().tenant = "other".into();
    let err = chain(&s.events).err().unwrap();
    assert!(
        err.contains("ENTRY REWRITE") && err.contains("signs tenant"),
        "{err}"
    );
}

/// A v1 manifest on another tenant's chain is not a downgrade of this one.
#[test]
fn a_downgrade_is_per_tenant_chain() {
    let mut a = TenantChain::new();
    a.manifest(true);
    let mut events = a.events;
    let mut b = fixture();
    b.stream_id = STREAM.into();
    b.tenant = "other".into();
    b.seq = 200;
    b.chain = Some(ChainRefPb {
        kind: 1,
        seq: 0,
        ..Default::default()
    });
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let m = b.manifest.as_mut().unwrap();
    m.stream_id = STREAM.into();
    m.tenant = "other".into();
    m.chains.clear();
    m.signature = sk.sign(&signed_digest(m)).to_bytes().to_vec();
    let digest = entry_digest(m).to_vec();
    let prev = ChainKey::new(1, STREAM, "other", "", "", 0)
        .unwrap()
        .genesis()
        .to_vec();
    b.checksum = Some(link(&prev, &digest));
    b.prev_checksum = prev;
    b.digest = Some(digest);
    events.push(b);
    assert_eq!(chain(&events).unwrap().manifests.len(), 2);
}
