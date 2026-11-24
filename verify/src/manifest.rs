//! The `CHAIN_MANIFEST` payload (envelope tag 30, `chain_bundle` v2), written from `seam-event.v1.md`
//! §CHAIN_MANIFEST and pinned by `conformance/chain/chain_manifest_vectors.json` (copied byte for byte from
//! seam-runtime `fixtures/chain/`, rt#1910 @ `a196a6c1`).
//!
//! ```text
//! manifest = P("seam.audit.chain-manifest.v2") ‖ P(stream_id) ‖ P(tenant) ‖ P(governing_doc_sha256)
//!            ‖ P(le64 governing_generated_at) ‖ P(le64 manifest_at) ‖ P(le32 n)
//!            ‖ n × { P(flow_id) ‖ P(env) ‖ V ‖ P(le64 len) ‖ P(head) ‖ P(le32 state) }
//!            ‖ P(issuer_aid) ‖ P(le32 digest_schema) ‖ P(le64 tenant_len) ‖ P(tenant_head)
//! signature    = Ed25519(SHA-256(manifest))
//! entry digest = SHA-256(P("seam.audit.chain-manifest-entry.v1") ‖ P(manifest) ‖ P(signature))
//! ```
//!
//! **Domain v2 (W5, D-163).** Since runtime 0.117.0 the manifest also signs `tenant_len`/`tenant_head`,
//! the tenant chain it follows: the entry sits at `chain.seq = tenant_len` with `prev_checksum =
//! tenant_head` (`MANIFEST_TENANT_HEAD_MISMATCH`, checked in [`crate::verify::chain_by_tenant`]).
//!
//! **Domain v1 (runtime 0.115-0.116, before D-163).** Those manifests are still on live streams. They were
//! signed under `seam.audit.chain-manifest.v1` over fields 1-8 only. The wire carries no version, so the
//! marker is the absent tenant head ([`is_v1`]): a v2 manifest always signs a 32-byte `tenant_head` (the
//! tenant chain's genesis at `tenant_len` 0). The choice is signed, not trusted: a v1 manifest verifies
//! only under the v1 preimage, and the entry digest its tenant chain links is over that same preimage.
//! A v1 manifest gets no tenant-head check, and one after a v2 manifest on the same tenant chain is
//! `MANIFEST_DOWNGRADE`. This matches seam-runtime `crates/seam-verify/src/chains.rs` @ `253f4995`.
//!
//! The structural rules run before any signature work, in the spec's order: `chains_not_ascending`, then
//! per entry a [`ChainKey`] rule for a malformed `(flow_id, env, version)`, `state_unknown`, and
//! `empty_head_not_genesis`. Rule names are advisory, like every rule name.

use sha2::{Digest, Sha256};

use crate::chain_key::ChainKey;
use crate::wire::ChainManifestPb;

/// Signed-payload domain of a `CHAIN_MANIFEST` (v2, D-163).
pub const CHAIN_MANIFEST_DOMAIN: &[u8] = b"seam.audit.chain-manifest.v2";
/// Signed-payload domain of a `CHAIN_MANIFEST` sealed before D-163 (runtime 0.115-0.116): fields 1-8 only.
pub const CHAIN_MANIFEST_V1_DOMAIN: &[u8] = b"seam.audit.chain-manifest.v1";
/// Chain-entry digest domain of a `CHAIN_MANIFEST` entry.
pub const CHAIN_MANIFEST_ENTRY_DOMAIN: &[u8] = b"seam.audit.chain-manifest-entry.v1";

fn put(v: &mut Vec<u8>, x: &[u8]) {
    v.extend_from_slice(&(x.len() as u32).to_le_bytes());
    v.extend_from_slice(x);
}

/// Whether `m` was sealed before D-163 (domain v1): `tenant_len` 0 and an empty `tenant_head`. A v2
/// manifest always signs a 32-byte head, so no v2 manifest has this shape.
pub fn is_v1(m: &ChainManifestPb) -> bool {
    m.tenant_len == 0 && m.tenant_head.is_empty()
}

/// The signed preimage under the domain `m` was sealed with ([`is_v1`]): fields 1-8 under v1, fields 1-8,
/// 10 and 11 under v2, framed. Not hashed: [`signed_digest`] and [`entry_digest`] both consume it.
pub fn signed_preimage(m: &ChainManifestPb) -> Vec<u8> {
    let v1 = is_v1(m);
    let mut v = Vec::new();
    put(
        &mut v,
        if v1 {
            CHAIN_MANIFEST_V1_DOMAIN
        } else {
            CHAIN_MANIFEST_DOMAIN
        },
    );
    put(&mut v, m.stream_id.as_bytes());
    put(&mut v, m.tenant.as_bytes());
    put(&mut v, &m.governing_doc_sha256);
    put(&mut v, &m.governing_generated_at.to_le_bytes());
    put(&mut v, &m.manifest_at.to_le_bytes());
    put(&mut v, &(m.chains.len() as u32).to_le_bytes());
    for c in &m.chains {
        put(&mut v, c.flow_id.as_bytes());
        put(&mut v, c.env.as_bytes());
        // V: the absent form `P("")` for version 0, else `P(u32le(version))` — as in the chain key.
        if c.version == 0 {
            put(&mut v, b"");
        } else {
            put(&mut v, &c.version.to_le_bytes());
        }
        put(&mut v, &c.len.to_le_bytes());
        put(&mut v, &c.head);
        put(&mut v, &c.state.to_le_bytes());
    }
    put(&mut v, m.issuer_aid.as_bytes());
    put(&mut v, &m.digest_schema.to_le_bytes());
    if !v1 {
        put(&mut v, &m.tenant_len.to_le_bytes());
        put(&mut v, &m.tenant_head);
    }
    v
}

/// `SHA-256(signed_preimage)` — what the issuer's Ed25519 signature is over.
pub fn signed_digest(m: &ChainManifestPb) -> [u8; 32] {
    Sha256::digest(signed_preimage(m)).into()
}

/// The chained digest of a `CHAIN_MANIFEST` entry: the signature is inside it, so a re-signed or
/// rewritten manifest digests differently.
pub fn entry_digest(m: &ChainManifestPb) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [
        CHAIN_MANIFEST_ENTRY_DOMAIN,
        signed_preimage(m).as_slice(),
        m.signature.as_slice(),
    ] {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// The structural refusals, before the signature. `Err` is the spec's rule name.
pub fn check_structure(m: &ChainManifestPb) -> Result<(), &'static str> {
    // Strictly ascending by flow_id, then env (both bytewise), then version (numeric).
    for w in m.chains.windows(2) {
        let a = (w[0].flow_id.as_bytes(), w[0].env.as_bytes(), w[0].version);
        let b = (w[1].flow_id.as_bytes(), w[1].env.as_bytes(), w[1].version);
        if a >= b {
            return Err("chains_not_ascending");
        }
    }
    for c in &m.chains {
        let key = ChainKey::new(2, &m.stream_id, &m.tenant, &c.flow_id, &c.env, c.version)?;
        if !(1..=4).contains(&c.state) {
            return Err("state_unknown");
        }
        if c.len == 0 && c.head.as_slice() != key.genesis().as_slice() {
            return Err("empty_head_not_genesis");
        }
    }
    Ok(())
}

/// Verify a manifest against a **pinned** issuer AID: the structure first, then the AID the manifest
/// names against the pin (a mismatch is refused before any signature work, as for an erasure certificate:
/// a key taken from the manifest alone would verify a forger against themselves), then Ed25519 over
/// [`signed_digest`].
pub fn verify_signature(pinned_aid: &str, m: &ChainManifestPb) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    check_structure(m).map_err(|rule| format!("the manifest is malformed ({rule})"))?;
    if pinned_aid != m.issuer_aid {
        return Err(format!(
            "the manifest names issuer '{}', but you pinned '{}'.",
            m.issuer_aid, pinned_aid
        ));
    }
    let key = crate::verify::aid_to_key(pinned_aid)?;
    let vk = VerifyingKey::from_bytes(&key).map_err(|e| format!("bad issuer key: {e}"))?;
    let sig: [u8; 64] = m
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;
    vk.verify(&signed_digest(m), &Signature::from_bytes(&sig))
        .map_err(|_| {
            "signature_invalid — the manifest does not verify under the pinned issuer's key (forged, \
             or altered after signing)."
                .to_string()
        })
}
