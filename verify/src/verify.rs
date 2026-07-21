//! The two things worth verifying, implemented from the published specs alone.

use sha2::{Digest, Sha256};

use crate::wire::{Attestation, Cert, Decision, Event};

/// The chain's genesis head: 32 zero bytes (`seam-event.v1.md` §Ordering & integrity).
pub const GENESIS: [u8; 32] = [0u8; 32];

/// The chain link: `checksum = SHA256(prev_checksum ‖ digest)`.
pub fn link(prev: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(digest);
    h.finalize().to_vec()
}

pub struct ChainReport {
    pub events: usize,
    pub links: usize,
    pub advisory: usize,
    pub duplicates: usize,
    /// Events with no chain fields that are NOT advisory — pre-cutover history, which this tool
    /// **cannot** verify. Disclosed, never silently folded in with the advisory ones.
    pub unverifiable: Vec<u64>,
    pub head: Vec<u8>,
    /// The running head after each link, in order: `heads[0]` is genesis, `heads[k]` is the head after
    /// `k` chained links. Its length is `links + 1`. This is what an attestation's `(attested_len,
    /// attested_head)` is checked against — `heads[attested_len]` must equal the attested head.
    pub heads: Vec<Vec<u8>>,
}

/// Collapse at-least-once duplicates.
///
/// A duplicate is **byte-identical**, full stop — that is precisely what a retried delivery is.
///
/// It is tempting to key this on `event_id` (the spec says *"event_id dedups"*), and it is wrong: an
/// `event_id` is only unique for **chained** events, whose id embeds the store's audit sequence. The
/// periodic chain anchor is `chain-anchor:{len}#{len}`, so two anchors emitted over a *quiet* stream —
/// nothing sealed between them, the normal case — share an id and differ only in their timestamp. Refusing
/// that stream as a forgery is a false alarm on a healthy chain, and a verifier that cries wolf is worse
/// than no verifier.
///
/// The impostor check — two *different* events wearing one identity — therefore applies **only to chained
/// events**, where uniqueness is real and a substitution would be a genuine attack.
pub fn dedup(events: Vec<Event>) -> Result<(Vec<Event>, usize), String> {
    use std::collections::{HashMap, HashSet};
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut chained: HashMap<String, Vec<u8>> = HashMap::new();
    let mut out = Vec::with_capacity(events.len());
    let mut duplicates = 0;

    for e in events {
        if seen.contains(&e.bytes) {
            duplicates += 1;
            continue;
        }
        if e.is_link() {
            if let Some(first) = chained.get(&e.event_id) {
                if *first != e.bytes {
                    return Err(format!(
                        "chained event_id {} appears TWICE with DIFFERENT content.\n  \
                         A chained event's id embeds the audit sequence, a primary key — it cannot \
                         legitimately repeat. These are two different events wearing one identity: one is \
                         a forgery, and which one you accepted would depend on arrival order.",
                        e.event_id
                    ));
                }
            }
            chained.insert(e.event_id.clone(), e.bytes.clone());
        }
        seen.insert(e.bytes.clone());
        out.push(e);
    }
    Ok((out, duplicates))
}

/// Verify the hash chain from the stream alone.
///
/// Per `seam-event.v1.md`: start at genesis; for each event **that carries a `digest`**, in `seq` order,
/// assert `prev_checksum == running_head` and `checksum == H(prev_checksum ‖ digest)`, then advance.
///
/// **Chained-ness is by field PRESENCE, not by `kind`.** A verifier keyed on `kind` trips over the first
/// `LEARNING_DECISION` in an unfiltered stream, and over the deliberately off-chain `chain_anchor`.
pub fn chain(events: &[Event]) -> Result<ChainReport, String> {
    let mut head: Vec<u8> = GENESIS.to_vec();
    let mut r = ChainReport {
        events: events.len(),
        links: 0,
        advisory: 0,
        duplicates: 0,
        unverifiable: Vec::new(),
        head: head.clone(),
        heads: vec![head.clone()], // heads[0] = genesis
    };

    for e in events {
        let (Some(digest), Some(checksum)) = (e.digest.as_ref(), e.checksum.as_ref()) else {
            if e.is_advisory() {
                r.advisory += 1;
            } else {
                // A chained kind with no chain fields: either pre-cutover history, or an attacker who
                // stripped the fields. We cannot tell them apart from bytes — and we do not pretend to.
                // The tamper is caught at the NEXT link (its prev_checksum will not match the head this
                // event should have produced); the history is caught by --strict.
                r.unverifiable.push(e.seq);
            }
            continue;
        };

        if e.prev_checksum != head {
            return Err(format!(
                "seq {}: BROKEN CHAIN — prev_checksum does not match the running head.\n  \
                 expected {}\n  got      {}\n  \
                 An event was forged, inserted, reordered, dropped, or had its chain fields stripped at \
                 or before this point.",
                e.seq,
                hex(&head),
                hex(&e.prev_checksum)
            ));
        }
        let expect = link(&e.prev_checksum, digest);
        if checksum != &expect {
            return Err(format!(
                "seq {}: FORGED LINK — checksum != H(prev_checksum ‖ digest).\n  \
                 expected {}\n  got      {}\n  \
                 This event's own digest does not produce the head it claims. Its body was rewritten.",
                e.seq,
                hex(&expect),
                hex(checksum)
            ));
        }
        head = checksum.clone();
        r.links += 1;
        r.heads.push(head.clone());
    }
    r.head = head;
    Ok(r)
}

// ---- the erasure certificate -----------------------------------------------------------------------

/// The digest an erasure certificate signs over — `seam.erasure-certificate.v1`.
///
/// Transcribed from `erasure-certificate.v1.md`. Two details are easy to get wrong and both are load-bearing:
///
/// 1. the **domain tag is length-PREFIXED**, not NUL-terminated;
/// 2. the `erased`/`held` **counts are themselves `put()`** — i.e. `u32le(4) ‖ u32le(count)`, not a bare
///    count. Get that wrong and every signature fails, which at least fails loudly.
///
/// List ORDER is part of the signed content. If it were not, ids could be permuted freely — harmless
/// looking, but it would mean the signature does not actually pin the list it claims to.
fn erasure_payload(c: &Cert) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut put = |part: &[u8]| {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    };
    put(b"seam.erasure-certificate.v1");
    put(c.subject.as_bytes());
    put(&(c.erased.len() as u32).to_le_bytes());
    for id in &c.erased {
        put(id.as_bytes());
    }
    put(&(c.held.len() as u32).to_le_bytes());
    for id in &c.held {
        put(id.as_bytes());
    }
    put(&c.erased_at.to_le_bytes());
    put(&c.chain_head);
    put(c.issuer_aid.as_bytes());
    h.finalize().into()
}

/// Extract the ed25519 public key from an AID.
///
/// Two textual forms are in use — `aid:pubkey:<base64url>` and the algorithm-tagged
/// `aid:pubkey:ed25519:<base64url>`. Both encode the same 32 bytes; verification binds at the KEY level,
/// so the text form is not security-relevant, only its stability is.
pub fn aid_to_key(aid: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let b64 = aid
        .strip_prefix("aid:pubkey:ed25519:")
        .or_else(|| aid.strip_prefix("aid:pubkey:"))
        .ok_or_else(|| format!("not an AID: {aid}"))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("AID does not decode: {e}"))?;
    raw.try_into()
        .map_err(|_| "AID does not embed a 32-byte ed25519 key".to_string())
}

/// Verify a certificate against a **pinned** issuer AID.
///
/// # The pin is the whole point — do not remove it
///
/// `pinned_aid` is what YOU obtained out of band (Seam serves it at `GET /v1/trust/issuer-aid`). It is
/// compared against the AID the certificate *names*, and a mismatch is rejected before any signature work.
///
/// Deriving the key from `cert.issuer_aid` alone would make this **tautological**: an attacker forges a
/// certificate, signs it with their own key, names their own AID — and it verifies perfectly, against
/// themselves. A signature only means something relative to a key you already trusted. This is where that
/// trust enters.
pub fn erasure_certificate(pinned_aid: &str, c: &Cert) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if pinned_aid != c.issuer_aid {
        return Err(format!(
            "the certificate names issuer '{}', but you pinned '{}'.\n  \
             A signature only means something relative to a key you already trusted.",
            c.issuer_aid, pinned_aid
        ));
    }
    let key = aid_to_key(pinned_aid)?;
    let vk = VerifyingKey::from_bytes(&key).map_err(|e| format!("bad issuer key: {e}"))?;
    let sig: [u8; 64] = c
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;

    vk.verify(&erasure_payload(c), &Signature::from_bytes(&sig))
        .map_err(|_| {
            "the signature does not verify against the issuer's public key. The certificate is forged, \
             or its contents were altered after signing."
                .to_string()
        })
}

// ---- the chain-head attestation (A14 authenticity, design-b) ---------------------------------------

/// The 32-byte digest a `CHAIN_HEAD_ATTESTATION` signs over — `seam.audit.chain-head-attestation.v1`.
///
/// Transcribed verbatim from `seam-event.v1.md` §CHAIN_HEAD_ATTESTATION. `frame(x) = u32le(len) ‖ x`, and
/// the integers are framed **little-endian** (`le64`/`le32`) — the same length-prefixed discipline as the
/// erasure payload, and the same two easy-to-miss details: the domain tag is length-prefixed (not
/// NUL-terminated), and `attested_len`/`digest_schema` are the raw LE bytes wrapped in a frame, never a
/// bare number. The signature is `Ed25519` over **this digest**, not over the preimage.
fn chain_head_attestation_payload(a: &Attestation) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut frame = |part: &[u8]| {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    };
    frame(b"seam.audit.chain-head-attestation.v1");
    frame(&a.attested_len.to_le_bytes());
    frame(&a.attested_head);
    frame(&a.attested_at.to_le_bytes());
    frame(&a.digest_schema.to_le_bytes());
    frame(a.issuer_aid.as_bytes());
    h.finalize().into()
}

pub struct IssuerReport {
    /// The number of `CHAIN_HEAD_ATTESTATION`s that verified (signature + head-at-position). At least 1
    /// is required — see [`verify_authenticity`].
    pub attestations: usize,
    /// The longest prefix any valid attestation covers (its `attested_len`) — the issuer-signed reach.
    pub covered_prefix: u64,
    /// The number of v2 `DECISION_SEALED` records whose digest-v2 recomputed and matched the wire `digest`
    /// (design-a). v1 records are link-only (not recomputable) and not counted.
    pub records_recomputed: usize,
}

/// The 32-byte record digest a v2 `DECISION_SEALED` commits to — `seam.audit.record-digest.v2`.
///
/// Transcribed verbatim from `seam-event.v1.md` §Record digest (v2). `frame(x) = u32le(len) ‖ x`;
/// `opt(x) = 0x00` when absent, `0x01 ‖ frame(x)` when present — so `None` and `Some("")` are DISTINCT (a
/// naive empty-string collapse is a real bug), and the presence byte is RAW (never itself framed).
/// `ciphertext_digest` is `SHA256(ciphertext)` framed directly (the stream carries the digest, never the
/// ciphertext — the recompute never re-hashes plaintext). The preimage order is NOT the wire tag order:
/// `outcome` precedes the optional `mode`/`policy_version`/`supersedes`.
fn record_digest_v2(d: &Decision) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::new();
    let frame = |buf: &mut Vec<u8>, part: &[u8]| {
        buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
        buf.extend_from_slice(part);
    };
    let opt = |buf: &mut Vec<u8>, x: Option<&str>| match x {
        None => buf.push(0x00),
        Some(s) => {
            buf.push(0x01);
            buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
    };
    frame(&mut buf, b"seam.audit.record-digest.v2");
    frame(&mut buf, d.decision_id.as_bytes());
    frame(&mut buf, d.tenant.as_bytes());
    frame(&mut buf, d.namespace.as_bytes());
    frame(&mut buf, &d.ciphertext_digest);
    frame(&mut buf, &d.sealed_at.to_le_bytes());
    frame(&mut buf, d.outcome.as_bytes());
    opt(&mut buf, d.mode.as_deref());
    opt(&mut buf, d.policy_version.as_deref());
    opt(&mut buf, d.supersedes.as_deref());
    frame(&mut buf, &d.schema_version.to_le_bytes());
    Sha256::digest(&buf).into()
}

/// Verify every `CHAIN_HEAD_ATTESTATION` in the stream against the **pinned** issuer AID (A14, design-b).
///
/// # Why every attestation, and why at least one
///
/// A plain SHA-256 chain over a public genesis is *unkeyed*: a transport-controlling adversary can rebuild
/// a self-consistent chain from any fork point, and integrity-only verification passes it. The signed head
/// is the keyed root that closes this — a forger cannot mint a valid attestation without the issuer key.
/// So:
///   * **the pin is load-bearing** (as for the erasure cert): the key comes from the caller's `--issuer`
///     AID, never from the attestation's own `issuer_aid` (that would let a forgery verify against its
///     forger). A named issuer that differs from the pin is refused before any signature work.
///   * **head-at-position** (`heads[attested_len] == attested_head`) is what kills an *authentic*
///     attestation spliced into a forged chain: the signature checks out, but it attests a head the
///     fabricated chain never produced at that position.
///   * **zero valid attestations ⇒ REFUSE.** A forger cannot mint one, so their absence over a stream the
///     caller asked to authenticate is the fabricated-chain tell; reporting green on it would be a
///     coverage hole reporting green.
///
/// `heads` is [`ChainReport::heads`] from a passing [`chain`] call (the caller runs integrity first).
/// Every attestation present must pass; a single failure aborts with `Err` (a forged one in the mix is an
/// attack, even if others pass).
///
/// # design-a — every v2 record self-verifies (Phase 4)
///
/// The attestation (design-b) covers a *prefix* and only exists if the runtime emitted one; a payload
/// rewrite in an unattested tail would slip past it. So under `--issuer` this ALSO recomputes each v2
/// `DECISION_SEALED`'s digest from its structural columns (spec §Record digest) and compares it to the
/// wire `digest` (tag 19): a mismatch is a **payload rewrite** (a column changed after sealing; the link's
/// triple still hashes, but the digest no longer matches the payload). And a v2 record that lacks a
/// non-empty `ciphertext_digest` (tag 10) is REFUSED — a **tag-10 strip / downgrade**, the exact hole
/// "cannot recompute ⇒ not a failure" would leave open. v1 records are not recomputable and are skipped,
/// never failed (selected by `schema_version`, never silently green on a version we cannot recompute).
pub fn verify_authenticity(
    events: &[Event],
    heads: &[Vec<u8>],
    pinned_aid: &str,
) -> Result<IssuerReport, String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key = aid_to_key(pinned_aid)?;
    let vk = VerifyingKey::from_bytes(&key).map_err(|e| format!("bad issuer key: {e}"))?;

    let mut attestations = 0usize;
    let mut covered_prefix = 0u64;
    let mut records_recomputed = 0usize;

    // design-a: every v2 DECISION_SEALED recomputes; a v2 record with no ciphertext_digest is a strip.
    for e in events {
        let Some(d) = e.decision.as_ref() else {
            continue;
        };
        if d.schema_version < 2 {
            continue; // v1: the historical digest is not stream-recomputable — link-only, not a failure.
        }
        if d.ciphertext_digest.is_empty() {
            return Err(format!(
                "a v2 DECISION_SEALED ({}) carries NO ciphertext_digest (tag 10).\n  \
                 A v2 record is required to commit its SHA256(ciphertext); an absent tag 10 on a covered \
                 record is a strip/downgrade attack (rewrite a field, drop the commitment, leave the \
                 (prev,digest,checksum) triple intact so the signed head still matches) — refused, not \
                 treated as cannot-recompute-so-pass.",
                d.decision_id
            ));
        }
        // Compare against the event's own digest (tag 19). A chained DECISION_SEALED always carries it;
        // if it is absent the integrity pass already flagged the event UNVERIFIABLE, so there is nothing to
        // compare here (do not invent a pass).
        let Some(wire_digest) = e.digest.as_ref() else {
            continue;
        };
        let recomputed = record_digest_v2(d);
        if wire_digest.as_slice() != recomputed {
            return Err(format!(
                "a v2 DECISION_SEALED ({}) does NOT match its own digest.\n  \
                 recomputed {}\n  wire       {}\n  \
                 A structural column (e.g. outcome) was rewritten after sealing: the chain link still \
                 hashes, but the record digest no longer matches the payload it commits to.",
                d.decision_id,
                hex(&recomputed),
                hex(wire_digest)
            ));
        }
        records_recomputed += 1;
    }

    for e in events {
        let Some(a) = e.attestation.as_ref() else {
            continue;
        };
        // The pin, before any signature work (as for the erasure cert).
        if a.issuer_aid != pinned_aid {
            return Err(format!(
                "a CHAIN_HEAD_ATTESTATION names issuer '{}', but you pinned '{}'.\n  \
                 A signature only means something relative to a key you already trusted; deriving the key \
                 from the attestation's own issuer would let a forgery verify against its forger.",
                a.issuer_aid, pinned_aid
            ));
        }
        let sig: [u8; 64] = a
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "attestation signature is not 64 bytes".to_string())?;
        vk.verify(
            &chain_head_attestation_payload(a),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| {
            format!(
                "a CHAIN_HEAD_ATTESTATION over len {} does not verify against the pinned issuer's key. \
                 The attestation is forged, or its (len, head) was altered after signing.",
                a.attested_len
            )
        })?;
        // Head-at-position: the attested head must be the running head after `attested_len` links. An
        // attestation over a prefix the stream never reaches has no head to check against — a FAIL, not a
        // silent pass (it cannot be attesting *this* stream).
        let want = heads.get(a.attested_len as usize).ok_or_else(|| {
            format!(
                "a CHAIN_HEAD_ATTESTATION attests len {}, but the stream has only {} chained links — it \
                 cannot be covering this chain.",
                a.attested_len,
                heads.len().saturating_sub(1)
            )
        })?;
        if want != &a.attested_head {
            return Err(format!(
                "a CHAIN_HEAD_ATTESTATION attests head {} at len {}, but this chain's head there is {}.\n  \
                 The signature is authentic, so this is an issuer-signed head SPLICED onto a different \
                 (forged or diverged) chain — exactly what the position check exists to catch.",
                hex(&a.attested_head),
                a.attested_len,
                hex(want)
            ));
        }
        attestations += 1;
        covered_prefix = covered_prefix.max(a.attested_len);
    }

    if attestations == 0 {
        return Err(
            "--issuer was given, but the stream carries NO chain-head attestation.\n  \
             An issuer-signed head cannot be minted without the issuer key, so its absence over a stream \
             you asked to authenticate is the fabricated-chain tell — refusing rather than reporting a \
             green chain no issuer ever signed."
                .to_string(),
        );
    }
    Ok(IssuerReport {
        attestations,
        covered_prefix,
        records_recomputed,
    })
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin `chain_head_attestation_payload`'s framing byte-for-byte against the runtime's committed
    /// `chain_head_attestation` KAT (seam-client/tests/conformance_vectors.json): the precomputed signature
    /// must verify against the KAT issuer key over our recomputed digest. A single wrong `frame`/`le`/order
    /// makes the digest total-mismatch and the signature fail — so this catches any framing drift, and is
    /// the independent proof (nothing of Seam's is linked) that we transcribed the spec correctly.
    #[test]
    fn attestation_payload_matches_the_runtime_kat() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // KAT issuer AID (short form, as signed) and its precomputed signature.
        let issuer_aid = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
        let att = Attestation {
            attested_len: 1000,
            attested_head: vec![0xab; 32],
            attested_at: 1_700_000_000_000,
            issuer_aid: issuer_aid.to_string(),
            digest_schema: 2,
            signature: hex_to_bytes(
                "5169458689b92af81fbbfbd1bd07aff82cb68993919837232a1b54204a0e565e\
                 e58791b607c40a48dae6a9dbf8c6129e7028fdbd0e14095d7a4c0a99c775a90a",
            ),
        };
        let key = aid_to_key(issuer_aid).unwrap();
        let vk = VerifyingKey::from_bytes(&key).unwrap();
        let sig: [u8; 64] = att.signature.as_slice().try_into().unwrap();
        vk.verify(
            &chain_head_attestation_payload(&att),
            &Signature::from_bytes(&sig),
        )
        .expect("the KAT signature must verify against our recomputed digest — framing is correct");
    }

    /// A one-bit change to any framed field must break the KAT signature (proves the framing is not lax).
    #[test]
    fn attestation_payload_is_tamper_sensitive() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let issuer_aid = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
        let mut att = Attestation {
            attested_len: 1000,
            attested_head: vec![0xab; 32],
            attested_at: 1_700_000_000_000,
            issuer_aid: issuer_aid.to_string(),
            digest_schema: 2,
            signature: hex_to_bytes(
                "5169458689b92af81fbbfbd1bd07aff82cb68993919837232a1b54204a0e565e\
                 e58791b607c40a48dae6a9dbf8c6129e7028fdbd0e14095d7a4c0a99c775a90a",
            ),
        };
        att.attested_len += 1; // one field off
        let key = aid_to_key(issuer_aid).unwrap();
        let vk = VerifyingKey::from_bytes(&key).unwrap();
        let sig: [u8; 64] = att.signature.as_slice().try_into().unwrap();
        assert!(
            vk.verify(
                &chain_head_attestation_payload(&att),
                &Signature::from_bytes(&sig)
            )
            .is_err(),
            "a tampered attested_len must not verify"
        );
    }

    /// Pin `record_digest_v2`'s framing byte-for-byte against the runtime's committed `record_digest_v2`
    /// KAT (seam-client/tests/conformance_vectors.json). A single wrong `frame`/`opt`/`le`/order produces a
    /// total-mismatch digest — so this catches any drift and independently proves (nothing of Seam's is
    /// linked) that design-a's recompute is exactly the runtime's. `policy_version`/`supersedes` are `None`
    /// here, exercising the `opt` absent-byte; `mode` is `Some`, exercising the present branch.
    #[test]
    fn record_digest_v2_matches_the_runtime_kat() {
        let d = Decision {
            decision_id: "dec:conformance".into(),
            tenant: "acme".into(),
            namespace: "fraud".into(),
            mode: Some("decision.v1".into()),
            policy_version: None,
            outcome: "Resolved".into(),
            supersedes: None,
            sealed_at: 1_700_000_000_000,
            schema_version: 2,
            ciphertext_digest: hex_to_bytes(
                "67d9f6952981d85f7a2cabb0d5468e6934dc63ec55b480f18339277afc7635a6",
            ),
        };
        assert_eq!(
            hex(&record_digest_v2(&d)),
            "3817863521537d347c112bb95d7960d3d9f3007ee041f59c87bcaaf88ac40785",
            "the digest-v2 framing must match the runtime KAT byte-for-byte"
        );
    }

    /// `None` and `Some("")` must NOT collapse — the `opt` presence byte makes them distinct preimages.
    #[test]
    fn record_digest_v2_distinguishes_none_from_empty_string() {
        let base = Decision {
            decision_id: "d".into(),
            tenant: "t".into(),
            namespace: "n".into(),
            mode: None,
            policy_version: None,
            outcome: "Resolved".into(),
            supersedes: None,
            sealed_at: 1,
            schema_version: 2,
            ciphertext_digest: vec![0u8; 32],
        };
        let mut with_empty = base.clone();
        with_empty.mode = Some(String::new());
        assert_ne!(
            record_digest_v2(&base),
            record_digest_v2(&with_empty),
            "mode: None must differ from mode: Some(\"\")"
        );
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
