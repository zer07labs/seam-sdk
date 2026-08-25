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
    /// The number of v2/v3 `DECISION_SEALED` records whose record digest recomputed and matched the wire
    /// `digest` (design-a). v1 records are link-only (not recomputable) and not counted; a version this
    /// build does not implement is refused outright rather than left uncounted.
    pub records_recomputed: usize,
}

/// Every v3 sub-digest is a SHA-256, so exactly this many bytes. A wire value of any other length
/// is malformed, not a shorter digest.
const V3_DIGEST_LEN: usize = 32;

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

/// A mandatory v3 sub-digest (wire tag 11 or 12): present, and exactly 32 bytes.
///
/// Absent is a **strip**, and the spec is explicit that it must be reported *distinctly* from a
/// digest mismatch — "someone removed a field" and "someone rewrote one" are different events with
/// different responses, and a verifier that blurs them costs an operator the one clue that
/// distinguishes them. Wrong-length is refused rather than hashed for the same reason: hashing a
/// malformed field would produce a well-formed digest that fails the comparison, surfacing a
/// MALFORMED record as though it had been REWRITTEN.
fn v3_required<'a>(
    name: &str,
    tag: u32,
    value: &'a [u8],
    decision_id: &str,
) -> Result<&'a [u8], String> {
    // `len == 0` IS absence here — a total mapping over any bytes a decoder can be handed, including
    // an explicitly-encoded zero-length field (spec §"Presence on the wire"). A conforming producer
    // never emits one; proto3 still obliges us to accept and classify it, and the classification is
    // "absent", which on tags 11/12 means STRIP.
    match if value.is_empty() { None } else { Some(value) } {
        None => Err(format!(
            "a v3 DECISION_SEALED ({decision_id}) carries NO {name} (wire tag {tag}).\n  \
             The v3 record-digest formula requires it. This is a STRIP, not a digest mismatch: the \
             record is REFUSED — not defaulted to an empty digest, and not recomputed under the v2 \
             formula. Falling back to v2 is what a downgrade attack wants; defaulting to empty is \
             what makes 'nobody participated' indistinguishable from 'somebody deleted the field'."
        )),
        Some(b) if b.len() != V3_DIGEST_LEN => Err(format!(
            "a v3 DECISION_SEALED ({decision_id}) carries a MALFORMED {name} (wire tag {tag}): {} \
             bytes, not {V3_DIGEST_LEN}.\n  \
             Refused rather than hashed. Hashing it would yield a well-formed digest that fails the \
             comparison, reporting a malformed field as though the record had been rewritten.",
            b.len()
        )),
        Some(b) => Ok(b),
    }
}

/// The optional v3 sub-digest (wire tag 13). Absent is LEGITIMATE — it means no policy was bound to
/// that commitment, today's common case — so absence is data here, carried into the preimage by the
/// `opt` presence byte rather than refused. Present-but-wrong-length is still malformed.
fn v3_optional<'a>(
    name: &str,
    tag: u32,
    value: &'a [u8],
    decision_id: &str,
) -> Result<Option<&'a [u8]>, String> {
    // Same total `len == 0` rule as `v3_required`, but here absence is a legitimate value rather than
    // a strip: it frames as `opt(None)`. An explicitly-encoded `0x6a 0x00` from a non-conforming
    // producer therefore verifies GREEN, identically to an omitted field — it must NOT be refused as
    // malformed, which is what treating it as `Some(b"")` did.
    match if value.is_empty() { None } else { Some(value) } {
        None => Ok(None),
        Some(b) if b.len() != V3_DIGEST_LEN => Err(format!(
            "a v3 DECISION_SEALED ({decision_id}) carries a MALFORMED {name} (wire tag {tag}): \
             present but {} bytes, not {V3_DIGEST_LEN}.\n  \
             Absent is legitimate (no policy was bound); present-and-wrong-length is not, and is \
             refused rather than hashed.",
            b.len()
        )),
        Some(b) => Ok(Some(b)),
    }
}

/// The 32-byte record digest a v3 `DECISION_SEALED` commits to — `seam.audit.record-digest.v3`.
///
/// Transcribed from `seam-event.v1.md` §Record digest (v3). v3 is v2 plus the three columns carrying
/// the product's actual claims: what context the decision consumed, who participated, and which
/// policy rules gated the commitment. They arrive as **opaque 32-byte sub-digests on the wire**
/// (tags 11/12/13); their internal formulas belong to the runtime and to auditors, and are
/// deliberately not reimplemented here — this is a wire-input recompute, exactly as
/// [`record_digest_v2`] is.
///
/// Three things the spec singles out as easy to get wrong:
///
/// * **Digest slots are offset by one from the proto tags.** `context_digest` is preimage slot 10 but
///   wire tag 11. The new slots are *inserted before* `schema_version`, never appended after it — a
///   verifier selects the whole formula by `schema_version`, so position is fixed by the spec rather
///   than by append order.
/// * **Slots 10 and 11 are framed; slot 12 is `opt`ed.** The asymmetry is deliberate: framing the two
///   mandatory digests is precisely what stops "no participants" from aliasing with "field stripped".
/// * **`None` is not `Some(&[])`.** `opt(None)` is one byte, `opt(Some(&[]))` is five.
///
/// The `frame`/`opt` closures are duplicated from [`record_digest_v2`] rather than shared, on
/// purpose: v2's bytes are frozen forever, and a shared helper would put them behind a refactor
/// surface. Duplication is the safety property here.
fn record_digest_v3(d: &Decision) -> Result<[u8; 32], String> {
    let context_digest = v3_required(
        "context_digest",
        11,
        &d.context_digest,
        &d.decision_id,
    )?;
    let participation_digest = v3_required(
        "participation_digest",
        12,
        &d.participation_digest,
        &d.decision_id,
    )?;
    let policy_rules_digest = v3_optional(
        "policy_rules_digest",
        13,
        &d.policy_rules_digest,
        &d.decision_id,
    )?;

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
    let opt_bytes = |buf: &mut Vec<u8>, x: Option<&[u8]>| match x {
        None => buf.push(0x00),
        Some(b) => {
            buf.push(0x01);
            buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
            buf.extend_from_slice(b);
        }
    };
    frame(&mut buf, b"seam.audit.record-digest.v3");
    frame(&mut buf, d.decision_id.as_bytes());
    frame(&mut buf, d.tenant.as_bytes());
    frame(&mut buf, d.namespace.as_bytes());
    frame(&mut buf, &d.ciphertext_digest);
    frame(&mut buf, &d.sealed_at.to_le_bytes());
    frame(&mut buf, d.outcome.as_bytes());
    opt(&mut buf, d.mode.as_deref());
    opt(&mut buf, d.policy_version.as_deref());
    opt(&mut buf, d.supersedes.as_deref());
    frame(&mut buf, context_digest);
    frame(&mut buf, participation_digest);
    opt_bytes(&mut buf, policy_rules_digest);
    frame(&mut buf, &d.schema_version.to_le_bytes());
    Ok(Sha256::digest(&buf).into())
}

/// Verify every `CHAIN_HEAD_ATTESTATION` in the stream against the **pinned** issuer AIDs (A14, design-b).
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
    pinned_aids: &[String],
) -> Result<IssuerReport, String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // `--issuer` is repeatable: a chain that spans an issuer-key ROTATION carries attestations from the
    // retired key AND the new one, and each must verify against SOME AID the caller pinned. Every pinned
    // AID must be well-formed up front — a typo'd pin silently matching nothing would weaken the gate.
    let keys: Vec<(&str, VerifyingKey)> = pinned_aids
        .iter()
        .map(|aid| {
            let key = aid_to_key(aid)?;
            let vk = VerifyingKey::from_bytes(&key).map_err(|e| format!("bad issuer key: {e}"))?;
            Ok((aid.as_str(), vk))
        })
        .collect::<Result<_, String>>()?;

    let mut attestations = 0usize;
    let mut covered_prefix = 0u64;
    let mut records_recomputed = 0usize;

    // design-a: every v2/v3 DECISION_SEALED recomputes; a covered record with no ciphertext_digest is a
    // strip, and a v3 record missing tag 11 or 12 is a strip too — reported distinctly from a mismatch.
    for e in events {
        let Some(d) = e.decision.as_ref() else {
            continue;
        };
        if d.schema_version < 2 {
            // v1 is link-only: its historical digest is not stream-recomputable, so it is skipped
            // rather than failed. That skip is a hole an attacker can climb into — rewrite a column
            // AND set schema_version to 1, and the record is waved through — so the exit is guarded by
            // the one thing a genuine v1 record cannot fake.
            //
            // The spec is unambiguous about what a v1 payload looks like: `ciphertext_digest` "is
            // absent (no wire bytes) only on `schema_version = 1` payloads", and tags 11/12/13 arrived
            // with v3. A payload that declares v1 while CARRYING one of those columns is therefore not
            // a v1 record at all — it is a covered record wearing v1's exemption, which is the same
            // strip/downgrade shape as dropping tag 10 and gets the same answer.
            //
            // Note this is the ONE downgrade direction that has to be caught structurally: every other
            // version is dispatched to a formula and fails the comparison. A downgrade INTO the skip
            // is invisible to the recompute by construction, because the whole point of the skip is
            // that no recompute happens.
            let smuggled = [
                ("ciphertext_digest", 10, !d.ciphertext_digest.is_empty()),
                ("context_digest", 11, !d.context_digest.is_empty()),
                ("participation_digest", 12, !d.participation_digest.is_empty()),
                ("policy_rules_digest", 13, !d.policy_rules_digest.is_empty()),
            ];
            if let Some((name, tag, _)) = smuggled.iter().find(|(_, _, present)| *present) {
                return Err(format!(
                    "a DECISION_SEALED ({}) declares schema_version {} but carries {name} (wire tag \
                     {tag}), which only exists on schema_version >= 2.\n  \
                     A genuine v1 record has none of these columns. Declaring v1 is what exempts a \
                     record from the digest recompute, so a covered record wearing v1's version number \
                     is a DOWNGRADE — rewrite a column, relabel the version, and the recompute never \
                     runs. Refused rather than skipped.",
                    d.decision_id, d.schema_version
                ));
            }
            continue;
        }
        // A version this build does not implement is REFUSED, never skipped.
        //
        // Before B3 this arm did not exist, and it was not merely a missing feature: a v3 record fell
        // through to the v2 formula, mismatched (v3 binds three more slots), and was reported as "a
        // structural column was rewritten after sealing". That is a false accusation with a real
        // cost — an operator would go looking for a tamper that never happened. Skipping instead
        // would be worse: "I cannot check this, so it passes" is precisely the shape of a downgrade.
        // The only honest answer to an unknown version is to say so and fail.
        if d.schema_version > 3 {
            return Err(format!(
                "a DECISION_SEALED ({}) declares schema_version {}, which is NEWER THAN THIS \
                 VERIFIER.\n  \
                 This build implements the v2 and v3 record-digest formulas; it cannot prove a record \
                 matches a digest computed under a formula it does not have. Refused rather than \
                 skipped — treating an unknown version as cannot-recompute-so-pass is how a downgrade \
                 gets through. Upgrade seam-verify to a build that implements schema_version {}.",
                d.decision_id, d.schema_version, d.schema_version
            ));
        }
        if d.ciphertext_digest.is_empty() {
            return Err(format!(
                "a v{} DECISION_SEALED ({}) carries NO ciphertext_digest (tag 10).\n  \
                 Every covered record (schema_version >= 2) is required to commit its SHA256(ciphertext); \
                 an absent tag 10 on a covered \
                 record is a strip/downgrade attack (rewrite a field, drop the commitment, leave the \
                 (prev,digest,checksum) triple intact so the signed head still matches) — refused, not \
                 treated as cannot-recompute-so-pass.",
                d.schema_version, d.decision_id
            ));
        }
        // Compare against the event's own digest (tag 19). A chained DECISION_SEALED always carries it;
        // if it is absent the integrity pass already flagged the event UNVERIFIABLE, so there is nothing to
        // compare here (do not invent a pass).
        let Some(wire_digest) = e.digest.as_ref() else {
            continue;
        };
        // The formula is selected by `schema_version`, never guessed and never tried in turn: a
        // verifier that fell back from v3 to v2 on mismatch would hand an attacker a downgrade for
        // free. The `?` below is what keeps a STRIP distinct from a MISMATCH — a strip leaves through
        // the error channel with its own wording, a mismatch is the inequality tested underneath.
        let recomputed = match d.schema_version {
            2 => record_digest_v2(d),
            3 => record_digest_v3(d)?,
            // Unreachable: `< 2` continued above and `> 3` returned above. Written as a refusal
            // rather than `unreachable!()` so that widening the bounds without adding an arm fails
            // loudly instead of panicking a CLI in an auditor's hands.
            v => return Err(format!("no record-digest formula for schema_version {v}")),
        };
        if wire_digest.as_slice() != recomputed {
            return Err(format!(
                "a v{} DECISION_SEALED ({}) does NOT match its own digest.\n  \
                 recomputed {}\n  wire       {}\n  \
                 A structural column (e.g. outcome) was rewritten after sealing: the chain link still \
                 hashes, but the record digest no longer matches the payload it commits to.",
                d.schema_version,
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
        // The pin, before any signature work (as for the erasure cert): the attestation must NAME one of
        // the AIDs the caller pinned. An issuer outside the pinned set = FAIL, exactly as a single-pin
        // mismatch always was.
        let Some((_, vk)) = keys.iter().find(|(aid, _)| *aid == a.issuer_aid) else {
            return Err(format!(
                "a CHAIN_HEAD_ATTESTATION names issuer '{}', but you pinned [{}].\n  \
                 A signature only means something relative to a key you already trusted; deriving the key \
                 from the attestation's own issuer would let a forgery verify against its forger.",
                a.issuer_aid,
                pinned_aids.join(", ")
            ));
        };
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
            // v2 carries none of the B3 columns. Present only because the struct gained the fields;
            // no v2 input or expectation in this test changed.
            context_digest: Vec::new(),
            participation_digest: Vec::new(),
            policy_rules_digest: Vec::new(),
        };
        assert_eq!(
            hex(&record_digest_v2(&d)),
            "3817863521537d347c112bb95d7960d3d9f3007ee041f59c87bcaaf88ac40785",
            "the digest-v2 framing must match the runtime KAT byte-for-byte"
        );
    }

    /// A fully-populated v3 `Decision`, for the unit tests below.
    fn v3_decision() -> Decision {
        Decision {
            decision_id: "dec:v3".into(),
            tenant: "acme".into(),
            namespace: "fraud".into(),
            mode: Some("decision.v1".into()),
            policy_version: Some("policy-7".into()),
            outcome: "Resolved".into(),
            supersedes: Some("dec:prior".into()),
            sealed_at: 1_700_000_000_000,
            schema_version: 3,
            ciphertext_digest: vec![0x44; 32],
            context_digest: vec![0x11; 32],
            participation_digest: vec![0x22; 32],
            policy_rules_digest: vec![0x33; 32],
        }
    }

    /// The v3 distinctions, as unit tests rather than only as vectors.
    ///
    /// `tests/conformance.rs` covers these through the committed cross-repo vectors, but it is in
    /// `Cargo.toml`'s package `exclude` — it reads `../conformance/vectors.json`, which a standalone
    /// published tarball does not have. Without these, the published crate would ship a v3
    /// implementation whose distinguishing behaviour nothing in the package tests. Someone who
    /// `cargo install`s this and runs `cargo test` should be able to see the formula defended.
    #[test]
    fn record_digest_v3_distinguishes_none_from_empty_string() {
        let base = v3_decision();
        let mut none = base.clone();
        none.mode = None;
        let mut empty = base.clone();
        empty.mode = Some(String::new());
        assert_ne!(
            record_digest_v3(&none).unwrap(),
            record_digest_v3(&empty).unwrap(),
            "`opt(None)` is one byte and `opt(Some(\"\"))` is five — a present-but-empty mode is DATA"
        );
    }

    /// An explicitly-encoded ZERO-LENGTH tag 13 must verify GREEN, identically to an omitted one.
    ///
    /// This is the case a hostile producer can actually send. A conforming encoder never emits it —
    /// prost skips a singular scalar at its default — but proto3 *obliges a decoder to accept* an
    /// explicitly-encoded default, so `0x6a 0x00` can be handed to this verifier. `seam-event.v1.md`
    /// §"Presence on the wire" therefore states the consumer rule as a TOTAL mapping over every byte
    /// sequence a decoder can be handed: on tags 10-13, `len == 0` means absent **however the bytes
    /// arose**. For tag 13 absent is legitimate (no policy bound) and frames as `opt(None)`.
    ///
    /// This test is in two halves on purpose. The first asserts what the DECODER actually produces
    /// from those bytes — without it the second half would be asserting a premise rather than a
    /// behaviour, and would keep passing if the wire types changed underneath it.
    #[test]
    fn an_explicitly_encoded_zero_length_policy_rules_digest_is_absent_not_malformed() {
        use prost::Message;

        let pb = crate::wire::DecisionSealedPb {
            decision_id: "dec:v3".into(),
            tenant: "acme".into(),
            namespace: "fraud".into(),
            mode: Some("decision.v1".into()),
            policy_version: Some("policy-7".into()),
            outcome: "Resolved".into(),
            supersedes: Some("dec:prior".into()),
            sealed_at: 1_700_000_000_000,
            schema_version: 3,
            ciphertext_digest: vec![0x44; 32],
            context_digest: vec![0x11; 32],
            participation_digest: vec![0x22; 32],
            policy_rules_digest: Vec::new(),
        };

        let mut bytes = Vec::new();
        pb.encode(&mut bytes).expect("encode");
        // A conforming encoder emits nothing for tag 13 here...
        assert!(
            !bytes.windows(2).any(|w| w == [0x6a, 0x00]),
            "the encoder must not put a zero-length tag 13 on the wire"
        );
        // ...but a non-conforming one can append it, and proto3 says we must accept it.
        bytes.extend_from_slice(&[0x6a, 0x00]);
        let decoded = crate::wire::DecisionSealedPb::decode(&bytes[..]).expect("decode");
        assert!(
            decoded.policy_rules_digest.is_empty(),
            "the crafted bytes must decode to an empty tag 13 — otherwise this test proves nothing"
        );

        // The verdict must be identical to the omitted case, not a MALFORMED refusal.
        let mut crafted = v3_decision();
        crafted.policy_rules_digest = decoded.policy_rules_digest;
        let mut omitted = v3_decision();
        omitted.policy_rules_digest = Vec::new();

        let c = record_digest_v3(&crafted)
            .expect("an explicitly-encoded zero-length tag 13 is ABSENT, not malformed");
        let o = record_digest_v3(&omitted).expect("an omitted tag 13 is absent");
        assert_eq!(c, o, "`len == 0` is absence however the bytes arose");
    }

    /// The same rule, in the direction that must NOT change: tags 11/12 are mandatory on v3, so a
    /// zero-length occurrence is a STRIP and is still refused.
    #[test]
    fn an_explicitly_encoded_zero_length_mandatory_digest_is_still_refused() {
        for (name, set) in [
            ("context_digest", 0usize),
            ("participation_digest", 1usize),
        ] {
            let mut d = v3_decision();
            if set == 0 {
                d.context_digest = Vec::new();
            } else {
                d.participation_digest = Vec::new();
            }
            let err = record_digest_v3(&d)
                .expect_err("a zero-length mandatory digest must be refused, never hashed");
            assert!(err.contains(name), "the refusal must name {name}: {err}");
        }
    }

    /// Tag 13 is `opt`ed, so absent and present must differ — and absent must NOT equal a 32-zero-byte
    /// digest, which is what an implementation that framed the slot (or defaulted absence) would produce.
    #[test]
    fn record_digest_v3_distinguishes_an_absent_policy_rules_digest_from_a_present_one() {
        let base = v3_decision();
        let mut absent = base.clone();
        absent.policy_rules_digest = Vec::new();
        let mut zeros = base.clone();
        zeros.policy_rules_digest = vec![0u8; 32];

        let a = record_digest_v3(&absent).unwrap();
        let z = record_digest_v3(&zeros).unwrap();
        let s = record_digest_v3(&base).unwrap();
        assert_ne!(a, z, "absent must not equal a zeroed digest");
        assert_ne!(a, s);
        assert_ne!(z, s);
    }

    /// The two mandatory sub-digests occupy adjacent, identically-framed, identically-sized slots, so a
    /// swap produces a perfectly well-formed preimage. Only distinct values make it detectable.
    #[test]
    fn record_digest_v3_binds_context_and_participation_to_their_own_slots() {
        let base = v3_decision();
        let mut swapped = base.clone();
        std::mem::swap(
            &mut swapped.context_digest,
            &mut swapped.participation_digest,
        );
        assert_ne!(
            record_digest_v3(&base).unwrap(),
            record_digest_v3(&swapped).unwrap(),
            "swapping tags 11 and 12 did not change the digest — the two slots are interchangeable"
        );
    }

    /// A strip is an `Err`, a mismatch is an unequal `Ok` — the distinction is structural, so no caller
    /// can conflate them however it treats the message text. Both refusals must also NAME the field and
    /// its wire tag, and must NOT borrow the vocabulary of a mismatch.
    #[test]
    fn a_stripped_or_malformed_v3_sub_digest_is_refused_not_hashed() {
        let base = v3_decision();
        for (field, tag, mutate) in [
            (
                "context_digest",
                11,
                (|d: &mut Decision| d.context_digest = Vec::new()) as fn(&mut Decision),
            ),
            ("participation_digest", 12, |d: &mut Decision| {
                d.participation_digest = Vec::new()
            }),
            ("context_digest", 11, |d: &mut Decision| {
                d.context_digest = vec![0x11; 31]
            }),
            ("participation_digest", 12, |d: &mut Decision| {
                d.participation_digest = Vec::new()
            }),
            ("policy_rules_digest", 13, |d: &mut Decision| {
                d.policy_rules_digest = vec![0x33; 33]
            }),
        ] {
            let mut d = base.clone();
            mutate(&mut d);
            let err = record_digest_v3(&d).expect_err(&format!("{field} must be refused"));
            assert!(
                err.contains(field),
                "the refusal must name the field: {err}"
            );
            assert!(
                err.contains(&format!("wire tag {tag}")),
                "the refusal must name the tag: {err}"
            );
            assert!(
                !err.contains("does NOT match its own digest"),
                "a strip/malformed field is being described as a mismatch: {err}"
            );
        }
        // And the mirror: a rewritten column still RETURNS a digest, for the caller to compare.
        let mut rewritten = base.clone();
        rewritten.outcome = "Denied".into();
        assert_ne!(
            record_digest_v3(&rewritten).unwrap(),
            record_digest_v3(&base).unwrap()
        );
    }

    /// v2 and v3 must not collide on the columns they share — the domain tag carries the version, so
    /// even the same structural columns cannot verify under the wrong formula.
    #[test]
    fn record_digest_v3_does_not_collide_with_v2() {
        let d = v3_decision();
        let mut as_v2 = d.clone();
        as_v2.schema_version = 3; // same version field; only the FORMULA differs
        assert_ne!(
            record_digest_v3(&d).unwrap().to_vec(),
            record_digest_v2(&as_v2).to_vec(),
            "the v3 domain tag is not separating the two formulas"
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
            context_digest: Vec::new(),
            participation_digest: Vec::new(),
            policy_rules_digest: Vec::new(),
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
