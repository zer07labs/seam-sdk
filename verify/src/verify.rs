//! The two things worth verifying, implemented from the published specs alone.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::entry;
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
    /// **Spec §Versioning — unverified CONTENT.** `(seq, kind)` for every verified link whose `kind`
    /// this build does not model ([`wire::MODELLED_KINDS`]): a kind from a later additive revision of
    /// `seam-event.v1`. Their linkage is fully checked and they advance the head like any other link —
    /// the spec requires exactly that, since the link check needs no payload semantics. What cannot be
    /// checked is the *content*: there is no payload model to recompute the `digest` from, so the
    /// digest is known to commit to the head and not known to commit to anything in particular.
    ///
    /// §Versioning makes disclosing them a MUST ("MUST disclose such events as unverified content …
    /// and MUST NOT fold them into a green claim"), and this field is the only thing that can.
    /// `links - records_recomputed` cannot: that difference is ALREADY non-zero on a perfectly healthy
    /// stream, for two entirely benign reasons that have nothing to do with unmodelled kinds —
    /// `AUDIT_ENTRY`/`ERASURE_CERTIFICATE`/`CHAIN_HEAD_ATTESTATION` are chained kinds that legitimately
    /// never recompute, and v1 `DECISION_SEALED` records are link-only and deliberately skipped. A
    /// reader doing that subtraction cannot tell a kind we model and choose not to recompute from a
    /// kind we could not parse at all, which is the precise distinction the clause asks to be
    /// disclosed. So it is counted here, separately, at the point the link is verified.
    pub unmodelled: Vec<(u64, String)>,
    pub head: Vec<u8>,
    /// The running head after each link, in order: `heads[0]` is genesis, `heads[k]` is the head after
    /// `k` chained links. Its length is `links + 1`. This is what an attestation's `(attested_len,
    /// attested_head)` is checked against — `heads[attested_len]` must equal the attested head.
    pub heads: Vec<Vec<u8>>,
    /// The highest `DECISION_SEALED.schema_version` seen in the first `k` chained links, in order:
    /// `max_schema_by_link[0]` is 0 (empty prefix), `max_schema_by_link[k]` covers `k` links. Same
    /// length and same indexing as `heads`, deliberately — spec clause (e) is a statement about the
    /// **attested prefix**, exactly the span `heads` already indexes, so the two are maintained side by
    /// side in `chain()` rather than the max being re-derived in a second pass that could disagree
    /// about which events are links.
    ///
    /// A link carrying no decision (or a non-`DECISION_SEALED` chained kind) contributes 0, so a prefix
    /// with no sealed records has max 0 and clause (e) cannot fire on it — the rule is existential over
    /// the covered records, not a claim about the prefix's length.
    pub max_schema_by_link: Vec<u32>,
    /// **Spec clause (f) — the anchored start.** The absolute position this report's window begins
    /// at: `0` for a genesis start (produced by [`chain`]), or an anchor's `attested_len` for an
    /// anchored one (produced by [`chain_anchored`]). `heads`/`max_schema_by_link` are indexed
    /// **relative to this** — `heads[k]` is the head after `k` links PAST the start, at absolute
    /// position `base_len + k` — never by the absolute position itself.
    ///
    /// **Multi-tenant note (U-RT-1/U-RT-3):** this field, like `head`/`heads`/`links`/
    /// `max_schema_by_link` above, is the SINGLE-TENANT VIEW — it mirrors [`TenantChain::base_len`]
    /// for the one tenant present when [`ChainReport::tenants`] has exactly one entry (true for
    /// every window this crate verified before per-tenant chains existed, and for any genuinely
    /// single-tenant window today). For a window spanning more than one tenant these top-level
    /// fields fall back to the genesis sentinel (`0`, `[GENESIS]`, `0`, `[0]`) — a caller verifying a
    /// multi-tenant window must read [`ChainReport::tenants`] instead; the old scalar fields have no
    /// single honest value to report there.
    pub base_len: u64,
    /// **Per-tenant chain state (U-RT-1/U-RT-3), keyed by [`crate::wire::Event::tenant`].** The hash
    /// chain is walked independently per tenant — each tenant chains against its own prior entry,
    /// from its own genesis (or its own anchor), never against another tenant's. See
    /// [`chain_by_tenant`] for the walk itself and [`TenantChain`] for what each entry holds.
    pub tenants: BTreeMap<String, TenantChain>,
    /// **Spec clause (f0).** An anchor was supplied for a tenant that this window contains NO
    /// chained event for — i.e. a tenant in the anchors map passed to [`chain_by_tenant`] that never
    /// made it into [`ChainReport::tenants`]. Non-empty here means the caller asked to authenticate a
    /// start the window does not contain, and `cmd_chain` refuses outright rather than silently
    /// ignoring the anchor (`chain_by_tenant` itself does not refuse — its caller decides, the same
    /// division of labour genesis-vs-anchored validation already has between [`verify_anchor`] and
    /// [`chain_anchored`]). Maps tenant name to the anchor's `attested_len`, for the refusal message.
    pub unconsumed_anchors: BTreeMap<String, u64>,
}

/// One tenant's independent hash-chain state within a [`ChainReport`] — the per-tenant analogue of
/// the single running head this crate used before U-RT-1/U-RT-3 partitioned the chain. Every field
/// has the exact same meaning [`ChainReport`]'s own (now mirrored) fields always had, just scoped to
/// this one tenant's own chain instead of the whole interleaved stream.
#[derive(Clone)]
pub struct TenantChain {
    pub head: Vec<u8>,
    pub links: usize,
    pub heads: Vec<Vec<u8>>,
    pub max_schema_by_link: Vec<u32>,
    pub base_len: u64,
}

/// **Payload binds to kind** (spec §Ordering & integrity, code-health A4): *"each payload field belongs
/// to exactly one kind, so an event carries only its own kind's payload, and a known kind carries it. A
/// known advisory kind (or the chain anchor) that carries `digest`/`checksum` is refused, not linked."*
///
/// Three rules, in this order, mirroring the runtime verifier's `check_kind_payload` so the two refuse
/// the same streams with the same markers:
///
/// 1. No payload is present that belongs to a kind other than `e.kind` (`KIND/PAYLOAD MISMATCH`).
/// 2. A **known** kind — one of the eleven payload owners below — carries its own payload
///    (`KIND/PAYLOAD MISMATCH`). An unknown, future kind may carry none of the known ones (rule 1), and
///    carrying nothing is not a mismatch: it is a link like any other, disclosed as unmodelled.
/// 3. An [`Event::is_advisory`] event — a known advisory kind, or the `chain_anchor` audit entry —
///    carries neither `digest` nor `checksum` (`ADVISORY EVENT WITH CHAIN FIELDS`).
///
/// Without it, *"a sealed decision relabelled as an advisory kind would still count as a link"* — and
/// under `--issuer` as a recomputed seal. It runs in **every** mode, integrity included, because the
/// hole it closes is a linkage hole, not an authenticity one. It reads only presence: the five
/// unmodelled payloads are never decoded ([`crate::wire::PayloadPresence`]).
///
/// The field labels and the marker strings are the runtime's verbatim, so a differential harness can
/// map one side's diagnosis onto the other's.
pub fn check_kind_payload(e: &Event) -> Result<(), String> {
    let p = &e.presence;
    let fields: [(&str, bool, &str); 11] = [
        ("payload (tag 13)", e.decision.is_some(), "DECISION_SEALED"),
        (
            "learning_decision (tag 14)",
            p.learning_decision,
            "LEARNING_DECISION",
        ),
        (
            "learning_outcome (tag 15)",
            p.learning_outcome,
            "LEARNING_OUTCOME",
        ),
        ("audit_entry (tag 16)", e.audit.is_some(), "AUDIT_ENTRY"),
        ("budget_breach (tag 17)", p.budget_breach, "BUDGET_BREACH"),
        (
            "erasure_certificate (tag 18)",
            e.cert.is_some(),
            "ERASURE_CERTIFICATE",
        ),
        (
            "session_lifecycle (tag 21)",
            p.session_lifecycle,
            "SESSION_LIFECYCLE",
        ),
        (
            "chain_head_attestation (tag 22)",
            e.attestation.is_some(),
            "CHAIN_HEAD_ATTESTATION",
        ),
        (
            "authorize_evaluated (tag 23)",
            e.authorize.is_some(),
            "AUTHORIZE_EVALUATED",
        ),
        (
            "policy_denied (tag 24)",
            e.denial.is_some(),
            "POLICY_DENIED",
        ),
        (
            "event_redriven (tag 26)",
            p.event_redriven,
            "EVENT_REDRIVEN",
        ),
    ];
    // Rule 1: "each payload field belongs to exactly one kind, so an event carries only its own kind's
    // payload".
    if let Some((field, _, owner)) = fields
        .iter()
        .find(|(_, present, owner)| *present && *owner != e.kind)
    {
        return Err(format!(
            "tenant '{}': seq {}: KIND/PAYLOAD MISMATCH — a {} event carries {field}, which only a {owner} \
             carries. A payload was grafted onto another kind (e.g. a sealed decision dressed as an \
             advisory row), or the producer is non-conforming.",
            e.tenant, e.seq, e.kind
        ));
    }
    // Rule 2: "and a known kind carries it". After rule 1 the only payload that can still be present is
    // the event's own, so its presence is the whole test.
    if let Some((_, present, owner)) = fields.iter().find(|(_, _, owner)| *owner == e.kind) {
        if !present {
            return Err(format!(
                "tenant '{}': seq {}: KIND/PAYLOAD MISMATCH — a {} event carries no {owner} payload.",
                e.tenant, e.seq, e.kind
            ));
        }
    }
    // Rule 3: "a known advisory kind (or the chain anchor) that carries `digest`/`checksum` is refused,
    // not linked". Either field alone is enough: a half-chained advisory row is no more a link than a
    // fully chained one.
    if e.is_advisory() && (e.digest.is_some() || e.checksum.is_some()) {
        return Err(format!(
            "tenant '{}': seq {}: ADVISORY EVENT WITH CHAIN FIELDS — a {} event is never a chain link, but \
             it carries digest/checksum. An advisory row cannot be promoted into the chain.",
            e.tenant, e.seq, e.kind
        ));
    }
    Ok(())
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

/// Verify the hash chain from the stream alone, **one running head per tenant** (spec §Ordering &
/// integrity, U-RT-1/U-RT-3): each tenant chains against its own prior entry, from its own start —
/// never against another tenant's, and never one chain over the whole interleaved outbox.
///
/// `anchors` seeds a tenant's start from an anchored position (spec clause (f)) instead of genesis —
/// `(base_len, base_head)` per tenant name, exactly as the single-tenant `base_len`/`base_head` pair
/// used to seed the one chain this crate had before U-RT-1/U-RT-3. A tenant absent from `anchors`
/// starts at genesis. This function does **not** validate any `base_head` — the caller must have
/// already verified every one against a pinned issuer key before seeding it here ([`verify_anchor`]);
/// seeding an unverified head is exactly the "bare `(len, head)` pair" shape spec clause (f1) forbids.
///
/// Per `seam-event.v1.md`: for each event **that carries a `digest`**, in `seq` order **within its own
/// tenant's subsequence**, assert `prev_checksum == running_head` and `checksum == H(prev_checksum ‖
/// digest)`, then advance that tenant's head. A consumer walking the raw interleaved stream with one
/// shared head across tenants would see spurious chain breaks the moment two tenants both have chain
/// activity — this function walks the stream once but keeps the heads apart.
///
/// **Chained-ness is by field PRESENCE, not by `kind`.** A verifier keyed on `kind` trips over the first
/// `LEARNING_DECISION` in an unfiltered stream, and over the deliberately off-chain `chain_anchor`.
/// This check (and `advisory`/`unverifiable` counting) is GLOBAL, never per-tenant — an event with no
/// chain fields is counted once, before any tenant lookup, exactly as it always was.
///
/// **The cutover-backfill trap.** A tenant's first *attempted* link not matching its start (genesis,
/// since an anchored tenant's start was already validated and cannot itself be wrong) is ambiguous:
/// either tampering, or an honest export that begins mid-chain for that tenant (a window cut after
/// that tenant's genesis, or — the concrete historical case — a pre-tenant-partitioning backfill that
/// zeroed `tenant` on old rows without rewriting their chain fields). Fired only when this is the
/// tenant's OWN first attempted link and it is unanchored (`links == 0 && base_len == 0`) — every
/// subsequent break, and every anchored tenant's first link, is unambiguous tampering (an anchored
/// start was already signature-verified, so a mismatch there cannot be an honest gap) and gets the
/// ordinary `BROKEN CHAIN` message.
pub fn chain_by_tenant(
    events: &[Event],
    anchors: &BTreeMap<String, (u64, Vec<u8>)>,
) -> Result<ChainReport, String> {
    let mut tenants: BTreeMap<String, TenantChain> = BTreeMap::new();
    let mut unconsumed_anchors: BTreeMap<String, u64> = anchors
        .iter()
        .map(|(t, (len, _))| (t.clone(), *len))
        .collect();

    let mut r = ChainReport {
        events: events.len(),
        links: 0,
        advisory: 0,
        duplicates: 0,
        unverifiable: Vec::new(),
        unmodelled: Vec::new(),
        head: GENESIS.to_vec(),
        heads: vec![GENESIS.to_vec()],
        max_schema_by_link: vec![0],
        base_len: 0,
        tenants: BTreeMap::new(),
        unconsumed_anchors: BTreeMap::new(),
    };

    for e in events {
        // First, before the link/advisory split and before any `unverifiable` counting — as the runtime
        // does — so a relabelled or stripped event reports the binding, never a downstream symptom of
        // it. Every entry point (`chain`, `chain_anchored`, and `bundle` through it) inherits it here.
        check_kind_payload(e)?;
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

        let is_fresh_partition = !tenants.contains_key(&e.tenant);
        let chain = tenants.entry(e.tenant.clone()).or_insert_with(|| {
            let (base_len, base_head) = anchors
                .get(&e.tenant)
                .map(|(len, head)| (*len, head.clone()))
                .unwrap_or((0, GENESIS.to_vec()));
            unconsumed_anchors.remove(&e.tenant);
            TenantChain {
                head: base_head.clone(),
                links: 0,
                heads: vec![base_head],
                max_schema_by_link: vec![0],
                base_len,
            }
        });

        if e.prev_checksum != chain.head {
            if is_fresh_partition && chain.links == 0 && chain.base_len == 0 {
                return Err(format!(
                    "seq {}: NON-GENESIS FIRST LINK — tenant {:?}'s first observed chained event does \
                     not start at genesis.\n  \
                     expected {}\n  got      {}\n  \
                     EITHER this event was forged/inserted/reordered, OR this is an honest export that \
                     begins mid-chain for this tenant (a window cut after this tenant's genesis, or a \
                     cutover-spanning export predating this tenant's chain partitioning). Re-run with \
                     --from-anchor over a validated anchor for this tenant to resolve the ambiguity; \
                     absent one, treat this as tampering.",
                    e.seq,
                    e.tenant,
                    hex(&chain.head),
                    hex(&e.prev_checksum)
                ));
            }
            return Err(format!(
                "seq {}: BROKEN CHAIN — prev_checksum does not match tenant {:?}'s running head.\n  \
                 expected {}\n  got      {}\n  \
                 An event was forged, inserted, reordered, dropped, or had its chain fields stripped at \
                 or before this point.",
                e.seq,
                e.tenant,
                hex(&chain.head),
                hex(&e.prev_checksum)
            ));
        }
        let expect = link(&e.prev_checksum, digest);
        if checksum != &expect {
            return Err(format!(
                "seq {}: FORGED LINK — checksum != H(prev_checksum ‖ digest) for tenant {:?}.\n  \
                 expected {}\n  got      {}\n  \
                 This event's own digest does not produce the head it claims. Its body was rewritten.",
                e.seq,
                e.tenant,
                hex(&expect),
                hex(checksum)
            ));
        }
        chain.head = checksum.clone();
        chain.links += 1;
        chain.heads.push(chain.head.clone());
        // §Versioning: this link is verified — the check above needed no payload semantics — but if
        // its kind is one this build has never seen, its CONTENT is not. Recorded here rather than
        // inferred downstream, because by the time the report is printed the kind is gone. GLOBAL,
        // like `advisory`/`unverifiable` — not scoped per tenant.
        if !e.is_modelled() {
            r.unmodelled.push((e.seq, e.kind.clone()));
        }
        // Clause (e): track the running max over the SAME span this tenant's `heads` indexes. Taken
        // from the decision this link actually carries — an event with no decision leaves the max
        // where it was.
        let max_schema = match e.decision.as_ref() {
            Some(d) => (*chain.max_schema_by_link.last().unwrap_or(&0)).max(d.schema_version),
            None => *chain.max_schema_by_link.last().unwrap_or(&0),
        };
        chain.max_schema_by_link.push(max_schema);
    }

    r.tenants = tenants;
    r.unconsumed_anchors = unconsumed_anchors;
    // Single-tenant mirror (§0): every window this crate verified before U-RT-1/U-RT-3, and any
    // genuinely single-tenant window today, hits exactly one entry here — and the top-level scalar
    // fields below reproduce that one entry's values byte-for-byte, so this is NOT a behaviour change
    // for any existing caller. A window spanning more than one tenant has no single honest value for
    // these fields; they fall back to the genesis sentinel and the caller is expected to read
    // `r.tenants` instead.
    if r.tenants.len() == 1 {
        let only = r.tenants.values().next().expect("len == 1");
        r.head = only.head.clone();
        r.heads = only.heads.clone();
        r.links = only.links;
        r.max_schema_by_link = only.max_schema_by_link.clone();
        r.base_len = only.base_len;
    }
    Ok(r)
}

/// Verify the hash chain from the stream alone, from an **anchored start** (spec clause (f)):
/// `base_len`/`base_head` seed the running head of `anchor_tenant`'s chain in place of genesis; every
/// other tenant in the window is walked from genesis. [`chain`] is the special case `base_len == 0,
/// base_head == GENESIS`.
///
/// **Attribution is the anchor's own signed tenant (#835 step 4).** `anchor_tenant` is the anchor's
/// payload `tenant` — pass `&anchor.tenant` after [`verify_anchor`] accepted it. Since step 4 a
/// non-empty tenant verifies under the v2 framing only, which signs it, so the tenant an anchor seeds
/// is the one its issuer signed over. An untenanted anchor is a v1 signature, which never binds a
/// tenant: it seeds **only** the `""` (system) partition. The pre-#835 fallback that attributed an
/// untenanted anchor to the window's sole chained tenant is gone — it seeded a tenant chain from a
/// signature that never named that tenant. An anchor whose tenant has no chained event in the window
/// is left in [`ChainReport::unconsumed_anchors`] for the caller to refuse (spec clause (f0)).
pub fn chain_anchored(
    events: &[Event],
    anchor_tenant: &str,
    base_len: u64,
    base_head: &[u8],
) -> Result<ChainReport, String> {
    let mut anchors: BTreeMap<String, (u64, Vec<u8>)> = BTreeMap::new();
    if base_len != 0 {
        anchors.insert(anchor_tenant.to_string(), (base_len, base_head.to_vec()));
    }
    chain_by_tenant(events, &anchors)
}

/// Verify the hash chain from the stream alone, from **genesis**. The common case; see
/// [`chain_anchored`] for the general form spec clause (f) adds.
pub fn chain(events: &[Event]) -> Result<ChainReport, String> {
    chain_anchored(events, "", 0, &GENESIS)
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

/// The v1 chain-head attestation domain tag: `tenant` is not signed.
const CHAIN_HEAD_ATTESTATION_DOMAIN_V1: &[u8] = b"seam.audit.chain-head-attestation.v1";
/// The v2 domain tag (seam-runtime #835): the v1 frames, then `frame(tenant)`.
const CHAIN_HEAD_ATTESTATION_DOMAIN_V2: &[u8] = b"seam.audit.chain-head-attestation.v2";

/// The 32-byte digest a `CHAIN_HEAD_ATTESTATION` signs over. `tenant: None` is the **v1** framing
/// (`seam.audit.chain-head-attestation.v1`); `Some(tenant)` is **v2** (`…v2`, then `frame(tenant)`).
///
/// Transcribed verbatim from `seam-event.v1.md` §CHAIN_HEAD_ATTESTATION. `frame(x) = u32le(len) ‖ x`, and
/// the integers are framed **little-endian** (`le64`/`le32`) — the same length-prefixed discipline as the
/// erasure payload, and the same two easy-to-miss details: the domain tag is length-prefixed (not
/// NUL-terminated), and `attested_len`/`digest_schema` are the raw LE bytes wrapped in a frame, never a
/// bare number. The signature is `Ed25519` over **this digest**, not over the preimage. A new domain tag
/// rather than a frame appended under the old one, so a tag always names exactly one framing.
fn chain_head_attestation_payload(a: &Attestation, tenant: Option<&str>) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut frame = |part: &[u8]| {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    };
    frame(match tenant {
        None => CHAIN_HEAD_ATTESTATION_DOMAIN_V1,
        Some(_) => CHAIN_HEAD_ATTESTATION_DOMAIN_V2,
    });
    frame(&a.attested_len.to_le_bytes());
    frame(&a.attested_head);
    frame(&a.attested_at.to_le_bytes());
    frame(&a.digest_schema.to_le_bytes());
    frame(a.issuer_aid.as_bytes());
    if let Some(tenant) = tenant {
        frame(tenant.as_bytes());
    }
    h.finalize().into()
}

/// Does `sig` verify over `a` under the ONE framing its payload `tenant` selects? The seam-runtime
/// #835 step-4 rule, mirrored exactly (`verify_chain_head_attestation` in `seam-trust-aitp`): an empty
/// `tenant` verifies under **v1 only** (the system partition — v2 is never minted over an empty
/// tenant, and a v2 signature over `""` is refused), and a non-empty `tenant` under **v2 only**, so the
/// tenant is always inside the signature and relabelling it breaks verification.
///
/// There is no fallback, grace period or toggle. A v1 attestation carrying a non-empty `tenant` —
/// what the runtime minted for every tenant before #835 step 3 — is refused: its `tenant` sits outside
/// the signature and could have been relabelled. History signed that way does not verify here; verify
/// it from a v2 anchor onward.
fn attestation_signature_verifies(
    vk: &ed25519_dalek::VerifyingKey,
    a: &Attestation,
    sig: &ed25519_dalek::Signature,
) -> bool {
    use ed25519_dalek::Verifier;
    let framing = (!a.tenant.is_empty()).then_some(a.tenant.as_str());
    vk.verify(&chain_head_attestation_payload(a, framing), sig)
        .is_ok()
}

pub struct IssuerReport {
    /// The number of `CHAIN_HEAD_ATTESTATION`s that verified (signature + non-vacuous). In genesis
    /// mode this always equals `covering` (every valid attestation is, trivially, past position 0).
    /// In anchored mode it also counts below-window and at-anchor attestations (verified, but not
    /// covering — see [`ChainReport::base_len`]).
    pub attestations: usize,
    /// The longest `attested_len` of any valid attestation — **absolute**, i.e. not relative to
    /// `base_len`, unlike `heads`/`max_schema_by_link` indexing.
    pub covered_prefix: u64,
    /// The number of `DECISION_SEALED` records whose v4 record digest recomputed and matched the wire
    /// `digest` (design-a). Every other `schema_version` is refused outright rather than left
    /// uncounted.
    pub records_recomputed: usize,
    /// **Spec (b′).** The number of chained, non-`DECISION_SEALED` links whose own fields recomputed
    /// the digest the chain links (today: `AUDIT_ENTRY`, under the domain its action selects, with its
    /// envelope classification bound). A mismatch is refused as `ENTRY REWRITE`, never counted.
    pub entries_recomputed: usize,
    /// **Spec (b′).** Chained, non-`DECISION_SEALED` links this build has no preimage for — an unknown
    /// action, `fact_appended`, or a kind it does not recompute — in stream order. Neither recomputed
    /// nor refused here: a caller must disclose them and must not fold them into a green claim.
    pub uncovered: Vec<Uncovered>,
    /// **Spec clause (f4).** The number of valid attestations whose `attested_len` is strictly greater
    /// than `base_len` — the ones that actually warrant the window, as opposed to the anchor (which
    /// never counts, clause (f4)) or a below-window straggler (clause (f3), which never counts either).
    /// At least one is required for an anchored start to pass — see [`verify_authenticity_anchored`].
    /// In genesis mode (`base_len == 0`) this equals `attestations`, and is what the old zero-attestation
    /// refusal already required.
    pub covering: usize,
    /// **Spec clause (f3).** The number of valid attestations whose `attested_len` is strictly less
    /// than `base_len` — signature-verified (a forged one anywhere still fails the whole chain), but
    /// their position is not checkable against a window that does not contain it, so they are skipped
    /// and reported here rather than silently dropped. Always `0` in genesis mode.
    pub below_window: usize,
}

/// One chained link [`verify_authenticity_anchored`] could not recompute (spec (b′)): see
/// [`IssuerReport::uncovered`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uncovered {
    pub seq: u64,
    /// The envelope tenant.
    pub tenant: String,
    pub kind: String,
    /// The `AUDIT_ENTRY` action, when the link carries one.
    pub action: Option<String>,
}

/// The only record-digest formula this build implements (P7). Every other `schema_version` is
/// refused as unknown — never skipped, never recomputed under a formula it was not sealed with.
pub const RECORD_DIGEST_SCHEMA: u32 = 4;

/// Every v4 sub-digest (tags 11, 12, 13 and 15) is a SHA-256, so exactly this many bytes. A wire
/// value of any other length is malformed, not a shorter digest.
const V4_DIGEST_LEN: usize = 32;

/// A mandatory v4 digest slot (wire tag 11, 12 or 15): present, and exactly 32 bytes.
///
/// Absent is a **strip**, and the spec is explicit that it must be reported *distinctly* from a
/// digest mismatch — "someone removed a field" and "someone rewrote one" are different events with
/// different responses. Wrong-length is refused rather than hashed for the same reason: hashing a
/// malformed field would produce a well-formed digest that fails the comparison, surfacing a
/// MALFORMED record as though it had been REWRITTEN.
fn v4_required_digest<'a>(
    name: &str,
    tag: u32,
    value: &'a [u8],
    decision_id: &str,
) -> Result<&'a [u8], String> {
    // `len == 0` IS absence here — a total mapping over any bytes a decoder can be handed, including
    // an explicitly-encoded zero-length field (spec §"Presence on the wire").
    if value.is_empty() {
        return Err(strip_message(name, tag, decision_id));
    }
    if value.len() != V4_DIGEST_LEN {
        return Err(format!(
            "a v4 DECISION_SEALED ({decision_id}) carries a MALFORMED {name} (wire tag {tag}): {} \
             bytes, not {V4_DIGEST_LEN}.\n  \
             Refused rather than hashed. Hashing it would yield a well-formed digest that fails the \
             comparison, reporting a malformed field as though the record had been rewritten.",
            value.len()
        ));
    }
    Ok(value)
}

/// A mandatory v4 string slot (wire tag 14, 16 or 17): present, i.e. non-empty. The spec makes every
/// one of them mandatory on a conforming payload (a trust-less seal stamps the `"none"` sentinel
/// rather than leaving a slot empty), so empty is a strip, refused distinctly from a mismatch.
fn v4_required_str<'a>(
    name: &str,
    tag: u32,
    value: &'a str,
    decision_id: &str,
) -> Result<&'a str, String> {
    if value.is_empty() {
        return Err(strip_message(name, tag, decision_id));
    }
    Ok(value)
}

fn strip_message(name: &str, tag: u32, decision_id: &str) -> String {
    format!(
        "a v4 DECISION_SEALED ({decision_id}) carries NO {name} (wire tag {tag}).\n  \
         The v4 record-digest formula requires it. This is a STRIP, not a digest mismatch: the \
         record is REFUSED — not defaulted to an empty value, and there is no older formula to fall \
         back to. Defaulting to empty is what makes 'nobody participated' indistinguishable from \
         'somebody deleted the field'."
    )
}

/// The optional v4 sub-digest (wire tag 13). Absent is LEGITIMATE — it means no policy was bound to
/// that commitment — so absence is data here, carried into the preimage by the `opt` presence byte
/// rather than refused. Present-but-wrong-length is still malformed.
fn v4_optional_digest<'a>(
    name: &str,
    tag: u32,
    value: &'a [u8],
    decision_id: &str,
) -> Result<Option<&'a [u8]>, String> {
    // Same total `len == 0` rule as `v4_required_digest`, but here absence frames as `opt(None)`: an
    // explicitly-encoded zero-length tag 13 verifies identically to an omitted one.
    match value.len() {
        0 => Ok(None),
        V4_DIGEST_LEN => Ok(Some(value)),
        n => Err(format!(
            "a v4 DECISION_SEALED ({decision_id}) carries a MALFORMED {name} (wire tag {tag}): \
             present but {n} bytes, not {V4_DIGEST_LEN}.\n  \
             Absent is legitimate (no policy was bound); present-and-wrong-length is not, and is \
             refused rather than hashed."
        )),
    }
}

/// The 32-byte record digest a v4 `DECISION_SEALED` commits to — `seam.audit.record-digest.v4`.
///
/// Transcribed from `seam-event.v1.md` §Record digest (v4). `frame(x) = le32(len) ‖ x`;
/// `opt(x) = 0x00` when absent, `0x01 ‖ frame(x)` when present — so `None` and `Some("")` are
/// DISTINCT, and the presence byte is RAW (never itself framed).
///
/// ```text
/// frame("seam.audit.record-digest.v4")
/// ‖ frame(decision_id) ‖ frame(tenant) ‖ frame(namespace)
/// ‖ frame(ciphertext_digest) ‖ frame(le64(sealed_at))
/// ‖ frame(outcome) ‖ opt(mode) ‖ opt(policy_version) ‖ opt(supersedes)
/// ‖ frame(context_digest) ‖ frame(participation_digest) ‖ opt(policy_rules_digest)
/// ‖ frame(classification) ‖ frame(participants_digest)
/// ‖ frame(trust_basis_commitment) ‖ frame(auth_method)
/// ‖ frame(le32(schema_version))
/// ```
///
/// The sub-digests and the trust-basis commitment arrive **opaque on the wire** (tags 11-17); their
/// internal formulas belong to the runtime and to auditors and are deliberately not reimplemented
/// here — this is a wire-input recompute. `trust_basis_commitment` is framed as its ASCII string,
/// never the HMAC bytes, so no key is needed. `schema_version` is always the last slot. Strips of
/// the mandatory slots leave through the error channel, distinct from a mismatch.
pub fn record_digest_v4(d: &Decision) -> Result<[u8; 32], String> {
    let id = d.decision_id.as_str();
    let context_digest = v4_required_digest("context_digest", 11, &d.context_digest, id)?;
    let participation_digest =
        v4_required_digest("participation_digest", 12, &d.participation_digest, id)?;
    let policy_rules_digest =
        v4_optional_digest("policy_rules_digest", 13, &d.policy_rules_digest, id)?;
    let classification = v4_required_str("classification", 14, &d.classification, id)?;
    let participants_digest =
        v4_required_digest("participants_digest", 15, &d.participants_digest, id)?;
    let trust_basis_commitment =
        v4_required_str("trust_basis_commitment", 16, &d.trust_basis_commitment, id)?;
    let auth_method = v4_required_str("auth_method", 17, &d.auth_method, id)?;

    let mut buf: Vec<u8> = Vec::new();
    let frame = |buf: &mut Vec<u8>, part: &[u8]| {
        buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
        buf.extend_from_slice(part);
    };
    let opt = |buf: &mut Vec<u8>, x: Option<&[u8]>| match x {
        None => buf.push(0x00),
        Some(b) => {
            buf.push(0x01);
            buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
            buf.extend_from_slice(b);
        }
    };
    frame(&mut buf, b"seam.audit.record-digest.v4");
    frame(&mut buf, d.decision_id.as_bytes());
    frame(&mut buf, d.tenant.as_bytes());
    frame(&mut buf, d.namespace.as_bytes());
    frame(&mut buf, &d.ciphertext_digest);
    frame(&mut buf, &d.sealed_at.to_le_bytes());
    frame(&mut buf, d.outcome.as_bytes());
    opt(&mut buf, d.mode.as_deref().map(str::as_bytes));
    opt(&mut buf, d.policy_version.as_deref().map(str::as_bytes));
    opt(&mut buf, d.supersedes.as_deref().map(str::as_bytes));
    frame(&mut buf, context_digest);
    frame(&mut buf, participation_digest);
    opt(&mut buf, policy_rules_digest);
    frame(&mut buf, classification.as_bytes());
    frame(&mut buf, participants_digest);
    frame(&mut buf, trust_basis_commitment.as_bytes());
    frame(&mut buf, auth_method.as_bytes());
    frame(&mut buf, &d.schema_version.to_le_bytes());
    Ok(Sha256::digest(&buf).into())
}

/// Verify every `CHAIN_HEAD_ATTESTATION` in a window against the **pinned** issuer AIDs (A14,
/// design-b), from an **anchored start** (spec clause (f)): `base_len`/`base_head` are the position
/// and head the window begins at — `0`/[`GENESIS`] for a plain chain, or a validated anchor's
/// `(attested_len, attested_head)` for an anchored one. [`verify_authenticity`] is the special case.
///
/// # Why every attestation, and why at least one covers the window
///
/// A plain SHA-256 chain over a public genesis (or a public anchor — `GET /v1/anchors` is
/// unauthenticated) is *unkeyed*: a transport-controlling adversary can rebuild a self-consistent
/// chain from any fork point, and integrity-only verification passes it. The signed head is the
/// keyed root that closes this — a forger cannot mint a valid attestation without the issuer key. So:
///   * **the pin is load-bearing** (as for the erasure cert): the key comes from the caller's `--issuer`
///     AID, never from the attestation's own `issuer_aid` (that would let a forgery verify against its
///     forger). A named issuer that differs from the pin is refused before any signature work.
///   * **head-at-position** is what kills an *authentic* attestation spliced into a forged chain: the
///     signature checks out, but it attests a head the fabricated chain never produced at that
///     position. Position is **anchor-relative** (clause (f3)): link *k* of the window sits at
///     absolute position `base_len + k`, so an attestation at absolute `attested_len = P` is checked
///     against `heads[P - base_len]`.
///   * **zero COVERING attestations ⇒ REFUSE** (clause (f4), which re-scopes plain clause (d)). A
///     covering attestation is one whose `attested_len` is strictly greater than `base_len` — the
///     anchor itself never counts (the anchor feed is public, so a fabricated window appended to a
///     genuine anchor would otherwise authenticate with zero issuer coverage of its own), and neither
///     does an attestation landing exactly on the anchor's own position. A forger cannot mint a
///     covering attestation, so its absence over a window the caller asked to authenticate is the
///     fabricated-window tell.
///   * **a vacuous attestation (`attested_len == 0`) ⇒ REFUSE, outright**, wherever it lands. It
///     claims nothing — a conforming producer never signs the empty chain — so its wire presence is
///     itself the non-conforming-producer tell (spec clause (d), second sentence), and no valid
///     attestation beside it can save the window. Checked before window classification, so it applies
///     uniformly (this can only actually fire when `base_len == 0`, i.e. genesis mode — an anchored
///     window's `base_len` is never 0, spec clause (f2), so `attested_len == 0` there is necessarily
///     `< base_len` and would otherwise read as a below-window straggler).
///   * **a below-window attestation (`attested_len < base_len`) is signature-verified but its
///     position is uncheckable** — the window holds no head for it (clause (f3)). It is skipped and
///     REPORTED (`IssuerReport::below_window`), never silently dropped and never counted toward
///     coverage: the read→sign→append race the spec permits can legitimately place such an
///     attestation inside a window cut right after it.
///
/// `heads`/`max_schema_by_link` are [`ChainReport::heads`]/[`ChainReport::max_schema_by_link`] from a
/// passing [`chain_anchored`] call with the SAME `base_len`/`base_head` (the caller runs integrity
/// first). Every attestation present must pass signature verification; a single failure aborts with
/// `Err` (a forged one in the mix is an attack, even if others pass).
///
/// # design-a — every record self-verifies (record digest v4, P7)
///
/// The attestation (design-b) covers a *prefix* and only exists if the runtime emitted one; a payload
/// rewrite in an unattested tail would slip past it. So under `--issuer` this ALSO recomputes each
/// `DECISION_SEALED`'s v4 digest from its structural columns (spec §Record digest) and compares it to
/// the wire `digest` (tag 19): a mismatch is a **payload rewrite** (a column changed after sealing; the
/// link's triple still hashes, but the digest no longer matches the payload). A record missing a
/// mandatory column (tag 10, 11, 12, 14, 15, 16 or 17) is REFUSED as a **strip**, distinct from a
/// mismatch. Any `schema_version` other than 4 is REFUSED as cannot-verify — never skipped, and never
/// recomputed under another formula.
pub fn verify_authenticity_anchored(
    events: &[Event],
    heads: &[Vec<u8>],
    max_schema_by_link: &[u32],
    pinned_aids: &[String],
    base_len: u64,
    base_head: &[u8],
) -> Result<IssuerReport, String> {
    use ed25519_dalek::{Signature, VerifyingKey};

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
    let mut covering = 0usize;
    let mut below_window = 0usize;
    let mut covered_prefix = 0u64;
    let mut records_recomputed = 0usize;
    let mut entries_recomputed = 0usize;
    let mut uncovered = Vec::new();

    // design-a: every DECISION_SEALED recomputes under v4. A version other than 4 is refused; a v4
    // record missing a mandatory column is a strip — reported distinctly from a mismatch.
    //
    // (b′): every OTHER chain link recomputes from its own fields, here, in this first loop. It runs to
    // completion before the attestation loop below starts, so no below-window or at-anchor `continue`
    // there can ever skip past a rewritten entry.
    for e in events {
        if e.is_link() && e.decision.is_none() {
            match entry::recompute(e) {
                entry::Body::Recomputed => entries_recomputed += 1,
                entry::Body::Uncovered => uncovered.push(Uncovered {
                    seq: e.seq,
                    tenant: e.tenant.clone(),
                    kind: e.kind.clone(),
                    action: e.audit.as_ref().map(|a| a.action.clone()),
                }),
                entry::Body::Rewritten(what) if what.ends_with("classification") => {
                    return Err(format!(
                        "seq {}: ENTRY REWRITE — the chained {what} ({:?}) is not the label its action \
                         fixes.\n  The envelope classification sits outside the digest, so a relabel \
                         leaves the link hashing; it is bound to the action instead, and this one was \
                         changed after the entry was chained.",
                        e.seq, e.classification
                    ));
                }
                entry::Body::Rewritten(what) => {
                    return Err(format!(
                        "seq {}: ENTRY REWRITE — the chained {what}'s fields do not recompute the \
                         digest the chain links.\n  A field (e.g. an actor, reason or session) was \
                         rewritten after the entry was chained: the link still hashes, but the entry no \
                         longer matches it.",
                        e.seq
                    ));
                }
            }
        }
        let Some(d) = e.decision.as_ref() else {
            continue;
        };
        // A version other than 4 is REFUSED, never skipped (spec §Record digest: "a verifier
        // recomputes v4 only and refuses every other schema_version as unknown").
        //
        // There is deliberately no older formula and no link-only exemption any more. Before P7 a v1
        // record was skipped as "not recomputable", and that skip was a hole the verifier had to guard
        // structurally (relabel a covered record to v1 and the recompute never ran). With one formula
        // there is nothing to downgrade INTO: a relabel to 1, 2 or 3 lands here and fails, and a newer
        // version is refused rather than misreported as a rewrite. "I cannot check this, so it passes"
        // is precisely the shape of a downgrade, so the only honest answer is to say so and fail.
        if d.schema_version != RECORD_DIGEST_SCHEMA {
            let relation = if d.schema_version > RECORD_DIGEST_SCHEMA {
                "NEWER THAN THIS VERIFIER"
            } else {
                "RETIRED (v1-v3 were retired by P7)"
            };
            return Err(format!(
                "CANNOT VERIFY: a DECISION_SEALED ({}) declares schema_version {}, which is {relation}.\n  \
                 This build implements only the v{RECORD_DIGEST_SCHEMA} record-digest formula; it cannot \
                 prove a record matches a digest computed under a formula it does not have. Refused \
                 rather than skipped — treating an unknown version as cannot-recompute-so-pass is how a \
                 downgrade gets through.",
                d.decision_id, d.schema_version
            ));
        }
        if d.ciphertext_digest.is_empty() {
            return Err(format!(
                "a v{} DECISION_SEALED ({}) carries NO ciphertext_digest (tag 10).\n  \
                 Every record is required to commit its SHA256(ciphertext); an absent tag 10 is a \
                 strip/downgrade attack (rewrite a field, drop the commitment, leave the \
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
        // The `?` is what keeps a STRIP distinct from a MISMATCH — a strip leaves through the error
        // channel with its own wording, a mismatch is the inequality tested underneath.
        let recomputed = record_digest_v4(d)?;
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
        // U-RT-3 Phase 3 — reader obligations on tenant, checked FIRST, before the pin and the
        // signature, exactly where seam-runtime's own seam-verify checks it. Since #835 step 4 the
        // payload tenant selects the one signed framing, so a relabelled or stripped tenant would also
        // fail the signature — but checking agreement first names the actual defect (the artifact
        // disagrees with itself) instead of a generic signature failure.
        //
        // The payload tenant must EQUAL the envelope's (#835 step 4). An empty payload tenant under a
        // named envelope — an attestation minted before U-RT-3 Phase 2 — used to be accepted on the
        // envelope's word and counted as "tenant-unbound"; it is now this same refusal, with or without
        // `--strict`, because its v1 signature never named the tenant whose chain it is attributed to.
        if a.tenant != e.tenant {
            return Err(format!(
                "ATTESTATION TENANT MISMATCH — a CHAIN_HEAD_ATTESTATION over len {} carries payload \
                 tenant '{}', but its own envelope tenant is '{}'.\n  \
                 The envelope is set by the transport, the payload tenant by the signer's own record \
                 of which tenant it was attesting (and, since #835 step 4, signed); a genuine \
                 attestation always agrees with itself. An empty payload tenant under a named \
                 envelope (minted before U-RT-3 Phase 2) is this same refusal, with or without \
                 --strict. Refused outright, never silently trusted on either field alone.",
                a.attested_len, a.tenant, e.tenant
            ));
        }
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
        if !attestation_signature_verifies(vk, a, &Signature::from_bytes(&sig)) {
            return Err(format!(
                "a CHAIN_HEAD_ATTESTATION over len {} (tenant {:?}) does not verify against the pinned \
                 issuer's key under the one framing its tenant selects (v1 for the empty tenant, v2 for \
                 a named one — #835 step 4, no fallback). The attestation is forged, or its (len, head, \
                 tenant) was altered after signing, or it is a v1 signature carrying a tenant (minted \
                 before #835 step 3: verify from a v2 anchor onward) — or it was signed under a framing \
                 newer than this verifier, in which case upgrade seam-verify before concluding forgery.",
                a.attested_len, a.tenant
            ));
        }
        // spec clause (d), second sentence, checked FIRST and unconditionally — before any window
        // classification — exactly as spec clause (f)'s position table orders it: an attestation whose
        // `attested_len` is 0 makes no claim (a conforming producer never signs the empty chain, spec
        // §Triggers), so its presence on the wire is itself the non-conforming-producer tell, and it
        // can never be the attestation that satisfies coverage. REFUSED outright and unconditionally,
        // even when valid attestations sit beside it. Checked after the signature so "the pinned
        // issuer really signed this nothing" is established fact, not conjecture, when refused.
        if a.attested_len == 0 {
            return Err(format!(
                "a CHAIN_HEAD_ATTESTATION is VACUOUS — attested_len is 0, a signed claim about the \
                 empty prefix.\n  \
                 It claims nothing (a conforming producer never signs the empty chain), so its very \
                 presence on the wire means a non-conforming or rolled-back producer signed with \
                 issuer '{}'. Refused outright per spec clause (d) — it can never be the attestation \
                 that authenticates a stream.",
                a.issuer_aid
            ));
        }

        attestations += 1;
        covered_prefix = covered_prefix.max(a.attested_len);

        // Spec clause (f3) — window positions are anchor-relative. `attested_len` is an ABSOLUTE
        // position; the window only holds heads for positions >= base_len.
        if a.attested_len < base_len {
            // Uncheckable against this window (it has no head there) — the signature above already
            // proved this is a genuine, issuer-signed artifact, so it is not a failure, just not
            // evidence FOR this window either. Skipped and reported, never counted toward coverage.
            below_window += 1;
            continue;
        }
        if a.attested_len == base_len {
            // Checkable against the anchor itself (or, in genesis mode with base_len == 0, this arm is
            // unreachable — attested_len == 0 already returned above). The head must match the start
            // this window began at; it does NOT count toward coverage (clause (f4)) — attesting the
            // anchor's own position warrants nothing IN the window.
            if a.attested_head.as_slice() != base_head {
                return Err(format!(
                    "a CHAIN_HEAD_ATTESTATION attests head {} at len {}, this window's anchor \
                     position, but the anchor's head there is {}.\n  \
                     The signature is authentic, so this is an issuer-signed head SPLICED onto a \
                     different (forged or diverged) chain — exactly what the position check exists to \
                     catch.",
                    hex(&a.attested_head),
                    a.attested_len,
                    hex(base_head)
                ));
            }
            continue;
        }

        // base_len < attested_len: a genuine in-window position. Relative index into THIS window's
        // heads/max_schema_by_link — `heads[0]` is the start, `heads[k]` is after k links past it.
        let rel = (a.attested_len - base_len) as usize;

        // Head-at-position: the attested head must be the running head after `rel` links past the
        // start. An attestation over a position the window never reaches has no head to check against
        // — a FAIL, not a silent pass (it cannot be attesting *this* window).
        let want = heads.get(rel).ok_or_else(|| {
            format!(
                "a CHAIN_HEAD_ATTESTATION attests len {}, but the window (anchored at {}) has only {} \
                 chained links — it cannot be covering this window.",
                a.attested_len,
                base_len,
                heads.len().saturating_sub(1)
            )
        })?;
        if want.as_slice() != a.attested_head.as_slice() {
            return Err(format!(
                "a CHAIN_HEAD_ATTESTATION attests head {} at len {}, but this window's head there is \
                 {}.\n  \
                 The signature is authentic, so this is an issuer-signed head SPLICED onto a different \
                 (forged or diverged) chain — exactly what the position check exists to catch.",
                hex(&a.attested_head),
                a.attested_len,
                hex(want)
            ));
        }
        // spec (e)/(f5): the CEILING check, re-scoped to the window. `digest_schema` asserts that
        // every record in the attested SPAN (from the start to `rel` links past it) has
        // `schema_version <= digest_schema`. Checked here — after the position check above, so we
        // already know this attestation really covers THIS window at THIS length, and a ceiling
        // failure is never reported for an attestation that was actually spliced.
        //
        // Indexed by `rel`, NOT a running max over everything seen so far, and never seeded from the
        // anchor's own `digest_schema` (clause (f5) — that field is a CEILING on the prefix below the
        // window, not the window's actual max; seeding from it would refuse a genuinely old in-window
        // attestation over an all-v4 span). A stale attestation legitimately covers a SHORTER prefix
        // than the window's current length (the head is read, signed, and appended without a lock, so
        // the chain advances underneath it) — comparing it against records sealed after it was signed
        // would refuse a valid attestation for a race the design explicitly permits.
        //
        // `>=`, never `==`: a ceiling only ever rises and attestations are never re-signed, so an
        // attestation's ceiling may legitimately sit above every record it covers.
        // FAIL-CLOSED on a short slice, never `unwrap_or(0)` — see [`verify_authenticity`]'s doc for
        // why (reachable by an embedder passing mismatched vectors, not by this crate's own CLI).
        let Some(max_covered) = max_schema_by_link.get(rel).copied() else {
            return Err(format!(
                "internal: max_schema_by_link has {} entries but an attestation covers len {} (window \
                 position {rel}).\n  \
                 This cannot happen for a report produced by `chain_anchored()` — the two vectors are \
                 built together and are always the same length. It means a caller passed a `heads` and \
                 a `max_schema_by_link` from different reports. Refusing rather than skipping the \
                 ceiling check: a verifier that silently drops a refusal is worse than one that stops.",
                max_schema_by_link.len(),
                a.attested_len
            ));
        };
        if a.digest_schema < max_covered {
            return Err(format!(
                "a CHAIN_HEAD_ATTESTATION claims digest_schema {} at len {}, but a DECISION_SEALED \
                 in the window it covers is schema_version {}.\n  \
                 The signature is authentic, so the ISSUER signed a false ceiling: the attestation \
                 understates the verification regime of the very records it attests. This is a \
                 SIGNED DOWNGRADE claim — distinct from a payload rewrite (the records are intact) \
                 and from a tag-10 strip (nothing is missing). The usual cause is a rolled-back \
                 producer whose CURRENT_SCHEMA_VERSION regressed while the chain ahead of it did not.",
                a.digest_schema, a.attested_len, max_covered
            ));
        }
        covering += 1;
    }

    if covering == 0 {
        return Err(format!(
            "--issuer was given, but the window carries NO chain-head attestation covering it \
             (attested_len strictly greater than {base_len}).\n  \
             An issuer-signed head cannot be minted without the issuer key, so its absence over a \
             window you asked to authenticate is the fabricated-window tell. The start's own anchor \
             cannot satisfy this by itself — spec clause (f4): the anchor feed is public, so a \
             fabricated window appended to a genuine anchor would otherwise authenticate with zero \
             issuer coverage of its own — refusing rather than reporting a green window no issuer \
             ever signed."
        ));
    }
    Ok(IssuerReport {
        attestations,
        covered_prefix,
        records_recomputed,
        entries_recomputed,
        uncovered,
        covering,
        below_window,
    })
}

/// Verify every `CHAIN_HEAD_ATTESTATION` in the stream against the **pinned** issuer AIDs, from
/// **genesis**. The common case; see [`verify_authenticity_anchored`] for the general form spec
/// clause (f) adds, and for the full rationale (every point below still applies here — genesis is
/// simply `base_len == 0, base_head == GENESIS`).
pub fn verify_authenticity(
    events: &[Event],
    heads: &[Vec<u8>],
    max_schema_by_link: &[u32],
    pinned_aids: &[String],
) -> Result<IssuerReport, String> {
    verify_authenticity_anchored(events, heads, max_schema_by_link, pinned_aids, 0, &GENESIS)
}

/// [`verify_authenticity_anchored`], fanned out **per tenant** over a [`ChainReport`] from
/// [`chain_by_tenant`]/[`chain_anchored`]/[`chain`] — U-RT-1/U-RT-3's chains are independent per
/// tenant, so authenticity is too: one tenant's attestations say nothing about another's, and running
/// every tenant's events through a single window's `heads`/`max_schema_by_link` (as pre-U-RT-1 code
/// did) would check records against the WRONG chain the moment more than one tenant is present.
///
/// Each tenant's events are its own (filtered by envelope `tenant`), its own window is
/// `tc.heads`/`tc.max_schema_by_link`, and its own start is `(tc.base_len, tc.heads[0])` — genesis for
/// an unanchored tenant, `chain_by_tenant`'s own seed for an anchored one (see that function: it stores
/// the start head as `heads[0]` before any link is appended). A tenant failing authenticity fails the
/// whole call — there is no such thing as "some tenants authenticated."
pub fn verify_authenticity_by_tenant(
    events: &[Event],
    report: &ChainReport,
    pinned_aids: &[String],
) -> Result<BTreeMap<String, IssuerReport>, String> {
    let mut out = BTreeMap::new();
    for (tenant, tc) in &report.tenants {
        let tenant_events: Vec<Event> = events
            .iter()
            .filter(|e| &e.tenant == tenant)
            .cloned()
            .collect();
        let base_head = tc.heads.first().map(Vec::as_slice).unwrap_or(&GENESIS);
        let ir = verify_authenticity_anchored(
            &tenant_events,
            &tc.heads,
            &tc.max_schema_by_link,
            pinned_aids,
            tc.base_len,
            base_head,
        )
        .map_err(|e| format!("tenant {tenant:?}: {e}"))?;
        out.insert(tenant.clone(), ir);
    }
    Ok(out)
}

/// Validate an anchor `CHAIN_HEAD_ATTESTATION` against a **pinned** issuer AID, BEFORE it is trusted
/// as an anchored start (spec clauses (f1)/(f2)). Run standalone, ahead of [`chain_anchored`]: the
/// anchor seeds the window that function verifies, so it must be validated before that window is even
/// parsed — seeding an unverified head is exactly the "bare `(len, head)` pair" shape clause (f1)
/// forbids as an input.
///
/// This is deliberately a small, self-contained duplicate of the pin+signature+vacuous checks inside
/// [`verify_authenticity_anchored`]'s attestation loop, in the spirit of this crate's preference
/// for duplication over a shared helper across a control-flow seam: the anchor check runs at a different point in the caller's control
/// flow (before a `ChainReport` exists at all) and sharing a helper across that seam is not worth the
/// coupling.
pub fn verify_anchor(anchor: &Attestation, pinned_aids: &[String]) -> Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let keys: Vec<(&str, VerifyingKey)> = pinned_aids
        .iter()
        .map(|aid| {
            let key = aid_to_key(aid)?;
            let vk = VerifyingKey::from_bytes(&key).map_err(|e| format!("bad issuer key: {e}"))?;
            Ok((aid.as_str(), vk))
        })
        .collect::<Result<_, String>>()?;

    let Some((_, vk)) = keys.iter().find(|(aid, _)| *aid == anchor.issuer_aid) else {
        return Err(format!(
            "the anchor names issuer '{}', but you pinned [{}].\n  \
             A signature only means something relative to a key you already trusted; deriving the key \
             from the anchor's own issuer would let a forged anchor verify against its forger.",
            anchor.issuer_aid,
            pinned_aids.join(", ")
        ));
    };
    let sig: [u8; 64] = anchor
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "anchor signature is not 64 bytes".to_string())?;
    if !attestation_signature_verifies(vk, anchor, &Signature::from_bytes(&sig)) {
        return Err(format!(
            "the anchor's signature (tenant {:?}) does not verify against the pinned issuer's key under \
             the one framing its tenant selects (v1 for the empty tenant, v2 for a named one — #835 \
             step 4, no fallback). It is forged, or its (len, head, tenant) was altered after signing, \
             or it is a v1 signature carrying a tenant (minted before #835 step 3: use a v2 anchor) — \
             or it was signed under a framing newer than this verifier, in which case upgrade \
             seam-verify before concluding forgery.",
            anchor.tenant
        ));
    }

    // spec clause (f2): a vacuous anchor (attested_len == 0) claims the empty prefix — a conforming
    // producer never signs it (spec clause (d)), so accepting it as a start would re-create genesis
    // seeding through the back door, under an artifact no conforming producer emits. Checked AFTER the
    // signature, per (f1): "the anchor's signature MUST verify ... before anything is verified from
    // it" — so "the pinned issuer really signed this nothing" is established fact when refused.
    if anchor.attested_len == 0 {
        return Err(format!(
            "the anchor is VACUOUS — attested_len is 0, a signed claim about the empty prefix.\n  \
             It claims nothing (a conforming producer never signs the empty chain), so accepting it \
             as an anchored start would re-create genesis seeding through the back door, under an \
             artifact no conforming producer emits, signed by issuer '{}'.",
            anchor.issuer_aid
        ));
    }
    Ok(())
}

/// The truncation check (seam-sdk#140), unblocked by `seam-runtime`'s `GET /v1/anchors` feed
/// (seam-runtime#422, live since 2026-08-26).
///
/// A stream cut at the tail is **internally consistent and verifies green** — every link that
/// exists still chains correctly, so [`chain`]/[`chain_anchored`] alone can never tell "this is
/// the whole chain" from "this is a truncated prefix of it". That is not a bug in those
/// functions; it is a property of hashing alone, and it is why this is a SEPARATE check rather
/// than a flag on them. What closes the gap is an **independently-held** signed artifact the
/// caller did not get from the stream under test — fetched out of band (the anchor feed; this
/// crate makes no network calls of its own, see `lib.rs`'s own doc on why) and validated with
/// [`verify_anchor`] BEFORE it reaches here, exactly as `chain_anchored`'s start anchor is.
/// `expect` need not appear anywhere in `events` — the whole point is that it did not have to.
///
/// **Tenant attribution** is the anchor's own signed tenant, exactly as for [`chain_anchored`]'s start
/// anchor (#835 step 4): `expect.tenant` names the tenant directly, and since [`verify_anchor`]
/// accepted it, a non-empty one is inside its v2 signature. An untenanted anchor is a v1 signature and
/// is attributed to the `""` (system) partition only — the pre-#835 fallback to the window's sole
/// tenant is gone, for the same reason it is gone from [`chain_anchored`]: it attributed a tenant's
/// chain to a signature that never named that tenant.
///
/// **The length comparison.** `report.tenants[tenant]`'s covered length is `base_len + links` —
/// the absolute position its own chain walk actually reached, by construction identical to
/// `base_len + (heads.len() - 1)`. A tenant the window never saw at all counts as covered `0`,
/// deliberately folded into the same TRUNCATED verdict rather than a separate "tenant absent"
/// case: both mean this window does not reach as far as the anchor says the real chain does.
/// `expect.attested_len > covered` is truncation.
///
/// **The head comparison, when length alone passes.** Reaching far enough is not the whole
/// claim — a window that was cut and then spliced with a DIFFERENT, same-length-or-longer
/// fabricated tail would pass a length-only check while disagreeing with reality from the cut
/// point on. So whenever `expect.attested_len` falls inside this tenant's own window (at or
/// past `base_len`), the running head this tenant's chain walk actually had AT that position
/// (`tc.heads[expect.attested_len - tc.base_len]`) must equal `expect.attested_head` — the same
/// head-at-position pinning [`verify_authenticity_anchored`] already does for an attestation
/// found IN the stream, applied here to one that was not. An `expect.attested_len` older than
/// this window's own start (`< base_len`) has no head here to check against — skipped, not
/// failed, the same `below_window` posture `verify_authenticity_anchored` already has for that
/// case — and an unanchored tenant's `base_len` is always `0`, so this is unreachable there.
pub fn check_not_truncated(report: &ChainReport, expect: &Attestation) -> Result<(), String> {
    let tenant = expect.tenant.as_str();
    let tc = report.tenants.get(tenant);
    let covered = tc.map(|c| c.base_len + c.links as u64).unwrap_or(0);
    if expect.attested_len > covered {
        return Err(format!(
            "TRUNCATED STREAM — tenant {tenant:?}: an independently-held CHAIN_HEAD_ATTESTATION \
             (fetched separately, e.g. from GET /v1/anchors, and signature-verified against the \
             pinned issuer before this check ran) attests length {}, but this window's verified \
             chain only reaches {covered}.\n  \
             The window you verified is internally consistent — a truncated stream always is, \
             which is exactly what makes truncation undetectable from the stream alone. This \
             anchor proves events exist past where this stream stops.",
            expect.attested_len
        ));
    }

    if let Some(tc) = tc {
        if expect.attested_len >= tc.base_len {
            let rel = (expect.attested_len - tc.base_len) as usize;
            if let Some(want) = tc.heads.get(rel) {
                if want.as_slice() != expect.attested_head.as_slice() {
                    return Err(format!(
                        "ANCHOR DIVERGENCE — tenant {tenant:?}: an independently-held \
                         CHAIN_HEAD_ATTESTATION attests head {} at len {}, but this window's own \
                         chain walk reached head {} at that same position.\n  \
                         The window reaches far enough, but does not agree with the \
                         independently-held anchor from that point — it is long enough to pass a \
                         length-only check while having been cut and spliced with a different \
                         tail. The anchor's signature is valid, so this window diverges from the \
                         real chain, not the other way around.",
                        hex(&expect.attested_head),
                        expect.attested_len,
                        hex(want)
                    ));
                }
            }
        }
    }
    Ok(())
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
            // Empty: this is the v1 KAT, and an empty tenant selects the v1 framing (step 4).
            tenant: String::new(),
        };
        let key = aid_to_key(issuer_aid).unwrap();
        let vk = VerifyingKey::from_bytes(&key).unwrap();
        let sig: [u8; 64] = att.signature.as_slice().try_into().unwrap();
        vk.verify(
            &chain_head_attestation_payload(&att, None),
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
            // Empty: this is the v1 KAT, and an empty tenant selects the v1 framing (step 4).
            tenant: String::new(),
        };
        att.attested_len += 1; // one field off
        let key = aid_to_key(issuer_aid).unwrap();
        let vk = VerifyingKey::from_bytes(&key).unwrap();
        let sig: [u8; 64] = att.signature.as_slice().try_into().unwrap();
        assert!(
            vk.verify(
                &chain_head_attestation_payload(&att, None),
                &Signature::from_bytes(&sig)
            )
            .is_err(),
            "a tampered attested_len must not verify"
        );
    }

    /// The vendored v2 KAT (`conformance/chain_head_attestation_v2_vector.json`, verbatim from
    /// seam-runtime's `conformance_vectors_extended.json`, #835 step 1): the runtime's v2 signature must
    /// verify over our v2 recompute, and the dispatch must pick v2 for its non-empty tenant.
    fn v2_kat() -> (ed25519_dalek::VerifyingKey, Attestation) {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../conformance/chain_head_attestation_v2_vector.json"
        ))
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let i = &v["inputs"];
        assert_eq!(i["domain"], "seam.audit.chain-head-attestation.v2");
        let order: Vec<&str> = v["frame_order"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(
            order,
            [
                "domain",
                "attested_len",
                "attested_head",
                "attested_at",
                "digest_schema",
                "issuer_aid",
                "tenant"
            ],
            "the runtime's frame order moved — chain_head_attestation_payload must follow it"
        );
        let issuer_aid = v["issuer_aid"].as_str().unwrap();
        let att = Attestation {
            attested_len: i["attested_len"].as_u64().unwrap(),
            attested_head: hex_to_bytes(i["attested_head_hex"].as_str().unwrap()),
            attested_at: i["attested_at"].as_u64().unwrap(),
            issuer_aid: issuer_aid.to_string(),
            digest_schema: i["digest_schema"].as_u64().unwrap() as u32,
            signature: hex_to_bytes(v["signature_hex"].as_str().unwrap()),
            tenant: i["tenant"].as_str().unwrap().to_string(),
        };
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&aid_to_key(issuer_aid).unwrap()).unwrap();
        (vk, att)
    }

    fn sig_of(a: &Attestation) -> ed25519_dalek::Signature {
        ed25519_dalek::Signature::from_bytes(&a.signature.as_slice().try_into().unwrap())
    }

    #[test]
    fn attestation_v2_payload_matches_the_runtime_kat() {
        use ed25519_dalek::Verifier;
        let (vk, att) = v2_kat();
        vk.verify(
            &chain_head_attestation_payload(&att, Some(&att.tenant)),
            &sig_of(&att),
        )
        .expect("the v2 KAT signature must verify against our recomputed v2 digest");
        assert!(attestation_signature_verifies(&vk, &att, &sig_of(&att)));
    }

    /// v2 binds the tenant: relabelling it — to another tenant, or to the empty tenant (v1 only) —
    /// breaks the signature, as does any other field.
    #[test]
    fn attestation_v2_binds_the_tenant() {
        let (vk, att) = v2_kat();
        let tampers: [fn(&mut Attestation); 5] = [
            |a| a.tenant = "acmf".into(),
            |a| a.tenant = String::new(),
            |a| a.attested_len += 1,
            |a| a.digest_schema += 1,
            |a| a.signature[0] ^= 1,
        ];
        for (i, tamper) in tampers.iter().enumerate() {
            let mut t = att.clone();
            tamper(&mut t);
            assert!(
                !attestation_signature_verifies(&vk, &t, &sig_of(&t)),
                "tamper #{i} must fail"
            );
        }
    }

    /// The shared v1 conformance vector (`conformance/vectors.json`'s `chain_head_attestation`), whose
    /// tenant is empty — the system partition's framing.
    fn v1_vector() -> (ed25519_dalek::VerifyingKey, Attestation) {
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
            tenant: String::new(),
        };
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&aid_to_key(issuer_aid).unwrap()).unwrap();
        (vk, att)
    }

    /// #835 step 4 (strict, mirroring the runtime's `conformance_drift` test): the v1 vector verifies
    /// with its empty tenant, and relabelled to a non-empty tenant it is REFUSED — a v1 signature
    /// carries the tenant outside the signature, so there is no fallback for it.
    #[test]
    fn the_v1_vector_is_refused_under_a_non_empty_tenant() {
        let (vk, mut att) = v1_vector();
        assert!(attestation_signature_verifies(&vk, &att, &sig_of(&att)));
        att.tenant = "acme".into();
        assert!(
            !attestation_signature_verifies(&vk, &att, &sig_of(&att)),
            "a v1 signature carrying a non-empty tenant must be refused (#835 step 4)"
        );
    }

    /// #835 step 4: a v2 signature over the EMPTY tenant (never minted; hand-rolled here with the
    /// vector's own seed, 07×32) is refused — an empty tenant selects v1 only. The v1 signature over
    /// the same inputs verifies, so the refusal is the framing, not the key.
    #[test]
    fn a_v2_signature_over_the_empty_tenant_is_refused() {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
        let (vk, mut att) = v1_vector();
        assert_eq!(sk.verifying_key(), vk, "seed 07×32 is the vector's issuer");
        att.signature = sk
            .sign(&chain_head_attestation_payload(&att, Some("")))
            .to_bytes()
            .to_vec();
        assert!(!attestation_signature_verifies(&vk, &att, &sig_of(&att)));
        att.signature = sk
            .sign(&chain_head_attestation_payload(&att, None))
            .to_bytes()
            .to_vec();
        assert!(attestation_signature_verifies(&vk, &att, &sig_of(&att)));
    }

    #[test]
    fn the_v1_and_v2_payloads_differ() {
        let (_, att) = v2_kat();
        let v1 = chain_head_attestation_payload(&att, None);
        assert_ne!(v1, chain_head_attestation_payload(&att, Some("acme")));
        assert_ne!(
            v1,
            chain_head_attestation_payload(&att, Some("")),
            "the domain tag alone separates the framings"
        );
    }

    /// The `record_digest_v4` inputs of the runtime's committed KAT (seam-client
    /// `conformance_vectors.json`, block `record_digest_v4`), as a `Decision`.
    fn v4_kat_decision() -> Decision {
        Decision {
            decision_id: "dec:conformance".into(),
            tenant: "acme".into(),
            namespace: "fraud".into(),
            mode: Some("decision.v1".into()),
            policy_version: None,
            outcome: "Resolved".into(),
            supersedes: None,
            sealed_at: 1_700_000_000_000,
            schema_version: 4,
            ciphertext_digest: hex_to_bytes(
                "67d9f6952981d85f7a2cabb0d5468e6934dc63ec55b480f18339277afc7635a6",
            ),
            context_digest: hex_to_bytes(
                "206f43bde4db008ca2c9b648cd6782252cfd8dbbbd70f63e63765601c6e653cd",
            ),
            participation_digest: hex_to_bytes(
                "66c8ae346f5284cc62cf29e6681b16a98db7a3bba458a4d494273a267ba69c02",
            ),
            policy_rules_digest: vec![0x5a; 32],
            classification: "Internal".into(),
            participants_digest: hex_to_bytes(
                "58b8fac506c099ccb4af417df40f632c69e614fb03531e8e21570a90caf7fc4a",
            ),
            trust_basis_commitment:
                "hmac-sha256:0a1b2c3d:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                    .into(),
            auth_method: "aitp-pinned-handshake".into(),
        }
    }

    /// Pin `record_digest_v4`'s framing byte-for-byte against the runtime's committed KATs, both the
    /// policy-bound block and `record_digest_v4_absent_policy` (tag 13 absent → `opt(None)`).
    ///
    /// `tests/conformance.rs` reads the same vectors from `../conformance/vectors.json`, but it is in
    /// `Cargo.toml`'s package `exclude`; these copies are what a standalone published crate tests.
    #[test]
    fn record_digest_v4_matches_the_runtime_kats() {
        let d = v4_kat_decision();
        assert_eq!(
            hex(&record_digest_v4(&d).unwrap()),
            "5af04d4b472bbd9f7c258392ad95bab82b6562d1904c086abf9f761968fbb241",
            "the digest-v4 framing must match the runtime KAT byte-for-byte"
        );
        let mut absent = d.clone();
        absent.policy_rules_digest = Vec::new();
        assert_eq!(
            hex(&record_digest_v4(&absent).unwrap()),
            "1e1cafdf76786feecbd18a83a74bfd65a2364b555f388d083abda431eaed6f8c",
            "an absent policy_rules_digest must frame as opt(None)"
        );
    }

    /// The KAT's `participants_digest_hex` is the spec's `seam.audit.participants.v4` over its
    /// `participants` roster. The verifier never recomputes it (tag 15 is opaque on the wire), but an
    /// auditor can — this pins that the formula the spec states is the one the vector carries.
    #[test]
    fn the_kat_participants_digest_follows_the_spec_formula() {
        let frame = |buf: &mut Vec<u8>, x: &[u8]| {
            buf.extend_from_slice(&(x.len() as u32).to_le_bytes());
            buf.extend_from_slice(x);
        };
        let digest = |ids: &[&str]| -> [u8; 32] {
            let mut buf = Vec::new();
            frame(&mut buf, b"seam.audit.participants.v4");
            buf.extend_from_slice(&(ids.len() as u32).to_le_bytes());
            for id in ids {
                frame(&mut buf, id.as_bytes());
            }
            Sha256::digest(&buf).into()
        };
        assert_eq!(
            digest(&["fraud-v3", "risk-v2"]).to_vec(),
            v4_kat_decision().participants_digest
        );
        // Stored order, never sorted: the reverse roster is a different digest.
        assert_ne!(
            digest(&["risk-v2", "fraud-v3"]),
            digest(&["fraud-v3", "risk-v2"])
        );
    }

    /// `opt(None)` is one byte and `opt(Some(""))` is five — a present-but-empty mode is DATA.
    #[test]
    fn record_digest_v4_distinguishes_none_from_empty_string() {
        let base = v4_kat_decision();
        let mut none = base.clone();
        none.mode = None;
        let mut empty = base.clone();
        empty.mode = Some(String::new());
        assert_ne!(
            record_digest_v4(&none).unwrap(),
            record_digest_v4(&empty).unwrap()
        );
    }

    /// An explicitly-encoded ZERO-LENGTH tag 13 must verify GREEN, identically to an omitted one.
    ///
    /// A conforming encoder never emits it, but proto3 obliges a decoder to accept an
    /// explicitly-encoded default, so `0x6a 0x00` can be handed to this verifier. On tags 10-17
    /// `len == 0` means absent however the bytes arose (spec §"Presence on the wire"); for tag 13
    /// absent is legitimate and frames as `opt(None)`. The first half asserts what the DECODER
    /// produces, so the second half asserts a behaviour rather than a premise.
    #[test]
    fn an_explicitly_encoded_zero_length_policy_rules_digest_is_absent_not_malformed() {
        use prost::Message;

        let d = v4_kat_decision();
        let pb = crate::wire::DecisionSealedPb {
            decision_id: d.decision_id.clone(),
            tenant: d.tenant.clone(),
            namespace: d.namespace.clone(),
            mode: d.mode.clone(),
            policy_version: d.policy_version.clone(),
            outcome: d.outcome.clone(),
            supersedes: d.supersedes.clone(),
            sealed_at: d.sealed_at,
            schema_version: 4,
            ciphertext_digest: d.ciphertext_digest.clone(),
            context_digest: d.context_digest.clone(),
            participation_digest: d.participation_digest.clone(),
            policy_rules_digest: Vec::new(),
            classification: d.classification.clone(),
            participants_digest: d.participants_digest.clone(),
            trust_basis_commitment: d.trust_basis_commitment.clone(),
            auth_method: d.auth_method.clone(),
        };

        let mut bytes = Vec::new();
        pb.encode(&mut bytes).expect("encode");
        bytes.extend_from_slice(&[0x6a, 0x00]);
        let decoded = crate::wire::DecisionSealedPb::decode(&bytes[..]).expect("decode");
        assert!(
            decoded.policy_rules_digest.is_empty(),
            "the crafted bytes must decode to an empty tag 13 — otherwise this test proves nothing"
        );

        let mut crafted = d.clone();
        crafted.policy_rules_digest = decoded.policy_rules_digest;
        let mut omitted = d;
        omitted.policy_rules_digest = Vec::new();
        assert_eq!(
            record_digest_v4(&crafted).expect("a zero-length tag 13 is ABSENT, not malformed"),
            record_digest_v4(&omitted).unwrap()
        );
    }

    /// Tag 13 is `opt`ed, so absent must NOT equal a 32-zero-byte digest.
    #[test]
    fn record_digest_v4_distinguishes_an_absent_policy_rules_digest_from_a_zeroed_one() {
        let base = v4_kat_decision();
        let mut absent = base.clone();
        absent.policy_rules_digest = Vec::new();
        let mut zeros = base.clone();
        zeros.policy_rules_digest = vec![0u8; 32];
        assert_ne!(
            record_digest_v4(&absent).unwrap(),
            record_digest_v4(&zeros).unwrap()
        );
    }

    /// Identically-framed adjacent slots are interchangeable under a swap unless their values bind to
    /// position. Each pair below is swapped and must change the digest.
    #[test]
    fn record_digest_v4_binds_each_column_to_its_own_slot() {
        let base = v4_kat_decision();
        let mut swapped = base.clone();
        std::mem::swap(
            &mut swapped.context_digest,
            &mut swapped.participation_digest,
        );
        assert_ne!(
            record_digest_v4(&base).unwrap(),
            record_digest_v4(&swapped).unwrap()
        );
        let mut swapped = base.clone();
        std::mem::swap(
            &mut swapped.participation_digest,
            &mut swapped.participants_digest,
        );
        assert_ne!(
            record_digest_v4(&base).unwrap(),
            record_digest_v4(&swapped).unwrap()
        );
        let mut swapped = base.clone();
        std::mem::swap(
            &mut swapped.trust_basis_commitment,
            &mut swapped.auth_method,
        );
        assert_ne!(
            record_digest_v4(&base).unwrap(),
            record_digest_v4(&swapped).unwrap()
        );
    }

    /// Each of the four v4 columns is bound: changing any one changes the digest.
    #[test]
    fn record_digest_v4_binds_the_four_new_columns() {
        let base = v4_kat_decision();
        let b = record_digest_v4(&base).unwrap();
        let mut d = base.clone();
        d.classification = "Financial".into();
        assert_ne!(record_digest_v4(&d).unwrap(), b);
        let mut d = base.clone();
        d.participants_digest = vec![0x01; 32];
        assert_ne!(record_digest_v4(&d).unwrap(), b);
        let mut d = base.clone();
        d.trust_basis_commitment.push('0');
        assert_ne!(record_digest_v4(&d).unwrap(), b);
        let mut d = base;
        d.auth_method = "aitp-tct".into();
        assert_ne!(record_digest_v4(&d).unwrap(), b);
    }

    /// A strip is an `Err`, a mismatch is an unequal `Ok` — the distinction is structural. Every
    /// refusal must NAME the field and its wire tag, and must NOT borrow a mismatch's vocabulary.
    #[test]
    fn a_stripped_or_malformed_v4_column_is_refused_not_hashed() {
        let base = v4_kat_decision();
        type Mutate = fn(&mut Decision);
        let cases: [(&str, u32, Mutate); 9] = [
            ("context_digest", 11, |d| d.context_digest = Vec::new()),
            ("participation_digest", 12, |d| {
                d.participation_digest = Vec::new()
            }),
            ("context_digest", 11, |d| d.context_digest = vec![0x11; 31]),
            ("policy_rules_digest", 13, |d| {
                d.policy_rules_digest = vec![0x33; 33]
            }),
            ("classification", 14, |d| d.classification = String::new()),
            ("participants_digest", 15, |d| {
                d.participants_digest = Vec::new()
            }),
            ("participants_digest", 15, |d| {
                d.participants_digest = vec![0x01; 16]
            }),
            ("trust_basis_commitment", 16, |d| {
                d.trust_basis_commitment = String::new()
            }),
            ("auth_method", 17, |d| d.auth_method = String::new()),
        ];
        for (field, tag, mutate) in cases {
            let mut d = base.clone();
            mutate(&mut d);
            let err = record_digest_v4(&d).expect_err(&format!("{field} must be refused"));
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
        let mut rewritten = base.clone();
        rewritten.outcome = "Denied".into();
        assert_ne!(
            record_digest_v4(&rewritten).unwrap(),
            record_digest_v4(&base).unwrap()
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
