//! `seam-evidence-bundle.v1` — verify a self-contained evidence bundle directory from its files and a
//! **pinned** issuer AID alone (`docs/evidence-bundle.v1.md` § Verifying).
//!
//! The six steps run in the spec's order and the first failure refuses:
//!
//! 1. **Manifest** — `format`, the pinned issuer, every listed file's SHA-256 and size, the required
//!    and paired members, and `disclosed` agreeing with `files`.
//! 2. **Chain** — the window is walked exactly as `chain events.jsonl --issuer AID --from-anchor
//!    anchor.json --strict` walks it, through the same library functions.
//! 3. **Inclusion** — exactly one chained `DECISION_SEALED` for the manifest's decision, in its tenant,
//!    whose `checksum` is `inclusion.record_checksum`.
//! 4. **Commitment** — the TCT (when present) verifies against the pinned AID and binds this
//!    Commitment's `seam-commitment-digest:v3`; `supersedes` matches the chained payload's.
//! 5. **Binding** — the `seam.evidence-binding.v1` signature verifies against the pinned AID and names
//!    this decision, tenant, link checksum and recomputed Commitment digest.
//! 6. **Disclosures** — `context.json` recomputes the chained `context_digest`;
//!    `SHA-256(policy.json)` is the chained `policy_rules_digest`.
//!
//! The manifest is unsigned: it is an index, never a reason to trust anything. Trust enters through
//! the pin, and every manifest claim this verifier reads is checked against the other files.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::commitment::{self, Commitment, ExplanationEntry};
use crate::verify;
use crate::wire::{Attestation, Event};

/// The only format tag this build knows. Any other is refused (spec § Versioning).
pub const FORMAT: &str = "seam-evidence-bundle.v1";

/// The binding's signing domain.
pub const BINDING_DOMAIN: &str = "seam.evidence-binding.v1";

/// Why a bundle did not verify. The split is the CLI's exit code: `Usage` is 1, `Failed` is 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// Not a bundle this tool can read at all: the directory or its `manifest.json` cannot be read,
    /// or the pinned AID is not an AID. Nothing was verified, and nothing was refused.
    Usage(String),
    /// The bundle was read and **refused**. `step` is the spec's step number (1–6).
    Failed { step: u8, message: String },
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Usage(m) => write!(f, "{m}"),
            BundleError::Failed { step, message } => write!(f, "step {step}: {message}"),
        }
    }
}

fn failed(step: u8, message: impl Into<String>) -> BundleError {
    BundleError::Failed {
        step,
        message: message.into(),
    }
}

/// What a verified bundle established, and what it was told was left out.
#[derive(Debug, Clone)]
pub struct BundleReport {
    pub decision_id: String,
    pub tenant: String,
    /// The window's chain report numbers (step 2).
    pub window_events: usize,
    pub window_links: usize,
    pub attestations: usize,
    pub covering: usize,
    pub anchor_len: u64,
    pub head: Vec<u8>,
    /// `Some(true)` when a TCT verified, `Some(false)` when the Commitment carries none (a record
    /// sealed under `identity: local-sealed`, bound by the binding alone), `None` when no Commitment
    /// was disclosed.
    pub tct_verified: Option<bool>,
    /// The checks that passed, in order, as one human-readable line each.
    pub checks: Vec<String>,
    /// The manifest's `withheld` list, `(item, reason)`, verbatim. Part of what the reader is told.
    pub withheld: Vec<(String, String)>,
}

// ── small helpers ─────────────────────────────────────────────────────────────────────────────

fn read_member(dir: &Path, name: &str, step: u8) -> Result<Vec<u8>, BundleError> {
    std::fs::read(dir.join(name)).map_err(|e| {
        failed(
            step,
            format!("{name}: the manifest lists it, but it cannot be read: {e}"),
        )
    })
}

fn parse_json(bytes: &[u8], name: &str, step: u8) -> Result<serde_json::Value, BundleError> {
    serde_json::from_slice(bytes)
        .map_err(|e| failed(step, format!("{name} is not valid JSON: {e}")))
}

fn str_field<'a>(
    v: &'a serde_json::Value,
    key: &str,
    file: &str,
    step: u8,
) -> Result<&'a str, BundleError> {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| failed(step, format!("{file}: missing string field '{key}'")))
}

fn b64_std(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// `frame(x) = le32(len(x)) ‖ x` — the chain-head attestation's framing, which the binding and the
/// v3 context digest reuse.
fn frame(h: &mut Sha256, x: &[u8]) {
    h.update((x.len() as u32).to_le_bytes());
    h.update(x);
}

/// `opt(x) = 0x00` absent, `0x01 ‖ frame(x)` present.
fn opt(h: &mut Sha256, x: Option<&[u8]>) {
    match x {
        None => h.update([0u8]),
        Some(x) => {
            h.update([1u8]);
            frame(h, x);
        }
    }
}

// ── the two framings this module owns ─────────────────────────────────────────────────────────

/// The digest an evidence binding's Ed25519 signature is over (spec § `binding.json`).
pub fn evidence_binding_digest(
    decision_id: &str,
    tenant: &str,
    record_checksum: &[u8],
    commitment_digest: &[u8],
    bound_at: u64,
    issuer_aid: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    frame(&mut h, BINDING_DOMAIN.as_bytes());
    frame(&mut h, decision_id.as_bytes());
    frame(&mut h, tenant.as_bytes());
    frame(&mut h, record_checksum);
    frame(&mut h, commitment_digest);
    frame(&mut h, &bound_at.to_le_bytes());
    frame(&mut h, issuer_aid.as_bytes());
    h.finalize().into()
}

/// The v3 `context_digest` (`seam.audit.context-provenance.v3`, `docs/seam-event.v1.md`
/// § `context_digest`) over `context.json`'s `bindings`, in the order given.
pub fn context_digest(ctx: &serde_json::Value) -> Result<[u8; 32], String> {
    let bindings = ctx
        .get("bindings")
        .and_then(serde_json::Value::as_array)
        .ok_or("context.json: missing array 'bindings'")?;
    let s = |b: &serde_json::Value, k: &str| -> Result<String, String> {
        b.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("context.json: missing string field '{k}'"))
    };
    let o = |b: &serde_json::Value, k: &str| -> Result<Option<String>, String> {
        match b.get(k) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(v)) => Ok(Some(v.clone())),
            Some(_) => Err(format!("context.json: '{k}' is not a string or null")),
        }
    };
    let mut h = Sha256::new();
    frame(&mut h, b"seam.audit.context-provenance.v3");
    h.update((bindings.len() as u32).to_le_bytes());
    for b in bindings {
        frame(&mut h, s(b, "ctx_ref")?.as_bytes());
        frame(&mut h, s(b, "fidelity")?.as_bytes());
        frame(&mut h, s(b, "classification")?.as_bytes());
        opt(&mut h, o(b, "lineage_id")?.as_deref().map(str::as_bytes));
        let version = b
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or("context.json: 'version' must be a u32")?;
        frame(&mut h, &version.to_le_bytes());
        let derived = b
            .get("derived_from")
            .and_then(serde_json::Value::as_array)
            .ok_or("context.json: missing array 'derived_from'")?;
        h.update((derived.len() as u32).to_le_bytes());
        for d in derived {
            let d = d
                .as_str()
                .ok_or("context.json: 'derived_from' entries must be strings")?;
            frame(&mut h, d.as_bytes());
        }
        for k in [
            "content_hash",
            "receipt_hash",
            "key_status",
            "resolved_status",
        ] {
            opt(&mut h, o(b, k)?.as_deref().map(str::as_bytes));
        }
    }
    Ok(h.finalize().into())
}

// ── commitment.json ───────────────────────────────────────────────────────────────────────────

/// Parse `commitment.json` (spec § `commitment.json`). Top-level fields are required strings
/// (`supersedes` may be `null`); within an entry, a missing or `null` string field is the empty
/// string, and `confidence`/`rationale_ref` are `null` when absent.
pub fn parse_commitment(c: &serde_json::Value) -> Result<Commitment, String> {
    let req = |k: &str| -> Result<String, String> {
        c.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("commitment.json: missing string field '{k}'"))
    };
    let supersedes = match c.get("supersedes") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(_) => return Err("commitment.json: 'supersedes' is not a string or null".into()),
    };
    let entries = c
        .get("explanation")
        .and_then(serde_json::Value::as_array)
        .ok_or("commitment.json: missing array field 'explanation'")?;
    let mut explanation = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        let at = |m: &str| format!("commitment.json: explanation[{i}]: {m}");
        let text = |k: &str| -> Result<String, String> {
            match e.get(k) {
                None | Some(serde_json::Value::Null) => Ok(String::new()),
                Some(serde_json::Value::String(s)) => Ok(s.clone()),
                Some(_) => Err(at(&format!("'{k}' is not a string"))),
            }
        };
        let kind = e
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| at("'kind' is not a string"))?
            .to_owned();
        let confidence = match e.get("confidence") {
            None | Some(serde_json::Value::Null) => None,
            Some(n) => Some(
                n.as_f64()
                    .ok_or_else(|| at("'confidence' is not a number"))?,
            ),
        };
        let rationale_ref = match e.get("rationale_ref") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(at("'rationale_ref' is not a string")),
        };
        explanation.push(ExplanationEntry {
            kind,
            participant: text("participant")?,
            proposal_id: text("proposal_id")?,
            value: text("value")?,
            reason: text("reason")?,
            confidence,
            rationale_ref,
        });
    }
    Ok(Commitment {
        id: req("id")?,
        action: req("action")?,
        authority: req("authority")?,
        supersedes,
        auth_method: req("auth_method")?,
        trust_basis: req("trust_basis")?,
        committer: req("committer")?,
        explanation,
        signed_artifact: req("signed_artifact")?,
    })
}

// ── step 1 ────────────────────────────────────────────────────────────────────────────────────

/// The members whose presence `disclosed` must agree with, `(item, file)`.
const DISCLOSABLE: &[(&str, &str)] = &[
    ("commitment", "commitment.json"),
    ("binding", "binding.json"),
    ("context", "context.json"),
    ("policy", "policy.json"),
];

fn check_manifest(dir: &Path, pinned: &str) -> Result<serde_json::Value, BundleError> {
    // A directory with no readable manifest is not a bundle this tool can read: exit 1, as for any
    // other unreadable input. Everything the manifest then LISTS is evidence, and a listed member
    // that is missing is a refusal (exit 2), never an IO error.
    let raw = std::fs::read(dir.join("manifest.json")).map_err(|e| {
        BundleError::Usage(format!(
            "{}: cannot read manifest.json ({e}) — is this a seam-evidence-bundle.v1 directory?",
            dir.display()
        ))
    })?;
    let m = parse_json(&raw, "manifest.json", 1)?;
    let format = str_field(&m, "format", "manifest.json", 1)?;
    if format != FORMAT {
        return Err(failed(
            1,
            format!("manifest.json: format '{format}' is not '{FORMAT}' — a verifier refuses a format it does not know"),
        ));
    }
    let named = m
        .pointer("/issuer/aid")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if named != pinned {
        return Err(failed(
            1,
            format!(
                "the bundle names issuer '{named}', but you pinned '{pinned}' — trust comes from the \
                 pin, never from the bundle, so a bundle naming another issuer is refused"
            ),
        ));
    }
    // `ed25519_public_key` is a convenience copy of the AID's key. Optional, but when present it is a
    // manifest claim, and the spec says a manifest that disagrees with the files is refused.
    if let Some(k) = m.pointer("/issuer/ed25519_public_key") {
        let key = verify::aid_to_key(pinned).map_err(BundleError::Usage)?;
        if k.as_str() != Some(verify::hex(&key).as_str()) {
            return Err(failed(
                1,
                "manifest.json: issuer.ed25519_public_key is not the pinned AID's key",
            ));
        }
    }
    let files = m
        .get("files")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| failed(1, "manifest.json: missing object 'files'"))?;
    for required in ["events.jsonl", "anchor.json"] {
        if !files.contains_key(required) {
            return Err(failed(
                1,
                format!("manifest.json: required file '{required}' is not listed"),
            ));
        }
    }
    if files.contains_key("commitment.json") != files.contains_key("binding.json") {
        return Err(failed(
            1,
            "commitment.json and binding.json must come as a pair: a Commitment without its binding \
             is unlinked from the chain, and a binding without its Commitment proves nothing",
        ));
    }
    for (name, meta) in files {
        // Flat directory: a listed name that could reach outside it is refused before it is opened.
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name.starts_with('.')
            || name == "manifest.json"
        {
            return Err(failed(
                1,
                format!("manifest.json: file name '{name}' is not a plain member name"),
            ));
        }
        let bytes = read_member(dir, name, 1)?;
        let want = meta
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let got = verify::hex(&Sha256::digest(&bytes));
        if got != want {
            return Err(failed(
                1,
                format!("{name}: sha256 {got} does not match the manifest's {want}"),
            ));
        }
        if meta.get("bytes").and_then(serde_json::Value::as_u64) != Some(bytes.len() as u64) {
            return Err(failed(
                1,
                format!("{name}: size {} does not match the manifest", bytes.len()),
            ));
        }
    }
    let disclosed: Vec<&str> = m
        .get("disclosed")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();
    for (item, file) in DISCLOSABLE {
        if disclosed.contains(item) != files.contains_key(*file) {
            return Err(failed(
                1,
                format!("manifest.json: 'disclosed' and 'files' disagree about {item} ({file})"),
            ));
        }
    }
    Ok(m)
}

// ── step 2 ────────────────────────────────────────────────────────────────────────────────────

struct Window {
    events: Vec<Event>,
    report: verify::ChainReport,
    issuer: verify::IssuerReport,
    anchor: Attestation,
}

/// `chain events.jsonl --issuer AID --from-anchor anchor.json --strict`, through the same library
/// calls `seam-verify chain` makes, so the two cannot disagree about a window.
fn check_window(dir: &Path, pinned: &str) -> Result<Window, BundleError> {
    let f2 = |m: String| failed(2, m);
    let pins = [pinned.to_owned()];

    let raw = String::from_utf8(read_member(dir, "anchor.json", 2)?)
        .map_err(|_| f2("anchor.json is not UTF-8".into()))?;
    let anchor = Attestation::parse_document(&raw).map_err(|e| f2(format!("anchor.json: {e}")))?;
    verify::verify_anchor(&anchor, &pins).map_err(|e| f2(format!("ANCHOR REJECTED: {e}")))?;

    let raw = String::from_utf8(read_member(dir, "events.jsonl", 2)?)
        .map_err(|_| f2("events.jsonl is not UTF-8".into()))?;
    let mut events = Vec::new();
    for (i, l) in raw.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        events.push(Event::parse(l).map_err(|e| f2(format!("events.jsonl line {}: {e}", i + 1)))?);
    }
    if events.is_empty() {
        return Err(f2("events.jsonl holds no events".into()));
    }
    let (mut events, duplicates) = verify::dedup(events).map_err(f2)?;
    events.sort_by_key(|e| e.seq);

    // The anchor seeds exactly the tenant it names — its signed tenant (#835 step 4); an untenanted
    // (v1) anchor seeds only the `""` partition, never a tenant's chain.
    let mut report = verify::chain_anchored(
        &events,
        &anchor.tenant,
        anchor.attested_len,
        &anchor.attested_head,
    )
    .map_err(f2)?;
    report.duplicates = duplicates;
    if !report.unconsumed_anchors.is_empty() {
        return Err(f2(format!(
            "the anchor seeds tenant {:?}, which this window has no chained event for (an anchor \
             with no tenant is v1 and seeds only the system partition, never a tenant's chain)",
            anchor.tenant
        )));
    }
    // A bundle's window is one tenant's: the single-tenant view below (`report.heads`) is only
    // meaningful for exactly one chain, so a window spanning more is refused rather than checked
    // against the genesis sentinel.
    if report.tenants.len() != 1 {
        return Err(f2(format!(
            "the window's chained events span {} tenants — an evidence bundle's window is exactly \
             one tenant's, the one its anchor names",
            report.tenants.len()
        )));
    }
    if !report.unverifiable.is_empty() {
        return Err(f2(format!(
            "REFUSED (--strict): {} event(s) carry no digest/checksum and are not advisory (first \
             seq {})",
            report.unverifiable.len(),
            report.unverifiable[0]
        )));
    }
    let issuer = verify::verify_authenticity_anchored(
        &events,
        &report.heads,
        &report.max_schema_by_link,
        &pins,
        anchor.attested_len,
        &anchor.attested_head,
    )
    .map_err(f2)?;
    Ok(Window {
        events,
        report,
        issuer,
        anchor,
    })
}

// ── the whole verification ────────────────────────────────────────────────────────────────────

/// Verify the bundle in `dir` against the **pinned** issuer AID. `now_secs` is the clock the TCT's
/// `iat`/`exp` are checked against (the CLI passes the system clock).
pub fn verify_bundle(dir: &Path, pinned: &str, now_secs: u64) -> Result<BundleReport, BundleError> {
    let key = verify::aid_to_key(pinned)
        .map_err(|e| BundleError::Usage(format!("--issuer is not a usable AID: {e}")))?;

    // 1. Manifest.
    let m = check_manifest(dir, pinned)?;
    let has = |f: &str| m.pointer(&format!("/files/{f}")).is_some();
    let decision_id = str_field(&m, "decision_id", "manifest.json", 1)?.to_owned();
    let tenant = str_field(&m, "tenant", "manifest.json", 1)?.to_owned();
    let mut checks = vec![format!(
        "manifest: {FORMAT}, issuer is the pinned AID, every listed file matches its SHA-256 and size"
    )];

    // 2. Chain.
    let w = check_window(dir, pinned)?;
    if let Some(n) = m
        .pointer("/inclusion/anchor_attested_len")
        .and_then(serde_json::Value::as_u64)
    {
        if n != w.anchor.attested_len {
            return Err(failed(
                2,
                "manifest.json: inclusion.anchor_attested_len is not anchor.json's attested_len",
            ));
        }
    }
    checks.push(format!(
        "window authenticated from the issuer-signed anchor (base_len {}): {} link(s), {} covering \
         attestation(s)",
        w.anchor.attested_len, w.report.links, w.issuer.covering
    ));

    // 3. Inclusion.
    let mut sealed: Option<&Event> = None;
    for ev in &w.events {
        let is_it = ev.is_link()
            && ev
                .decision
                .as_ref()
                .is_some_and(|d| d.decision_id == decision_id);
        if is_it {
            if sealed.is_some() {
                return Err(failed(
                    3,
                    format!(
                        "the window carries two chained DECISION_SEALED links for '{decision_id}'"
                    ),
                ));
            }
            sealed = Some(ev);
        }
    }
    let sealed = sealed.ok_or_else(|| {
        failed(
            3,
            format!("the window carries no chained DECISION_SEALED for '{decision_id}'"),
        )
    })?;
    if sealed.tenant != tenant {
        return Err(failed(
            3,
            format!(
                "the decision is in tenant '{}', the manifest says '{tenant}'",
                sealed.tenant
            ),
        ));
    }
    let checksum = sealed.checksum.clone().unwrap_or_default();
    let claimed = m
        .pointer("/inclusion/record_checksum")
        .and_then(serde_json::Value::as_str)
        .and_then(b64_std)
        .unwrap_or_default();
    if claimed != checksum {
        return Err(failed(
            3,
            "manifest.json: inclusion.record_checksum is not the decision link's checksum",
        ));
    }
    let payload = sealed
        .decision
        .clone()
        .expect("is_it requires a decision payload");
    checks.push(format!(
        "decision '{decision_id}' is a chained link of tenant '{tenant}' inside the authenticated window"
    ));

    // 4 + 5. Commitment, then its binding.
    let mut tct_verified = None;
    if has("commitment.json") {
        let c = parse_json(
            &read_member(dir, "commitment.json", 4)?,
            "commitment.json",
            4,
        )?;
        let c = parse_commitment(&c).map_err(|e| failed(4, e))?;
        let digest = commitment::commitment_digest(&c).map_err(|e| failed(4, e))?;
        if c.signed_artifact.is_empty() {
            tct_verified = Some(false);
            checks.push(
                "the Commitment has no TCT (sealed under `identity: local-sealed`); it is bound to the \
                 chain by the issuer's binding signature only"
                    .into(),
            );
        } else {
            commitment::verify_tct(pinned, &c.signed_artifact, &digest, now_secs).map_err(|e| {
                failed(
                    4,
                    format!(
                        "commitment.json: the TCT does not verify against the pinned issuer for this \
                         Commitment: {e}"
                    ),
                )
            })?;
            tct_verified = Some(true);
            checks.push(
                "the Commitment's TCT verifies against the pinned issuer and binds its \
                 seam-commitment-digest:v3"
                    .into(),
            );
        }
        if c.supersedes != payload.supersedes {
            return Err(failed(
                4,
                "commitment.json: supersedes differs from the chained record's",
            ));
        }

        let b = parse_json(&read_member(dir, "binding.json", 5)?, "binding.json", 5)?;
        let s = |k: &str| str_field(&b, k, "binding.json", 5);
        let b_issuer = s("issuer_aid")?;
        if b_issuer != pinned {
            return Err(failed(
                5,
                format!("binding.json: it names issuer '{b_issuer}', but you pinned '{pinned}'"),
            ));
        }
        let b_decision = s("decision_id")?;
        let b_tenant = s("tenant")?;
        let b_checksum = b64_std(s("record_checksum")?)
            .ok_or_else(|| failed(5, "binding.json: record_checksum is not base64"))?;
        let b_digest = hex_decode(s("commitment_digest")?)
            .ok_or_else(|| failed(5, "binding.json: commitment_digest is not hex"))?;
        let bound_at = b
            .get("bound_at")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| failed(5, "binding.json: missing u64 'bound_at'"))?;
        let sig: [u8; 64] = b64_std(s("signature")?)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| failed(5, "binding.json: signature is not 64 base64 bytes"))?;
        {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let vk = VerifyingKey::from_bytes(&key)
                .map_err(|e| BundleError::Usage(format!("bad issuer key: {e}")))?;
            let d = evidence_binding_digest(
                b_decision,
                b_tenant,
                &b_checksum,
                &b_digest,
                bound_at,
                b_issuer,
            );
            vk.verify(&d, &Signature::from_bytes(&sig)).map_err(|_| {
                failed(
                    5,
                    "binding.json: the signature does not verify against the pinned issuer",
                )
            })?;
        }
        if b_decision != decision_id || b_tenant != tenant || b_checksum != checksum {
            return Err(failed(
                5,
                "binding.json: it binds a different decision, tenant or chain link",
            ));
        }
        if b_digest != digest {
            return Err(failed(
                5,
                "binding.json: it binds a different Commitment than commitment.json",
            ));
        }
        checks.push(
            "the issuer's signed binding ties this Commitment to the decision's chain link".into(),
        );
    }

    // 6. Disclosures.
    if has("context.json") {
        let ctx = parse_json(&read_member(dir, "context.json", 6)?, "context.json", 6)?;
        let got = context_digest(&ctx).map_err(|e| failed(6, e))?;
        if got.as_slice() != payload.context_digest.as_slice() {
            return Err(failed(
                6,
                "context.json does not recompute the chained context_digest",
            ));
        }
        checks.push("context.json recomputes the chained context_digest".into());
    }
    if has("policy.json") {
        let got = Sha256::digest(read_member(dir, "policy.json", 6)?);
        if got.as_slice() != payload.policy_rules_digest.as_slice() {
            return Err(failed(
                6,
                "SHA-256(policy.json) is not the chained policy_rules_digest",
            ));
        }
        checks.push("SHA-256(policy.json) is the chained policy_rules_digest".into());
    }

    let withheld = m
        .get("withheld")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|w| {
                    let g = |k: &str| {
                        w.get(k)
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("")
                            .to_owned()
                    };
                    (g("item"), g("reason"))
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(BundleReport {
        decision_id,
        tenant,
        window_events: w.report.events,
        window_links: w.report.links,
        attestations: w.issuer.attestations,
        covering: w.issuer.covering,
        anchor_len: w.anchor.attested_len,
        head: w.report.head,
        tct_verified,
        checks,
        withheld,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec § `binding.json`, the worked example: `decision_id = "dec:s1"`, `tenant = "acme"`,
    /// `record_checksum` 32 × 0xab, `commitment_digest` 32 × 0xcd, `bound_at = 1700000`, and the AID of
    /// issuer seed 32 × 0x09. Pinned by the runtime's `evidence_binding_payload_golden`.
    #[test]
    fn binding_digest_matches_the_spec_worked_example() {
        let d = evidence_binding_digest(
            "dec:s1",
            "acme",
            &[0xab; 32],
            &[0xcd; 32],
            1_700_000,
            "aid:pubkey:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg",
        );
        assert_eq!(
            verify::hex(&d),
            "ce1b699d3e67cfd8c16a3c0686eb22e1ea525b926d9d3a44a393ed838aa84ce6"
        );
    }

    #[test]
    fn binding_digest_moves_with_every_field() {
        let base = || {
            (
                "dec:s1".to_string(),
                "acme".to_string(),
                vec![0xab; 32],
                vec![0xcd; 32],
                1_700_000u64,
                "aid:pubkey:x".to_string(),
            )
        };
        let d = |t: &(String, String, Vec<u8>, Vec<u8>, u64, String)| {
            evidence_binding_digest(&t.0, &t.1, &t.2, &t.3, t.4, &t.5)
        };
        let golden = d(&base());
        let mut t = base();
        t.0.push('x');
        assert_ne!(d(&t), golden);
        let mut t = base();
        t.1.push('x');
        assert_ne!(d(&t), golden);
        let mut t = base();
        t.2[0] ^= 1;
        assert_ne!(d(&t), golden);
        let mut t = base();
        t.3[0] ^= 1;
        assert_ne!(d(&t), golden);
        let mut t = base();
        t.4 += 1;
        assert_ne!(d(&t), golden);
        let mut t = base();
        t.5.push('x');
        assert_ne!(d(&t), golden);
        // Length-prefixed, so a boundary shift between decision_id and tenant is not a collision.
        assert_ne!(
            evidence_binding_digest("dec:s1a", "cme", &[0xab; 32], &[0xcd; 32], 1, "a"),
            evidence_binding_digest("dec:s1", "acme", &[0xab; 32], &[0xcd; 32], 1, "a"),
        );
    }
}
