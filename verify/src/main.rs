//! `seam-verify` — check Seam's claims **without trusting Seam**.
//!
//! Seam says: *"don't trust us — verify it yourself."* This is the tool that makes that sentence mean
//! something. It links **nothing of Seam's** (see `Cargo.toml`, where the dependency list is the argument):
//! it is written from the published specs, takes bytes and a public key, and answers yes or no.
//!
//! ```text
//! seam-verify chain <FILE> [--strict]              # the seam-event.v1 hash chain, from the stream alone
//! seam-verify chain <FILE> --issuer <AID>          # + AUTHENTICITY: every issuer-signed head verifies
//! seam-verify chain <FILE> --issuer <AID> --allow-uncovered  # diagnostic report; never exit 0 over one
//! seam-verify erasure-cert <FILE> --issuer <AID>   # a GDPR erasure certificate, from the issuer AID alone
//! seam-verify bundle <DIR> --issuer <AID>          # a seam-evidence-bundle.v1 directory, end to end
//! ```
//!
//! `FILE` is one event per line — the JSON projection or base64 protobuf; `-` reads stdin.
//!
//! # Exit codes
//!
//! `0` verified · `1` usage/IO error · `2` **VERIFICATION FAILED**
#![forbid(unsafe_code)]

// The verification logic lives in `lib.rs` so it is EMBEDDABLE, not only invocable: an auditor
// running verification inside their own pipeline should not have to shell out and parse `--json`.
// This binary is a shell over that library, so the CLI and an embedding caller run exactly the same
// code — there is no second implementation here to drift.
use seam_verify::{verify, wire};

use std::process::ExitCode;
use wire::Event;

const FAILED: u8 = 2;

fn usage() -> ! {
    eprintln!(
        "seam-verify — check Seam's audit chain and erasure certificates without trusting Seam\n\
         \n\
         USAGE:\n    \
             seam-verify chain <FILE> [--strict] [--issuer <AID>] [--from-anchor <FILE>]\n                             \
             [--expect-anchor <FILE>] [--allow-uncovered] [--json]\n    \
             seam-verify erasure-cert <FILE> --issuer <AID> [--json]\n    \
             seam-verify bundle <DIR> --issuer <AID> [--json]\n\
         \n\
         chain <FILE>\n    \
             Verify the seam-event.v1 hash chain from the stream ALONE. One event per line: the JSON\n    \
             projection or base64 protobuf ('-' reads stdin).\n\
         \n\
             An event is a link iff it carries `digest` and `checksum` — by FIELD PRESENCE, never by\n    \
             kind. Advisory events (LEARNING_*, BUDGET_BREACH, SESSION_LIFECYCLE, AUTHORIZE_EVALUATED,\n     \
             POLICY_DENIED, EVENT_REDRIVEN)\n    \
             and the off-chain `chain_anchor` carry neither, and do not advance the head.\n\
         \n    \
             A link whose `kind` this build does not model is STILL VERIFIED as a link and still\n    \
             advances the head — the link check needs no payload semantics, and skipping it would\n    \
             falsely report the chain broken at the NEXT link. What it costs is CONTENT coverage: the\n    \
             digest cannot be recomputed from a payload this build cannot parse. Those events are\n    \
             reported on the `unverified content` line (and as `unverified_content` under --json),\n    \
             never folded into a green claim.\n\
         \n\
             --strict  Refuse a stream containing any non-advisory event with no digest/checksum.\n              \
                       Events written before Seam added those fields look exactly like advisory ones\n              \
                       here: by default they are SKIPPED and counted, and a green result would then be\n              \
                       a claim about history that was never actually checked.\n\
         \n    \
             --issuer <AID>  Upgrade integrity to AUTHENTICITY. Every CHAIN_HEAD_ATTESTATION must verify\n                      \
                       against a PINNED issuer key AND sit at the head it attests, and at least one must\n                      \
                       be present — a plain SHA-256 chain over a public genesis can be rebuilt by a\n                      \
                       transport-controlling forger, but an issuer-signed head cannot be minted without\n                      \
                       the key. A stream with no attestation is REFUSED, not passed. Additionally, every\n                      \
                       DECISION_SEALED's digest is RECOMPUTED under record digest v4 from its payload and\n                      \
                       compared to the wire digest (catching a payload rewrite in an unattested tail); a\n                      \
                       record missing a mandatory column (ciphertext_digest, context_digest,\n                      \
                       participation_digest, classification, participants_digest, trust_basis_commitment\n                      \
                       or auth_method) is REFUSED as a STRIP, distinctly from a digest mismatch. Any\n                      \
                       schema_version other than 4 is REFUSED as cannot-verify, never skipped.\n                      \
                       REPEATABLE: pass once per trusted issuer to verify a chain spanning a key ROTATION\n                      \
                       (an attestation passes iff it verifies against ANY pinned AID; one naming an issuer\n                      \
                       outside the pinned set is a FAIL).\n                      \
                       TENANT BINDING (seam-runtime #835 step 4, with or without --strict): an attestation's\n                      \
                       payload tenant must EQUAL its envelope's, and its signature must verify under the\n                      \
                       one framing that tenant selects — v2 for a named tenant, v1 for the empty (system)\n                      \
                       partition. A tenant attestation minted before step 3 (v1) is REFUSED: verify that\n                      \
                       history from a v2 anchor onward.\n                      \
                       EVERY OTHER CHAINED ENTRY (AUDIT_ENTRY, CHAIN_HEAD_ATTESTATION, ERASURE_CERTIFICATE)\n                      \
                       is recomputed from its own fields too: a mismatch is an ENTRY REWRITE. One this\n                      \
                       build has no preimage for (an unknown action, fact_appended, an unknown kind) is\n                      \
                       UNCOVERED and REFUSED: its content was never checked. The report prints\n                      \
                       `entries recomputed` and `uncovered`, zero included.\n\
         \n    \
             --allow-uncovered  DIAGNOSIS ONLY (chain, with --issuer, never with --json): print the full\n                      \
                       report with each uncovered (seq, tenant, kind, action) instead of refusing. It is\n                      \
                       NOT an authentication: the banner is AUTHENTICITY NOT ESTABLISHED and the exit is\n                      \
                       still 2. Over a stream with nothing uncovered it changes nothing.\n\
         \n    \
             --from-anchor <FILE>  ANCHORED START (spec clause (f)): seed the running head from an\n                      \
                       issuer-signed CHAIN_HEAD_ATTESTATION instead of genesis, and verify the window from\n                      \
                       there. FILE is one anchor: a bare anchor JSON object (one element of\n                      \
                       GET /v1/anchors) or a full seam-event.v1 CHAIN_HEAD_ATTESTATION event line.\n                      \
                       Requires --issuer: the anchor is verified against the pinned AID before it is\n                      \
                       trusted — an unsigned or wrong-issuer anchor is REFUSED, never silently seeded.\n                      \
                       It seeds exactly the tenant it names (its signed tenant); an anchor with no tenant\n                      \
                       is v1 and seeds only the system partition (\"\"), never a tenant's chain.\n\
         \n    \
             --expect-anchor <FILE>  TRUNCATION CHECK (seam-sdk#140): FILE is a later anchor you hold\n                      \
                       INDEPENDENTLY of this stream (fetch one from GET /v1/anchors — this tool makes no\n                      \
                       network call of its own). Same shape as --from-anchor; it does not need to appear\n                      \
                       in the stream. A window cut at the tail is internally consistent and verifies\n                      \
                       green on its own — that is what makes truncation undetectable from the stream\n                      \
                       alone. If the window's verified chain does not reach as far as this anchor attests,\n                      \
                       the stream is REFUSED as TRUNCATED; if it reaches far enough but the head there\n                      \
                       disagrees with the anchor, it is REFUSED as an ANCHOR DIVERGENCE (a cut-and-spliced\n                      \
                       tail can be as long as the real one). Requires --issuer, for the same reason\n                      \
                       --from-anchor does: an unvalidated anchor proves nothing either way.\n\
         \n\
         erasure-cert <FILE> --issuer <AID>\n    \
             Verify a signed GDPR erasure certificate against the issuer AID and NOTHING else. Get the\n    \
             AID out of band (Seam serves it at GET /v1/trust/issuer-aid). Pinning it is what makes the\n    \
             signature mean anything: a forged certificate verifies perfectly against its own forger.\n\
         \n\
         bundle <DIR> --issuer <AID>\n    \
             Verify a seam-evidence-bundle.v1 directory (docs/evidence-bundle.v1.md) against the pinned\n    \
             issuer AID, in the spec's order, refusing at the first failure: (1) the manifest: format,\n    \
             pinned issuer, every listed file's sha256 and size; (2) the window, exactly as `chain\n    \
             events.jsonl --issuer AID --from-anchor anchor.json --strict`; (3) the decision's chained\n    \
             DECISION_SEALED and its checksum; (4) the Commitment's TCT and seam-commitment-digest:v3;\n    \
             (5) the issuer's signed binding of that Commitment to the chain link; (6) the disclosed\n    \
             context.json and policy.json against the chained digests. Withheld items are printed.\n    \
             Exactly one --issuer: the bundle names its issuer, and that name is never trusted.\n\
         \n\
         EXIT CODES:\n    \
             0  verified     1  usage/IO error     2  VERIFICATION FAILED"
    );
    std::process::exit(1);
}

fn read_lines(path: &str) -> Result<Vec<String>, String> {
    let raw = if path == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?
    };
    Ok(raw
        .lines()
        .map(str::to_owned)
        .filter(|l| !l.trim().is_empty())
        .collect())
}

fn q(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// A JSON array of strings, escaped by `serde_json` for the same reason [`q`] is: these come off the
/// WIRE. A `kind` is whatever the emitter — or, in this tool's threat model, a transport-controlling
/// forger — put on the stream, and hand-quoting it would let a crafted one break out of the report a
/// CI consumer parses.
fn q_arr(v: &[&str]) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".into())
}

fn fail(msg: &str, json: bool, banner: &str) -> ExitCode {
    if json {
        println!("{{\"verified\":false,\"error\":{}}}", q(msg));
    } else {
        eprintln!("\n{banner}\n\n{msg}");
    }
    ExitCode::from(FAILED)
}

/// The exit-1 (usage/IO/parse) path. Under `--json` a CI consumer parses stdout — an error that left
/// stdout EMPTY would be indistinguishable from a crashed pipe, so the same `{"verified":false,"error"}`
/// shape as the exit-2 report is emitted there too. The human line stays on stderr either way.
fn io_error(msg: &str, json: bool) -> ExitCode {
    if json {
        println!("{{\"verified\":false,\"error\":{}}}", q(msg));
    }
    eprintln!("seam-verify: {msg}");
    ExitCode::from(1)
}

/// Load and validate the `--from-anchor` FILE, spec clauses (f1)/(f2), BEFORE anything is verified
/// from it — an unsigned, forged, or unpinned-issuer anchor must never seed a running head.
///
/// Returns `Ok(None)` when no anchor was requested (`--from-anchor` absent), `Ok(Some(attestation))`
/// on a validated anchor, or a pre-formed `ExitCode` on a load/validation failure — a parse failure
/// (bad file, wrong shape) is exit 1 (usage/IO), while a signature/pin/vacuous failure is exit 2 under
/// a banner naming which: `ANCHOR REJECTED` or `VACUOUS ANCHOR`.
fn load_anchor(
    from_anchor: Option<&str>,
    issuers: &[String],
    json: bool,
) -> Result<Option<wire::Attestation>, ExitCode> {
    let Some(anchor_path) = from_anchor else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(anchor_path)
        .map_err(|e| io_error(&format!("{anchor_path}: {e}"), json))?;
    let anchor = wire::Attestation::parse_document(&raw).map_err(|e| {
        // A full-event anchor whose payload tenant differs from its envelope's is a defect in the
        // anchor itself (exit 2, like ANCHOR REJECTED), not an unreadable input (exit 1).
        if e.starts_with(wire::ANCHOR_SELF_CONTRADICTS) {
            fail(
                &format!("{anchor_path}: {e}"),
                json,
                wire::ANCHOR_SELF_CONTRADICTS,
            )
        } else {
            io_error(&format!("{anchor_path}: {e}"), json)
        }
    })?;
    if let Err(e) = verify::verify_anchor(&anchor, issuers) {
        let banner = if e.contains("VACUOUS") {
            "VACUOUS ANCHOR"
        } else {
            "ANCHOR REJECTED"
        };
        return Err(fail(&e, json, banner));
    }
    Ok(Some(anchor))
}

fn cmd_chain(
    path: &str,
    strict: bool,
    json: bool,
    issuers: &[String],
    from_anchor: Option<&str>,
    expect_anchor: Option<&str>,
    allow_uncovered: bool,
) -> ExitCode {
    let anchor = match load_anchor(from_anchor, issuers, json) {
        Ok(a) => a,
        Err(code) => return code,
    };
    // Same loader as `--from-anchor`: parse + pin + signature + non-vacuous. `load_anchor`'s own
    // error text names no flag, so it reads correctly for either caller.
    let expect = match load_anchor(expect_anchor, issuers, json) {
        Ok(a) => a,
        Err(code) => return code,
    };

    let lines = match read_lines(path) {
        Ok(l) => l,
        Err(e) => return io_error(&e, json),
    };
    if lines.is_empty() {
        return io_error(
            &format!("{path}: no events — refusing to report a green chain over nothing"),
            json,
        );
    }

    let mut events = Vec::with_capacity(lines.len());
    for (i, l) in lines.iter().enumerate() {
        match Event::parse(l) {
            Ok(e) => events.push(e),
            Err(e) => return io_error(&format!("line {}: {e}", i + 1), json),
        }
    }

    // Collapse retries BEFORE sorting: two copies of one event sort adjacent, and the second would
    // otherwise read as a second link on the same head.
    let (mut events, duplicates) = match verify::dedup(events) {
        Ok(v) => v,
        Err(e) => return fail(&e, json, "CHAIN VERIFICATION FAILED"),
    };
    // Delivery is not ordered (at-least-once, replays, merged shards). Sort rather than demand order.
    events.sort_by_key(|e| e.seq);

    let report = match &anchor {
        Some(a) => verify::chain_anchored(&events, &a.tenant, a.attested_len, &a.attested_head),
        None => verify::chain(&events),
    };

    match report {
        Err(e) => fail(&e, json, "CHAIN VERIFICATION FAILED"),
        Ok(mut r) => {
            r.duplicates = duplicates;
            // Spec clause (f0): an anchor was given for a tenant this window has no chained event for —
            // including an untenanted (v1) anchor, which seeds only the `""` partition (#835 step 4), over
            // a window holding only tenant chains. `chain_by_tenant` itself does not refuse this (see
            // `ChainReport::unconsumed_anchors`'s own doc comment); this caller does, fail-closed (exit
            // 2), as seam-runtime's own seam-verify does: the operator asked for a start the window does
            // not contain, and verifying the window anyway would vouch for a start nobody chose.
            if let Some((t, len)) = r.unconsumed_anchors.iter().next() {
                return fail(
                    &format!(
                        "tenant {t:?}: NO VALID ATTESTATION — an anchor was given for this tenant \
                         (attested_len {len}), but the window has no chained event for it, so nothing \
                         was verified from that start.\n  \
                         An anchor seeds exactly the tenant it names: a tenant anchor must be v2 over \
                         that tenant, and an anchor with no tenant (v1) seeds only the system partition \
                         \"\" — never a tenant's chain (#835 step 4)."
                    ),
                    json,
                    "AUTHENTICITY VERIFICATION FAILED",
                );
            }
            // Truncation check (seam-sdk#140): independent of authenticity below — it compares the
            // verified window's own reach against an anchor the caller holds separately, and needs
            // nothing from `--issuer`'s in-stream attestation checking to do it.
            if let Some(e) = &expect {
                match verify::check_not_truncated(&r, e) {
                    Ok(()) => {}
                    Err(err) if err.starts_with("ANCHOR DIVERGENCE") => {
                        return fail(&err, json, "ANCHOR DIVERGENCE")
                    }
                    Err(err) => return fail(&err, json, "TRUNCATED STREAM"),
                }
            }
            if strict && !r.unverifiable.is_empty() {
                let msg = format!(
                    "{} event(s) carry no digest/checksum and are not advisory (first seq: {}). They \
                     predate the chain fields, so this tool CANNOT verify them — and --strict refuses to \
                     report a green chain over history it never checked.",
                    r.unverifiable.len(),
                    r.unverifiable[0]
                );
                return fail(&msg, json, "REFUSED (--strict)");
            }
            // --issuer upgrades integrity → AUTHENTICITY: every chain-head attestation must verify against
            // the pinned key AND sit at the head it attests, and at least one covering attestation must be
            // present. Integrity has already passed (the head sequence in `r.heads` is trustworthy to
            // check positions against).
            //
            // A window spanning more than one tenant has no single running head to check attestations
            // against (§0's genesis-sentinel fallback on `r.heads`/`r.max_schema_by_link`) — it is
            // fanned out per tenant instead, via `tenant_issuer_reports` below. Under `--from-anchor`
            // that is the anchored tenant from its anchor (`tc.base_len`/`tc.heads[0]`) and every other
            // tenant from genesis — the anchor seeds exactly the tenant it names (#835 step 4).
            let multi_tenant = r.tenants.len() > 1;
            // The library refuses an uncovered entry (spec `:293`) unless this is set, and only the
            // `--allow-uncovered` diagnostic sets it (argument validation keeps it off `--json`).
            let opts = verify::AuthOptions::allow_uncovered(allow_uncovered);
            let issuer_report = if issuers.is_empty() || multi_tenant {
                None
            } else {
                let (base_len, base_head): (u64, &[u8]) = match &anchor {
                    Some(a) => (a.attested_len, &a.attested_head),
                    None => (0, &verify::GENESIS),
                };
                match verify::verify_authenticity_anchored_with(
                    &events,
                    &r.heads,
                    &r.max_schema_by_link,
                    issuers,
                    base_len,
                    base_head,
                    &opts,
                ) {
                    Ok(ir) => Some(ir),
                    Err(e) => return authenticity_failed(&e, json),
                }
            };
            let tenant_issuer_reports = if issuers.is_empty() || !multi_tenant {
                None
            } else {
                match verify::verify_authenticity_by_tenant_with(&events, &r, issuers, &opts) {
                    Ok(m) => Some(m),
                    Err(e) => return authenticity_failed(&e, json),
                }
            };
            // Every report under `--issuer`, single or per tenant, and the uncovered entries across all
            // of them. Non-empty only under `--allow-uncovered`: the library refused otherwise.
            let all_reports: Vec<&verify::IssuerReport> = issuer_report
                .iter()
                .chain(tenant_issuer_reports.iter().flat_map(|m| m.values()))
                .collect();
            let mut uncovered: Vec<&verify::Uncovered> =
                all_reports.iter().flat_map(|ir| &ir.uncovered).collect();
            uncovered.sort_by_key(|u| u.seq);
            let entries_recomputed: usize =
                all_reports.iter().map(|ir| ir.entries_recomputed).sum();
            if !uncovered.is_empty() && json {
                // Unreachable: `--allow-uncovered` never pairs with `--json`. Kept so a future change to
                // argument validation still cannot print a JSON green over an uncovered entry.
                return fail(
                    &format!(
                        "{} — {} uncovered chained entr{} (this build cannot recompute them)",
                        verify::UNCOVERED_ENTRY,
                        uncovered.len(),
                        if uncovered.len() == 1 { "y" } else { "ies" }
                    ),
                    json,
                    "REFUSED (--issuer)",
                );
            }
            // Additive: a window spanning more than one tenant (`r.tenants` — see [`ChainReport`]'s own
            // doc comment on its genesis-sentinel top-level fields in that case) reports each tenant's
            // OWN links/head/authenticity here. Absent entirely for `r.tenants.len() <= 1` — the one
            // existing caller shape — so neither output byte changes for it.
            let tenants_json = if multi_tenant {
                let entries: Vec<String> = r
                    .tenants
                    .iter()
                    .map(|(t, tc)| {
                        let auth = match tenant_issuer_reports.as_ref().and_then(|m| m.get(t)) {
                            Some(ir) => format!(
                                ",\"authenticated\":true,\"attestations\":{},\"covered_prefix\":{},\
                                 \"records_recomputed\":{}",
                                ir.attestations, ir.covered_prefix, ir.records_recomputed,
                            ),
                            None => String::new(),
                        };
                        format!(
                            "{{\"tenant\":{},\"links\":{},\"base_len\":{},\"head\":\"{}\"{}}}",
                            q(t),
                            tc.links,
                            tc.base_len,
                            verify::hex(&tc.head),
                            auth,
                        )
                    })
                    .collect();
                format!(",\"tenants\":[{}]", entries.join(","))
            } else {
                String::new()
            };
            // Anchored-only key, so JSON stays byte-identical to before this flag existed whenever
            // `--expect-anchor` is absent.
            let truncation_extra = match &expect {
                Some(e) => format!(",\"not_truncated_through\":{}", e.attested_len),
                None => String::new(),
            };
            if json {
                let authenticity = match &issuer_report {
                    Some(ir) => {
                        // Anchored-only keys, so genesis-mode JSON stays byte-identical to before this
                        // flag existed — `anchor_extra` is the empty string there.
                        let anchor_extra = match &anchor {
                            Some(a) => format!(
                                ",\"anchored\":true,\"base_len\":{},\"base_head\":\"{}\",\
                                 \"covering_attestations\":{},\"below_window\":{}",
                                a.attested_len,
                                verify::hex(&a.attested_head),
                                ir.covering,
                                ir.below_window,
                            ),
                            None => String::new(),
                        };
                        format!(
                            ",\"authenticated\":true,\"attestations\":{},\"covered_prefix\":{},\
                             \"records_recomputed\":{}{}",
                            ir.attestations, ir.covered_prefix, ir.records_recomputed, anchor_extra,
                        )
                    }
                    None => String::new(),
                };
                println!(
                    "{{\"verified\":true,\"events\":{},\"links\":{},\"advisory\":{},\"duplicates\":{},\
                     \"unverifiable\":{},\"unverified_content\":{},\"unmodelled_kinds\":{},\
                     \"head\":\"{}\"{}{}{}}}",
                    r.events,
                    r.links,
                    r.advisory,
                    r.duplicates,
                    r.unverifiable.len(),
                    r.unmodelled.len(),
                    q_arr(&{
                        let mut k: Vec<&str> = r.unmodelled.iter().map(|(_, k)| k.as_str()).collect();
                        k.sort_unstable();
                        k.dedup();
                        k
                    }),
                    verify::hex(&r.head),
                    authenticity,
                    tenants_json,
                    truncation_extra,
                );
            } else {
                // `--allow-uncovered` with something uncovered REPLACES the AUTHENTICATED banners: no
                // line of that report may read as a green claim (spec §Versioning, `:1679-1683`), and
                // it exits 2 below. The banner deliberately contains neither VERIFIED nor
                // AUTHENTICATED (nor UNVERIFIED, which contains VERIFIED).
                if uncovered.is_empty() {
                    println!(
                        "{}",
                        match (&anchor, &issuer_report, &tenant_issuer_reports) {
                            (Some(_), Some(_), _) => "WINDOW AUTHENTICATED (issuer-anchored start)",
                            (None, Some(_), _) =>
                                "CHAIN AUTHENTICATED (integrity + issuer-signed head)",
                            (Some(_), None, Some(_)) => {
                                "WINDOW AUTHENTICATED (issuer-anchored start, per tenant)"
                            }
                            (None, None, Some(_)) => {
                                "CHAIN AUTHENTICATED (integrity + issuer-signed head, per tenant)"
                            }
                            _ => "CHAIN VERIFIED",
                        }
                    );
                } else {
                    println!(
                        "AUTHENTICITY NOT ESTABLISHED: {} uncovered chained entr{} \
                         (--allow-uncovered diagnostic report)",
                        uncovered.len(),
                        if uncovered.len() == 1 { "y" } else { "ies" }
                    );
                }
                println!("  events            : {}", r.events);
                if multi_tenant {
                    println!(
                        "  links checked     : {} (top-level — N/A across {} tenants, see below)",
                        r.links,
                        r.tenants.len()
                    );
                } else {
                    println!("  links checked     : {}", r.links);
                }
                println!("  advisory (skipped): {}", r.advisory);
                // Spec §Versioning's MUST. Printed UNCONDITIONALLY, including the zero — the other
                // optional lines here (duplicates, below-window) are zero-suppressed because absence
                // and zero mean the same thing for them. They do not for this one: a coverage
                // disclosure that vanishes when it is zero cannot be told apart from a build that
                // never measured it, and "the stream carried none" is exactly the claim a reader
                // needs stated rather than inferred from a missing line.
                if r.unmodelled.is_empty() {
                    println!(
                        "  unverified content: 0 (every link's kind is modelled by this build)"
                    );
                } else {
                    let mut kinds: Vec<&str> =
                        r.unmodelled.iter().map(|(_, k)| k.as_str()).collect();
                    kinds.sort_unstable();
                    kinds.dedup();
                    println!(
                        "  unverified content: {} link(s) of unmodelled kind: {} (first seq {})\n\
                         {:22}LINKAGE verified — folded into the head above, exactly as for a kind\n\
                         {:22}this build models. CONTENT not verified: no payload model, so the\n\
                         {:22}digest was not recomputed, and these are in NO recompute count.",
                        r.unmodelled.len(),
                        kinds.join(", "),
                        r.unmodelled[0].0,
                        "",
                        "",
                        "",
                    );
                }
                if let Some(ir) = &issuer_report {
                    println!("  attestations      : {} (issuer-signed)", ir.attestations);
                    println!("  covered prefix    : {} links", ir.covered_prefix);
                    println!(
                        "  records recomputed: {} (v4 record-digest recompute)",
                        ir.records_recomputed
                    );
                    if let Some(a) = &anchor {
                        println!(
                            "  anchored start    : base_len {} / base_head {}",
                            a.attested_len,
                            verify::hex(&a.attested_head)
                        );
                        println!(
                            "  covering (len > base_len): {} (these satisfy spec clause (f4))",
                            ir.covering
                        );
                        if ir.below_window > 0 {
                            println!(
                                "  below-window      : {} (skipped, reported — spec clause (f3))",
                                ir.below_window
                            );
                        }
                    }
                }
                // Spec (b′). Both printed UNCONDITIONALLY under --issuer, zero included, for the same
                // reason as `unverified content` above: a coverage disclosure that vanishes at zero
                // cannot be told apart from one never measured.
                if !issuers.is_empty() {
                    println!(
                        "  entries recomputed: {entries_recomputed} (audit, attestation and erasure \
                         entry digests)"
                    );
                    println!("  uncovered         : {}", uncovered.len());
                    for u in &uncovered {
                        println!("    {}", u.describe());
                    }
                }
                if r.duplicates > 0 {
                    println!(
                        "  duplicates        : {} (at-least-once retries)",
                        r.duplicates
                    );
                }
                if !r.unverifiable.is_empty() {
                    println!(
                        "  UNVERIFIABLE      : {}  <- no digest/checksum; these predate the chain \
                         fields. Re-run with --strict to refuse rather than skip them.",
                        r.unverifiable.len()
                    );
                }
                if multi_tenant {
                    println!("  tenants           : {}", r.tenants.len());
                    for (t, tc) in &r.tenants {
                        println!(
                            "    {t:?}: links {}, head {}",
                            tc.links,
                            verify::hex(&tc.head)
                        );
                        if let Some(ir) = tenant_issuer_reports.as_ref().and_then(|m| m.get(t)) {
                            println!(
                                "      attestations {} (issuer-signed), covered prefix {} links, \
                                 records recomputed {}, entries recomputed {}, uncovered {}",
                                ir.attestations,
                                ir.covered_prefix,
                                ir.records_recomputed,
                                ir.entries_recomputed,
                                ir.uncovered.len()
                            );
                        }
                    }
                } else {
                    println!("  head              : {}", verify::hex(&r.head));
                }
                if let Some(e) = &expect {
                    println!(
                        "  not truncated thru: {} (checked against an independently-held anchor — \
                         seam-sdk#140)",
                        e.attested_len
                    );
                }
                if !uncovered.is_empty() {
                    // stderr, like every other refusal's prose: stdout is the report above.
                    eprintln!(
                        "\nNOT AN AUTHENTICATION: the {} entr{} listed under `uncovered` carr{} an \
                         action or kind this build cannot recompute, so {} content was never checked. \
                         --allow-uncovered prints this report for diagnosis and still exits 2; without \
                         it --issuer refuses the stream. A newer producer needs a newer seam-verify.",
                        uncovered.len(),
                        if uncovered.len() == 1 { "y" } else { "ies" },
                        if uncovered.len() == 1 { "ies" } else { "y" },
                        if uncovered.len() == 1 { "its" } else { "their" },
                    );
                    return ExitCode::from(FAILED);
                }
            }
            ExitCode::SUCCESS
        }
    }
}

/// An authenticity refusal. An uncovered entry is named as the runtime names it (`REFUSED (--issuer)`)
/// and gains the diagnostic hint; every other library refusal keeps its banner.
fn authenticity_failed(e: &str, json: bool) -> ExitCode {
    if e.contains(verify::UNCOVERED_ENTRY) {
        let msg = format!(
            "{e}\n  (`chain --issuer <AID> --allow-uncovered` prints a diagnostic report of them; it \
             still exits 2)"
        );
        fail(&msg, json, "REFUSED (--issuer)")
    } else {
        fail(e, json, "AUTHENTICITY VERIFICATION FAILED")
    }
}

fn cmd_cert(path: &str, issuer: &str, json: bool) -> ExitCode {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => return io_error(&format!("{path}: {e}"), json),
    };
    // Accept every shape a holder can plausibly have:
    //   * the whole `seam-event.v1` event  — what a webhook sink receives;
    //   * the bare certificate             — what `GET /v1/erasure/certificate` returns;
    //   * a `{ "cert": { ... } }` wrapper  — the published reference vector's shape.
    // A verifier that only accepts the form its author happened to test with is a verifier nobody can run.
    //
    // The shape-sniffing lives in `Cert::parse_document` rather than here, so the CLI and an embedding
    // caller share ONE parse. While it was inline in this binary, an embedder had to reimplement it to
    // accept the same files the CLI accepts — a second implementation of exactly the kind this crate
    // exists to avoid.
    let cert = match wire::Cert::parse_document(&raw) {
        Ok(c) => c,
        Err(e) => {
            return io_error(
                &format!(
                    "{path}: not a certificate in any recognised shape (a seam-event.v1 \
                     event, a bare certificate, or a {{\"cert\": ...}} wrapper): {e}"
                ),
                json,
            );
        }
    };

    match verify::erasure_certificate(issuer, &cert) {
        Err(e) => fail(&e, json, "ERASURE CERTIFICATE REJECTED"),
        Ok(()) => {
            if json {
                println!(
                    "{{\"verified\":true,\"subject\":{},\"erased\":{},\"held\":{},\"erased_at\":{}}}",
                    q(&cert.subject),
                    cert.erased.len(),
                    cert.held.len(),
                    cert.erased_at
                );
            } else {
                println!("ERASURE CERTIFICATE VERIFIED");
                println!("  subject   : {}", cert.subject);
                println!("  erased    : {} decision(s)", cert.erased.len());
                println!(
                    "  held      : {} (withheld under legal hold — NOT erased)",
                    cert.held.len()
                );
                println!("  erased_at : {}", cert.erased_at);
                println!("  issuer    : {}", cert.issuer_aid);
            }
            ExitCode::SUCCESS
        }
    }
}

fn cmd_bundle(dir: &str, issuer: &str, json: bool) -> ExitCode {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match seam_verify::verify_bundle(std::path::Path::new(dir), issuer, now) {
        Err(seam_verify::BundleError::Usage(m)) => io_error(&m, json),
        Err(seam_verify::BundleError::Failed { step, message }) => fail(
            &format!("step {step}: {message}"),
            json,
            "EVIDENCE BUNDLE FAILED VERIFICATION",
        ),
        Ok(r) => {
            if json {
                let checks: Vec<&str> = r.checks.iter().map(String::as_str).collect();
                let withheld: Vec<String> = r
                    .withheld
                    .iter()
                    .map(|(i, why)| format!("{{\"item\":{},\"reason\":{}}}", q(i), q(why)))
                    .collect();
                println!(
                    "{{\"verified\":true,\"format\":{},\"decision_id\":{},\"tenant\":{},\
                     \"events\":{},\"links\":{},\"attestations\":{},\"covering_attestations\":{},\
                     \"base_len\":{},\"head\":\"{}\",\"tct\":{},\"checks\":{},\"withheld\":[{}]}}",
                    q(seam_verify::bundle::FORMAT),
                    q(&r.decision_id),
                    q(&r.tenant),
                    r.window_events,
                    r.window_links,
                    r.attestations,
                    r.covering,
                    r.anchor_len,
                    verify::hex(&r.head),
                    match r.tct_verified {
                        Some(true) => "\"verified\"",
                        Some(false) => "\"absent\"",
                        None => "null",
                    },
                    q_arr(&checks),
                    withheld.join(","),
                );
            } else {
                println!("EVIDENCE BUNDLE VERIFIED ({})", seam_verify::bundle::FORMAT);
                println!("  decision  : {}", r.decision_id);
                println!("  tenant    : {}", r.tenant);
                println!("  head      : {}", verify::hex(&r.head));
                for c in &r.checks {
                    println!("  - {c}");
                }
                for (item, why) in &r.withheld {
                    println!("  - withheld: {item} ({why})");
                }
            }
            ExitCode::SUCCESS
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first().map(String::as_str) else {
        usage()
    };
    if matches!(cmd, "-h" | "--help") {
        usage();
    }

    let (mut json, mut strict) = (false, false);
    // Repeatable: one `--issuer` per trusted AID, so a chain spanning an issuer-key rotation (attestations
    // from the retired key AND the new one) can be authenticated end-to-end. One --issuer behaves as before.
    let mut issuers: Vec<String> = Vec::new();
    let mut positional: Option<String> = None;
    // Anchored start (spec clause (f)): exactly one anchor seeds a start, so a second `--from-anchor`
    // is refused loudly, the same shape as a second positional FILE below — silently keeping the LAST
    // one would seed a start the caller never actually asked for.
    let mut from_anchor: Option<String> = None;
    // Truncation check (seam-sdk#140): exactly one independently-held anchor to check the window's
    // reach against, same one-wins-loudly shape as `from_anchor` above.
    let mut expect_anchor: Option<String> = None;
    // `--allow-uncovered`: chain only, with `--issuer`, never with `--json` (checked below, before any
    // verification runs, so a rejected combination never reaches stdout).
    let mut allow_uncovered = false;

    let mut it = argv[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--strict" => strict = true,
            "--allow-uncovered" => allow_uncovered = true,
            "--issuer" => match it.next() {
                Some(v) => issuers.push(v.clone()),
                None => {
                    eprintln!("seam-verify: --issuer requires an AID");
                    usage();
                }
            },
            "--from-anchor" => match it.next() {
                Some(v) => {
                    if from_anchor.is_some() {
                        eprintln!(
                            "seam-verify: --from-anchor given twice — exactly one anchor seeds a start"
                        );
                        usage();
                    }
                    from_anchor = Some(v.clone());
                }
                None => {
                    eprintln!("seam-verify: --from-anchor requires a FILE");
                    usage();
                }
            },
            "--expect-anchor" => match it.next() {
                Some(v) => {
                    if expect_anchor.is_some() {
                        eprintln!(
                            "seam-verify: --expect-anchor given twice — exactly one anchor checks \
                             the window's reach"
                        );
                        usage();
                    }
                    expect_anchor = Some(v.clone());
                }
                None => {
                    eprintln!("seam-verify: --expect-anchor requires a FILE");
                    usage();
                }
            },
            "-h" | "--help" => usage(),
            o if o.starts_with('-') && o != "-" => {
                eprintln!("seam-verify: unknown option '{o}'");
                usage();
            }
            o => match positional {
                // A second input file is ambiguous — silently keeping the LAST one would verify a file
                // the caller never asked about, under a green banner. Refuse loudly instead.
                Some(ref first) => {
                    eprintln!(
                        "seam-verify: more than one input file given ('{first}' and '{o}') — \
                         exactly one FILE is accepted"
                    );
                    usage();
                }
                None => positional = Some(o.to_owned()),
            },
        }
    }

    match cmd {
        "chain" => match positional {
            Some(p) => {
                if from_anchor.is_some() && issuers.is_empty() {
                    eprintln!(
                        "seam-verify: --from-anchor requires --issuer — the anchor is verified against \
                         the pinned AID before it is trusted; an unsigned or wrong-issuer anchor is \
                         REFUSED, never silently seeded"
                    );
                    usage();
                }
                if expect_anchor.is_some() && issuers.is_empty() {
                    eprintln!(
                        "seam-verify: --expect-anchor requires --issuer — an unvalidated anchor \
                         proves nothing either way, so it is verified against the pinned AID before \
                         the window is checked against it"
                    );
                    usage();
                }
                // Never with --json: an automated caller must not be able to get a green, or a
                // parseable "verified", over an entry whose content was never checked.
                if allow_uncovered && json {
                    eprintln!(
                        "seam-verify: --allow-uncovered is a human diagnostic report only; it never \
                         pairs with --json"
                    );
                    usage();
                }
                // Stricter than the runtime, which accepts it as a no-op: without --issuer nothing is
                // recomputed, so there is nothing for it to allow.
                if allow_uncovered && issuers.is_empty() {
                    eprintln!(
                        "seam-verify: --allow-uncovered requires --issuer — only --issuer recomputes \
                         entries, so without it there is nothing uncovered to report"
                    );
                    usage();
                }
                cmd_chain(
                    &p,
                    strict,
                    json,
                    &issuers,
                    from_anchor.as_deref(),
                    expect_anchor.as_deref(),
                    allow_uncovered,
                )
            }
            None => {
                eprintln!("seam-verify: chain requires a FILE (or '-')");
                usage();
            }
        },
        "erasure-cert" => {
            if from_anchor.is_some() {
                eprintln!("seam-verify: --from-anchor is a chain-only flag");
                usage();
            }
            if expect_anchor.is_some() {
                eprintln!("seam-verify: --expect-anchor is a chain-only flag");
                usage();
            }
            if allow_uncovered {
                eprintln!("seam-verify: --allow-uncovered is a chain-only flag");
                usage();
            }
            // A certificate names exactly ONE signer; repeatable --issuer is a chain-only affordance for
            // key rotation. Anything but exactly one pin here is a usage error.
            let (Some(p), [i]) = (positional, issuers.as_slice()) else {
                eprintln!(
                    "seam-verify: erasure-cert requires a FILE and exactly one --issuer <AID>"
                );
                usage();
            };
            cmd_cert(&p, i, json)
        }
        "bundle" => {
            if from_anchor.is_some() || expect_anchor.is_some() {
                eprintln!(
                    "seam-verify: bundle takes its anchor from the bundle's own anchor.json; \
                     --from-anchor/--expect-anchor are chain-only flags"
                );
                usage();
            }
            // A bundle's chain step always refuses an uncovered entry; there is no diagnostic mode.
            if allow_uncovered {
                eprintln!("seam-verify: --allow-uncovered is a chain-only flag");
                usage();
            }
            // Like a certificate, a bundle names exactly ONE issuer, and the pin must be that issuer.
            let (Some(p), [i]) = (positional, issuers.as_slice()) else {
                eprintln!("seam-verify: bundle requires a DIR and exactly one --issuer <AID>");
                usage();
            };
            // `--strict` is accepted and redundant: the bundle's chain step is always strict.
            cmd_bundle(&p, i, json)
        }
        o => {
            eprintln!("seam-verify: unknown command '{o}'");
            usage();
        }
    }
}
