//! `seam-verify` — check Seam's claims **without trusting Seam**.
//!
//! Seam says: *"don't trust us — verify it yourself."* This is the tool that makes that sentence mean
//! something. It links **nothing of Seam's** (see `Cargo.toml`, where the dependency list is the argument):
//! it is written from the published specs, takes bytes and a public key, and answers yes or no.
//!
//! ```text
//! seam-verify chain <FILE> [--strict]              # the seam-event.v1 hash chain, from the stream alone
//! seam-verify chain <FILE> --issuer <AID>          # + AUTHENTICITY: every issuer-signed head verifies
//! seam-verify erasure-cert <FILE> --issuer <AID>   # a GDPR erasure certificate, from the issuer AID alone
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
             [--expect-anchor <FILE>] [--json]\n    \
             seam-verify erasure-cert <FILE> --issuer <AID> [--json]\n\
         \n\
         chain <FILE>\n    \
             Verify the seam-event.v1 hash chain from the stream ALONE. One event per line: the JSON\n    \
             projection or base64 protobuf ('-' reads stdin).\n\
         \n\
             An event is a link iff it carries `digest` and `checksum` — by FIELD PRESENCE, never by\n    \
             kind. Advisory events (LEARNING_*, BUDGET_BREACH, SESSION_LIFECYCLE, AUTHORIZE_EVALUATED,\n     \
             POLICY_DENIED)\n    \
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
                       v2 and v3 DECISION_SEALED's digest is RECOMPUTED from its payload and compared to\n                      \
                       the wire digest (catching a payload rewrite in an unattested tail); a record missing\n                      \
                       its ciphertext_digest (a strip/downgrade) is REFUSED, as is a v3 record missing its\n                      \
                       context_digest or participation_digest -- reported as a STRIP, distinctly from a\n                      \
                       digest mismatch. A schema_version this build does not implement is REFUSED, never\n                      \
                       skipped.\n                      \
                       REPEATABLE: pass once per trusted issuer to verify a chain spanning a key ROTATION\n                      \
                       (an attestation passes iff it verifies against ANY pinned AID; one naming an issuer\n                      \
                       outside the pinned set is a FAIL).\n\
         \n    \
             --from-anchor <FILE>  ANCHORED START (spec clause (f)): seed the running head from an\n                      \
                       issuer-signed CHAIN_HEAD_ATTESTATION instead of genesis, and verify the window from\n                      \
                       there. FILE is one anchor: a bare six-field JSON object (one element of\n                      \
                       GET /v1/anchors) or a full seam-event.v1 CHAIN_HEAD_ATTESTATION event line.\n                      \
                       Requires --issuer: the anchor is verified against the pinned AID before it is\n                      \
                       trusted — an unsigned or wrong-issuer anchor is REFUSED, never silently seeded.\n\
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
    let anchor = wire::Attestation::parse_document(&raw)
        .map_err(|e| io_error(&format!("{anchor_path}: {e}"), json))?;
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
        Some(a) => verify::chain_anchored(&events, a.attested_len, &a.attested_head),
        None => verify::chain(&events),
    };

    match report {
        // `chain_anchored`'s own usage error (an anchor given over a window spanning more than one
        // tenant, spec clause (f0)) is a caller mistake, not a verification failure — exit 1, not 2.
        Err(e) if e.starts_with("USAGE ERROR:") => io_error(&e, json),
        Err(e) => fail(&e, json, "CHAIN VERIFICATION FAILED"),
        Ok(mut r) => {
            r.duplicates = duplicates;
            // Spec clause (f0): an anchor was given for a tenant this window has no chained event for.
            // `chain_by_tenant` itself does not refuse this (see `ChainReport::unconsumed_anchors`'s own
            // doc comment) — it is this caller's decision, the same division `verify_anchor`/
            // `chain_anchored` already have between validating an anchor and trusting it as a start.
            // Not reachable through this CLI's own single-file `--from-anchor` today (its wrapper only
            // ever attributes the anchor to a tenant proven present in the window), but the check is
            // cheap, matches the documented contract, and holds as soon as that changes.
            if !r.unconsumed_anchors.is_empty() {
                let mut names: Vec<String> = r
                    .unconsumed_anchors
                    .iter()
                    .map(|(t, len)| format!("{t:?} (attested_len {len})"))
                    .collect();
                names.sort();
                return io_error(
                    &format!(
                        "USAGE ERROR: an anchor was given for {} tenant(s) this window has NO chained \
                         event for: {}.\n  \
                         An anchor with nothing to seed cannot be a starting point for verification.",
                        r.unconsumed_anchors.len(),
                        names.join(", ")
                    ),
                    json,
                );
            }
            // Truncation check (seam-sdk#140): independent of authenticity below — it compares the
            // verified window's own reach against an anchor the caller holds separately, and needs
            // nothing from `--issuer`'s in-stream attestation checking to do it.
            if let Some(e) = &expect {
                match verify::check_not_truncated(&r, e) {
                    Ok(()) => {}
                    Err(err) if err.starts_with("USAGE ERROR:") => return io_error(&err, json),
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
            // fanned out per tenant instead, via `tenant_issuer_reports` below. `--from-anchor` cannot
            // reach this branch: `chain_anchored` already refused a multi-tenant window as a usage error
            // before this match was ever entered, so `r.tenants.len() > 1` here is always genesis mode.
            let multi_tenant = r.tenants.len() > 1;
            let issuer_report = if issuers.is_empty() || multi_tenant {
                None
            } else {
                let res = match &anchor {
                    Some(a) => verify::verify_authenticity_anchored(
                        &events,
                        &r.heads,
                        &r.max_schema_by_link,
                        issuers,
                        a.attested_len,
                        &a.attested_head,
                    ),
                    None => verify::verify_authenticity(
                        &events,
                        &r.heads,
                        &r.max_schema_by_link,
                        issuers,
                    ),
                };
                match res {
                    Ok(ir) => Some(ir),
                    Err(e) => return fail(&e, json, "AUTHENTICITY VERIFICATION FAILED"),
                }
            };
            let tenant_issuer_reports = if issuers.is_empty() || !multi_tenant {
                None
            } else {
                match verify::verify_authenticity_by_tenant(&events, &r, issuers) {
                    Ok(m) => Some(m),
                    Err(e) => return fail(&e, json, "AUTHENTICITY VERIFICATION FAILED"),
                }
            };
            // U-RT-3 Phase 3's `--strict`-equivalent: a stream carrying a pre-Phase-2 attestation (no
            // payload tenant to cross-check) is silently trusted on the envelope alone by default, and
            // refused under --strict — the same posture as `r.unverifiable` above, extended to the one
            // new kind of "this tool could not actually check that" this field introduces.
            if strict {
                let tenant_unbound: usize = match (&issuer_report, &tenant_issuer_reports) {
                    (Some(ir), None) => ir.tenant_unbound,
                    (None, Some(m)) => m.values().map(|ir| ir.tenant_unbound).sum(),
                    _ => 0,
                };
                if tenant_unbound > 0 {
                    let msg = format!(
                        "{tenant_unbound} attestation(s) carry no payload tenant (pre-U-RT-3-Phase-2, \
                         accepted on the envelope alone) — and --strict refuses to report a green \
                         result over an attestation this tool could not cross-check against itself."
                    );
                    return fail(&msg, json, "REFUSED (--strict)");
                }
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
                                 \"records_recomputed\":{},\"tenant_unbound\":{}",
                                ir.attestations, ir.covered_prefix, ir.records_recomputed, ir.tenant_unbound,
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
                             \"records_recomputed\":{},\"tenant_unbound\":{}{}",
                            ir.attestations,
                            ir.covered_prefix,
                            ir.records_recomputed,
                            ir.tenant_unbound,
                            anchor_extra,
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
                println!(
                    "{}",
                    match (&anchor, &issuer_report, &tenant_issuer_reports) {
                        (Some(_), Some(_), _) => "WINDOW AUTHENTICATED (issuer-anchored start)",
                        (None, Some(_), _) =>
                            "CHAIN AUTHENTICATED (integrity + issuer-signed head)",
                        (None, None, Some(_)) => {
                            "CHAIN AUTHENTICATED (integrity + issuer-signed head, per tenant)"
                        }
                        _ => "CHAIN VERIFIED",
                    }
                );
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
                         {:22}digest was never recomputed, and these are in NO recompute count.",
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
                        "  records recomputed: {} (v2/v3 record-digest recompute)",
                        ir.records_recomputed
                    );
                    if ir.tenant_unbound > 0 {
                        println!(
                            "  tenant_unbound    : {} (attestation predates U-RT-3 Phase 2 — accepted \
                             on envelope alone; re-run with --strict to refuse rather than accept them)",
                            ir.tenant_unbound
                        );
                    }
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
                                 records recomputed {}",
                                ir.attestations, ir.covered_prefix, ir.records_recomputed
                            );
                            if ir.tenant_unbound > 0 {
                                println!(
                                    "      tenant_unbound {} (attestation predates U-RT-3 Phase 2 — \
                                     accepted on envelope alone)",
                                    ir.tenant_unbound
                                );
                            }
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
            }
            ExitCode::SUCCESS
        }
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

    let mut it = argv[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--strict" => strict = true,
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
                cmd_chain(
                    &p,
                    strict,
                    json,
                    &issuers,
                    from_anchor.as_deref(),
                    expect_anchor.as_deref(),
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
        o => {
            eprintln!("seam-verify: unknown command '{o}'");
            usage();
        }
    }
}
