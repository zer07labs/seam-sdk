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
             seam-verify chain <FILE> [--strict] [--issuer <AID>] [--json]\n    \
             seam-verify erasure-cert <FILE> --issuer <AID> [--json]\n\
         \n\
         chain <FILE>\n    \
             Verify the seam-event.v1 hash chain from the stream ALONE. One event per line: the JSON\n    \
             projection or base64 protobuf ('-' reads stdin).\n\
         \n\
             An event is a link iff it carries `digest` and `checksum` — by FIELD PRESENCE, never by\n    \
             kind. Advisory events (LEARNING_*, BUDGET_BREACH, SESSION_LIFECYCLE, AUTHORIZE_EVALUATED)\n    \
             and the off-chain `chain_anchor` carry neither, and do not advance the head.\n\
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

fn cmd_chain(path: &str, strict: bool, json: bool, issuers: &[String]) -> ExitCode {
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

    match verify::chain(&events) {
        Err(e) => fail(&e, json, "CHAIN VERIFICATION FAILED"),
        Ok(mut r) => {
            r.duplicates = duplicates;
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
            // the pinned key AND sit at the head it attests, and at least one must be present. Integrity
            // has already passed (the head sequence in `r.heads` is trustworthy to check positions against).
            let issuer_report = if issuers.is_empty() {
                None
            } else {
                match verify::verify_authenticity(&events, &r.heads, issuers) {
                    Ok(ir) => Some(ir),
                    Err(e) => return fail(&e, json, "AUTHENTICITY VERIFICATION FAILED"),
                }
            };
            if json {
                let authenticity = match &issuer_report {
                    Some(ir) => format!(
                        ",\"authenticated\":true,\"attestations\":{},\"covered_prefix\":{},\
                         \"records_recomputed\":{}",
                        ir.attestations, ir.covered_prefix, ir.records_recomputed
                    ),
                    None => String::new(),
                };
                println!(
                    "{{\"verified\":true,\"events\":{},\"links\":{},\"advisory\":{},\"duplicates\":{},\
                     \"unverifiable\":{},\"head\":\"{}\"{}}}",
                    r.events,
                    r.links,
                    r.advisory,
                    r.duplicates,
                    r.unverifiable.len(),
                    verify::hex(&r.head),
                    authenticity,
                );
            } else {
                println!(
                    "{}",
                    if issuer_report.is_some() {
                        "CHAIN AUTHENTICATED (integrity + issuer-signed head)"
                    } else {
                        "CHAIN VERIFIED"
                    }
                );
                println!("  events            : {}", r.events);
                println!("  links checked     : {}", r.links);
                println!("  advisory (skipped): {}", r.advisory);
                if let Some(ir) = &issuer_report {
                    println!("  attestations      : {} (issuer-signed)", ir.attestations);
                    println!("  covered prefix    : {} links", ir.covered_prefix);
                    println!(
                        "  records recomputed: {} (v2/v3 record-digest recompute)",
                        ir.records_recomputed
                    );
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
                println!("  head              : {}", verify::hex(&r.head));
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
            Some(p) => cmd_chain(&p, strict, json, &issuers),
            None => {
                eprintln!("seam-verify: chain requires a FILE (or '-')");
                usage();
            }
        },
        "erasure-cert" => {
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
