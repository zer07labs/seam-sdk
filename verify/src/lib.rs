//! `seam-verify` — check Seam's claims **without trusting Seam**.
//!
//! Seam says: *"don't trust us — verify it yourself."* This crate is what makes that sentence mean
//! something. It links **nothing of Seam's** — see `Cargo.toml`, where the dependency list is the
//! argument, and `.github/workflows/ci.yml`, where `cargo tree -e normal` turns that argument into a
//! gate rather than a comment. It is written from the published specs, takes bytes and a public key,
//! and answers yes or no.
//!
//! # Why there is a library and not only a binary
//!
//! An auditor who wants verification **inside their own pipeline** should not have to shell out to a
//! CLI and parse `--json`. Shelling out makes the verification result a string to be re-parsed, and a
//! parse step between the answer and the decision is somewhere a wrong answer can be introduced. So
//! the logic lives here and `main.rs` is a shell over it — the CLI and an embedding caller run
//! **exactly the same code**.
//!
//! # What this crate verifies, and what it does not
//!
//! Verified:
//!
//! * the **`seam-event.v1` hash chain** — internal consistency of a stream, from the stream alone
//!   ([`chain`]);
//! * **authenticity** — every `CHAIN_HEAD_ATTESTATION` verifies against a pinned issuer key and sits
//!   at the head it attests, and every `DECISION_SEALED` digest is recomputed from its payload
//!   under record digest v4 ([`verify_authenticity`]). A record missing a mandatory column (tags
//!   10-12, 14-17) is refused as a **strip**, reported distinctly from a digest mismatch; any
//!   `schema_version` other than 4 is refused as cannot-verify, never skipped;
//! * **GDPR erasure certificates**, from the issuer AID alone ([`erasure_certificate`]).
//! * **Truncation — conditionally, when the caller supplies a later anchor** ([`check_not_truncated`],
//!   seam-sdk#140). A stream cut at the tail is internally consistent and verifies green **on its
//!   own** — that is a property of hashing, not a gap this crate can close by itself. What closes it
//!   is `seam-runtime`'s `GET /v1/anchors` feed (seam-runtime#422, live since 2026-08-26): fetch the
//!   latest anchor out of band (this crate makes no network call of its own), validate it with
//!   [`verify_anchor`], and check it against the verified [`ChainReport`]. That check also pins the
//!   HEAD at the overlapping position, not only the length — a cut-and-spliced tail can be made as
//!   long as the real one, so length alone is not the whole claim. A caller who does not supply one
//!   is in exactly the position this crate was always in: it can prove the chain it was **given** is
//!   consistent, and nothing more.
//! * **Evidence bundles** (`seam-evidence-bundle.v1`, seam-sdk#225) — a decision-scoped directory an
//!   operator hands an adverse party, verified from its files and the pinned issuer AID alone
//!   ([`verify_bundle`]): the manifest's hashes, the anchored window (the same calls as
//!   `chain --from-anchor --strict`), the decision's inclusion, the Commitment's TCT, the issuer's
//!   signed binding of that Commitment to the chain link, and the disclosed context and policy.
//! * **The commitment digest** (`seam-commitment-digest:v3`, with `seam-explanation-digest:v1`) and
//!   the self-issued TCT that carries it ([`commitment`]) — implemented for the bundle's step 4, and
//!   pinned by the spec's worked examples and the shared `conformance/` vectors.
//!
//! **Not** verified, and stated here so no caller infers otherwise:
//!
//! * **A standalone Commitment proof** (`GET /v1/decisions/{id}/proof`). The digest and TCT code is
//!   here, but there is no `commitment` subcommand; the five SDK crypto shims are the supported path
//!   for a proof outside a bundle.
//!
//! # Example — verify the shipped reference vector through the library
//!
//! This is the acceptance test for the library surface, and it is a doctest on purpose: it runs on
//! every `cargo test`, and it exercises the **library API** rather than shelling out to the binary,
//! so it proves the embeddable path works rather than the CLI path.
//!
//! `fixtures/erasure_certificate_vector.json` is a real signature from the real signer, shipped so
//! this tool can be checked against something nobody has to take on faith — including by you, right
//! now.
//!
//! ```
//! use seam_verify::{erasure_certificate, wire::Cert};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let raw = std::fs::read_to_string("fixtures/erasure_certificate_vector.json")?;
//! let vector: serde_json::Value = serde_json::from_str(&raw)?;
//! let issuer = vector["issuer_aid"].as_str().expect("the vector carries an issuer AID");
//!
//! // The same parse the CLI uses — accepts an event line, a bare certificate, or a
//! // `{"cert": …}` wrapper, so an embedder handles every shape the CLI does.
//! let cert = Cert::parse_document(&raw)?;
//!
//! // Verified from the issuer AID alone — no Seam credential, no network call.
//! erasure_certificate(issuer, &cert).expect("the published vector must verify");
//!
//! // And it is genuinely checking the signature: a different issuer must NOT verify.
//! let other = "aid:pubkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
//! assert!(erasure_certificate(other, &cert).is_err(), "a wrong issuer must fail closed");
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]

pub mod bundle;
pub mod commitment;
pub mod verify;
pub mod wire;

// Re-exported at the crate root so an embedding caller writes `seam_verify::chain(..)` rather than
// reaching through the module path. These are the verification surface; everything else in
// `verify` is a helper they compose.
pub use bundle::{verify_bundle, BundleError, BundleReport};
pub use verify::{
    chain, chain_anchored, chain_by_tenant, check_not_truncated, erasure_certificate, link,
    verify_anchor, verify_authenticity, verify_authenticity_anchored,
    verify_authenticity_by_tenant, ChainReport, IssuerReport, TenantChain,
};
