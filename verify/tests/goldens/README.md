# Runtime goldens

Every file here was produced by seam-runtime's own code, not written by hand, and nothing here was
signed by this repository. This crate holds no issuer seed.

| File | Source |
|---|---|
| `attested_chain.jsonl`, `fabricated_chain.jsonl`, `payload_rewrite.jsonl`, `two_tenant_chain.jsonl` | copied verbatim from `seam-runtime/crates/seam-verify/tests/goldens/` (see the header of `tests/authenticity.rs`) |
| `entry_domains.jsonl` | `crates/seam-verify/tests/entry_recompute.rs` `stream()`: one entry from every audit writer, an erasure certificate, and signed heads for `acme`, `beta` and the system partition |
| `entry_domains.window.jsonl`, `entry_domains.anchor.json` | `crates/seam-verify/tests/anchored.rs` `two_anchor_stream()` cut by `window_from(&events, 2)`, and the anchor A1 that seeds it |
| `entry_domains.swapped-attestation.json` | the genuinely signed earlier attestation from `anchored.rs` `a_swapped_attestation_below_the_window_base_fails` |

## Pinning

The `entry_domains.*` files are pinned by sha256 in `tests/entry_vectors.rs`, so a silent edit turns
the suite red. Provenance (runtime commit, test function, issuer AID) is recorded in that file's
header. `.gitattributes` keeps git off their bytes.

A cross-repo pin (checking these bytes against a copy the runtime commits itself) waits until the
runtime commits these vectors (plan `plans/verify-a4-parity.md`, OQ-6).

To refresh them, re-run the runtime tests named above from a clean `git archive` export of the pinned
runtime commit, write each event with `SeamEvent::to_json` one per line, copy the bytes here, and update
the sha256 pins and the provenance header together.
