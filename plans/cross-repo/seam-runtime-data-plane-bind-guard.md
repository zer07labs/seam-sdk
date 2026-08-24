# seam-runtime — give the data plane a `validate_mgmt_bind` equivalent

> **Owner:** `seam-runtime`. **Filed by:** `seam-sdk`, 2026-08-23.
> **Issue:** [zer07labs/seam-runtime#420](https://github.com/zer07labs/seam-runtime/issues/420)
> **Source:** `seam-sdk/plans/archive/sdk-exec-w1-w7.md` (W2.1), PR
> [seam-sdk#51](https://github.com/zer07labs/seam-sdk/pull/51).
> One plan, one home — if you copy this into `seam-runtime`, delete it here and leave a pointer.
> **Anchors were true on 2026-08-23; re-verify before editing.**

---

## Context — and a correction to the claim that produced this

A review handed to `seam-sdk` asserted that *"`enforce_subject` defaults to `false`, so in default
configuration both proof endpoints are open to anyone who can reach the port, and the story about who
can read proofs depends entirely on an env var."*

**Re-verified against `main` on 2026-08-23, that framing is out of date and the design is better than
it says.** Enforcement is *derived*, not a bare boolean:

- `config.rs` `resolve_enforcement(mode, explicit)` selects the default from `SEAM_DEPLOYMENT_MODE`,
  and defaults it **ON** for `CloudMultiTenant` and `Network`.
- An unrecognized `SEAM_DEPLOYMENT_MODE` is **refused**, not downgraded to the least-enforcing mode.
- `SEAM_ENFORCE_SUBJECT=yes` is treated as *unset*, never as an explicit `false`.
- An explicit OFF under a mode that defaults ON is flagged `relaxed_from_default` and **warned about
  loudly** at boot in all three binaries.

That is a considered posture, not a foot-gun, and the "it all hangs on one env var" reading should be
retired. This ask is about the one combination it does **not** cover.

## The gap that survives

`Embedded` is the **default** mode and defaults enforcement **OFF** — coherent for its stated threat
model (*"in a customer VPC alongside their agents; single trust root"*). But nothing checks the
deployment actually matches that model:

- `authorize_read` short-circuits to `Ok(())` whenever enforcement is off, so `GetDecision` and
  `GetCommitmentProof` are readable by anyone who can reach the port.
- `GetCommitmentProof`'s only remaining gate is a clearance level read from a **caller-supplied
  header** that defaults to `Public`.
- The `relaxed_from_default` warning fires **only** for an explicit OFF under a mode that defaults
  ON. `Embedded` + a wildcard bind produces **no warning at all** — the risky combination is the
  silent one.

## Delivers

A boot-time refusal for the one combination that is almost certainly a misconfiguration: a
non-loopback data-plane listener with subject enforcement resolved OFF.

## Depends on

Nothing. Blocks [#421](https://github.com/zer07labs/seam-runtime/issues/421) in the sense that an
auditor role over an unenforced read path is decoration.

## Files (all in `seam-runtime`)

- `crates/seamd/src/boot.rs` — beside `validate_mgmt_bind`.
- The three binaries that already resolve the posture: `crates/seamd/src/bin/seam-server.rs`,
  `crates/seamd/src/bin/seam-grpc.rs`, `crates/seam-serving/src/main.rs`.

## Approach

**This repo already solved exactly this shape for the management plane.** `validate_mgmt_bind`
refuses a non-loopback management bind unless mTLS is on or an explicit plaintext-ack hatch is set,
with the rationale written out in full and the rules ordered.

Give the data plane the same treatment: at boot, if the data-plane listener is non-loopback **and**
subject enforcement resolves OFF, refuse — unless an explicit acknowledgement env var is set
(mirroring `plaintext_ack`), which then warns loudly.

**A warning alone is not sufficient**, and this repo family's own history is the argument: the
0.7.17 band in `seam-sdk` came from a guard that could not fail, and that repo's `publish.yml`
records the lesson — *"A guard that cannot fail for the reason it claims is worse than no guard,
because it is also a promise."*

## Acceptance criteria

1. A test that boots with a non-loopback data-plane bind and enforcement resolved OFF, and asserts
   **refusal**.
2. A test that the acknowledgement hatch permits it, with a warning.
3. Loopback + enforcement off stays allowed, unchanged — local dev must not break.
4. An audit of every deployment config (Railway, `compose/local/`, and `seam-aegis/compose/local/`)
   recording which mode each selects. `seam-aegis/CLAUDE.md` records local/remote config drift as a
   known failure mode here.

## Tests

The two boot tests above, plus the existing loopback-dev path proving no regression.
