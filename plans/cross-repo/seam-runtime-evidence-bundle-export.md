# seam-runtime — a bearer-scoped evidence bundle (an export, not a read grant)

> **Owner:** `seam-runtime`. **Filed by:** `seam-sdk`, 2026-08-23.
> **Issue:** [zer07labs/seam-runtime#421](https://github.com/zer07labs/seam-runtime/issues/421)
> **Source:** `seam-sdk/plans/archive/sdk-exec-w1-w7.md` (W2.2/W2.3), PR
> [seam-sdk#51](https://github.com/zer07labs/seam-sdk/pull/51).
> One plan, one home — if you copy this into `seam-runtime`, delete it here and leave a pointer.
> **Anchors were true on 2026-08-23; re-verify before editing.**

---

## Context

An external auditor **cannot fetch a proof**, and the reason is structural rather than a missing
permission. Both proof verbs funnel into `authorize_read`, which — once enforcement is on — requires
a subject AID, resolves its **enrolled tenant** via `tenant_directory.tenant_for_subject`, and then
enforces hard tenant isolation in `authorize_record_access`.

An auditor is not an enrolled, tenant-matched subject, and should not be made one.

**The tenant-isolation rule is correct and must not be loosened.** Adding an "auditor" role that can
read across tenants would trade a real isolation guarantee for a convenience, and would make the
isolation claim conditional on a role assignment.

## Delivers

A specified, bearer-scoped, time-boxed **evidence bundle** — a thing you hand someone, not a door you
open — plus the verb that produces it.

## Depends on

[#420](https://github.com/zer07labs/seam-runtime/issues/420) in practice: designing an auditor path
over a read path whose enforcement posture is only implied by a deployment mode is decoration.

## Files (all in `seam-runtime`)

- `crates/seam-api/proto/seam/api/v1/seam.proto` — the export verb.
- `crates/seamd/src/facade.rs` — the bundle assembly, beside the existing proof paths.
- `docs/specs/` — the bundle's shape, so a consumer can verify it without reading Rust.

## Approach

Carry exactly what the published verifier already consumes (`seam-sdk/verify/src/main.rs`):

- the sealed record,
- its `ciphertext_digest`,
- the enclosing chain segment,
- the chain-head attestations that cover that segment.

Nothing in that set is a cross-tenant read: it is a scoped extract about one decision, produced
deliberately by someone who already has access.

## The acceptance test, and why it is the important part

> An auditor holding **only the bundle and the issuer AID** runs the published `seam-verify` and gets
> **exit 0** — with no Seam credential and no network call.

That is the acceptance test for the entire *"don't trust us, verify it yourself"* claim. **If it
cannot be written, the claim is not yet true**, and that is worth knowing independently of whether
this ships.

## Acceptance criteria

1. The bundle is specified in `docs/specs/`, not only implemented.
2. The export verb is additive to `seam.api.v1` (`buf breaking` clean).
3. The end-to-end test above passes, driven by the **published** verifier rather than an in-tree one.
4. Tenant isolation on the existing read path is unchanged — a test proves a cross-tenant read still
   fails.

## Sequencing

**Sequence the proto change with the next contract change so it rides one regeneration**, not two:
each SDK regeneration is a release and each release is an exposure event. `seam-sdk` batched four
proto changes into one regeneration for exactly this reason (PR #51); this verb should join whatever
lands next rather than triggering its own cycle.

## Tests

The auditor-with-only-a-bundle test is the phase's whole point. Add a negative: a bundle missing its
chain-head attestations must fail verification rather than pass with reduced coverage.
