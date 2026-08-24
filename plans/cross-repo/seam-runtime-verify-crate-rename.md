# seam-runtime — rename `crates/seam-verify` so two crates stop sharing a package name

> **Owner:** `seam-runtime`. **Filed by:** `seam-sdk`, 2026-08-23.
> **Issue:** [zer07labs/seam-runtime#419](https://github.com/zer07labs/seam-runtime/issues/419)
> **Source:** `seam-sdk/plans/archive/sdk-exec-w1-w7.md` (W1.1), PR
> [seam-sdk#51](https://github.com/zer07labs/seam-sdk/pull/51).
> One plan, one home — if you copy this into `seam-runtime`, delete it here and leave a pointer.
> **Anchors were true on 2026-08-23; re-verify before editing.**

---

> **DOWNGRADED 2026-08-24 — this is hygiene, not a blocker.** It was filed as the one irreversible
> step in the W1–W7 workstream, on the assumption that `seam-sdk/verify/` would publish to
> **crates.io**, where a shared name is claimed permanently by whoever publishes first. An owner
> directive changed that: `seam-sdk` packages go to the org's **private Cloudsmith registry**, and
> `verify/Cargo.toml` now declares `publish = ["zer07labs"]` — an allow-list, so an accidental
> crates.io publish is a cargo error rather than a namespace claim. With that crate on Cloudsmith and
> this one at `publish = false`, **the two never meet in a shared namespace.** Nothing is racing for
> a name and `seam-sdk` is no longer waiting on this.

## Context

Two crates in this org are **both named `seam-verify`**:

| Crate | Links Seam crates? |
|---|---|
| `seam-sdk/verify` | **No** — six general-purpose crates, enforced by a CI gate (`cargo tree -e normal`) |
| `seam-runtime/crates/seam-verify` | **Yes** — `seam-store` and `seam-trust-aitp` |

The runtime copy is the one that **cannot** be public: the product claim is "don't trust Seam —
verify it yourself", and a verifier linking Seam's own store is Seam checking itself. Its own
manifest comment already makes that argument. Its role is the **differential oracle** — the second
implementation the parity harness drives over the same streams so neither side becomes a rubber
stamp — and that role needs it internal.

## Delivers

One org, one package name per crate. `cargo` output that says `seam-verify` stops being ambiguous
about which of two crates it means.

## Depends on

Nothing.

## Files (all in `seam-runtime`)

- `crates/seam-verify/Cargo.toml` — the `name` field.

## Approach

Rename the package to **`seam-verify-internal`**.

- **Keep `publish = false`.** This frees a name; it is not a step toward publishing.
- **Keep `[[bin]] name = "seam-verify"`.** The binary name is what operator scripts and the
  differential harness invoke; only the *package* name needs to move, and nothing that runs the
  binary should notice.
- The directory can stay `crates/seam-verify/` — only the package name collides.

## Acceptance criteria

1. `cargo metadata` shows `seam-verify-internal`.
2. The runtime workspace builds.
3. The differential-parity job still drives both binaries over the same streams and still requires
   agreement.

## Tests

The existing differential harness, unchanged, still passing.

## Note for whoever picks this up

Publishing `seam-sdk/verify` to a **private** registry does not make the verifier obtainable by an
adverse third party, and `seam-sdk` has been careful not to claim otherwise. The auditor path is, and
always was, cloning the public Apache-2.0 repo and building — `verify/` is a standalone cargo
workspace with zero Seam dependencies precisely so that works anywhere.
