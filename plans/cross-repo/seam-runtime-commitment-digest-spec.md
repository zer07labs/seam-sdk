# seam-runtime — write `docs/specs/seam-commitment-digest.v1.md`

> **Owner:** `seam-runtime`. **Filed by:** `seam-sdk`, 2026-08-23.
> **Issue:** [zer07labs/seam-runtime#423](https://github.com/zer07labs/seam-runtime/issues/423)
> **Source:** `seam-sdk/plans/archive/sdk-exec-w1-w7.md` (§8), PR
> [seam-sdk#51](https://github.com/zer07labs/seam-sdk/pull/51).
> One plan, one home — if you copy this into `seam-runtime`, delete it here and leave a pointer.
> **Anchors were true on 2026-08-23; re-verify before editing.**

---

## Context — and why this is smaller than it was first priced

A review of `seam-sdk` argued its single highest-value item, ahead of every numbered work item, was:
**write a spec for the record digest and the commitment digest**, because a doc comment in a private
repo is not something a second implementer can work from.

Re-verifying that on 2026-08-23, **half was already done, and it was the expensive half.** The
**record digest** has a real, published, byte-exact spec: `docs/specs/seam-event.v1.md` carries
`## Record digest`, with `### Record digest (v2)` giving the full framing and `### Record digest (v1,
historical)` beside it. That is exactly the artifact the argument asks for.

**What is missing is the commitment digest.** `seam-commitment-digest:v1`'s normative description is
the doc comment in `crates/seam-trust-aitp/src/lib.rs` — in this **private** repo. There is no
`docs/specs/` document for it.

## Delivers

`docs/specs/seam-commitment-digest.v1.md` — enough for someone with no access to this repo to
implement the framing and agree byte-for-byte.

## Depends on

Nothing.

## Files (all in `seam-runtime`)

- `docs/specs/seam-commitment-digest.v1.md` (new).
- Optionally `crates/seam-client/examples/conformance_vectors.rs` — see *A vector would help more
  than the doc alone*.

## Why this framing specifically

It has the **widest fan-out of anything in the SDK** — mirrored byte-for-byte in **all five** SDK
languages (`go/crypto/crypto.go`, `java/…/SeamCrypto.java`, `kotlin/…/SeamCrypto.kt`,
`python/seam_sdk/crypto.py`, `ts/src/crypto.ts`), all computing
`SHA-256( Σ over [domain, id, action, authority, supersedes, auth_method, trust_basis] of (u64-BE
length ‖ field bytes) )`.

**But those five are not five independent implementations.** They are ports by one author from one
source. Independence comes from working from spec text alone — which requires there to be spec text.
That is the whole argument, and it is why a third verifier written by the same person would add
nothing.

## What the spec must carry

1. The domain tag `seam-commitment-digest:v1`, bound **first**, inside the preimage.
2. The exact field tuple **and its order** — order is load-bearing and nothing outside the code
   states it.
3. The **8-byte big-endian** length prefix per field, and **why**: without it `("a\0b","c")` and
   `("a","b\0c")` produce identical preimages, letting one Commitment verify under another's TCT.
   The fields are arbitrary text that may itself contain NUL, so this is reachable, not theoretical.
   Lift the rationale from `seam-trust-aitp/src/lib.rs` verbatim — it is the only thing stopping a
   future maintainer from "simplifying" the framing.
4. Absent-vs-empty for `supersedes` (both → eight zero bytes).
5. How it binds into the TCT via the `grants` claim, and why it rides there (the published
   `aitp-tct` builder does not expose `ext`).
6. A worked example with hex.

## A vector would help more than the doc alone

`seam-sdk`'s `conformance/vectors.json` has **no** commitment-digest section, and one cannot be added
from that side: the `sdk-digest-parity` job byte-diffs the whole file against this repo's emitter, so
a block added there turns **this repo's** CI red. **A commitment-digest vector has to originate
here.** Emitting one alongside the spec gives every future implementer a KAT rather than prose alone.

## Acceptance criteria

1. `docs/specs/seam-commitment-digest.v1.md` exists and covers all six points above.
2. Someone with only that document can reproduce the digest for the worked example.
3. If a vector ships: `seam-sdk`'s five shims reproduce it unmodified.

## Tests

The worked example, recomputed. If a vector ships, the existing `sdk-digest-parity` job covers the
cross-repo half automatically.

## What `seam-sdk` offers in return

- Five byte-identical ports as cross-language conformance evidence.
- All five now assert every field in the tuple is bound, plus injectivity across field boundaries —
  so the properties the spec would state are already test-enforced on the consumer side.
- Scope note: `seam-sdk/verify/` does **not** implement this digest. It is not a sixth mirror, and
  any doc saying the published verifier checks commitment digests is wrong.
