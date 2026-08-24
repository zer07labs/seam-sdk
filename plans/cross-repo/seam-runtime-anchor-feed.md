# seam-runtime — publish a read-only anchor feed

> **Owner:** `seam-runtime`. **Filed by:** `seam-sdk`, 2026-08-23.
> **Issue:** [zer07labs/seam-runtime#422](https://github.com/zer07labs/seam-runtime/issues/422)
> **Source:** `seam-sdk/plans/archive/sdk-exec-w1-w7.md` (W3.1), PR
> [seam-sdk#51](https://github.com/zer07labs/seam-sdk/pull/51).
> One plan, one home — if you copy this into `seam-runtime`, delete it here and leave a pointer.
> **Anchors were true on 2026-08-23; re-verify before editing.**

---

## Context — verified, not assumed

Grepped across `seam-runtime/crates` (excluding `target/`) on 2026-08-23:

| Term | Hits |
|---|---|
| `checkpoint` | **zero** |
| `transparency` | **zero** |
| `witness` | two, both the ordinary English word — and one of them names the gap outright |

That second one is in `crates/seam-verify/src/main.rs`: *"without an authenticity witness (bounded by
the attest cadence N)"*.

`anchor` **does** exist, but only internally, and it is **closer to serveable than "off by
default" would suggest** — worth stating precisely, because it changes the size of this ask:

- `Store::chain_anchor()` **reads** `(len, head)`; `emit_chain_anchor` is what emits the **outbox
  event** (`crates/seamd/src/facade.rs`).
- Anchoring is **on by default in a durable deployment** — `SEAM_CHAIN_ANCHOR` *overrides*, it does
  not enable (`crates/seamd/src/attest.rs:51-53`: *"forces it; unset ⇒ on iff the deployment is
  durable"*). So a production fleet is already emitting `chain_anchor` events.
- **No route in `server.rs` serves them.** That is the entire gap: the data is produced, and only
  an authorized outbox consumer can see it.

## The consequence, stated plainly

Detecting truncation requires either being an authorized outbox consumer or already holding a prior
chain-head attestation. So an auditor can prove the chain they were **given** is internally
consistent, and **cannot prove it is the whole chain.** A stream truncated at the tail verifies green.

`seam-sdk` treats this as binding on what it is allowed to claim: its `COMPATIBILITY.md` states that
"independently verifiable" covers chain integrity and erasure certificates but **not** truncation
detection, and `python/tests/test_retracted_claims.py` fails if any document in that repo starts
claiming otherwise. Honest, but a workaround for a missing capability.

## Delivers

A read-only, **unauthenticated** `GET /v1/anchors` returning signed chain-head attestations.

## Depends on

Nothing.

## Files (all in `seam-runtime`)

- `crates/seamd/src/server.rs` — the route, beside the existing `GET /v1/trust/issuer-aid`.
- `crates/seamd/src/facade.rs` — the read path over stored attestations.
- `docs/specs/audit-anchor.md` — **extend, do not duplicate.** It already exists and is marked
  **Normative**, and it gives the on-the-wire `Anchor` format and the observe-time semantics.

## Approach

**Unauthenticated is the right posture, and there is precedent in this repo**: `GET
/v1/trust/issuer-aid` is already unauthenticated, on the reasoning that it leaks only what the
artifact already commits to. An anchor feed is the same shape — a chain-head attestation is a signed
commitment to a length and a head, and publishing it reveals nothing the attestation does not already
bind.

That is not incidental: a feed that needs a credential cannot serve the adversarial-third-party case
that motivates it.

**One design tension to resolve rather than discover.** `docs/specs/audit-anchor.md` states as design
that *"the runtime only **emits chain heads** and never anchors in-process"*, with the notary
deliberately external so its value is independence. An unauthenticated in-process feed is not
obviously in conflict — serving a head the runtime already signed is not the same as *notarising* it
— but the spec is Normative and says so explicitly, so reconcile the two in that document rather than
leaving a reader to infer which one governs.

## Acceptance criteria

1. `seam-verify chain <stream> --issuer <AID>`, cross-checked against the feed, **detects a truncated
   stream**.
2. A test **constructs** the truncation and watches verification fail — built deliberately, not
   assumed to be caught.
3. The endpoint needs no credential.
4. Comment here when it lands: `seam-sdk` must then update `COMPATIBILITY.md` §5, and its
   retracted-claims guard currently *forbids* the claim, so that guard needs updating in the same
   change.

## Tests

The truncation test above is the whole point. A feed that returns attestations but cannot be used to
catch a truncated stream has not delivered this.

## Scope note

The structural answer is RFC-ACDP-0012 (transparency log) + RFC-ACDP-0015 (witness cosigning),
implemented in `acdp-rs` and currently unconsumed. **This is the tactical fix and should not wait on
that** — 0012/0015 adoption is quarters; this is days.
