# SDK exec workstream — adopt the landed contract, then close the release-exposure gaps (W1–W7)

> **Status: IN PROGRESS.** Written 2026-08-23 against `origin/main` @ `5f98ddd` (v0.7.42), branch
> `feat/sdk-exec-w1-w7`. Each phase's own `Status:` field below is authoritative — this banner is a
> summary of them, never a substitute.
> **Source:** `seam-aegis/plans/exec/seam-sdk.md` (559 lines, items W1–W7 plus §0 corrections and a
> §9 not-to-do list), read in full and **re-verified against this tree on 2026-08-23**.
> **seam-sdk only.** Sibling repos are read-only; cross-repo needs become GitHub issues, and the
> blocked line here cites the issue number.

## Context

The source plan was verified on **2026-08-19** against a tree at **0.7.31**. This tree is
`origin/main` @ `5f98ddd`, **0.7.42** — eleven releases later. The entire delta between the two is
two lines (`python/pyproject.toml:3`, `ts/package.json:3`); every release commit in that window is a
version stamp and nothing else. So the source plan's `[C]` claims about code, CI and docs are
re-verifiable at face value, and almost all of them re-verified clean.

What did move in those four days moved in **`seam-runtime`**, and it moved a lot. That is what
reorders this plan.

### The three §0 corrections this plan is built on

Carried explicitly because they are load-bearing and easy to lose:

1. **"Published to Cloudsmith" is true for two of five languages.** Python
   (`python/pyproject.toml:2-3`) and TypeScript (`ts/package.json:2-3`) publish to Cloudsmith
   `zer07labs/internal` (`.github/workflows/publish.yml:55`, `:135`; `ts/package.json:12`). Go is
   resolved by module proxy from the `go/vX.Y.Z` tag (`release-on-runtime.yml:72`) and has no
   in-tree version. **Java and Kotlin have no `version` and no `maven-publish` plugin at all** —
   build-from-source only. "Regenerate across five languages" is really *regenerate five, release
   two, hand-edit two.*
2. **Go/Java/Kotlin are crypto shims, not clients** (`README.md:110`). No generated transport, no
   verb methods. A new RPC verb costs them **nothing**; a change to a crypto **framing** costs them
   everything. That is the axis 0.7.17 broke on, and it is why Phase 2 touches three files and not
   five.
3. **"digest v3" means the audit *record* digest** (`seam.audit.record-digest.v2` → v3), **not** the
   commitment digest (`seam-commitment-digest:v1`, which has no v2 and no v3 planned). The two are
   routinely conflated. W7 is written against the record digest; the commitment digest's own
   obligation is Phase 8's second half.

### What changed under the source plan — the tree wins, and here is where they disagree

Six disagreements. Each names the `[C]` claim, the line it cited, and what is there now.

| # | The `[C]` claim (2026-08-19) | What is there now | Effect |
|---|---|---|---|
| **D1** | §4: "**Verified: none of the four claimed changes exists yet.**" — and the change list was `context_refs` / `confidence` / `rationale_ref` / quorum / `Evaluation`. | The four changes that landed are **different ones**, and they are on the BSR *and* in the runtime: `PolicyEnforcement policy_enforcement = 7`, `repeated ParticipantVerdict participant_verdicts = 8`, `optional CollectiveOutcome collective_outcome = 9`, enum `CollectiveVerdict`, plus quorum verbs `SubmitApprovalRequest`/`SubmitBallot`. `context_refs`/`confidence`/`rationale_ref` still do **not** exist (they are `seam-runtime` issues [#394](https://github.com/zer07labs/seam-runtime/issues/394), [#409](https://github.com/zer07labs/seam-runtime/issues/409) — still open). | W4 moves to **Phase 1**, and its scope is the landed set, not the predicted set. |
| **D2** | W4.1: "*`seam-sdk` cannot start until the BSR module is pushed.*" | **The BSR is already current.** `buf build buf.build/zer07labs/seam` at head carries every one of the five new symbols and both new RPCs. Latest module commit `7a28eb9…`. | W4's stated cross-repo blocker **does not exist**. Phase 1 is unblocked today. |
| **D3** | W7.1: the dispatch at `seam-store/src/lib.rs:346-360` is a catch-all `_ => v2`, and "**Close the catch-all *before* v3 is designed**" is an open `seam-runtime` work item. | **Already fixed upstream.** `seam-runtime` `d7f27c7` (#408, 2026-08-23) rewrote it to explicit `1 =>` / `2 =>` / `_ => None`, with the refusal rationale in the doc comment at `crates/seam-store/src/lib.rs:335-339` and the comment "No catch-all. An unknown stamp is refused so it can never verify green under the wrong formula" at `:377-378`. `recompute_sealed_digest` is symmetric. | **W7.1 is DONE. Do not file it.** Phase 8 keeps only the *SDK-side* half. |
| **D4** | §8 item 2: "There is **no dedicated spec document** for `seam-commitment-digest:v1`" — and the recommendation is scoped to *"a spec for the record digest and the commitment digest."* | Half-wrong, and the wrong half is the expensive half. **The record digest already has a published, byte-exact spec**: `seam-runtime/docs/specs/seam-event.v1.md:372` `## Record digest`, with `### Record digest (v2)` at `:379` and `### Record digest (v1, historical)` at `:399`, both giving the full framing. Only the **commitment digest** has no spec — its normative text is still the doc comment at `seam-trust-aitp/src/lib.rs:338-354`. | §8's headline item is **~half the work the source plan priced it at**. Decided in Phase 9. |
| **D5** | §0.4 / W6.2: `plans/build-agent-ingress.md:5` "asserts a live consumer is inside the broken band; the consumer is not," i.e. the whole line is stale. | **Only half the line is stale.** The line reads: *"pins `seam-sdk >=0.7,<0.8`, lock resolves 0.7.9 — **not** `0.7.20`"*. The **pin** half is stale (`seam-adapters/core/pyproject.toml:22` is `>=0.7.20,<0.8`). The **lock** half is still literally true: `seam-adapters/uv.lock:3920-3921` does resolve 0.7.9, because `seam-adapters/pyproject.toml:32` overrides with an unconditional editable path source. | The retraction must be **precise**. A blanket "this is wrong" would itself be a false retraction — the exact failure mode §9 exists to stop. |
| **D6** | W5 §"Both facts named as durable": the phrase *"only an install proves a wheel"* appears nowhere; quote the real text at `publish.yml:148-157`. | Confirmed, and worth quoting correctly because W6.1 will quote it: the real sentence is **"A guard that cannot fail for the reason it claims is worse than no guard, because it is also a promise."** | Quote that, not the paraphrase. |

One further correction, to my own handover rather than to the source plan: the `check-contract` admin
probe (`740d8a5`, #46) landed **2026-08-17**, *before* the source plan's verification date — so the
plan already accounts for it, and W4.4's blind-spot claim is about what that probe still does *not*
cover, not about a change that postdates it.

### What re-verified unchanged

Everything else in the source plan holds. Confirmed this session at `5f98ddd`:

| Claim | Verified at |
|---|---|
| `verify/` is `publish = false`, no `rust-version`, no `readme`, no `keywords`/`categories`, no `[lib]`, bin-only | `verify/Cargo.toml:15`, `:59-61`; keys absent |
| `verify/` links six general-purpose crates and zero Seam crates | `verify/Cargo.toml:45-51` |
| …and that is a CI **gate**, not a comment | `.github/workflows/ci.yml:283-292` (`cargo tree -e normal`) |
| Both verifier crates are literally named `seam-verify` | `verify/Cargo.toml:9`, `seam-runtime/crates/seam-verify/Cargo.toml:2` |
| The runtime crate links `seam-store` + `seam-trust-aitp` | `seam-runtime/crates/seam-verify/Cargo.toml:26-27` |
| `seam-commitment-digest` appears nowhere in `verify/` | grep, zero hits |
| `verify/src/wire.rs` mirrors the event wire by hand at every cited line | `:16,69,88,104,132,158,181,215,225,237,261,286` |
| G1 — npm has no install gate | `publish.yml:90-92` |
| G2 — nothing ever installs from the registry | no `dl.cloudsmith.io` in any workflow; `publish.yml:158-169` installs the **local** wheel |
| G3 — publish is not gated on CI | `publish.yml:48`, `:96` — `needs: version-check` only; `ci-ok` exists (`ci.yml:327`) and is never referenced |
| G4 — Go/Java/Kotlin consume only `admission` + `tct` | `go/crypto/crypto_test.go:50,65,74,87,137`; `ConformanceTest.java:51`; `ConformanceTest.kt:36,59,72,85` |
| The lockstep rule and its "cannot express its own semver" corollary | `CHANGELOG.md:3-7`, `:9-12` |
| No yank, deliberately | `CHANGELOG.md:64-67` |
| No compatibility matrix, no support window, no version-skew policy, no MSRV | grep across `README`/`CHANGELOG`/`DECISIONS`/`ASSUMPTIONS`/`verify/*`/`plans/*` — zero |
| All five commitment-digest shims are byte-identical over `[domain, id, action, authority, supersedes, auth_method, trust_basis]`, u64-BE length-prefixed | `crypto.go:128-145`, `SeamCrypto.java:139-155`, `SeamCrypto.kt:118-134`, `crypto.py:93-112`, `crypto.ts:108-123` |
| …and **Java and Kotlin carry no length-prefix rationale**, while Go/Python/TS do | `crypto.go:125-127`, `crypto.py:96-98`, `crypto.ts:100-101`; Java `:138` and Kotlin `:117` are blank |
| No anchor feed: `checkpoint`/`transparency` zero hits in `seam-runtime/crates` | re-grepped |

### The new constraint the source plan predates

`seam-runtime` PR #411 (`33c68b1`) added **`sdk-digest-parity (cross-repo lockstep)`** to
`seam-runtime/.github/workflows/ci.yml:294-338`, driving
`seam-runtime/scripts/sdk-digest-parity.sh`. Read before touching `conformance/vectors.json` or any
digest code. It does two things:

1. **Drift** — `diff -u` between **this repo's committed `conformance/vectors.json`** and the vectors
   `seam-runtime` emits from `cargo run -p seam-client --example conformance_vectors`. Not a subset
   check, not digest-blocks-only: **the whole file, byte-for-byte** (`sdk-digest-parity.sh:55`).
2. **Execution** — it loads **this repo's `python/seam_sdk/crypto.py`** directly and requires a
   same-named function per `record_digest_v*` block, discovered by prefix (`:90`), reproducing the
   digest exactly.

Two consequences that reshape W5.4 and W7:

- **`conformance/vectors.json` is now effectively owned by the runtime's emitter.** Any block added
  here by hand — even a correct one — makes `seam-runtime`'s CI red, because the emitted set will not
  contain it. Vectors must originate in the runtime and land there first. This is the mechanical
  enforcement of §9's "do not transcribe vectors," and it now has teeth in the other repo.
- **The checkout is unpinned.** Both this job (`ci.yml:316-319`) and the older
  `differential-parity` job (`ci.yml:258-292`) check out `zer07labs/seam-sdk` with **no `ref:`**, so
  they track this repo's **default branch**. A merge to `main` here takes effect in `seam-runtime`'s
  CI immediately, with no version gate in between. That is a real coupling and Phase 7 documents it.

The discovery-by-prefix design (`:87-89`) is deliberately forward-compatible: the day a
`record_digest_v3` block exists, the gate covers it automatically. That is W7.2's item 4 already
built — on the runtime side.

### Scope boundaries

- **This repo only.** `seam-runtime` work becomes a GitHub issue with a `file:line`, and the blocked
  line here cites the issue number.
- **No release is cut by this plan.** The SDK cannot choose its own version (`CHANGELOG.md:3-12`);
  entries accumulate under `## Unreleased` and the runtime retitles them.
- **`gen/`, `python/seam_sdk/_gen`, `ts/gen` are untracked build output** (`.gitignore:2,18,19`).
  Regeneration is not a commit; what gets committed is the hand-written surface that consumes it.

---

## Phases

### Phase 1 — W4.0/W4.1: prove the batched regeneration is additive, and record the probe

**Status:** DONE (2026-08-23).

**Delivers.** The W4.0 BSR re-probe, executed and recorded; proof that the four landed proto changes
are additive (a **minor**, not a break) obtained from `buf breaking` rather than asserted; the exact
symbol delta; and `README.md:77-79`'s probe date moved from 2026-08-14 to today.

**Depends on.** Nothing. First because W4.0 is explicitly mandatory before any W4 estimate is valid,
and because D2 means the thing the source plan thought was blocking is not.

**Files.** `README.md` (probe note), `CHANGELOG.md` (`## Unreleased`).

**Approach.** One batched regeneration covering all four changes, per W4.1 — each regen is a release
and each release is an exposure event, so four separate regens would be four exposures for one
contract movement.

1. `buf build buf.build/zer07labs/seam` and enumerate services/messages/enums from the descriptor.
2. `buf breaking` head **against the module commit `gen/` was last built from** — `8bef4b5…`
   (2026-08-16, matching `gen/`'s 2026-08-17 mtime) — under both `WIRE_JSON` **and** `FILE`. `FILE`
   is the strictest ruleset buf ships and covers source compatibility, not just wire.
3. Diff the two descriptors symbol-by-symbol, including field numbers, to prove nothing was removed
   and no tag was reused.
4. `make generate` (BSR path, the release source) + `make check-contract`.

*Rejected:* asserting additivity from "the fields are new." Field **numbers** 7/8/9 being unused in
the old descriptor is the actual claim, and only a descriptor diff shows it.

**Acceptance criteria.**
1. `buf breaking … --config '{"version":"v2","breaking":{"use":["FILE"]}}'` exits **0**. ✅ (also
   clean under `WIRE_JSON`.)
2. The symbol diff shows **zero removals**. ✅ — added: 5 messages (`ApprovalRequestRequest`,
   `BallotRequest`, `CollectiveOutcome`, `ParticipantVerdict`, `PolicyEnforcement`), 2 enums
   (`CollectiveVerdict`, `BallotChoice`), 2 RPCs (`SeamCoordination.SubmitApprovalRequest`,
   `SubmitBallot`), and 3 new fields on `DecisionResponse` at tags **7, 8, 9** — all previously
   unused.
3. Two additions **beyond the four named PRs** are recorded rather than silently absorbed: ✅
   `SessionStep.policy_enforcement = 3` (R1/R2's incremental-commit half) and
   `seam.event.v1 LearningOutcome.policy_key = 3`.
4. `make generate && make check-contract` both exit 0. ✅
5. `README.md:77-79`'s probe date updated, naming the module commit probed.

**Outcome / notes.** Additive is **proven, not assumed** — clean under `FILE`, the strictest
ruleset. So this is a minor, and it rides the runtime's next version per the lockstep rule.
`LearningOutcome.policy_key` is on the **event** wire, which `verify/src/wire.rs` hand-mirrors — but
`verify/` does not mirror `LearningOutcome` at all (grep: zero hits), so it does not reach the
verifier. That disposes of W4.3; see Phase 3.

---

### Phase 2 — W4.2: the two quorum verbs and the three new response fields, on the hand-written clients

**Status:** DONE (2026-08-23, 1 round). Diverged from plan in one way, amended in the acceptance
criteria below: the regeneration also **moved the protobuf gencode floor**, which this phase had to
raise. See *Outcome* at the end of the phase.

**Delivers.** `SubmitApprovalRequest` and `SubmitBallot` on all three transport clients, and the
`policy_enforcement` / `participant_verdicts` / `collective_outcome` response fields reachable
without a consumer reaching into raw protobuf.

**Depends on.** Phase 1.

**Files.** `python/seam_sdk/client.py`, `python/seam_sdk/aio.py`, `ts/src/client.ts`,
`ts/src/index.ts` (re-exports), `python/seam_sdk/__init__.py`. **Not** `go/`, `java/`, `kotlin/` —
§0.2: they are crypto shims, they carry no verb methods, and a new RPC costs them nothing.

**Approach.** Generated code covers the wire; it does not cover the clients. Verified absent today:
neither `submit_approval_request`/`submitApprovalRequest` nor `submit_ballot`/`submitBallot` exists
in any of the three (method inventories: `client.py:203-610`, `aio.py:157-517`,
`client.ts:220-573`).

1. Follow `submit_vote`'s existing shape exactly (`client.py:413`, `aio.py:325`, `client.ts:432`) —
   the quorum verbs return the same `SessionStep` and belong to the same open→step→commit lifecycle.
2. **`aio.py` moves in lockstep with `client.py`.** The async mirror drifting is a standing hazard
   in this repo; the two method inventories must stay equal.
3. `BallotChoice` must be re-exported so a caller never has to import from `seam_sdk._gen`.
4. Both verbs are quorum-mode-only and the runtime rejects them with a typed mode-mismatch error
   against any other mode (`seam.proto:507-508`). The docstring says so; the client does **not**
   pre-validate mode — that is the server's judgment to make, and a client-side mirror of a
   server-side rule is exactly the "implementing a grammar" failure the proto's own
   `CollectiveVerdict` comment warns against.

**Edge cases & failure modes.**
- `required_approvals` is `uint32`; a negative or overflowing Python int must fail at the client
  boundary with a clear error, not marshal into a surprising value.
- `usage` (`StepUsage`) is present on both new request messages and absent ⇒ zero. Mirror how
  `submit_vote` already threads `usage`, rather than inventing a second convention.
- `collective_outcome` is **`optional`** — absence and `COLLECTIVE_VERDICT_UNSPECIFIED` are
  different states on the wire and must not be flattened. See Phase 3, which is where the fail-closed
  reading is enforced.

**Acceptance criteria.**
1. `submit_approval_request` and `submit_ballot` exist on `SeamClient` (sync) and the `aio` mirror,
   with identical signatures modulo `async`; `submitApprovalRequest`/`submitBallot` on the TS client.
   ✅
2. A test asserts the sync and async Python method inventories are **equal as sets** — the drift
   guard, not a spot check. ✅ `python/tests/test_client_parity.py`. *Extended during
   implementation:* set equality alone would pass if a verb were forgotten on **both** sides, and
   would miss a parameter added to one side only — so it also asserts the two verbs by name and
   compares **parameter lists** per shared method.
3. `BallotChoice` is importable from `seam_sdk` and from the TS package root. ✅
4. `mypy`/`tsc` clean; existing conformance and unit suites still green. ✅ `tsc --noEmit` exit 0;
   Python 212 passed / 16 skipped; TS 49 passed / 10 skipped, 0 failed.
5. *Added during implementation:* the derived protobuf floor guard passes. ✅

**Outcome — the regeneration moved the protobuf floor, and the repo's own guard caught it.**
`make generate` emitted gencode **7.36.0**, while `python/pyproject.toml` declared
`protobuf>=7.35.1,<8`. `tests/test_protobuf_floor.py` failed exactly as designed — it derives the
floor from the emitted stubs rather than trusting a hand-maintained number, precisely because buf's
remote plugins track latest and move without anyone editing this repo. Floor raised to
`protobuf>=7.36.0,<8`.

This **refines Phase 1's additivity claim and must not be allowed to blur it**: the *contract* change
is additive (`buf breaking` clean under `FILE`). The *package* change is not purely so — a consumer
pinned at `protobuf==7.35.1` will fail to resolve, and one who force-installs it gets a
`VersionError` at `import seam_sdk`, not a wire error. "Additive on the wire" and "no consumer
impact" are different claims, and only the first one is true here. It goes in `COMPATIBILITY.md`
(Phase 7) as a matrix row, and it is the same defect class that once took `seam-adapters` from 88
passing to zero collected — caught this time before publication rather than in a consumer's CI.

---

### Phase 3 — W4.4 + the W5 finding: make a missing verb loud, and make the unrecognized verdict fail closed

**Status:** DONE (2026-08-23, 1 round). Diverged from plan in one way, amended in the acceptance
criteria: the meta-check is a **committed manifest compared as a set in both directions**, not the
probe-count-equals-RPC-count comparison W4.4 proposed. Reason in *Approach (a)* below.

**Delivers.** `check-contract` covering **every** `SeamCoordination` verb with a meta-check that the
probe count equals the descriptor's RPC count; a fail-closed reading of `CollectiveVerdict`; and
W4.3's per-field digest-preimage question answered in writing.

**Depends on.** Phase 2.

**Files.** `scripts/check-contract.sh`, `python/seam_sdk/client.py` (or a small
`python/seam_sdk/verdict.py`), `ts/src/client.ts` (or `ts/src/verdict.ts`), tests, `DECISIONS.md`.

**Approach — three separable pieces.**

**(a) W4.4 — the blind spot, demonstrated live.** `check-contract` passes green **right now** against
the freshly regenerated stubs while probing **zero of `SeamCoordination`'s 16 RPCs**. Its current
inventory is 15 probes: `VerifyPartyAttestation`; the Authorize surface (`:141-149`); the admin
surface (`:156-165`); four streamed-payload fields under `STREAM=1`; `ReportEventsConsumed` under
`EVENTS=1`. Both new verbs are absent from it, and it is green. That is the claim, reproduced.

The fix is not "add two more probes" — that repeats the pattern one release later. Add a
**meta-check**: parse the RPC set for every service out of the generated descriptor, compare it to
the probed set, and fail on any RPC the script does not probe. A new verb then cannot land unprobed.

**(b) The W5 finding that Phase 1 created.** The `CollectiveVerdict` growth policy is normative
(`seam.proto:246-249`): *any* value a client does not recognize — **including
`COLLECTIVE_VERDICT_UNSPECIFIED`** — MUST route to the adapter's FailPolicy, never to allow. The
generated surface makes the wrong thing easy in two distinct ways:

- proto3 makes `0` (`UNSPECIFIED`) the silent default, so a consumer who reads
  `resp.collective_outcome.verdict` on a response where the field is **absent** (an older runtime, or
  a path that does not populate it) gets `UNSPECIFIED` with no signal that nothing was decided;
- the natural negative test — `if verdict != COLLECTIVE_VERDICT_DECLINED: proceed` — **allows on
  every unrecognized value**, which is precisely the inversion the growth policy forbids.

So: ship a helper that makes the correct reading the easy one, in Python and TS. It returns a
three-state result — decided-approved / decided-not-approved / **cannot-decide** — and folds
absent, `UNSPECIFIED` and any unrecognized numeric into cannot-decide. It must **not** be named
`is_approved()`; a boolean is the shape that caused the problem.

*Rejected:* re-deriving the verdict client-side from `approve_count`/`reject_count`. The proto says
outright those counters are observability and a client-side tally is self-grading and unverifiable
(`seam.proto:274-277`). The helper reads `verdict` and nothing else.

**(c) W4.3 — answer the question rather than inherit it.** W4.3 requires an explicit, written
per-field decision on whether a new field enters the record-digest preimage, because "an unanswered
question here is how v1→v2 happened." The answer for all four changes is **no**, and the reason is
structural, not a judgment call: every new field is on `DecisionResponse` / `SessionStep`, which are
`seam.api.v1` **response** messages. The record digest is computed over `DECISION_SEALED`'s payload
columns (`seam-event.v1.md:379-393`); `verify/src/wire.rs` mirrors the **event** wire only. The one
event-wire addition, `LearningOutcome.policy_key`, is on a message `verify/` does not mirror. So
`verify/src/wire.rs` needs **no change**, and this is not a digest version bump. Written down, with
the reasoning, so the next regeneration inherits the method and not just the conclusion.

**Edge cases & failure modes.**
- The meta-check must read the **descriptor**, not grep the `.proto` — the SDK has no `.proto` in
  tree, and the descriptor is what the stubs were actually built from.
- It must probe Python and TS **independently**; `check-contract`'s existing design is explicit that
  one stub tree can be stale beside the other, and a merged check would hide that.
- The helper must be exercised against a **numeric value outside the current enum** (e.g. `99`), not
  only the six defined ones — that is the case the growth policy exists for and the only one that
  proves the default branch is reachable.

**Acceptance criteria.**
1. **Red first:** with `SubmitBallot` removed from the manifest, `check-contract` **fails** naming
   it in both languages. ✅ exit **5**, `NOT IN THE MANIFEST, present in the python stubs` +
   the same for ts.
2. Deleting a verb from a local regeneration makes `check-contract` fail (the source plan's own
   stated acceptance test for W4.4). ✅ exit **5**,
   `MISSING from the python stubs (stale/partial generation): - SeamCoordination/SubmitApprovalRequest`.
   Restored, back to exit 0. Both directions proven, not just the one W4.4 named.
3. The decoder distinguishes absent / `UNSPECIFIED` / out-of-range, per language. ✅ Python 14
   tests, TS 8 tests. *Amended from "returns cannot-decide":* absent returns `None`/`undefined`
   and unrecognized **raises** — following this repo's own established `AuthorizeVerdict`
   precedent (`_authorize.py:46-51`, `errors.py:41`) rather than inventing a second shape for the
   same problem. Raising is also the only form with no truthiness that can go the wrong way.
4. A test asserts the helper has **no** boolean-returning public form. ✅ *Amended:* there is
   exactly one, `approved`, and a test asserts no `declined` twin exists — `not approved` must
   stay the safe reading.
5. `DECISIONS.md` records the W4.3 answer with its structural reason. ✅
6. *Added:* a test asserts the verdict is never re-derived from the counters, using a tally that
   **contradicts** the verdict. The proto says a client-side tally is self-grading and
   unverifiable; this fails if anyone ever teaches the client to grade the server's judgment.
7. *Added:* `conformance/vectors.json` untouched — verified by `git diff --stat`, per the
   cross-repo lockstep constraint.

---

### Phase 4 — W5.1/W5.2/W5.3: gate the publish, prove the tarball, prove the publication

**Status:** PENDING.

**Delivers.** G3, G1 and G2 closed, in that order — cheapest and most load-bearing first.

**Depends on.** Nothing in this plan (independent of Phases 1–3); sequenced here because Phase 1
regenerated the surface that these gates protect, and W5 exists to prevent exactly the exposure
Phase 1 created.

**Files.** `.github/workflows/publish.yml`, `.github/workflows/ci.yml`, `CHANGELOG.md`.

**Approach.**

- **W5.1 (G3) — gate publish on CI green.** `publish.yml`'s job graph is three jobs:
  `version-check` (no `needs`) → `npm` (`needs: version-check`, `:48`) → `python` (same, `:96`).
  `ci-ok` exists at `ci.yml:327` and `publish.yml` never references it. Because publish triggers on
  **tag push** and CI runs on the branch, this cannot be a plain `needs:` — it has to resolve the
  CI conclusion for the tagged **commit** and refuse if it is not success. Refuse, not warn.
- **W5.2 (G1) — mirror the wheel gate for npm.** `publish.yml:90-92` is `npm ci && npm run build &&
  npm publish` with nothing between build and publish. Add: `npm pack`, install the **tarball** into
  a scratch dir outside the repo, import the entry point, and assert one real crypto operation
  against `conformance/vectors.json`. Outside the repo matters for the same reason
  `publish.yml:158-169` uses a fresh venv — the build tree is on the resolution path and would
  satisfy the import no matter what the tarball contains.
- **W5.3 (G2) — post-publish smoke against the registry.** Nothing has ever installed the published
  artifact from this repo. Install from **`dl.cloudsmith.io`**, which is a *different host* from the
  upload host (`README.md:144-145` records this explicitly), import, run the vectors.

**Edge cases & failure modes.**
- The `ci-ok` lookup must fail closed on *absent* as well as *failed* — a tag on a commit CI never
  ran is exactly the 0.7.17 shape and must not read as "not failed, therefore fine."
- Cloudsmith index propagation is not instantaneous; the smoke job needs bounded retry with a hard
  ceiling, and a timeout must fail the job, never pass it as "probably fine."
- W5.3 runs **after** upload and so cannot prevent a bad publish — only detect one. Say that in the
  job's own comment so a later reader does not mistake it for a preventive gate. The preventive
  gates are W5.1/W5.2 and (structurally) W5.5.

**Acceptance criteria.**
1. A tag pushed on a red commit is **refused** by publish — demonstrated, not asserted.
2. Breaking `ts/package.json`'s `files`/`exports` makes the npm gate fail before `npm publish`.
3. The smoke job's log shows the resolved install URL is the Cloudsmith **download** host, not a
   local path.
4. Each gate's comment states which of G1–G4 it closes and whether it prevents or detects.

---

### Phase 5 — W5.4/W5.5: a vector per framing per language, and close the 11-minute window

**Status:** PENDING (W5.5 partly cross-repo — see below).

**Delivers.** G4 closed; and the structural fix for the cause of 0.7.17, or a filed, cited issue if
its runtime half cannot land here.

**Depends on.** Phase 4.

**Files.** `go/crypto/crypto_test.go`, `java/src/test/java/com/zer07labs/seam/ConformanceTest.java`,
`kotlin/src/test/kotlin/com/zer07labs/seam/ConformanceTest.kt`, `.github/workflows/ci.yml`,
`scripts/`.

**Approach.**

**W5.4 (G4).** The rule that prevents recurrence: **a framing with no cross-language KAT may not be
released.** Go/Java/Kotlin consume only `admission` + `tct` today; `conformance/vectors.json`'s
top-level keys are `_comment`, `admission`, `tct`, `chain_head_attestation`, `record_digest_v2`.
Extend each shim's consumption to every section it actually implements, and add a CI assertion that
**implemented-framing list == consumed-vector list** per shim, so the next framing cannot be added
without its vector.

> **Hard constraint from the new lockstep gate.** `conformance/vectors.json` may **not** grow a block
> here. `seam-runtime`'s `sdk-digest-parity` diffs the whole file byte-for-byte against its own
> emitter, so a block added in this repo turns `seam-runtime`'s CI red. Everything in W5.4 must
> therefore be **consumption-side only** against the five keys that already exist. A genuinely new
> framing's vector originates in `seam-runtime/crates/seam-client/examples/conformance_vectors.rs`
> and lands there first. This is §9's "never transcribe vectors" with mechanical teeth, and it now
> reaches across repos.

**W5.5 — the highest-value item in the source plan.** The SDK has no independent version by design
(`CHANGELOG.md:3-7`, `README.md:120-126`, `release-on-runtime.yml:3-9`), so a runtime wire change
**automatically triggers an SDK release whether or not the SDK has adapted**. That is the structural
cause of 0.7.17; W5.1–W5.4 only make the failure louder. The fix is a framing handshake: the
runtime's dispatch payload carries a `wire_framing_version`, this repo stores its supported value,
and a mismatch **blocks the tag** and requires a human PR.

The SDK half is implementable here alone, and fails closed on its own: `release-on-runtime.yml`
refuses to tag when the dispatch payload's `wire_framing_version` is **absent or unequal** to the
stored value. Absent-is-refused is what makes it work before the runtime half exists — but it also
means merging it stops all releases until the runtime emits the field, so the two halves must land
in the right order. File the runtime half as an issue, land the SDK half **behind** it, and cite the
issue number on the blocked line.

**Acceptance criteria.**
1. Adding a dummy framing to the Go shim with no vector makes CI fail (the source plan's own test).
2. Each of Go/Java/Kotlin consumes every section it implements; the equality assertion is a CI gate.
3. `conformance/vectors.json` is **byte-identical** to its pre-phase state — verified by
   `git diff --stat` showing it untouched.
4. A simulated dispatch with a bumped/absent `wire_framing_version` makes the tag step refuse.
5. The runtime-side issue exists and is cited on the blocked line here.

---

### Phase 6 — W1: resolve the crates.io name collision, then make the manifest publishable

**Status:** PENDING (blocked on a cross-repo rename — see below).

**Delivers.** The one irreversible decision in this plan, settled before anything is published; a
publishable manifest; a recorded lib-vs-bin decision; and a publish gated on the independence proof.

**Depends on.** The `seam-runtime` rename issue. **Nothing is published before that is resolved.**

**Files.** `verify/Cargo.toml`, `verify/src/lib.rs` (new, if lib is chosen), `verify/src/main.rs`,
`DECISIONS.md`, `.github/workflows/publish.yml`.

**Approach.**

**W1.1 — the collision, first.** Both crates are literally named `seam-verify`
(`verify/Cargo.toml:9`; `seam-runtime/crates/seam-verify/Cargo.toml:2`). crates.io has one
namespace and the first publish claims the name **permanently**. The runtime crate is the one that
**cannot** be public — it links `seam-store` and `seam-trust-aitp`
(`seam-runtime/crates/seam-verify/Cargo.toml:26-27`), which inverts the very claim its own comment
defends. It is the differential oracle: keep it internal and rename it.

So: this repo's crate takes `seam-verify`; the runtime's is renamed (`seam-verify-internal`),
keeping `publish = false` and keeping `[[bin]] name = "seam-verify"`
(`seam-runtime/crates/seam-verify/Cargo.toml:38-39`) so no operator script breaks. That is a
`seam-runtime` edit ⇒ **GitHub issue**, and this phase does not publish until it is closed.

**W1.2 — the manifest.** Flip `publish = false` (`:15`); add `rust-version` (**there is none today**,
so crates.io would accept any toolchain claim and users get no MSRV signal), `readme =
"README.md"` (`verify/README.md` exists, 194 lines), `keywords`, `categories`.

**W1.3 — bin-only vs lib+bin, decided and written down.** `verify/` is bin-only today (`[[bin]]` at
`:59-61`, no `src/lib.rs`, no `[lib]`). Published bin-only is installable but **not embeddable**: an
auditor wanting verification inside their own pipeline must shell out and parse `--json`.
Recommendation stands — add a thin `src/lib.rs` over the existing
`verify::{link, dedup, chain, erasure_certificate, verify_authenticity}`
(`verify/src/verify.rs:11,46,85,204,333`) and keep `main.rs` as a shell over it. *(Note: the source
plan lists four names against five line numbers; the fifth is `dedup` at `:46`.)*

**W1.4 — gate the publish on the independence proof.** A `publish-verify` job that runs the
`cargo tree -e normal` assertion (`ci.yml:283-292`) **and** re-verifies `verify/fixtures/` before
`cargo publish`. Not the Python/npm job — its Cloudsmith credentials are irrelevant; this is public
crates.io.

**W1.5 — claim exactly what was published.** `seam-verify` verifies the **event chain** and
**erasure certificates** (`verify/src/main.rs:49-56`). It does **not** implement
`seam-commitment-digest:v1` — that string appears nowhere in `verify/`. And it **cannot detect
truncation** (§3 / Phase 9). Both caveats land in Phase 7's document.

**State W1's value honestly.** Acquisition is **not** the break. This repo is already **PUBLIC** and
Apache-2.0 (`LICENSE:2-4`); `verify/` is its own standalone cargo workspace by design
(`verify/Cargo.toml:6`, rationale `:1-5`); and its zero-Seam-dependency claim is a **CI gate**
(`ci.yml:283-292`), not a comment. Publishing is a **distribution and trust-anchoring improvement**.
Selling it as unblocking the audit is the overclaim §9 exists to stop, and the document must not
make it.

**Acceptance criteria.**
1. The runtime rename issue is **closed** before any `cargo publish` runs. Cited by number here.
2. `cargo publish --dry-run --locked` clean in `verify/`; `cargo metadata` shows a declared MSRV.
3. `ci.yml:283-292` still passes **unmodified**.
4. An ADR in `DECISIONS.md` records the lib-vs-bin choice; if lib is added, a doc-test verifies the
   shipped fixture **through the library API**, not the CLI.
5. On a machine with no Seam checkout: `cargo install seam-verify && seam-verify chain <fixture>
   --issuer <AID>` exits 0. Transcript in the PR.

---

### Phase 7 — W6: the compatibility statement, and a precise retraction

**Status:** PENDING.

**Delivers.** `COMPATIBILITY.md`; the `build-agent-ingress.md:5` retraction, correct in both halves;
and the matrix linked where consumers look.

**Depends on.** Phases 1–6 for their facts (published-verifier status, the new lockstep coupling).

**Files.** `COMPATIBILITY.md` (new), `README.md`, `plans/build-agent-ingress.md`,
`plans/consolidation-2026-08-14.md`, `plans/README.md`.

**Approach.** Verified absent today: no compatibility matrix, no support window, no version-skew
policy, no MSRV for `verify/`. `COMPATIBILITY.md` must contain:

1. **The lockstep rule and its consequence**, quoting `CHANGELOG.md:9-12` **verbatim** — *"this SDK
   cannot express its own semver. A breaking change here ships under whatever number the runtime's
   history computes, which may be a patch."* Do not soften it. A consumer cannot use semver to avoid
   a break, so the document must give them something else — which is what the rest of the file is.
2. **A runtime ↔ SDK ↔ adapters matrix with verified pins only.** Every row cites a `file:line`.
   Two real rows beat a wrong grid (§9). Seed rows: `seam-adapters/core/pyproject.toml:22`
   (`seam-sdk>=0.7.20,<0.8`) and `seam-aegis/pyproject.toml:28`
   (`seam-agent-core[sdk]>=0.1,<0.2`).
3. **The known-bad bands, permanently:** 0.7.13–0.7.15 unimportable; 0.7.17–0.7.19 wire-broken;
   floor **0.7.20**. Nothing was yanked (`CHANGELOG.md:64-67`), deliberately — so these versions are
   still installable and **this document is the only barrier**. Do not re-litigate the yank (§9).
4. **Per-language support reality** (§0.1): Python and TS published and supported; Go tag-resolved;
   **Java and Kotlin build-from-source and unversioned**. A consumer must not learn this by trying.
5. **What "independently verifiable" does and does not cover** — chain integrity and erasure
   certificates **yes**; commitment digests **no** (not implemented in `verify/`); truncation
   detection **no**, and not until the anchor feed exists. §9: do not claim the published verifier
   detects truncation.
6. **A declared support window.** There is none today, so any number is an improvement; N-2 minors,
   with the caveat that "minor" is the runtime's.
7. **The cross-repo CI coupling** (new, not in the source plan): merging to `main` here immediately
   affects `seam-runtime`'s CI, because both its `sdk-digest-parity` and `differential-parity` jobs
   check this repo out at its **default branch, unpinned**.

**W6.2 — the retraction, precisely.** Per D5, `build-agent-ingress.md:5` is stale in its **pin**
half and still true in its **lock** half, for a recorded reason (an editable path override at
`seam-adapters/pyproject.toml:32`). Retract the pin claim; keep the lock observation and cite why it
still holds. `plans/consolidation-2026-08-14.md:80` carries a related residual note and gets the
same treatment. **A blanket retraction here would itself be a false claim** — the exact failure mode
§9 guards.

**Acceptance criteria.**
1. Every matrix row cites a `file:line` that resolves today. A row without one is deleted, not
   softened.
2. `CHANGELOG.md:9-12` appears verbatim, unsoftened.
3. `build-agent-ingress.md:5` retracts the pin claim **and** preserves the lock observation with its
   cause — a test or grep-guard asserts the retracted string is gone and the qualifier is present.
4. The truncation caveat is present and unhedged.
5. Linked from `README.md`. The `seam/CLAUDE.md` services-table pointer is a **single-row** edit in
   another repo ⇒ filed as an issue, per that file's own maintenance rules.

---

### Phase 8 — W7: the dual-verify obligation, and the two shims missing their rationale

**Status:** PENDING.

**Delivers.** The record-digest dual-verify rule written where implementers will hit it; the
length-prefix rationale added to Java and Kotlin; W7.1 closed as done-upstream rather than re-filed.

**Depends on.** Phase 7 (same document set).

**Files.** `java/src/main/java/com/zer07labs/seam/SeamCrypto.java`,
`kotlin/src/main/kotlin/com/zer07labs/seam/SeamCrypto.kt`, `DECISIONS.md`, `COMPATIBILITY.md`.

**Approach.**

**W7.1 — do not re-file.** Per D3, `seam-runtime` `d7f27c7` (#408) already replaced the catch-all
with `1 =>` / `2 =>` / `_ => None`. Record that it landed and that the SDK-side obligation survives
it; filing it would be filing a fixed bug.

**W7.2 — the rule, as a rule.** When v3 lands: every verifier verifies v1, v2 **and** v3
simultaneously, selected by the record's own `schema_version` — never "latest wins," never a global
flag; **v2 code is never deleted** (a record sealed under v2 must verify in 2126); both
implementations move together, and the differential harness must be extended to drive
**mixed-version streams**; a KAT per version, **generated from the Rust**, with the v2 vector kept
forever; and a mixed-version chain test as the acceptance test for the whole item.

Two notes the source plan could not have had:

- The runtime's parity gate **already discovers `record_digest_v*` blocks by prefix**
  (`sdk-digest-parity.sh:90`), so W7.2's item 4 is mechanically enforced from the runtime side the
  day the v3 block exists. Point at it rather than restating it.
- The gate resolves the Python function **by exact name** (`getattr(crypto, name)`), so
  `python/seam_sdk/crypto.py` must expose `record_digest_v3` under precisely that name. TS
  (`recordDigestV2`, `ts/src/crypto.ts:299`) and Rust (`record_digest_v2`, `verify/src/verify.rs:273`)
  are **not** checked by it — their parity is only asserted by this repo's own suites. That
  asymmetry is worth writing down; it is where drift would hide.

**W7.3 — the commitment digest.** Verified genuinely byte-identical across all five shims: SHA-256
over `[domain, id, action, authority, supersedes, auth_method, trust_basis]`, each u64-BE
length-prefixed, with only cosmetic `supersedes` null-handling differences that all collapse absent
→ empty → eight zero bytes. **Java (`:138`) and Kotlin (`:117`) carry no rationale comment**, while
Go/Python/TS do. Add it, mirroring `seam-trust-aitp/src/lib.rs:350-354` — the rationale is the only
thing stopping a future maintainer from "simplifying" the framing, and §9 names that as a way one
artifact comes to verify under another's signature.

Record the rule: any change to what the commitment digest binds requires **six coordinated edits**
(five shims + the runtime), a bumped domain label, and a KAT per version. When the need is additive,
**add a separate digest** — do not extend v1's field tuple (§9).

And do **not** describe `verify/` as a sixth mirror: `seam-commitment-digest` appears nowhere in it.

**Acceptance criteria.**
1. Java and Kotlin carry the length-prefix rationale, naming the `("a\0b","c")` vs `("a","b\0c")`
   collision concretely — a grep-guard asserts all five shims carry it.
2. `DECISIONS.md` records the dual-verify rule, the six-edit rule, the separate-digest preference,
   and the Python-name coupling to the runtime gate.
3. No shim's digest **behaviour** changes — `git diff` touches comments only, and the conformance
   suites confirm it.
4. `conformance/vectors.json` untouched.

---

### Phase 9 — Cross-repo issues, and the §8 decision that has no W-number

**Status:** PENDING.

**Delivers.** Every runtime-side item filed with a `file:line`; and an explicit, recorded decision on
the spec — scheduled or not, but **decided**.

**Depends on.** Nothing; last because the issue bodies cite what the earlier phases established.

**Files.** `DECISIONS.md`, `plans/README.md`, this plan's blocked lines.

**Approach — issues to file in `seam-runtime`** (read-only sibling; each cites a `file:line`):

| Item | Cites | Ask |
|---|---|---|
| **W1.1** | `crates/seam-verify/Cargo.toml:2` | Rename to `seam-verify-internal`; keep `publish = false` and `[[bin]] name = "seam-verify"` (`:38-39`). **Blocks Phase 6.** |
| **W2.1** | `crates/seamd/src/lib.rs:2141`, `crates/seamd/src/facade.rs:422-424` | `enforce_subject` defaults to **`false`**, and `authorize_read` returns `Ok(())` unconditionally when it is off — so in default configuration both proof endpoints are open to anyone who can reach the port, with `GetCommitmentProof`'s only remaining gate a caller-supplied clearance header defaulting to `Public` (`grpc.rs:735-740`). Flip the default, or **refuse to boot** on a non-loopback bind with it off. A warning is insufficient — a guard that cannot fail is a promise. |
| **W2.2/W2.3** | `crates/seamd/src/facade.rs:468-470`, `verify/src/main.rs:49-56` | Tenant isolation is correct and must not be loosened; the auditor needs an **export**, not a read grant. Bearer-scoped, time-boxed evidence bundle carrying exactly what `seam-verify` consumes. Sequence the export verb with the next contract change so it rides one regeneration. |
| **W3.1** | `crates/seamd/src/facade.rs:1240,1264-1267`, `crates/seamd/src/attest.rs:46-80`, `crates/seamd/src/server.rs:263` | Chain anchors exist but only as outbox events; no route serves them. Publish `GET /v1/anchors` — unauthenticated on the same reasoning as `GET /v1/trust/issuer-aid`. **Until this lands, the SDK must not claim truncation detection** (§9). |

**§8 — the recommendation with no W-number, decided explicitly.** §8's top item is *write a spec*,
on the argument that it is the prerequisite for every future external implementation. Per **D4**,
that argument is half-satisfied already: the **record** digest has a real published spec
(`seam-runtime/docs/specs/seam-event.v1.md:372,379,399`) giving both v2 and historical-v1 framings
byte-exactly. What is missing is a spec for **`seam-commitment-digest:v1`**, whose normative text is
still a doc comment at `seam-trust-aitp/src/lib.rs:338-354` in a **private** repo — which a second
implementer cannot work from.

**Decision: schedule it, scoped to the commitment digest only.** It is roughly half the work §8
priced, it is the only remaining half, and this repo already contains five byte-identical
independent ports to write it against. It is filed as a `seam-runtime` issue (the doc belongs beside
`docs/specs/seam-event.v1.md`), with this repo offering the five shims as the cross-language
conformance evidence. Logged in `DECISIONS.md` so it cannot fall off for lack of a W-number.

Also record §8's honest framing, unsoftened: the five SDK shims are **ports by one author from one
source**, not independent implementations, and a third verifier by the same author would add no
independence. Independence comes from working from spec text alone — which requires there to be a
spec text.

**Acceptance criteria.**
1. Every issue above exists, cites a `file:line`, and its number appears on the blocked line here.
2. `DECISIONS.md` records the §8 decision **and** its D4 rescoping.
3. No claim of truncation detection appears anywhere in this repo — grep-guarded.
4. `plans/README.md`'s active table lists this plan.

---

## Open questions

1. **W5.5 ordering.** The SDK half fails closed on absent, which is what makes it safe alone — and
   also means merging it before the runtime emits `wire_framing_version` halts all releases. Land it
   behind the runtime issue, or land it with an explicit dated escape hatch? Recommendation: behind
   the issue; a release-halting gate with an escape hatch is a gate that will be escaped.
2. ~~**W1.3 lib-vs-bin.**~~ **RESOLVED 2026-08-23.** **lib + bin.** A thin `src/lib.rs` re-exports
   the existing `verify::{link, dedup, chain, erasure_certificate, verify_authenticity}` and
   `main.rs` becomes a shell over it. Embeddability is the point of publishing at all — bin-only
   would leave an auditor shelling out and parsing `--json`. Accepted cost: a public Rust API
   surface with its own semver.
3. ~~**`verify/`'s version independence.**~~ **RESOLVED 2026-08-23.** **Deliberate — keep `verify/`
   independently versioned** (`0.1.0`, not the SDK's `0.7.42`). `verify/` is its own cargo
   workspace with zero Seam dependencies, and an independent version lets it express real semver,
   which this SDK explicitly **cannot** (`CHANGELOG.md:9-12`). Recorded as an ADR in `DECISIONS.md`
   before anything is published.
4. ~~**The publish step itself.**~~ **RESOLVED 2026-08-23.** **Prepare everything; stop before
   `cargo publish`.** Phase 6 lands the rename issue, the manifest, the ADR and the `publish-verify`
   CI job, and runs `cargo publish --dry-run --locked` with the transcript in the PR. The real
   publish is a human step: the crates.io name claim is permanent and the `seam-runtime` rename must
   close first.

## Repo map

| Path | Role here |
|---|---|
| `gen/`, `python/seam_sdk/_gen/`, `ts/gen/` | Untracked build output (`.gitignore:2,18,19`). Regenerated, never committed. |
| `python/seam_sdk/client.py`, `aio.py` | Hand-written sync client and its async mirror — must move in lockstep. |
| `ts/src/client.ts` | Hand-written TS client. |
| `go/crypto/`, `java/`, `kotlin/` | Crypto shims only. No transport, no verbs (§0.2). |
| `verify/` | Standalone zero-Seam-dependency verifier; its own cargo workspace. |
| `conformance/vectors.json` | **Byte-owned by `seam-runtime`'s emitter** via the lockstep gate. Consumption-side changes only. |
| `scripts/check-contract.sh` | Contract-surface gate. Phase 3 makes it verb-complete. |
