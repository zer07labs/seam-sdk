# Plan — #105: pinned-key proof timestamp encoding (aitp-handshake 0.4.1 → 0.11.0)

Status: **planned, not started.** Verified against seam-sdk HEAD `8382ecb` on 2026-09-05.
Companion plans (runtime-owned, read-verified): `../seam-runtime/plans/515-phase3-aitp-011.md`,
`../seam-runtime/plans/cross-repo/seam-sdk-aitp-0.11-vectors.md`.

> **Re-verified 2026-09-13 at HEAD `139d14d`, and committed — it had been sitting untracked in a
> working tree, which is not a plan.** Still blocked upstream: seam-runtime#684 is open with no
> comments, and the runtime lockfile still pins `aitp-handshake` `0.4.1`, so Blocker A stands and
> nothing here can start.
>
> **All ten mint-site line references below re-checked verbatim** — `crypto.py:45,65`,
> `crypto.ts:75-76`, `crypto.go:78,93-94`, `SeamCrypto.java:126` (and the do-not-touch `:175`),
> `SeamCrypto.kt:105` (and `:153`). Phases 2–6 are unaffected by eight days of unrelated commits.
>
> **What did rot is the acceptance arithmetic in Phases 7 and 8, and one piece of it was a trap.**
> Phase 8 required `check-contract.sh` to "still exit **6** with the expected-local-lag NOTE". That
> criterion can no longer be satisfied by any change: `contract/expected-local-lag.txt` was deleted
> when the seven-field `ContextBinding` lag closed, and the gate exits **0** on a current checkout
> (re-run 2026-09-13). Whoever picked this up would have chased a **6** that cannot occur, and the
> natural "fix" — running `--write-manifest` to make the gate agree — is the one thing Phase 8
> explicitly forbids. Both phases are corrected below to state the criterion relatively, against a
> baseline measured at the time, since these numbers move on every unrelated merge.

The change: the pinned-key admission-proof preimage's timestamp slot moves from an 8-byte
big-endian i64 (`timestamp.0.to_be_bytes()`) to the UTF-8 bytes of its base-10 decimal string
(`timestamp.0.to_string()`) — the RFC-AITP-0002 §3.1 erratum (spec issue #17). The domain
separator is unchanged, so the two forms are distinguishable only by trying both. Severity is
interop, not outage: our fleet is internally consistent today; what fails is third-party AITP
admission into Seam and our proofs against the reference `aitp-verifier-py`.

---

## 1. Verdict: is implement-and-merge-now (holding the release) safe?

**No — not as framed. Two mechanical blockers, both verified in the workflows. It becomes
genuinely safe once both are addressed, and the plan below addresses them.**

**Blocker A — the PR cannot even merge until seam-runtime `main` dual-accepts.**
seam-sdk's `integration (live seam-grpc round-trip)` job pulls
`ghcr.io/zer07labs/seam-runtime/seamd:main` (`.github/workflows/ci.yml:257`), and the live
suites perform real AITP admission: `SeamClient._presentation` calls `build_presentation`
(`python/seam_sdk/client.py:213`, `python/seam_sdk/aio.py:154`), and both
`python/tests/test_integration.py` and `ts/tests/integration.test.ts` run
admit → decide → seal round trips. `ci-ok` treats `integration` as advisory, but advisory means
**"may skip but must not fail"** (`.github/workflows/ci.yml:690-698` and the jq gate at
`:718-731`) — a red `integration` reddens `ci-ok` and blocks the merge. An SDK minting
ASCII-decimal proofs against a `seamd:main` that verifies only big-endian fails admission, so
`integration` fails, so the PR is unmergeable. **Precondition: the runtime's dual-accepting
verifier must be merged to runtime `main` and present in the published `seamd:main` image
before this PR can go green.** (Note: local runs of `test_integration.py` self-skip without
`SEAM_GRPC_BIN` — a green local suite proves nothing about this gate. The draft PR's own
`integration` job is the probe.)

**Blocker B — "holding the release" is not something a human can do here; it must be
mechanized.** Merging to `main` cuts no release — verified: `release-on-runtime.yml` triggers
only on `repository_dispatch` (type `seam-release`) and `workflow_dispatch`
(`.github/workflows/release-on-runtime.yml:14-17`). But the dispatch fires automatically on
**every** seam-runtime release (`../seam-runtime/.github/workflows/publish.yml:151-155`), and
the runtime releases frequently (v0.7.73 and v0.7.75 both shipped this month, and both
stamped commits landed on this repo's `main` untouched by any human). Merge the new encoding
without a hold and the next unrelated runtime release stamps, tags, and publishes an SDK whose
proofs production rejects — the exact 0.7.17 failure shape.

The hold exists and is designed for precisely this change: the framing handshake.
`contract/wire-framing.json` says in its own words to bump `supported` for "the pinned-key
presentation preimage", and `release-on-runtime.yml`'s gate ("The runtime's wire framing must be
one this SDK implements", `:81-165`) **refuses to tag** when the dispatched
`wire_framing_version` (hardcoded `"2"` at `../seam-runtime/.github/workflows/publish.yml:148`)
mismatches `supported`. Bump `supported` 2 → 3 **in the same PR** as the encoding change and
every release is machine-refused until the runtime dispatches `3` — which it will only do when
its own side ships. A refused release reports itself (#100/#101).

**With precondition A met and the framing bump in the PR, implement-and-merge-now is safe and
fully reversible**: nothing publishes, `git revert` restores the old encoding byte-for-byte, and
the only externality is the runtime's nightly `seam-sdk-drift.yml` alarm going red (expected —
see §6).

## 2. Corrections and confirmations of the issue framing

Checked against the tree rather than restated:

- **All five mint sites confirmed verbatim at HEAD `8382ecb`, same lines as quoted**:
  `python/seam_sdk/crypto.py:65`, `ts/src/crypto.ts:76`, `go/crypto/crypto.go:94`,
  `java/src/main/java/com/zer07labs/seam/SeamCrypto.java:126`,
  `kotlin/src/main/kotlin/com/zer07labs/seam/SeamCrypto.kt:105`. All four length-prefix
  do-not-touch sites confirmed: `ts/src/crypto.ts:112`, `go/crypto/crypto.go:140`,
  `SeamCrypto.java:175`, `SeamCrypto.kt:153` — each inside `seamCommitmentDigest`, whose output
  the TCT grant binds. Grep proves the inventory is complete: exactly two 8-byte BE encodes per
  file in TS/Go/Java/Kotlin, exactly one `struct.pack(">` in Python.
- **The prose list is bigger than "Python's docstring."** `go/crypto/crypto.go:78` spells
  `timestamp_be_i64` in the `BuildPresentation` doc comment; `ts/src/crypto.ts:76` carries
  `// big-endian i64`; `SeamCrypto.java:126` carries `// big-endian`. All four prose sites move
  with the code, not just `crypto.py:45`.
- **"Merging does not cut a release" — true but incomplete** (Blocker B above): the release is
  cut *for* us by the runtime's next dispatch, so the hold must be the framing bump, not intent.
- **The one-way door is the publication, not the merge.** Everything pre-release reverts
  cleanly. Published versions are immutable (see the 0.7.13–0.7.19 band and the #43 deletion
  effort); a bad vector or missed language that reaches a release is permanent.
- **`verify/` out of scope — confirmed**: no pinned-key or commitment-digest implementation
  (`python/tests/test_framing_rationale_is_documented.py::test_verify_is_not_a_sixth_mirror`
  asserts it stays that way).
- **The old proof value exists in exactly one file**: `conformance/vectors.json`. No test,
  fixture, or doc hardcodes it elsewhere (repo-wide grep).
- **Both proof values were independently reproduced during planning** (stock `cryptography`,
  no Seam code): the BE preimage yields the committed
  `A7qoBa1b…VHJVBw` and the ASCII preimage yields the runtime's measured
  `V3s1256xmBO57MxFezGToW7qbx0ZBx2X6FS9sv-3AfrM4wDY_8MbcFWYY1zDtsw-iJljtYwW0UCxliihOki6CQ`,
  bit-for-bit. The target value is verified, not trusted.

## 3. How `conformance/vectors.json` is regenerated (this reshapes the plan)

**Neither hand-maintained here nor generated by any seam-sdk script.** Its sole author is
seam-runtime's emitter: `cargo run --locked -q -p seam-client --example conformance_vectors`
(`../seam-runtime/scripts/sdk-digest-parity.sh:52`). The `scripts/emit_*.py` generators in this
repo produce only the *sibling* extended files (`authorize_jcs_int_extended.json`,
`record_digest_v3_extended.json`, `tct_exp_extended.json`) — never `vectors.json`
(`ASSUMPTIONS.md:294`: "exactly one author — seam-runtime's emitter").

Consequences:

- We **cannot regenerate** it (the emitter lives in `crates/seam-client`, clean-room for this
  lane, and the runtime tree that emits the new value doesn't exist on `main` yet).
- The runtime's **required** `sdk-digest-parity (cross-repo lockstep)` check byte-diffs the
  whole file against the seam-sdk checkout at `SEAM_SDK_REF`
  (`../seam-runtime/.github/workflows/ci.yml:396-440`, pinned to `284df67` = v0.7.73). Because
  the pin exists (runtime PR #546), our merge does **not** redden runtime CI — only the nightly
  drift alarm.
- Therefore the correct move is a **surgical splice**: edit the single
  `admission.presentation.descriptor.proof` string in place (preserving the emitter's
  formatting byte-for-byte everywhere else), old → new value as verified in §2. The runtime's
  atomic follow-up PR (aitp pins → 0.11.0 + regenerated runtime-side fixture + `SEAM_SDK_REF`
  bump) then byte-diffs its fresh emitter output against our spliced file — the final,
  machine-checked authority that the splice was exact. Our five migrated implementations
  reproducing the value from the vector inputs makes it six independent confirmations.

## 4. Phases

Single PR; the vector flip and all five shims land in **one commit** (a commit with the vector
but not all shims has failing suites — don't create bisect landmines; the framing bump and docs
may be a second commit in the same PR). Phases below are the working-and-verification order.

### Phase 0 — external precondition probe (no seam-sdk code)

The runtime lands its dual-accepting verifier on `main` **with the aitp pins still `=0.4.1` and
the emitter untouched** (its own required parity gate enforces the emitter half). `seamd:main`
republishes on that merge.

**Acceptance (falsifiable, from this repo alone):** open the eventual PR as a draft — the
`integration` job admitting with ASCII proofs against the pulled `seamd:main` **is** the probe.
Green = precondition met; red on admission = not met, and no amount of local testing overrides
that. Do not merge before this is green for the real reason (verify the failure isn't an
unrelated flake by reading the live-server log artifact, `ci.yml:414-425`).

### Phase 1 — the vector flip, and proof that it drives everything

Edit `conformance/vectors.json`: the one `proof` string, old → new.

**Acceptance:**
- `git diff conformance/vectors.json` shows exactly one changed line; no other file in
  `conformance/` changes at any point in this migration.
- Rerun the planning spike (recompute both proofs from the vector's inputs with stock crypto):
  old output == the removed string, new output == the inserted string.
- Run all five suites **before touching any shim**. Expected: each fails **exactly** its
  presentation KAT — `test_pinned_key_presentation_is_byte_exact`
  (`python/tests/test_conformance.py:20`), `"pinned-key presentation is byte-exact"`
  (`ts/tests/conformance.test.ts:17`), `TestPinnedKeyPresentationIsByteExact`
  (`go/crypto/crypto_test.go:50`), `pinnedKeyPresentationIsByteExact` (Java
  `ConformanceTest.java:51` / Kotlin `ConformanceTest.kt:36`) — and **nothing else**. Any
  other failure means something besides the five shims pins the old proof, and the plan's
  inventory was wrong: stop and find it. Every TCT/digest/attestation test staying green here
  is the baseline for the trap assertion in Phases 2–6.

### Phases 2–6 — one language at a time, red → green

Each phase edits exactly one implementation file, then runs that language's full suite.
Keep every edit **line-count-neutral** (see §6, citation cascade). Never use search-and-replace
in Java or Kotlin — `:126`/`:175` and `:105`/`:153` are textually identical apart from the
variable.

| Phase | File · edit | Suite |
|---|---|---|
| 2 · Python | `crypto.py:65` `struct.pack(">q", timestamp)` → `str(timestamp).encode("ascii")`; docstring `:45` `timestamp_be_i64` → `timestamp_ascii_decimal`. `struct` stays imported (used at `:373` on). | `cd python && .venv/bin/pytest -q` |
| 3 · TypeScript | `crypto.ts:75-76` two lines → comment + `const ts = enc.encode(String(timestamp));` (2:2). | `ts/`: `npm run typecheck && npm test` |
| 4 · Go | `crypto.go:93-94` two lines → comment + `ts := []byte(strconv.FormatInt(timestamp, 10))` (**FormatInt, not FormatUint** — Rust stringifies the signed i64); add `strconv` import; fix doc comment `:78`. `binary` stays (used at `:140`). | `go/`: `go test ./...` |
| 5 · Java | `SeamCrypto.java:126` **only** → `in.writeBytes(Long.toString(timestamp).getBytes(StandardCharsets.US_ASCII));` (drop the `// big-endian` comment). `:175` untouched; `ByteBuffer` stays imported. | `java/`: `./gradlew test --no-daemon` (JDK 17) |
| 6 · Kotlin | `SeamCrypto.kt:105` **only** → `buf.writeBytes(timestamp.toString().toByteArray(Charsets.US_ASCII)); buf.write(0)`. `:153` untouched. | `kotlin/`: `./gradlew test --no-daemon` (JDK 17) |

**Acceptance, identical shape per phase:**
1. That language's suite goes fully green (its presentation KAT flips red → green).
2. `git diff` for the file touches only the named lines — reviewed by eye against the two
   do-not-touch line numbers for that file.
3. The digest-invariance assertion (§5) for that language was green in Phase 1 and is still
   green now — i.e. it never transitioned.
4. Suites for not-yet-migrated languages still fail exactly their presentation KAT.

### Phase 7 — arm the release hold + prose

- `contract/wire-framing.json`: `"supported": 2` → `3`; add `"3"` to `history`
  ("RFC-AITP-0002 §3.1 erratum: pinned-key proof timestamp big-endian i64 → ASCII decimal.
  First correct in <next released version>."). No test fixture reads the real file
  (`scripts/test_release_gate.py` fabricates its own), so no test edits are needed.
- `CHANGELOG.md` under **Unreleased**: the break, the erratum, and the deploy-ordering caveat.
- Optional but recommended: a DECISIONS.md entry for the one-way door. If added, its citations
  must resolve — DECISIONS.md is citation-guarded.

**Acceptance:** full python suite green and `pytest scripts` green (the release-gate tests), each
matching the count you measure on a clean tree **immediately before starting** — not a number
written here. These grow on every unrelated merge, so a hardcoded baseline is a criterion with a
shelf life. (For scale only: 1186 / 20 on 2026-09-05, 1298 / 21 on 2026-09-13.) What the criterion
is actually asserting is that this change moves neither count, because the citation and
framing-rationale guards live in that suite and a `CHANGELOG.md`/`DECISIONS.md` edit is exactly
what perturbs them.

### Phase 8 — final sweep and merge

All five suites + `verify/` (`cargo test`, clippy, fmt) green;
`STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits with **exactly the code it exits with on a
clean tree before you start** — measure it first, do not take a number from this file. This change
touches no proto surface, so any movement in that code is real drift. **On 2026-09-13 that code is
0.** It was **6** when this plan was written, because the stubs here lagged the committed manifest
by seven `ContextBinding` fields and nobody could regenerate; `contract/expected-local-lag.txt`
existed to downgrade that standing refusal to a NOTE. Both are gone — `buf registry login` is done
on this workstation and `make generate` pulls the BSR module clean — so a local run and a CI run
now compare the same two things and agree. Do not go looking for the 6.

Versions untouched (`version-lockstep` stays green). Mark the draft PR ready once `integration` is
green in CI. **Do not run** `make generate*`, `make clean`, or `check-contract.sh
--write-manifest` — note that the last of these is precisely what someone chasing a stale expected
exit code would reach for, and it would convert the refusal this gate exists to raise back into the
silent pass it replaced.

### Phase 9 — post-merge handoffs (recorded here; executed in seam-runtime)

1. Runtime atomic PR: aitp pins → `=0.11.0`, regenerate
   `crates/seam-client/tests/conformance_vectors.json`, bump `SEAM_SDK_REF` to our merge SHA —
   its parity gate byte-verifies our Phase-1 splice.
2. **Before** the runtime's `publish.yml` `WIRE_FRAMING_VERSION` moves `"2"` → `"3"`: probe
   that production **runs** the dual-accepting verifier (probe the service — the deployment
   list is not evidence). The framing gate compares numbers, not deployments; bumping to `"3"`
   early re-arms Blocker B with the safety off.
3. Next runtime release dispatches `3` == our `supported` 3 → SDK tags and publishes. Clients
   upgrade on their schedule; the runtime's legacy fallback is removed later, evidence-driven.

## 5. The per-language digest-invariance assertion (the trap catcher)

No new tests are needed — the assertion already exists per language, and Phase 1 proves it
non-vacuous by running it against the flipped vector. The mechanism: `verifyTct` **recomputes**
`seamCommitmentDigest` (the function containing every do-not-touch length prefix) and compares
it against the digest bound inside `tct.signed_artifact_jws` — a runtime-signed value that this
migration leaves byte-identical. Flip a length prefix and "valid TCT must verify" fails in that
language and no other.

| Language | Test · file | What it pins |
|---|---|---|
| Python | `test_tct_verify_valid_and_tampered` (`python/tests/test_conformance.py:42`) + `test_record_digest_v2_matches_reference` (`:77`), `test_record_digest_v3_matches_reference_all_cases` (`:288`), `test_chain_head_attestation_signature_verifies` (`:98`) | commitment digest; all record digests; attestation |
| TypeScript | `"TCT verify: valid → true, tampered → false"` (`ts/tests/conformance.test.ts:28`) + record digest v2/v3 and attestation tests (`:55`, `:73`, `:262`) | `lenPrefix` at `crypto.ts:112`; the LE digest slots |
| Go | `TestTCTVerifyValidAndTampered` (`go/crypto/crypto_test.go:76`) + `TestCommitmentDigestBindsEveryField`, `TestCommitmentDigestIsInjectiveAcrossFieldBoundaries` | `crypto.go:140` |
| Java | `tctVerifyValidAndTampered` (`ConformanceTest.java:85`) + the two commitment-digest tests | `SeamCrypto.java:175` |
| Kotlin | `tctVerifyValidAndTampered` (`ConformanceTest.kt:72`) + the two commitment-digest tests | `SeamCrypto.kt:153` |

This is the per-language restatement of the runtime's "76 leaves, exactly one changed" —
one runner per language, per phase, not once against the emitted vector. Additionally the
runtime's `sdk-digest-parity` step 2 re-executes our Python `record_digest_v*` on every runtime
build, and Phase 9's whole-file byte diff covers everything at once.

## 6. Failure modes beyond the issue's list

- **The armed auto-release (Blocker B)** — the one that makes this a one-way door. Publication
  is irreversible; the framing bump is what converts "hold the release" from a hope into a
  refusal. Cost of the hold: runtime versions released during the window get no SDK counterpart
  (each refusal reports itself); acceptable and visible.
- **Premature `WIRE_FRAMING_VERSION` bump upstream** (Phase 9.2): the gate cannot see
  deployments. The invariant that makes even the release race harmless is *production runs
  dual-accept before any framing-3 SDK release exists*.
- **Citation cascade**: COMPATIBILITY.md / DECISIONS.md / PROGRESS.md carry line-anchored
  citations into `crypto.py` (`:175`–`:830`), `crypto.ts` (`:188`–`:945`), and `crypto.go`
  (`:194`–`:203`) — all **below** the edit sites, guarded by
  `test_compatibility_citations_resolve.py` with `CITATION_SLACK=3`. A net line-count change at
  the top of those files shifts them all. Line-neutral edits (the table in Phases 2–6 is
  designed for it; Go's `strconv` import is +1, within slack) avoid the cascade; if the guard
  still fires, repoint the listed citations in the same PR — never widen the slack.
- **The runtime's nightly `seam-sdk-drift.yml` goes red after our merge** and stays red until
  `SEAM_SDK_REF` bumps in Phase 9.1. Expected and by design ("a red run here means seam-sdk has
  moved somewhere these gates would not follow"). Nobody should "fix" it by reverting us or by
  regenerating vectors on the runtime side without the full Phase-9 PR.
- **Sibling editable installs propagate instantly**: `seam-adapters/pyproject.toml` overrides
  `seam-sdk` with `{ path = "../seam-sdk/python", editable = true }`, and seam-aegis reaches it
  transitively. The moment our merge lands in a sibling checkout, adapters/aegis live runs
  against any not-yet-dual-accepting runtime fail admission. Dev-only, but it will look like
  their bug, not ours — worth a heads-up at merge time.
- **Go sign trap**: the old code cast `uint64(timestamp)` before the BE encode; the new code
  must stringify the *signed* value (`FormatInt`) to match Rust's `i64::to_string()`.
  Irrelevant for real clocks, load-bearing for byte-compatibility of the definition.
- **Local green is not merge green**: the only executable check of the new encoding against a
  real verifier is CI's `integration` job (local runs skip without `SEAM_GRPC_BIN`). Treat the
  draft PR's `integration` result as the phase gate it is.
- **What is NOT at risk**: `spec-pin` vendors only `verify/docs/seam-event.v1.md` (event
  stream) — untouched by this migration. `check-contract.sh` gates proto/RPC surface —
  untouched. The extended conformance files and their `emit_*.py` generators — untouched.

## 7. Reversibility summary

Reversible with `git revert` at every point up to and including the merge (nothing publishes;
`supported: 3` + runtime dispatching `2` = refusal, in both directions of the revert). Stops
being reversible at the first release carrying the new encoding — published artifacts are
immutable, and consumers begin minting ASCII proofs. After the runtime later removes its legacy
fallback, reverting this change would re-break admission from the other side. The door swings
shut at Phase 9.3, not before — which is exactly why the framing bump must be in the same
commit-set as the encoding change, never a follow-up.
