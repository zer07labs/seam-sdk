# Changelog

seam-sdk does not choose its own version. The seam-runtime release is the version authority: it
fires a `seam-release` dispatch, `release-on-runtime.yml` stamps `ts/package.json` and
`python/pyproject.toml` to match, and tags — so the SDK is always the same version as the runtime
("one version everywhere"). Entries here therefore accumulate under **Unreleased** and are retitled
to the runtime version that carries them once it ships.

One consequence is worth knowing when reading these entries: **this SDK cannot express its own
semver.** A breaking change here ships under whatever number the runtime's history computes, which
may be a patch. Where that happens it is called out at the top of the version's section rather than
left for a consumer to discover.

Client-facing changes only. The protobuf contract is `seam.api.v1`; read it at the source rather
than trusting a summary here.

## Unreleased

### Added

- **The vendored spec's "verbatim" claim is now enforced** — `verify/docs/seam-event.v1.md` opens by
  declaring itself a byte-identical copy of seam-runtime's `docs/specs/seam-event.v1.md` at a named
  commit. Nothing checked that, and it had gone stale three times: once omitting the
  `AUTHORIZE_EVALUATED` advisory kind (which shipped a real verifier bug), once missing
  `§Record digest (v3)`, once missing `§"Presence on the wire"` — each caught by a person or a
  review gate, never by a test, because **no test in this repository could**: the proof lives in
  another repository and has to be fetched.

  `scripts/check_vendored_spec.py` fetches it. It runs in CI as the `spec-pin` job and asserts three
  things: the body is byte-identical at the pinned commit (INTEGRITY — a failure means the header is
  lying), that commit is reachable from the ref the header names (REACHABILITY), and the body matches
  that ref's tip (CURRENCY). Consumer-visible because this file is what a third party builds a
  verifier from when they have no runtime checkout — a stale copy ships them a spec that does not
  describe the verifier they are running.

  Drift **blocks the merge** rather than warning. `spec-pin` is advisory in `ci-ok` only in the sense
  that it may *skip* — it needs `RUNTIME_REPO_TOKEN`, which a fork PR has no access to — but an
  advisory job that runs and fails still reddens the gate. A warning was considered and rejected:
  three stalenesses survived precisely because nothing forced the issue.

  A copy may deliberately sit ahead of the runtime's default branch — `verify/` implements the v3
  record digest, whose spec text was still on an unmerged runtime branch. That has to be **declared**
  in the header (`@ <sha> tracking <branch>`); an undeclared off-main pin is refused. The exception
  expires by itself three ways — the branch stops existing, the pinned commit reaches the default
  branch, or the file goes byte-identical on both refs (which is what catches a squash or rebase
  merge, where the pinned commit never lands on the default branch at all). It expired within the
  hour: the branch landed as seam-runtime#440 and was deleted, the gate went red and said to
  re-pin, and the copy is now pinned to `main` at `25272a6`. The spec content is byte-identical
  either way — only the pin moved.

  The job reads the private runtime through a **short-lived seam-deps-bot App token scoped to
  `seam-runtime` alone**, not a PAT — the App already exists org-wide and is already installed
  there, so this needs no new long-lived credential. One limit, stated because the headline above
  does not carry it: a fork PR has no secrets, so `spec-pin` **skips** there and drift introduced
  that way is caught on the next push to `main` rather than at merge time. Its checker is
  separately exercised credential-free in `workflow-guards`, so a fork PR still proves the logic
  even when it cannot run the comparison.

- **`record_digest_v3` on the streamed authenticity helpers** — `verify_streamed_record_digest`
  (Python) and `verifyStreamedRecordDigest` (TypeScript) now recompute `schema_version = 3`
  `DECISION_SEALED` records from the wire, not just v2. Both dispatch on `schema_version`; the v2 path
  is unchanged. The "newer than this SDK" refusal moves from `>= 3` to `>= 4` — a v4 record still
  refuses loudly rather than being computed under a domain tag that does not apply to it, because
  answering `false` for a genuine record is a tamper verdict fabricated by version skew.

  **On a v3 record carrying its `ciphertext_digest`, a stripped `context_digest` (tag 11) or
  `participation_digest` (tag 12) raises `RecordDigestStripError` rather than returning `false`.** The spec makes both mandatory on a v3 payload and requires a
  consumer to refuse — never to substitute an empty digest, never to fall back to the v2 formula — and
  requires the refusal be reported *distinctly* from a digest mismatch, because "someone removed a
  field" and "someone rewrote one" have different responses. A mismatch remains the `false` it has
  always been. `RecordDigestStripError` subclasses `ValueError` (and `Error` in TS) and carries
  `field` plus `wire_tag` (`wireTag` in TS), so a caller routing a refusal to an alert or a metric
  never has to parse English.

  The qualifier on that rule is deliberate and worth knowing: the tag-10 strip check runs *before* the
  v3 arm, so a record stripped of tags 10 **and** 11/12 returns `false` rather than raising — an
  adversary who strips both gets the quieter diagnostic. The record fails either way; tag 10's rule is
  the older and broader one, covering every v2+ record, so it is answered first.

  **Absence on tags 10-13 is length, not field presence.** All four digest fields are singular proto3
  `bytes`, so no presence bit exists and `HasField` raises rather than answering. Per `seam-event.v1`
  §"Presence on the wire", `len == 0` is a **total** absence mapping over any bytes a decoder can be
  handed — including an explicitly-encoded zero-length field, which proto3 obliges a decoder to accept
  even though a conforming producer never emits one. Consumers writing their own verifier should test
  length, not presence. `mode`/`policy_version`/`supersedes` (tags 4/5/7) are the opposite case: they
  *are* optional, empty-string is a real value there, and absent stays distinct from `""`.

  The case most likely to bite a hand-rolled implementation: an absent `policy_rules_digest` (tag 13)
  is **legitimate** — it means no policy was bound — and frames as `opt(None)`, one byte. Passing the
  decoded empty value straight through frames `opt(Some(""))`, five bytes, and reports a mismatch on a
  perfectly genuine record. In TypeScript the `?? null` idiom does not help, because the generated
  field is an empty `Uint8Array` rather than `undefined`.

- **Contract regenerated from the BSR against the landed coordination surface** — one batched
  regeneration covering four `seam.api.v1` changes rather than four separate ones, because each
  regeneration is a release and each release is an exposure event. Adds `PolicyEnforcement`
  (`DecisionResponse.policy_enforcement`, `SessionStep.policy_enforcement`), `ParticipantVerdict`
  (`DecisionResponse.participant_verdicts`), `CollectiveOutcome` + the `CollectiveVerdict` enum
  (`DecisionResponse.collective_outcome`), and the quorum-mode verbs
  `SeamCoordination.SubmitApprovalRequest` / `SubmitBallot`.

  **This is additive — a minor, not a break — and that was proven rather than assumed:**
  `buf breaking` against the module commit the previous stubs were generated from
  (`8bef4b57…`, 2026-08-16) is clean under `FILE`, buf's strictest ruleset, which covers source
  compatibility and not only the wire. A descriptor-level symbol diff confirms zero removals and no
  reused field tags — the three new `DecisionResponse` fields take previously unused tags 7, 8 and 9.

  Note for consumers of `collective_outcome`: `CollectiveVerdict`'s growth policy is normative and
  fail-closed — any value a client does not recognize, **including
  `COLLECTIVE_VERDICT_UNSPECIFIED`**, must route to the caller's fail policy and never to allow. The
  field is `optional`, so absent and `UNSPECIFIED` are distinct wire states and must not be
  flattened into each other.

- **Quorum-mode verbs on the hand-written clients** — `submit_approval_request` / `submit_ballot`
  (Python sync **and** the `aio` mirror) and `submitApprovalRequest` / `submitBallot` (TypeScript),
  with `BallotChoice` re-exported from both package roots so a caller never reaches into the private
  generated tree to name a ballot. `required_approvals` is range-checked as a `uint32` at the client
  boundary, so an out-of-range value names the SDK argument instead of surfacing from a generated
  setter — or, in TypeScript, marshalling silently as a different quorum than the caller asked for.
  Go, Java and Kotlin are unchanged: they are crypto shims with no transport, so a new verb costs
  them nothing.
- `python/tests/test_client_parity.py` — asserts the sync and async clients expose the **same verbs
  with the same parameters**. A verb landing on one client and not the other is this package's
  standing drift hazard, and a per-verb spot check only ever proves the one you remembered.
- **`collective_outcome_of` / `collectiveOutcomeOf`** — fail-closed decoding of
  `DecisionResponse.collective_outcome`, the `CollectiveVerdict` twin of the existing
  `AuthorizeVerdict` handling and following the same discipline. An **absent** field returns
  `None`/`undefined` ("this response does not answer the question"); `COLLECTIVE_VERDICT_UNSPECIFIED`
  or any value this SDK version does not know **raises** `UnknownCollectiveVerdictError`, never an
  implicit allow.

  Both are required by the proto's normative growth policy, and both are easy to get wrong from the
  generated surface alone: the field is `optional`, so absent and UNSPECIFIED are distinct wire
  states a naive read flattens together; and proto3 makes `0` the silent default, so the natural
  negative test (`verdict != DECLINED`) allows on every unrecognized value — the exact inversion the
  policy forbids. The decoder never re-derives the verdict from `approve_count`/`reject_count`: the
  proto states those are observability and that a client-side tally is self-grading and
  unverifiable, which is the whole reason `verdict` is a field.
- **`contract/rpc-manifest.txt` + an RPC-completeness gate in `check-contract`.** The gate previously
  probed 15 named symbols, **none of them a `SeamCoordination` verb** — so a verb could land on the
  contract, regenerate into the stubs, and never be wired into the clients with CI green throughout.
  That is exactly what `SubmitApprovalRequest`/`SubmitBallot` did. The whole verb surface is now
  declared in one committed file and compared **as a set, per language, in both directions**: an RPC
  missing from the stubs is a stale generation; an RPC missing from the manifest is a new verb, and
  refusing there is the point — it forces someone to decide whether the clients take it. Set
  equality rather than a count comparison, because two verbs renamed in one release keeps the count
  identical while the surface changes underneath.
- `now_millis` / `nowMillis` exposed on `erase_subject`/`eraseSubject` and
  `erase_subject_confirmed`/`eraseSubjectConfirmed` (Python + TS) — the field already existed on
  the wire; only the hand-written wrappers omitted it, unlike `enforce_retention`, which already
  exposed the identical field (#39).

### Fixed

- **`digest_schema` is documented as a ceiling, not a description** — `verify/proto/seam/event/v1/
  seam_event.proto` described it as "the record-digest formula the attested chain uses", a reading
  seam-runtime retracted in #439. Since a chain is mixed (v2 and v3 records interleave), no scalar
  can name "the" formula in use; the field asserts every record in the attested prefix has
  `schema_version <= digest_schema`, which is why existing attestations stay true and are never
  re-signed. **No behaviour changed** — `verify/src/verify.rs` already dispatches per record on the
  record's own `schema_version` (`:584`) and only ever frames `digest_schema` into the attestation
  preimage (`:249`), which is exactly what the spec now mandates. The comment was the only thing
  asserting otherwise.

### Fixed — three things that documented themselves incorrectly, and the bug the third was hiding

- **A release-guard comment named a file that does not exist.**
  `release-on-runtime.yml` told the reader that `scripts/test_release_gate_order.sh` asserts the
  framing gate's step ordering. The guard is real but is named `scripts/test_release_gate.py`. A
  comment pointing at a nonexistent guard is worse than no comment: it tells the next person the
  ordering is protected and hands them a filename that returns nothing when they check it.

- **The `COMPATIBILITY.md` citation checker validated its own copy of a line number instead of the
  document's.** Its anchored table duplicated each cited line number and asserted the target file
  still held the right content near *that* line — so the table and `COMPATIBILITY.md` could drift
  apart silently, and did: the document cited `release-on-runtime.yml:120` (`git push origin
  HEAD:main`) for a claim about the `go/vX.Y.Z` tag, six lines off, while the test happily passed
  against its own pin of 126. The table had also needed repointing four times in one working
  session, each repoint a chance to "fix" the test by aiming it at the wrong line.

  The line numbers are gone. Each entry is now `(path, needle)`; the check finds the needle's line in
  the target file and asserts `COMPATIBILITY.md` cites *that* line — the document checked against the
  code, rather than against a copy kept in the test. The needle must be **unique** in its file, which
  is not a formality: four of the six were substrings occurring two to four times (`npm.cloudsmith.io`
  appears on four lines of `publish.yml`), so a search accepting any match would have let a citation
  drift hundreds of lines and still call itself resolved.

- **This repo's reference copy of `seam.event.v1` declared tags 11/12/13 `optional`, which the
  contract says is a semantic break.** `verify/proto/seam/event/v1/seam_event.proto` was written
  during the Rust v3 work, before seam-runtime#435 settled the cardinality question, and its comment
  argued at length that `optional` was load-bearing — the exact position that issue considered and
  rejected. The runtime's rule is the stronger one: a digest slot's domain is {absent} ∪ {32 bytes},
  and a singular field makes the empty value unrepresentable by a conforming encoder rather than
  merely discouraged. Corrected to singular, with the reasoning replaced rather than deleted, so the
  next reader sees why the obvious-looking choice is the wrong one.

  Nothing is generated from that file — `verify/` hand-decodes the wire in `src/wire.rs` and only
  cites the proto in a doc comment, and there is no `build.rs` — so the proto edit itself changes no
  behaviour. **The decoder beside it was a different story, and is fixed below.**

- **`seam-verify` refused a valid record: an explicitly-encoded zero-length `policy_rules_digest`
  (tag 13) was reported MALFORMED instead of read as absent.** `verify/src/wire.rs` declared tags
  11/12/13 with prost `optional`, so a zero-length occurrence decoded as `Some(b"")` rather than as
  absence. Tag 13 absent is legitimate — it means no policy was bound — so the verifier failed a
  record the contract calls valid, and disagreed with the Python and TypeScript implementations on
  identical bytes. A conforming producer never emits those bytes; proto3 obliges a decoder to accept
  them, which is exactly why the spec states the consumer rule as a total mapping over anything a
  decoder can be handed. Tags 11/12/13 are now singular and absence is carried by length, matching
  the wire contract and the other two implementations.

  Three behaviours change for consumers of `seam-verify`:

  - **A record with an empty tag 13 now VERIFIES instead of failing.** This is the fix.
  - **An empty tag 11 or 12 is still refused, but now reads as a STRIP rather than MALFORMED.** The
    verdict is unchanged — the record fails either way, and still fails in the vocabulary of a strip
    rather than a rewrite, which is the distinction that matters operationally. Only the diagnostic
    moves. Telling "omitted" from "explicitly-encoded-empty" requires reading raw wire bytes rather
    than a decoded message; the spec says both inputs verify identically and only the diagnostic
    differs.
  - **A `schema_version = 1` record carrying an explicitly-encoded zero-length tag 11/12/13 now
    passes the v1 skip instead of being refused as a DOWNGRADE.** The v1-smuggling check asks whether
    a v1-declared record carries a v2/v3-only column; under the old `Option` it read a zero-length
    field as "carried", now it reads it as absent — which is what the contract says it is, so the
    record really is v1-shaped and nothing with actual content slips through. Listed anyway, because
    it is a FAILED-to-VERIFIED flip on bytes an adversary can craft, and a verdict flip that a
    changelog does not mention is one an operator discovers from a graph.

  The JSON projection follows the same rule: a missing key and `""` are one state, absent — pinned by
  the spec because webhook and `GET /v1/events` consumers read the projection rather than the wire,
  and two projections disagreeing about absence would recompute two different digests from one record.

### Fixed — release-exposure gaps (W5, G1–G3)

Three independently sufficient causes of a 0.7.17-shaped incident, closed.

- **G3 — publish is now gated on CI.** `publish.yml` needed only `version-check`, so a tag pushed
  at a red commit published anyway. A new `ci-green` job resolves `ci-ok`'s conclusion for the
  tagged commit and refuses on anything but `success` — **including absent**. This could not be a
  plain `needs:`: CI runs on the branch push and publish on the tag push, and `needs:` only orders
  jobs within a single run. Absent is refused deliberately; "not failed" is not "passed", and
  treating it as such is how 0.7.17 shipped eleven minutes after the change that broke it.
- **G1 — the npm package is now packed, installed and imported before publish.** The job was
  `npm ci && npm run build && npm publish` with nothing in between, while the Python job has
  installed and imported its wheel since 0.7.16. The tarball is now installed **outside the repo**
  (the working tree would satisfy an import no matter what was packed — the same reasoning behind
  the Python gate's fresh venv) and must reproduce the committed conformance AID **and** the
  byte-exact pinned-key presentation. Verified by driving it red against a deliberately broken
  `files` list, per this repo's own standard that a guard which cannot fail for the reason it
  claims is worse than no guard.
- **G2 — a post-publish smoke installs from the registry.** Nothing in this repo had ever installed
  the published artifact; the only thing that ever had was `seam-adapters`' `live-wire` job, in
  another repo, by accident of being a consumer. Both packages are now installed from
  **`dl.cloudsmith.io`** — a different host from the upload host — and run the vectors, with bounded
  retry for index propagation and a hard ceiling that **fails**. This job **detects, it does not
  prevent**: it runs after upload, and a published version is immutable. Its own comment says so,
  so a later reader does not mistake it for a safety net it is not.

### Fixed — commitment-digest framing coverage and the release handshake (W5, G4 + W5.5)

- **All five crypto shims now prove the commitment digest binds every field it claims to**, not just
  one. G4's premise needed correcting: Go/Java/Kotlin do not implement `record_digest_v2` or
  `chain_head_attestation`, so never running those vectors was not a coverage gap. They *do*
  implement `seam-commitment-digest:v1`, and it was already covered indirectly — `verify_tct`
  recomputes it and compares against the grant inside the runtime-signed JWS.

  The real gap was the **field tuple**: the only tamper test changed `action`, so exactly one of
  seven framing inputs was proven bound. **An implementation that silently dropped `supersedes` from
  the preimage passed every test in all five languages** — the vector's commitment has no
  `supersedes`, so the KAT bytes are identical — and would have let a supersession be stripped from
  a sealed record undetected. Verified by applying that mutation in Go, Python and Kotlin and
  watching the old tests pass and the new ones fail.

  Each language now pins every field (including the previously unreachable `supersedes`
  present-branch) and asserts the framing is injective across field boundaries — the test that
  notices if someone "simplifies" the length prefixes away, letting one artifact verify under
  another's signature. Consumption-side only: `conformance/vectors.json` is byte-identical, because
  `seam-runtime`'s `sdk-digest-parity` job diffs the whole file against its own emitter.
- **`contract/wire-framing.json` + a framing handshake on the release path (W5.5).** This SDK has no
  independent version by design, so a runtime wire change automatically triggers an SDK release
  **whether or not the SDK has adapted** — the structural cause of 0.7.17, which published eleven
  minutes after the change that broke it. Every other gate here detects that after publication; this
  one refuses to tag.

  `release-on-runtime.yml` compares the dispatch's `wire_framing_version` against the supported value
  and refuses on mismatch, before any commit, tag or publish. It cannot be armed unilaterally —
  until the runtime emits the field every dispatch would look like a mismatch and halt all releases —
  so a committed `runtime_emits_version` latch tolerates absent for now, with a loud warning naming
  [`seam-runtime#418`](https://github.com/zer07labs/seam-runtime/issues/418). Flipping that latch
  once the runtime lands makes absent a refusal too, so a field that later stops being emitted is
  caught as a regression rather than silently reopening the hole.

### Added — compatibility, and the caveats this repo is not entitled to drop (W6 + W7)

- **`COMPATIBILITY.md`.** There was no compatibility matrix, no support window, no version-skew
  policy and no MSRV anywhere in the repo. It quotes the lockstep corollary verbatim and unsoftened
  (a version range cannot protect a consumer from a break here), carries only rows citing a
  verified `file:line`, records the known-bad bands permanently — nothing was yanked, so the
  document is the only barrier — states that Python and TypeScript are published while **Java and
  Kotlin are unversioned and build-from-source**, and declares an N-2-minors support window with
  the caveat that "minor" is the runtime's.

  It also states plainly what **"independently verifiable" does not cover**: the published verifier
  **cannot detect truncation** (a stream cut at the tail verifies green — there is no anchor feed,
  [`seam-runtime#422`](https://github.com/zer07labs/seam-runtime/issues/422)), does **not** implement
  the commitment digest, and cannot help an external auditor *acquire* a proof.
- **`python/tests/test_retracted_claims.py`.** The truncation caveat is a capability limit, not a
  wording preference, so it is test-enforced rather than trusted to survive editing. The guard also
  fails if any document *claims* truncation detection, or if a known-bad band is dropped.
- **Java and Kotlin gained the length-prefix rationale they never had** (Go, Python and TypeScript
  already carried it), and `python/tests/test_framing_rationale_is_documented.py` keeps all five
  honest. The comment is the only thing standing between a future maintainer and a "simplification"
  that would let one artifact verify under another's signature — so it is now load-bearing
  documentation with a test behind it.

### Fixed

- **Retracted a stale claim in `plans/build-agent-ingress.md:5`** that a live consumer pinned
  `seam-sdk >=0.7,<0.8` and therefore sat inside the wire-broken band. `seam-adapters` raised its
  floor to `>=0.7.20,<0.8` and this note did not follow, so it generated false alarms against a
  consumer that was fine.

  The retraction is **deliberately narrow**: only the *pin* half was wrong. The *lock* half — that
  `uv.lock` resolves 0.7.9 — is still literally true, because the adapters root overrides with an
  unconditional editable path source, so the lock records a sibling checkout rather than a resolved
  release. Retracting the whole line would have been a second false claim.

### Changed

- **`protobuf` floor raised `>=7.35.1` → `>=7.36.0`** (still `<8`). Not a chosen number: buf's remote
  plugins track latest, the batched regeneration above emitted **gencode 7.36.0**, and protobuf's
  runtime-version check rejects a runtime older than the gencode that produced a file.
  `tests/test_protobuf_floor.py` derives the floor from the emitted stubs and caught this before
  publication — which is the whole reason it derives rather than trusts.

  **This is the one part of the regeneration that is not additive for consumers.** The contract
  change is additive on the wire (`buf breaking` clean under `FILE`); the package's dependency floor
  is not. A consumer pinned at `protobuf==7.35.1` will fail to resolve, and one who force-installs
  gets a `VersionError` at `import seam_sdk` rather than a wire error.


### Fixed

- **TS `verifyDecision` decoded a non-UTF-8 `signedArtifact` lossily and returned `false`**, where
  Python's equivalent `.decode()` raises `UnicodeDecodeError` — the two SDKs disagreed on identical
  corrupted input, and the TS path silently downgraded a corrupted-artifact signal to the same
  `false` an ordinary invalid decision returns. TS now decodes with `{ fatal: true }` and throws,
  matching Python's fail-loud behavior.

### Added — `record_digest_v3` across three implementations (issue #56, B3)

- **`record_digest_v3` in Python, TypeScript and the published Rust verifier, plus conformance
  vectors** (issue [#56](https://github.com/zer07labs/seam-sdk/issues/56)). The v3 formula covers
  three more columns than v2 — `context_digest` (wire tag 11), `participation_digest` (tag 12), both
  mandatory, and `policy_rules_digest` (tag 13), optional. All three arrive as opaque 32-byte inputs;
  this SDK commits to them, it does not compute them. `record_digest_v2` is **byte-identical** and
  stays that way forever — the v2 vectors in `conformance/vectors.json` are untouched by this change,
  which is checked mechanically rather than by reading the diff.

  Three transcriptions were written independently from the published spec
  (`seam-runtime/docs/specs/seam-event.v1.md`, vendored at `verify/docs/`), never from the runtime's
  Rust. That is the point of the exercise: agreement between implementations that copied each other
  is not evidence. They agree with seam-runtime's fourth, independent implementation on every
  committed vector.

- **A distinct STRIP refusal**, in all three implementations. A v3 payload missing tag 11 or 12 is
  **refused** — never defaulted to an empty digest, never recomputed under the v2 formula — and the
  refusal is reported separately from a digest mismatch. Both fallbacks are worse than they look:
  falling back to v2 is what a downgrade attack wants, and defaulting to empty makes "nobody
  participated" indistinguishable from "somebody deleted the field". Python raises
  `RecordDigestStripError`; TypeScript throws the same-named class carrying `field` and `wireTag`;
  the verifier exits 2 with STRIP wording.

### Changed — `seam-verify` refusals that used to be misreported

- **`seam-verify` refuses an unimplemented `schema_version` instead of reporting a mismatch.**
  Previously a record whose `schema_version` this build did not implement was recomputed under the v2
  formula, which produced a *digest mismatch* — a confident wrong diagnosis, since the bytes may be
  perfectly intact and simply newer than the verifier. It now refuses, naming the version, and says
  the verifier is older than the record. **A record that used to report FAILED for the wrong reason
  now reports FAILED for the right one.**

  One previously-green shape does turn red, and it is stated rather than glossed: a `DECISION_SEALED`
  declaring a `schema_version` above 3 while carrying **no** event `digest` at all used to fall
  through as a non-link — unverifiable, but green without `--strict` — because the digest-presence
  check came first. The version refusal now runs before it (`verify/src/verify.rs:545`). This is the
  intended ordering: an unknown formula means the record cannot be checked *at all*, which is a
  refusal independent of whether there is a digest to compare, and "I cannot check this, so it
  passes" is the exact shape of a downgrade. No conforming producer emits it — the chain fields are
  mandatory for every covered record, and any v4 producer postdates that — so the real-world
  exposure is nil, but the claim "nothing turns red" would have been false as stated.

- **`seam-verify` refuses a `schema_version = 1` record that carries any digest-covered column.**
  v1 has no stream-recomputable digest, so v1 records are skipped by the recompute — which makes
  "relabel a v3 record as v1" the one downgrade the recompute cannot catch by construction, because
  a downgrade *into* the skip leaves nothing to compare. The spec supplies the tell: tag 10 is absent
  only on v1 payloads. A record declaring v1 while carrying tags 10, 11, 12 or 13 is now refused as a
  DOWNGRADE. Genuine v1 records still verify.

### Fixed — the release path's two gates, neither of which had ever run


- **`release-on-runtime.yml`'s wire-framing gate ran before `actions/checkout`, so it read
  `contract/wire-framing.json` out of an empty working directory and crashed on every release.**
  The gate is the one check that *prevents* a 0.7.17 instead of reporting one afterwards, and it was
  placed early on a sound instinct — a refusal should leave no commit, no tag, and nothing
  published. But `actions/checkout` has to follow the app-token mint, so "before the mint" also
  meant "before the repo exists".

  It failed **closed**, so nothing wrong was published — which is precisely why it went unnoticed
  for a day: a gate that always refuses is externally indistinguishable from a gate that is working.
  Four consecutive `seam-release` dispatches failed (2026-08-24 17:12Z through 2026-08-25 02:07Z)
  without the framing comparison executing once. Releases from `f68572f` onward were blocked, so the
  SDK stopped following the runtime version over that window.

  The gate now sits immediately after checkout and still ahead of the stamp and tag steps, which is
  where the invariant it was protecting actually lives. `scripts/test_release_gate.py` pins both
  ends — after checkout, before the stamp — so satisfying one by breaking the other fails CI. That
  guard was driven red against the shipped workflow before being trusted; it reports
  `assert 1 > 3`, the gate's step index against checkout's.

- **`publish.yml`'s "CI is green for this commit" gate read once, and so lost a race it could not
  win.** The release step pushes the commit and the tag seconds apart: the commit push starts
  `ci.yml`, the tag push starts `publish.yml`. The gate then asked for a `ci-ok` conclusion that had
  not registered yet and refused — correctly fail-closed, but for the wrong reason. `v0.7.47` hit
  exactly this: publish fired at 03:24:39Z, `ci-ok` appeared at 03:25:26Z. **It lost by 47 seconds**
  and the release needed a hand re-run to complete.

  Like the framing gate above, this landed in `f68572f` and had never executed — every release since
  died earlier — so its first real run was also the first sight of the race.

  It now waits up to 20 minutes, and only on the states that are genuinely transient: absent, pending,
  or a failed API call (an outage is not a verdict in either direction). A **settled** non-success
  still refuses immediately rather than burning the ceiling on an answer already given, and a timeout
  is still a refusal — running out of patience is not evidence of success. `scripts/test_publish_gate.py`
  executes the real script against a stubbed `gh` across all of it; 6 of its 13 assertions fail
  against the shipped gate, and the 7 that pass under both are the fail-closed ones, which is what
  shows the wait did not soften anything.

## 0.7.26 — 2026-08-14

### Added

- `SeamAdminClient.report_events_consumed(consumed_cursor)` / `reportEventsConsumed(consumedCursor)`
  — wraps the additive `SeamEvents.ReportEventsConsumed` RPC (seam-runtime #317), so the
  `seam-event.v1` relay can report its durably-consumed outbox cursor and let the runtime bound
  (garbage-collect) its outbox. `check-contract.sh` gates the RPC's presence under `EVENTS=1` (#32).

_(0.7.22–0.7.25 carry no seam-sdk tag in this repo's history — no client-facing SDK change shipped
under those version numbers.)_

## ⚠️ Advisory: 0.7.13–0.7.19 do not work against a current runtime

**If you have anything pinned below 0.7.20, upgrade.** These versions remain installable from
Cloudsmith — this advisory, not a yank, is the mitigation (see below) — but they fail in two
different ways, and a matching version number does **not** imply a matching wire contract:

| Range | Symptom | Root cause | Fixed by |
|---|---|---|---|
| 0.7.13–0.7.15 | `import seam_sdk` fails: `ModuleNotFoundError: No module named 'seam'` | `publish.yml` ran raw `buf generate` instead of `make generate` (which also runs `scripts/root_gen.py` to rewrite the top-level `seam.*` imports protoc emits into the rooted `seam_sdk._gen.*` form); the published wheel was never actually importable, and the publish guard couldn't tell because it checked file presence, not import. | 0.7.16 (#28) |
| 0.7.16–0.7.19 | Every `authorize()` call fails `UNAUTHENTICATED: admission ticket is not valid` — **the ticket is fine.** | seam-runtime #286 moved the per-call proof-of-possession signature from v1 (`ticket ‖ digest`) to v2 (five length-framed fields including `tool_name`/`agent_id`). Every SDK published before the fix still signed v1; 0.7.17 shipped 11 minutes *after* the runtime change landed and still carried it. The framing had no conformance vector, and both SDKs' tests verified a signature against a payload the test itself rebuilt — so a self-consistent signature looked conformant and stayed green. | 0.7.20 (#30) |

0.7.13–0.7.15 and 0.7.16–0.7.19 are each confirmed broken by their own defect (the two do not
overlap — 0.7.16 fixed the import bug the same release it stopped mattering for anyone hitting the
wire bug instead). Per git evidence (`import seam_sdk` failing on "every wheel this repo has ever
published" per #28) the import breakage may reach back further than 0.7.13 — this advisory covers
the versions this repo's own history can attribute with confidence. **0.7.20 is the first release
that is both importable and wire-correct.**

No yank: the existing `yank.yml` workflow (dry-run default) was not run for this window: the
versions install and produce a "reasonable anti-oracle" auth error rather than corrupting data or
executing anything unsafe, and revoking installability under a floor already in wide use (adapters,
aegis) is a bigger blast radius than a loud advisory. If that call needs revisiting, `yank.yml` is
ready. Downstream: `seam-adapters` and `seam-aegis` should pin `seam-sdk>=0.7.20` rather than the
current `>=0.7,<0.8`, which admits the whole broken range.

## 0.7.21 — 2026-08-09

### Internal

- CI's required-checks aggregator now treats a **skipped** job as a failure, closing a gap where a
  workflow condition quietly skipping a check let it read as passing (#29).
- Docs: import the shared cross-repo context from `zer07labs/seam` (#31).

## 0.7.20 — 2026-08-08

> **First wire-correct release since 0.7.16 — see the advisory above if you are on an older
> version.**

### Fixed

- **`authorize()` signed the v1 `call_sig` payload; the runtime has required v2 since seam-runtime
  #286.** Every ENFORCE call was rejected `UNAUTHENTICATED: admission ticket is not valid` — a
  first-line-misdiagnosis-shaped failure, since the ticket itself was fine. Fixed by signing the v2
  framing (`frame(context) ‖ frame(ticket) ‖ frame(digest) ‖ frame(tool_name) ‖ frame(agent_id)`,
  binding the tool and agent identity to the signature so a captured signature can't be re-pointed
  at a different tool or registry agent while the ticket is live) (#30).
- The fix ships with `conformance/call_sig_payload_vector.json`, generated by executing the
  runtime's own Rust `call_sig_payload` rather than transcribed from it, so both languages now
  assert against runtime-derived bytes instead of a self-consistent construction that could drift
  again silently.

## 0.7.19 — 2026-08-08

⚠️ **Broken — see the advisory above.** Version bump only; still signs the v1 `call_sig` payload.

## 0.7.18 — 2026-08-08

⚠️ **Broken — see the advisory above.** Version bump only; still signs the v1 `call_sig` payload.

## 0.7.17 — 2026-08-07

⚠️ **Broken — see the advisory above.** Version bump only, published 11 minutes after
seam-runtime #286 landed the v2 `call_sig` requirement; still signs v1.

## 0.7.16 — 2026-08-05

⚠️ **Wire-broken — see the advisory above** (still signs v1 `call_sig`), but this is the **first
importable wheel**.

### Fixed

- **Every published wheel back through 0.7.13 was unimportable**: `import seam_sdk` raised
  `ModuleNotFoundError: No module named 'seam'`. `publish.yml` ran raw `buf generate` in both its
  jobs instead of `make generate`, which also runs `scripts/root_gen.py` to rewrite the top-level
  `seam.*` imports protoc emits into the package-rooted form. CI tested the `make generate` output;
  the release published the raw one — never the same code. The publish guard listed the wheel's
  contents and confirmed the file was present, but never imported it, so it could not catch this.
  Found by `seam-adapters`' `live-wire` CI job, the first thing anywhere to install the published
  artifact rather than resolve a sibling checkout (#28).

## 0.7.15 — 2026-08-04

⚠️ **Broken — see the advisory above.** Version bump only; unimportable (`import seam_sdk` fails).

## 0.7.14 — 2026-08-03

⚠️ **Broken — see the advisory above.** Version bump only; unimportable (`import seam_sdk` fails).

## 0.7.13 — 2026-08-03

⚠️ **Also unimportable — see the advisory above.** `publish.yml`'s raw-`buf generate` defect
(fixed in 0.7.16, #28) predates this release too; the packaging fixes below landed in source but
never reached a consumer, because the wheel that shipped them couldn't be imported.

> **Shipped as a patch, but the packaging changes below are breaking.** The version number could not
> say so: seam-sdk follows the runtime's version, and the runtime's own history for this release
> contained nothing breaking, so release-plz computed a patch. Read this section before upgrading a
> pinned consumer. (Resolvers still do the safe thing — a consumer pinned below any floor resolves
> to 0.7.12 rather than installing something it cannot import — but the number is not the signal it
> would normally be.)

### Breaking — Python packaging metadata

Three declared dependency floors were wrong and are now correct. Each one previously **resolved
cleanly and then failed inside the consumer's process**, which is the worst shape a packaging defect
can have: the error names protobuf, or grpc, or nothing at all, and never names us.

| | Was | Now | What the old floor allowed |
|---|---|---|---|
| `requires-python` | `>=3.9` | `>=3.10` | A 3.9 install that resolved, then failed at `import seam_sdk` — protobuf 7.x needs 3.10. |
| `protobuf` | `>=5` | `>=7.35.1,<8` | Runtime 6.x against gencode 7.35.1 → `VersionError` at `import seam_sdk`. |
| `grpcio` | `>=1.60` | `>=1.64` | 1.60–1.62 → `TypeError: unexpected keyword argument '_registered_method'` at `SeamClient.connect()`. |

**If you pin below any of these, you can no longer resolve `seam-sdk`.** That is the intended
outcome — the alternative is resolving successfully and failing at import — but it is a breaking
change, and it is why this belongs in a minor release rather than a patch.

The protobuf one was not theoretical: it took a consumer's entire test suite from 88 passing to
**zero collected**, and from inside that repo it looked like their bug.

Both the protobuf and grpcio floors are now **derived from the generated stubs and asserted in CI**
(`python/tests/test_protobuf_floor.py`, `python/tests/test_grpcio_floor.py`) rather than pinned.
`_gen` is regenerated by `make generate` against buf's *remote* plugins, which track latest, so the
required versions move without anyone editing the dependency list. A regenerate that outruns a
declared floor now fails here instead of in a consumer's import.

`grpcio` needs the later of two versions, which is worth knowing if you maintain a fork: the stubs
use the registered-method convention on **both** sides — `_registered_method=True` on the client
(grpcio 1.63) and `server.add_registered_method_handlers`, emitted unguarded, on the server
(grpcio 1.64). A floor of 1.63 installs, connects, and then raises `AttributeError` from every
`add_*Servicer_to_server`.

### Fixed

- **Admission-ticket refresh stampede.** N concurrent callers receiving `UNAUTHENTICATED` produced
  N re-admits: each threw away the ticket the previous one had just minted. It triggers on mass
  revocation — precisely when the admission endpoint is least able to absorb a fan-out. Refresh now
  re-checks under a lock and coalesces to one re-admit. Cold start always coalesced correctly, which
  is why the existing suite stayed green over it.
- **Ticket locking is per-AID**, so a slow `Admit` for one identity no longer blocks another
  identity from reading its own cached ticket.

### Added

- `close()`, `__enter__`/`__exit__` on the two **sync** clients (`SeamClient`, `SeamAdminClient`).
  Only the aio client had them; a process that built a client per request leaked a channel, its
  connection, and its keepalive timers every time, silently.
- A `timeout` on **every** `SeamAdminClient` method, defaulting to `DEFAULT_ADMIN_TIMEOUT_S` (30 s).
  Previously none of them took one — including `erase_subject`, which crypto-shreds a subject's
  records and could hang an operator's process indefinitely with no way to learn whether the erasure
  landed. `stream_events` deliberately remains unbounded: a gRPC deadline bounds the whole stream,
  not the gap between events, so any finite default would kill a healthy `follow=True` tail.

### Changed

- `timeout` is documented as **per-RPC, not an overall call budget**. Unchanged behaviour, now
  stated: `authorize` may make up to six wire calls (admit handshake, the Authorize, a refresh, a
  retried Authorize), so a caller needing a hard overall bound must impose its own outer clock.

### Internal

- The version stamp moved from inline YAML to `scripts/set_version.sh`, tested on every PR by
  `scripts/test_set_version.sh`. It previously matched pyproject's `version` key by line number,
  with two lines of headroom in a file whose every other field carries a multi-line comment.
