#!/usr/bin/env python3
"""Is the version `main` claims to have released actually installable from the registry?

WHY THIS EXISTS
---------------
`publish.yml`'s `release-outcome` job reports a publish that RAN and failed. It is a job inside
`publish.yml`, so it can only speak when `publish.yml` speaks. A release that was never dispatched
at all — no tag pushed, the trigger misconfigured, the workflow file broken — fails exactly as
silently as before, because nothing executes and therefore nothing reports. Three such releases
(v0.7.69, v0.7.70, v0.7.72) were found by hand five days later; see `publish.yml:748-751`.

This check answers the durable question instead of the eventful one: **does the registry serve the
version `python/pyproject.toml` currently claims?** That is a statement about STATE, so it stays
true across re-runs, re-tags, and failures that happen for some new reason — and it runs on its own
schedule, so it does not depend on the thing it is watching having managed to start.

THE THREE STATES, AND WHY ONE COMPARISON COVERS TWO OF THEM
-----------------------------------------------------------
A. **Never dispatched.** No tag, version unchanged, registry unchanged. Consistent, not drift —
   `v0.7.74` was a runtime workspace-crate bump with no SDK release, and flagging it would be wrong.
B. **Tagged, publish refused.** `v<version>` exists; the registry does not serve it.
C. **Commit landed, tag push failed.** `main` claims the version; no tag exists.

`release-on-runtime.yml:180` pushes the version commit to `main` BEFORE `:182`/`:186`/`:187` create
and push the tags, under Actions' default `bash -eo pipefail`. So "is main's declared version
installable?" is true in state A and false in both B and C — one comparison, no tag involved. The
tag is read only to choose the REMEDIATION TEXT, never to reach the verdict. A tag-keyed check
("latest tag > latest published") is strictly weaker: it is blind to state C by construction, which
is the same blind spot `release-outcome` already has.

FOUR THINGS THAT ARE EASY TO GET WRONG
---------------------------------------
1. **Exit 1 is also Python's uncaught-exception code**, and 1 is this script's drift verdict — so
   without the handler at the bottom of this file, an `ImportError` or a typo reports itself as
   "the registry is behind the source". Every unexpected exception is mapped to 2. This is the
   never-a-verdict property `probe_framework_coinstall.py` is built around, with the hole that
   script still has closed.
2. **The registry is consulted BEFORE the grace window is applied.** The cheap implementation
   checks the age first and skips the query for a fresh version — and then a broken instrument goes
   unnoticed on exactly the runs that follow a release, which is when it is needed. The instrument
   is exercised on every run.
3. **The clock is `max(commit date, tag date)`, not the commit date.**
   `release-on-runtime.yml:176-181` has a branch where nothing is committed ("already at $VER —
   tagging only") and `:182`-`:187` tag and push anyway. A re-dispatch would otherwise inherit the
   original bump's date, get zero grace, and fire against a publish that started ninety seconds ago.
4. **An empty answer must never read as a clean one, and the two modes prove that differently.**
   Live, the query is scoped to one version, so a genuine drift really does return `[]` — and that
   emptiness is trusted only because `CANARY_VERSIONS` was queried FIRST, on the same credential in
   the same run, and came back with rows. Offline (`--packages-json`) there is no canary, so the
   file itself must carry the proof: at least one `seam-sdk` row at SOME version, or it is not a
   plausible response to a `seam-sdk` query and exits 2. These are deliberately opposite rules for
   the same-looking input; do not unify them.

WHY THERE IS A CANARY, AND WHY IT IS A SET
-------------------------------------------
Without one, every failure of the query surface — a wrong URL, a scope-less token, a silently
ignored `version:` qualifier — reads as "the registry does not have it", i.e. as drift. A confident
wrong verdict is the worst thing this check could produce, worse than no check, because it trains
its reader to ignore it.

A single pinned version does not work either, and its first draft proved it: pinned to the then-
current version, a real drift on that version made the canary come back empty and the run exit 2 —
"my instrument is broken" for precisely the condition it exists to report. Hence a roster, hence
the runtime rule that any entry equal to the target is dropped, and hence "healthy if ANY candidate
answers" — one yank must not brick the instrument.

TWO REPOSITORIES (seam-sdk#203)
-------------------------------
`zer07labs/internal` is where a release lands; `zer07labs/partner` is what design partners install
from, filled by `publish.yml`'s `promote-partner` job, which copies from internal. Both are asked,
on one clock and one grace ladder, each instrument proven before its answer is trusted (live:
the canary roster; offline: rule 4 above, applied to each dump). Internal is answered
first and is the root cause when both are short: one internal issue, whose table records partner's
observed state. Internal complete and partner short is a PROMOTION LAG — its own issue title,
`PARTNER_DRIFT_TITLE`, its own suppression scope, and "State P" remediation. A partner instrument
fault never hides an internal finding: beside an internal drift it is printed and the drift's 1
stands (unless that drift is suppressed, which leaves no finding to stand beside); anywhere else,
including that suppressed case, it is exit 2.

THE NEWEST RELEASE (seam-sdk#253)
---------------------------------
Main's declared version is not always the one partners need: while it is a suppressed internal
drift (0.45.1 under #250), the release that DID ship goes unexamined on partner. So a second
question is asked: one unscoped GET of internal, `NEWEST_QUERY` (`sort=-version`), finds the newest
version complete in both formats, and partner is judged on THAT version. The client re-checks the
server's ordering rather than trusting it, since a misspelt parameter is ignored silently, never
refused. It never chooses the version a full page may have cut, and the answer must be at least the
proving canary and at least a served declared version. Anything else is a fault: exit 2, unless an
unsuppressed declared drift stands beside it (then 1). Its clock is the
latest `uploaded_at` among internal's required-format rows at that version, not git, on the same
grace ladder. A lag files under `PARTNER_DRIFT_TITLE` for that version, the title the declared
question would use for it, so there is one issue per missing version whichever question finds it.
When the newest version IS the declared version, it is skipped: the question is already answered.
Coverage limit: a failed promotion of a version superseded within the hard window is never seen.

Usage:  scripts/check_registry_drift.py [--repo DIR] [--packages-json FILE]
                                        [--partner-packages-json FILE] [--now ISO8601]
                                        [--soft-grace-minutes N] [--hard-grace-minutes N]
                                        [--report]
        With --packages-json the response is read from that file and nothing is fetched; it
        must be an UNSCOPED `?query=seam-sdk` dump, because offline that file is the only
        proof the query ran at all. Partner is then checked only if --partner-packages-json
        is given too (same rules), and the output says plainly when it was NOT checked.
        --partner-packages-json alone is refused: a saved partner answer is never compared
        with a live internal one. Offline, the newest version is computed from the internal dump,
        whose rows must keep `uploaded_at` for the newest question's clock.
        Without them both repositories are queried live and SEAM_REGISTRY_TOKEN, which must
        read both, has to be set.
Exit:   0 = internal serves it (and so does partner, wherever partner was checked, for both the
            declared and the newest version), it is younger than the hard window, or the drift
            is suppressed by a closed issue carrying the `deliberately-unpublished` label
        1 = drift — internal missing it, internal serving it and partner not, or partner
            missing internal's newest complete release (whatever the declared question says)
        2 = infrastructure — never a verdict, INCLUDING every unhandled exception, and
            including a partner or newest-version answer that could not be read, unless an
            unsuppressed drift on the other question stands beside it
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

#: Below this, a publish is plausibly still running and there is nothing to say. The declared
#: ceilings in publish.yml sum to about 40 minutes: `ci-green` polls 40 x 30 s
#: (`publish.yml:82-83`), then the npm and python build+publish jobs, then `registry-smoke` retries
#: 10 x 30 s per ecosystem in one job (`:625,633` and `:721,724`). 90 is a bit over 2x, which
#: absorbs queue time, cold caches and a `setup-*` miss.
#:
#: The SAME window bounds `partner`, and that is a claim about publish.yml rather than a convenience:
#: `promote-partner` runs in the same workflow run, `needs:` `registry-smoke`, and carries its own
#: `timeout-minutes: 20` (`publish.yml:768-773`). Declared ceilings including it: about 60
#: minutes, still under 90. A second clock for partner would be a second thing to keep honest.
#:
#: The newest-version question (#253) reuses these minutes on a DIFFERENT clock: internal's
#: `uploaded_at` for that version, not git. Promotion starts after `registry-smoke`, which declares
#: no `timeout-minutes` of its own, so the upload clock bounds the promotion no worse than git does.
SOFT_GRACE_MINUTES = 90

#: GitHub's default per-job limit, so above this NO publish job for this version can still be
#: alive. Only past this does the check escalate, which is what guarantees it can never duplicate
#: `release-outcome` against a still-running publish.
#:
#: Between the two tiers the check warns and exits 0: the declared ceilings have been blown, so
#: something is wrong, but the hard ceiling has not, so it may still resolve itself. A single
#: 360-minute cliff represented that state as CLEAN, and a reader of a green run would believe it.
HARD_GRACE_MINUTES = 360

#: `git tag -l 'v*'` must return at least this many. Measured 67 at `f177cfb` for that exact glob
#: (`go/v*` tags do not match it); a third is 22, rounded down to 20 per this repo's floor
#: convention. Below it the checkout was fetched without tags, and EVERY release would be
#: misdiagnosed as state C — a confident wrong remediation on every run.
TAG_FLOOR = 20

#: How far `now` may sit BEFORE the release attempt before that stops being clock skew. A commit or
#: tag date a few seconds ahead of the checker is ordinary NTP jitter and should read as "zero
#: minutes old", i.e. brand new. A larger negative age is not jitter — it means `--now` is wrong,
#: the clone's dates are wrong, or the clock is. Left unhandled it is a SKIP PATH: a negative age
#: is always below the soft window, so the check would defer silently and forever, which is the one
#: outcome this file is built to make impossible.
CLOCK_SKEW_TOLERANCE_MINUTES = 5

#: The distribution, after a leading `@scope/` is stripped. npm publishes `@zer07labs/seam-sdk`,
#: Cloudsmith's python format carries `seam-sdk`; `yank.yml:75` reconciles them the same way.
PACKAGE_NAME = "seam-sdk"

#: Both are stamped to one version by `scripts/set_version.sh`, so a wheel-only check is a partial
#: answer — half a release is still a broken release.
REQUIRED_FORMATS = ("python", "npm")

#: Versions asserted to be published in BOTH formats. A roster rather than a single pin, so one
#: yank does not brick the instrument. Any entry equal to the target is dropped at runtime — a
#: canary that IS the target proves nothing, and would convert that version's drift into an exit 2,
#: muting the check on exactly the version it is watching.
#:
#: THE RULE, and it is a real predicate rather than the near-tautology this comment used to carry:
#: a canary is a version whose publish run's `registry-smoke` job is GREEN, and which is named in
#: no CHANGELOG advisory band.
#:
#: Why `registry-smoke` is the right clause, in the repo's own words at `publish.yml:790-794`: it
#: is "the ONLY job whose success proves the release landed: it installs the published artifact
#: back OUT of Cloudsmith and runs the conformance vectors against it." Anything weaker — a tag, a
#: green npm step — cannot tell a finished release from one that uploaded and never became
#: installable. An earlier draft of this comment applied "has a tag, minus the three refusals
#: anyone happened to record", and conceded it was weak; it was weaker than it looked, because the
#: reason only three refusals are on record (`publish.yml:748-749`) is that nothing was watching,
#: which is the premise of seam-sdk#100 and the reason this file exists.
#:
#: Evidence, recorded and re-checkable without a live query (2026-09-06):
#:   0.7.71 — publish run 33479578480 green, AND observed through THIS canary's own endpoint and
#:            query shape: yank run 33969742508 (2026-09-05, dry_run) printed
#:            `python seam-sdk 0.7.71` twice and `npm @zer07labs/seam-sdk 0.7.71`, then deleted
#:            nothing. That is `assert_live_instrument_healthy` passing for real, on the list API,
#:            on the production credential. It is the ONLY version in this repo's history with
#:            evidence of exactly the kind this assertion needs, which is why it is FIRST: the
#:            loop below short-circuits on the first healthy candidate, so ordering decides which
#:            version the normal path actually exercises, and it costs nothing.
#:   0.7.50 — publish run 32933376474, `registry-smoke` green (both formats).
#:   0.7.65 — publish run 33267190153, `registry-smoke` green (both formats).
#:   0.7.75 — publish run 33986357361, `registry-smoke` green (both formats). Also the NEWEST
#:            version that has published at all: every tag from v0.7.76 up failed at `ci-green`
#:            with all three publishing jobs skipped.
#: Those runs prove publication in both formats. Present-tense presence is inferred from the
#: complete yank history, not observed — see the next paragraph for why that inference is sound.
#:
#: What the yank predicate actually is, because getting this wrong is how the next editor
#: re-points this roster badly: `yank.yml` has 27 runs, and the ONLY versions ever deleted are
#: 0.7.7 and 0.7.13-0.7.19 — the exact scope of issue #43, which closed 16 minutes after the last
#: run. The predicate is "named in an advisory as unconditionally broken", NOT "old".
#: `CHANGELOG.md:662` names the two broken bands, and 0.7.39-0.7.43 was deliberately NOT deleted
#: despite being older than everything in this roster (`CHANGELOG.md:696`). No retention sweep has
#: ever run here. An earlier draft of this comment justified the age spread as a hedge against
#: retention aging all entries out at once; that hazard is not real in this repo, and stating a
#: wrong reason invites a future editor to optimise for the wrong variable — dropping a safe old
#: version in favour of one sitting inside an advisory band. Keep the spread if you like it, but
#: the reason is diversification against an unknown future predicate, not retention.
#:
#: The residual risk is real and unavoidable: 0.7.39-0.7.43 were fine until #52 found the
#: protobuf-floor defect, so any version can BECOME advisory-listed later. That is exactly what a
#: multi-entry roster with "healthy if ANY answers" is for.
#:
#: Note what the spread buys beyond the drop-if-equal rule: every entry is strictly BELOW the
#: current target (0.7.77), and the target only ever moves upward, so no entry can equal the
#: target again and the dropping branch can never actually shrink this roster. That rule stays
#: because it is what makes the roster safe to re-point carelessly — not because this roster
#: needs it.
#:
#: PARTNER. The roster proves the `partner` instrument too, and the evidence above does not carry
#: over: a green `registry-smoke` is a statement about `internal` only. Observed directly instead,
#: through this check's own query shape on the production credential (2026-10-12): every entry
#: returned `seam-sdk` python and `@zer07labs/seam-sdk` npm rows from `zer07labs/partner`, put there
#: by the `promote-partner-backfill.yml --since 0.7.47` backfill. Re-pointing this roster now has
#: two predicates, and an entry must satisfy both.
CANARY_VERSIONS = ("0.7.71", "0.7.50", "0.7.65", "0.7.75")

#: The list endpoint `yank.yml:69-71` uses. Same request shape deliberately: that is the shape
#: believed to work, and a drift check whose query differs from the one proven in production is
#: testing something else.
REGISTRY_URL = "https://api.cloudsmith.io/v1/packages/zer07labs/internal/"

#: The repository a design partner can be given a token to (`publish.yml:747-757`). The SAME
#: endpoint and query shape with only the repository slug changed — derived rather than written
#: out, so the two cannot drift apart in anything but the one segment that is meant to differ.
#: `CLOUDSMITH_API_KEY`, the credential the workflow resolves first, reads both (observed
#: 2026-10-12), so no second secret is involved.
PARTNER_REGISTRY_URL = REGISTRY_URL.replace("/zer07labs/internal/", "/zer07labs/partner/")

#: A response carrying exactly this many rows is treated as truncated — see `fetch_registry`.
PAGE_SIZE = 50

#: The ONE unscoped request this check makes (seam-sdk#253): every `seam-sdk` row on internal,
#: newest version first, so the newest release can be found without knowing its number.
#:
#: Pinned word for word by `test_the_newest_query_is_pinned_word_for_word`, because of what was
#: observed live on 2026-10-12: a wrong VALUE fails loudly (`sort=-bogus` is HTTP 400), but a wrong
#: parameter NAME does not — `ordering=-version` is silently ignored and the server falls back to
#: `-date`. A typo here would therefore not fail; it would quietly change which row comes first.
#: That is also why `fetch_newest` checks the order of what came back rather than trusting the
#: request: the test pins what is asked, the check proves what was answered.
#:
#: Full pages are the normal case here (internal held 231 rows that day), so the version-scoped
#: truncation guard in `fetch_registry` must NOT apply to this response. `fetch_newest` has a rule
#: of its own for the page edge instead.
NEWEST_QUERY = f"?query={PACKAGE_NAME}&sort=-version&page_size={PAGE_SIZE}"

#: Cloudsmith's `uploaded_at`, as observed on both repositories on 2026-10-12:
#: `2026-10-11T04:43:28.896556Z`. Strict on purpose. The newest question's clock is read out of a
#: RESPONSE rather than out of git, and a response is not ours to interpret generously: anything
#: that is not exactly a timestamp is refused, and refused without being echoed (see
#: `_parse_upload_stamp`). An offset is accepted alongside `Z` because it is the same instant
#: spelled the other ISO-8601 way, and refusing it would make a harmless serializer change exit 2.
UPLOAD_STAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)

#: `yank.yml` has no timeout; a hung GET in a scheduled job is a silent multi-hour burn.
CURL_MAX_SECONDS = 60

#: Resolved from `CLOUDSMITH_API_KEY` / `CARGO_REGISTRIES_ZER07LABS_TOKEN` by the workflow shell,
#: not here, so the resolution is testable as shell the way `yank.yml:55-63`'s is.
TOKEN_ENV = "SEAM_REGISTRY_TOKEN"

#: The version is interpolated into a URL query string (`?query=seam-sdk+version:<v>`), where `+`
#: means SPACE and `#`, `&`, `%` and whitespace are all structural. `yank.yml:64-66` guards its own
#: operator-typed input the same way. The obligation is stronger here: this value is read from
#: `main`, so a refusal means the world is not the world this script models — exit 2, never 1.
SAFE_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*$")

#: The reported issue's title, and it must never collide with `release-outcome`'s.
#:
#: That job (`publish.yml:788`) files `Release <tag> did not publish`, matching by EXACT title
#: equality over open issues (`publish.yml:822-824`). Two exact matchers over two title shapes that
#: share no prefix cannot find each other's issues in either direction — which is true by
#: construction, and therefore gets a test rather than a paragraph. The two mechanisms report
#: different things about the same release (an event that failed, versus a state that persists),
#: so both existing at once is correct; both writing to one issue would not be.
DRIFT_TITLE = "Registry drift: seam-sdk {version} is not installable"

#: A promotion lag: internal serves the version, `partner` does not (seam-sdk#203). Its own title,
#: so its own issue, its own suppression scope, and no collision with `DRIFT_TITLE` or
#: `RELEASE_NOTICE_TITLE` — all three are matched by exact equality, and no one of them is a
#: prefix of another, which `test_no_title_is_a_prefix_of_another` pins rather than this comment.
#: Separate rather than folded into the internal issue because the two have different fixes and
#: different owners: one is a publish that did not land, the other a copy that did not happen.
PARTNER_DRIFT_TITLE = "Registry drift: seam-sdk {version} is not on partner"

#: `release-outcome`'s title, rendered here ONLY to look for one to cross-link. Never written.
#: `GITHUB_REF_NAME` carries the `v`, so the tag — not the bare version — is what it interpolates.
RELEASE_NOTICE_TITLE = "Release v{version} did not publish"

#: Suppression: a CLOSED drift issue carrying this label means "we know, and we are leaving it".
#: Two deliberate acts, scoped to one version, and the label need not pre-exist — this script only
#: ever READS label names out of the listing and never filters by label server-side, so a label
#: nobody has created simply never matches.
SUPPRESSION_LABEL = "deliberately-unpublished"

#: A finite window over the issue list. The repository is around issue #100, so this is not close
#: to binding — but a listing that comes back at exactly the limit may be truncated, and the run
#: says so rather than concluding from a window it cannot see past.
ISSUE_LIMIT = 500

#: `gh` needs to be told which repository. The workflow passes `${{ github.repository }}`; a local
#: `--report` without it refuses rather than guessing from the checkout's remotes.
REPO_ENV = "REPO"

#: Same reasoning as `CURL_MAX_SECONDS`: a hung `gh` in a scheduled job is a silent burn.
GH_MAX_SECONDS = 60

#: The workflow's own filename, used to ask the Actions API about this check's run history. A
#: constant rather than a literal at the call site because renaming the file silently breaks the
#: query — the API answers 404, the heartbeat degrades to a warning nobody reads, and the staleness
#: arm is off forever. `test_the_workflow_filename_constant_is_the_real_filename` pins it.
WORKFLOW_FILENAME = "registry-drift.yml"

#: The workflow's cron, and the multiple of its period that counts as "the schedule has evidently
#: been skipping". The THRESHOLD IS DERIVED from the cron rather than written beside it as a second
#: number: a hardcoded "360 minutes" keeps agreeing with itself after the cron moves to twelve
#: hours, at which point the warning fires on every normal run and gets muted. Deriving it makes
#: that class of drift unrepresentable.
#: The label separator, ONE definition for what used to be three. The jq program that BUILDS the
#: field and the parser that READS it each held their own literal, and the test stub restated it a
#: third time — so `join(",")` in the jq passed every test while, in production, a label like
#: `foo,deliberately-unpublished` split into two, one of them equal to the suppression label, and a
#: real drift went silently suppressed. The jq spelling is DERIVED rather than written out, because
#: JSON — and therefore jq — has no `\x` escape: `\u001f` is the only form it accepts.
LABEL_SEP = "\x1f"
_LABEL_SEP_JQ = "\\u%04x" % ord(LABEL_SEP)

#: The projection, as a named constant so the argv can be pinned word-for-word by a test the way
#: the heartbeat's is. Kept next to the separator it uses: the two drifting apart is the failure
#: this whole block exists to prevent.
_ISSUE_LIST_JQ = (
    f'.[] | [.number, .state, ((.labels|map(.name))|join("{_LABEL_SEP_JQ}")), .title] | @tsv'
)

CRON = "17 */2 * * *"
STALENESS_MULTIPLIER = 3

#: The heartbeat's own question, as a query string. `status=completed`, NOT `status=success`: the
#: runs API filters on the check run's STATUS OR CONCLUSION, so `success` selects runs whose
#: CONCLUSION was green — a statement about the VERDICT, not about whether the schedule fired. This
#: check exits 1 on drift and 2 on infrastructure, so every run of a real incident is invisible
#: under `success`, and the first green run afterwards measures a span covering the whole incident
#: and announces that the schedule has been skipping when it never missed a beat — crying wolf
#: immediately after the arm's subject did the exact thing it was built to report.
#:
#: Dropping `status` altogether is not the fix either. With no filter the response also carries
#: `queued` and `in_progress` runs, which on a `schedule` trigger includes THIS run — so the
#: measurement would quietly mean one thing on a scheduled run and another on a `workflow_dispatch`
#: one. `completed` excludes the current run unconditionally, and that is what lets `now` be the
#: newest point rather than a tie with it.
HEARTBEAT_QUERY = "event=schedule&status=completed&per_page=5"

#: `[project].version` is the first `version = "..."` at column 0. Later tables are indented or come
#: after, and `grep -m1 '^version'` picks this same line — the rule `scripts/set_version.sh:46-50`
#: stamps by and `ci.yml:33` / `publish.yml:165` read by, so the three cannot drift apart.
PYPROJECT_VERSION = re.compile(r'^version = "([^"]+)"', re.MULTILINE)

#: A leading npm scope. Stripped for comparison, exactly as `yank.yml:75`'s `sub("^@[^/]+/"; "")`.
NPM_SCOPE = re.compile(r"^@[^/]+/")


class InfraError(RuntimeError):
    """A condition under which no verdict can be established. Always exit 2, never 1."""


def _git(repo: Path, *args: str) -> str:
    """Run git in `repo` and return stdout, stripped. Any failure is infrastructure."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise InfraError("`git` is not on PATH — cannot read the source tree") from exc
    except OSError as exc:
        # FileNotFoundError is only the spelling anyone thought of. Any other OSError — EAGAIN when
        # the machine cannot fork, EMFILE, a broken pipe — escaped to the top-level handler, which
        # correctly exits 2 but prints a traceback for a condition that has a one-line description.
        raise InfraError(f"could not run `git`: {exc}") from exc
    if proc.returncode != 0:
        raise InfraError(
            f"`git {' '.join(args)}` failed in {repo} (exit {proc.returncode}): "
            f"{proc.stderr.strip() or '<no stderr>'}"
        )
    return proc.stdout.strip()


def source_version(repo: Path) -> str:
    """The version `main` claims, cross-checked across both packages.

    A python/typescript mismatch is INFRASTRUCTURE, not drift. `ci.yml:23-38` (`version-lockstep`)
    makes it impossible on a green `main`, so if it happens the world is not the world this script
    models, and guessing a verdict there is what this whole file refuses to do.

    Only `FileNotFoundError` is caught. A missing file is an expected, nameable condition; anything
    else — a directory where a file should be, a permission error — is genuinely unexpected and
    belongs to the top-level handler, which reports it as 2 with a traceback rather than as a
    tidy-looking message that hides a bug in this script.
    """
    pyproject = repo / "python" / "pyproject.toml"
    package_json = repo / "ts" / "package.json"
    try:
        py_text = pyproject.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InfraError(f"{pyproject} does not exist — is --repo a seam-sdk checkout?") from exc
    try:
        ts_text = package_json.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InfraError(f"{package_json} does not exist — is --repo a seam-sdk checkout?") from exc

    matched = PYPROJECT_VERSION.search(py_text)
    if not matched:
        raise InfraError(f"no `version = \"...\"` at column 0 in {pyproject}")
    py_version = matched.group(1)

    try:
        ts_version = json.loads(ts_text).get("version")
    except json.JSONDecodeError as exc:
        raise InfraError(f"{package_json} is not valid JSON: {exc}") from exc
    if not ts_version:
        raise InfraError(f"{package_json} declares no `version`")

    if py_version != ts_version:
        raise InfraError(
            f"python ({py_version}) and typescript ({ts_version}) disagree on the version. "
            "`version-lockstep` (ci.yml:23-38) makes this impossible on a green main, so this is "
            "an infrastructure condition, not drift — there is no single version to check."
        )
    return py_version


def assert_query_safe(version: str) -> None:
    """Refuse a version that cannot be safely interpolated into the registry query string."""
    if not SAFE_VERSION.match(version):
        offending = sorted({ch for ch in version if not (ch.isdigit() or ch == ".")})
        rendered = ", ".join(repr(ch) for ch in offending) or "<empty>"
        raise InfraError(
            f"version {version!r} is not plain digits-and-dots (offending: {rendered}). It is "
            "interpolated into `?query=seam-sdk+version:<v>`, where `+` means space and `#`, `&` "
            "and `%` are structural, so a request built from it would silently ask a different "
            "question. Refusing to guess."
        )


def version_landed_at(repo: Path, version: str) -> datetime:
    """When `main` most recently started claiming this version.

    Content-derived (`git log -S`), not tag-derived, so it works identically in state B and state C
    — which is the entire reason this check is not keyed on the tag. `-S` takes a literal string by
    default (no `--pickaxe-regex`), so the dots in a version need no escaping.

    `-1` takes the most recent commit that changed the count, so a version reverted and then
    re-introduced dates from the re-introduction. That is correct: it is the moment `main` most
    recently began making this claim.
    """
    raw = _git(
        repo,
        "log",
        "-1",
        "--format=%cI",
        "-S",
        f'version = "{version}"',
        "--",
        "python/pyproject.toml",
    )
    if not raw:
        raise InfraError(
            f"cannot date version {version} on this checkout: no commit in the history of "
            "python/pyproject.toml introduces it. A shallow clone lands here — fetch with full "
            "history (`fetch-depth: 0`)."
        )
    return _parse_iso(raw, what=f"commit date for {version}")


def tag_created_at(repo: Path, version: str) -> datetime | None:
    """The tag's creator date, or None when there is no tag.

    These are annotated tags (`release-on-runtime.yml:182` uses `git tag -a`), so a creator date
    exists. Feeds the clock, never the verdict.
    """
    raw = _git(
        repo, "for-each-ref", "--format=%(creatordate:iso-strict)", f"refs/tags/v{version}"
    )
    if not raw:
        return None
    return _parse_iso(raw.splitlines()[0], what=f"tag date for v{version}")


def tag_present(repo: Path, version: str) -> bool:
    """Whether `v<version>` exists. DIAGNOSTIC ONLY — it selects remediation text, not the verdict.

    Guarded by a denominator floor. A checkout fetched without tags answers "no tag" for every
    version, which would make every single run print the state-C remediation with total confidence.
    Pinning the denominator is the same idiom the anti-vacuity floors in `scripts/test_ci_gate.py`
    use, applied at runtime.
    """
    all_tags = [t for t in _git(repo, "tag", "-l", "v*").splitlines() if t.strip()]
    if len(all_tags) < TAG_FLOOR:
        raise InfraError(
            f"`git tag -l 'v*'` returned {len(all_tags)} tags, below TAG_FLOOR={TAG_FLOOR} "
            "(measured 67 at f177cfb). This checkout was almost certainly fetched without tags, "
            "and every release would be misdiagnosed as 'tag push failed'. Fetch tags first."
        )
    return f"v{version}" in all_tags


def _parse_iso(raw: str, *, what: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise InfraError(f"cannot parse {what}: {raw!r}") from exc
    if parsed.tzinfo is None:
        raise InfraError(f"{what} carries no timezone: {raw!r}")
    return parsed.astimezone(timezone.utc)


def _seam_sdk_rows(rows: object) -> list[dict]:
    """Every `seam-sdk` row in a registry response, at any version, in any format."""
    if not isinstance(rows, list):
        raise InfraError(
            f"the registry response is a {type(rows).__name__}, not a list of packages. "
            "Cloudsmith's list endpoint returns a JSON array; anything else is an error body or a "
            "different endpoint."
        )
    matched: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            # The type only, never the row: a response is not ours to print, and a string row is
            # exactly the shape an echoed request header would take.
            raise InfraError(f"a registry row is a {type(row).__name__}, not an object")
        name = NPM_SCOPE.sub("", str(row.get("name", "")))
        if name == PACKAGE_NAME:
            matched.append(row)
    return matched


def registry_formats(rows: object, version: str) -> set[str]:
    """The formats serving `seam-sdk` at exactly `version`.

    Three clauses, each of which must hold: the version matches exactly, the format is one this
    release ships, and the name — with any leading `@scope/` stripped — is exactly `seam-sdk`. That
    last one is not decoration: `@zer07labs/seam-sdk-extra` must not satisfy `seam-sdk`. This is
    `yank.yml:73-76`'s jq filter, in Python so each clause can be driven red on its own.
    """
    return {
        str(row.get("format"))
        for row in _seam_sdk_rows(rows)
        if row.get("version") == version and row.get("format") in REQUIRED_FORMATS
    }


def assert_offline_instrument_healthy(rows: object, source: str) -> None:
    """A `--packages-json` response with no `seam-sdk` row in it is a broken instrument, not a lag.

    With no canary query available offline, the response is the only evidence that the query worked
    at all — so it has to carry some. A file that is empty, or full of unrelated packages, is not a
    plausible answer to a `seam-sdk` query, and reading it as "the registry does not have this
    version" is the confident-wrong-verdict failure this whole check exists to avoid. Exit 2.

    Deliberately NOT the live path's rule. There the query is scoped to one version, a real drift
    genuinely returns `[]`, and the positive control is a separate canary query on the same
    credential in the same run.
    """
    if not _seam_sdk_rows(rows):
        raise InfraError(
            f"{source} contains no `{PACKAGE_NAME}` package at any version. That is not a "
            "plausible response to a seam-sdk query — the query shape, the credential or the file "
            "is wrong. Refusing to report this as drift: an empty answer and a broken instrument "
            "must never look the same. If you captured this file with the check's own "
            "version-scoped query, that is the mistake: for a genuinely-absent version that "
            "response is legitimately `[]`, and offline it cannot be told apart from a query that "
            "failed. Re-capture without the `version:` qualifier."
        )


def registry_token() -> str:
    """The Cloudsmith credential, from the environment.

    Absent or empty is `InfraError`, exit 2 — a deliberate divergence from `yank.yml:61-63`, which
    exits 1. There, 1 means "refused". Here, 1 means "the registry is behind the source", and a
    missing secret must never be able to say that.
    """
    token = os.environ.get(TOKEN_ENV, "")
    if not token.strip():
        raise InfraError(
            f"{TOKEN_ENV} is unset or empty. The workflow resolves it from CLOUDSMITH_API_KEY "
            "with a CARGO_REGISTRIES_ZER07LABS_TOKEN fallback; if both are empty in this context "
            "the query cannot be made. Refusing rather than reporting an unqueried registry as "
            "behind the source."
        )
    # Returned stripped. Phase 5 resolves this from a secret in shell, where a trailing newline is
    # easy to carry in; it would build a malformed header — recoverable (curl errors, exit 2) but
    # pointlessly so.
    return token.strip()


def _query_for(version: str) -> str:
    """The query string, mirroring `yank.yml:70`. Safe to print — it carries no credential."""
    return f"?query={PACKAGE_NAME}+version:{version}&page_size={PAGE_SIZE}"


def registry_name(url: str) -> str:
    """The repository slug of a Cloudsmith list URL — `internal`, `partner`. For messages only."""
    return url.rstrip("/").rsplit("/", 1)[-1]


def _curl_json(url: str, query: str, token: str) -> object:
    """One GET, decoded and parsed. Every failure is an InfraError naming the registry and query.

    Shared by `fetch_registry` (one version) and `fetch_newest` (unscoped). Only the transport and
    the parse are shared: each caller keeps the guards that belong to ITS question on top, because
    the two answers have opposite shapes — a full page is a refusal for one and normal for the
    other.

    `curl`, not `urllib`, and that is not stylistic. This repo's hermeticity convention is stub
    executables first on `PATH` (`scripts/test_release_notice_gate.py:62-83`), with the rule "no
    mocks, no cassettes". `urllib` can only be controlled by monkeypatching, which would make this
    the one guard in the repo whose world is a mock. Shelling out also keeps the request
    byte-comparable to `yank.yml:69-71`.

    `-sf` matters: without `-f` a 401 or a 500 returns an error BODY with exit 0, and a body that
    is not a list of packages parses to "no rows" — which reads as drift. Every HTTP failure has
    to arrive as a non-zero exit.
    """
    where = registry_name(url)
    try:
        proc = subprocess.run(
            [
                "curl",
                "-sf",
                "--max-time",
                str(CURL_MAX_SECONDS),
                "-H",
                f"X-Api-Key: {token}",
                f"{url}{query}",
            ],
            capture_output=True,
            # `errors="replace"`: a body that is not UTF-8 must fail as "not JSON" below, an
            # InfraError naming the registry. Strict decoding raised UnicodeDecodeError instead,
            # whose repr carries the raw bytes, so a response quoting the request header would
            # reach a log through the error that reports it.
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise InfraError("`curl` is not on PATH — cannot query the registry") from exc
    except OSError as exc:
        # FileNotFoundError is only the spelling anyone thought of. Any other OSError — EAGAIN when
        # the machine cannot fork, EMFILE, a broken pipe — escaped to the top-level handler, which
        # correctly exits 2 but prints a traceback for a condition that has a one-line description.
        raise InfraError(f"could not run `curl`: {exc}") from exc
    if proc.returncode != 0:
        # Neither the argv nor stderr is echoed: the argv carries the credential, and curl's
        # stderr can quote the request. The exit status is the diagnosis (22 = HTTP >= 400,
        # 28 = timeout, 6 = DNS).
        raise InfraError(
            f"curl exited {proc.returncode} querying {where} {query} — the registry could not be "
            "read. "
            "22 is an HTTP error (a bad or unscoped credential lands here), 28 a timeout, 6 DNS. "
            "This is infrastructure: an unanswered query says nothing about what is published."
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise InfraError(f"the response from {where} to {query} is not JSON: {exc}") from exc


def fetch_registry(version: str, token: str, url: str = REGISTRY_URL) -> object:
    """GET the rows for one version from one Cloudsmith repository, through `_curl_json`, and
    refuse an answer that cannot have been scoped to that version."""
    query = _query_for(version)
    where = registry_name(url)
    rows = _curl_json(url, query, token)
    if isinstance(rows, list) and len(rows) == PAGE_SIZE:
        raise InfraError(
            f"the response from {where} to {query} carries exactly {PAGE_SIZE} rows, which is the "
            "page size. "
            "Treat that as evidence the `version:` qualifier was IGNORED and a first page of "
            "everything came back: a target version outside that page would read as absent, and "
            "the run would report drift for a published version. Raise page_size, or stop "
            "trusting the qualifier."
        )
    # The server-side positive control, and the ONLY check here that can observe the `version:`
    # qualifier actually being applied. Everything else re-filters client-side — `registry_formats`
    # applies `.version == version` again (see it below) — which is what makes an over-inclusive
    # response harmless, and is also exactly what LAUNDERS a filter that was never applied. The
    # truncation guard above catches the ignored-qualifier case only when the response comes back
    # at exactly PAGE_SIZE; a server that caps pages BELOW 50 makes that equality permanently
    # silent, and then a target outside the window reads as absent and exits 1 for a published
    # version. "Rows came back, none at the version I asked for" is a statement about the SERVER
    # that no client-side filter can restate.
    #
    # It cannot misfire in a working world: a correctly-filtered response carries only `version`,
    # and a genuine drift — or a yanked canary — returns zero seam-sdk rows, so `present` is empty
    # and this is silent. If it ever does fire, the message carries the versions that came back,
    # which is precisely the observation needed to settle the question, delivered as exit 2 and
    # never as a verdict.
    matched = _seam_sdk_rows(rows)
    if matched and not any(row.get("version") == version for row in matched):
        # Only values that ARE versions are echoed. The versions are the diagnosis, but they are
        # response content, and a field that does not look like a version is counted, not printed.
        seen = {str(row.get("version")) for row in matched}
        present = sorted(v for v in seen if SAFE_VERSION.match(v))
        withheld = len(seen) - len(present)
        listed = ", ".join(present[:5]) + (" and others" if len(present) > 5 else "")
        if withheld:
            listed = (listed + " and " if listed else "") + f"{withheld} non-version value(s)"
        raise InfraError(
            f"the response from {where} to {query} carries {len(matched)} `{PACKAGE_NAME}` rows — at "
            f"{listed} — and NONE at "
            f"{version}. A query scoped to one version cannot answer with other versions, so the "
            "`version:` qualifier was not applied and this response is a window over everything. "
            "The absence of the asked-for version from it is not evidence of anything. "
            "Infrastructure, never drift."
        )
    return rows


def assert_live_instrument_healthy(target: str, token: str, url: str = REGISTRY_URL) -> str:
    """Prove the query works before believing anything it says about the target. Returns the
    canary that answered.

    This is the runtime form of the repo's "pin the denominator" idiom. Without it EVERY failure
    of the query surface reads as drift, which is the worst outcome available here — a confident
    wrong verdict. It runs FIRST so no code path can interpret a target result against an
    unproven instrument.

    Healthy if ANY candidate returns both formats; unhealthy only if all of them come back short.
    That is what survives an individual yank, and it is why this is a roster rather than a pin.
    """
    for entry in CANARY_VERSIONS:
        # The roster reaches the SAME interpolation as the source version, via `_query_for`, and
        # only the source version was ever checked. A hand-edited constant is a narrow threat, but
        # this constant's own comment says values of this class must be validated, and an entry
        # carrying `&` would append a parameter to the request rather than fail.
        assert_query_safe(entry)
    candidates = [v for v in CANARY_VERSIONS if v != target]
    if not candidates:
        raise InfraError(
            f"every entry in CANARY_VERSIONS equals the target version {target}, so there is no "
            "independent probe left. A canary that IS the target cannot distinguish a broken "
            "query from a real lag. Add a published version to the roster."
        )
    tried: list[str] = []
    for candidate in candidates:
        formats = registry_formats(fetch_registry(candidate, token, url), candidate)
        tried.append(f"{candidate} -> {', '.join(sorted(formats)) or 'nothing'}")
        if set(REQUIRED_FORMATS) <= formats:
            return candidate
    raise InfraError(
        f"the {registry_name(url)} registry query returned nothing usable for any canary "
        "version ("
        + "; ".join(tried)
        + "). Either the query shape is wrong, or every canary has been yanked and "
        "CANARY_VERSIONS needs re-pointing. Refusing to read the target's answer through an "
        "instrument that has not been shown to work."
    )


# ── the newest version on internal (seam-sdk#253) ─────────────────────────────────────────────
#
# The declared-version question above cannot see a release that `main` has already moved past: if
# 0.45.0 landed on internal and never reached partner, and `main` now declares 0.45.1, nothing
# above ever asks partner about 0.45.0. So one more question is asked: what is the NEWEST version
# internal serves in both formats, and does partner serve that one too?
#
# Only the newest, by the owner's decision (D6). A short-lived version that fails promotion and is
# superseded inside the hard window is never newest-past-the-window, so it is never reported. That
# residual is recorded rather than covered.


def _plain(value: object) -> str | None:
    """`value` if it is a plain digits-and-dots version, else None.

    `fullmatch`, not `SAFE_VERSION.match`: `$` matches before a trailing newline, so `match`
    accepts `"0.45.0\\n"`. Every value this returns may be PRINTED — D8 lets only versions out of a
    response — so it has to be exactly a version and nothing else.
    """
    if isinstance(value, str) and SAFE_VERSION.fullmatch(value):
        return value
    return None


def _version_key(version: str) -> tuple[int, ...]:
    """Numeric order, the order `sort=-version` was observed to use. `0.10.0` > `0.9.0`."""
    return tuple(int(part) for part in version.split("."))


def newest_complete_version(rows: object, *, exclude: str | None = None) -> tuple[str | None, int]:
    """The largest plain version whose `seam-sdk` rows carry every REQUIRED_FORMAT, and how many
    distinct non-plain version values were set aside.

    Pure, and deliberately ORDER-BLIND: it takes the max, so a shuffled offline dump gives the same
    answer as a sorted one. The order of a LIVE response is a separate claim, checked separately in
    `fetch_newest`, where it is a statement about the server rather than about the data.

    "Complete" rather than "present" because half a release is not a release a partner could have
    been given: a version with only its wheel uploaded is the declared question's business while it
    is declared, and is no one's "newest".

    Non-plain versions — a pre-release, an empty field, a field that is not a version at all — are
    COUNTED, never returned and never printed. None were observed on 2026-10-12, so the count is
    there to make the first one visible rather than to describe today.

    `exclude` is the page-edge rule's hook: one version that may not be chosen. See `fetch_newest`.
    """
    formats: dict[str, set[str]] = {}
    withheld: set[str] = set()
    for row in _seam_sdk_rows(rows):
        version = _plain(row.get("version"))
        if version is None:
            # Counted by a hashable stand-in, never kept for output: the value is response content.
            withheld.add(repr(row.get("version")))
            continue
        if row.get("format") in REQUIRED_FORMATS:
            formats.setdefault(version, set()).add(str(row.get("format")))
    complete = [
        v for v, found in formats.items() if set(REQUIRED_FORMATS) <= found and v != exclude
    ]
    return (max(complete, key=_version_key) if complete else None), len(withheld)


def fetch_newest(token: str, *, proved_by: str, declared: str | None) -> tuple[str, object, int]:
    """GET internal's newest `seam-sdk` rows and prove the answer before using it.

    Returns `(newest complete version, the rows, non-plain count)`. The rows come back because the
    newest question's clock is read out of them (`newest_upload_clock`) — the same response, so the
    clock and the version cannot describe two different moments.

    `proved_by` is the canary that proved INTERNAL's instrument this run; `declared` is main's
    version when internal serves it in both formats, else None. Each guard below is an InfraError,
    so a failure here is exit 2 and never a verdict. None of them can fire in the world observed on
    2026-10-12; each is the cheapest statement that the world still is that one.

    1. **Some `seam-sdk` row came back.** `[]` from an unscoped query is not "nothing is
       published" — the canary just proved a published version exists. It is a broken query.
    2. **The order is non-increasing.** `sort=-version` is what makes "the first page" mean "the
       newest versions". A wrong parameter NAME is silently ignored by the server (observed:
       `ordering=` falls back to `-date`), and a page sorted by date would still usually put the
       newest version first — until a re-upload or a backfill of an old version lands, at which
       point the "newest" is whatever was touched last. Checked over every row with a plain
       version, whatever package it belongs to, because the sort is over the whole response.
    3. **Page edge.** On a FULL page the lowest version on it may continue onto the next page, so
       its rows here may be a subset — a version that looks complete may have been cut, and one
       that looks incomplete may not be. That version is never chosen. A full page of ONE version
       therefore has no candidate at all, which is correct: it says nothing about which version is
       newest.
    4. **At least the proving canary.** The canary is, by definition, published in both formats,
       and it was read on this credential in this run. A "newest" below it means the response is
       not the top of the list.
    5. **At least the declared version, when internal serves it.** Same argument, with the
       target's own answer from a few seconds ago as the floor.
    """
    raw = _curl_json(REGISTRY_URL, NEWEST_QUERY, token)
    if not _seam_sdk_rows(raw):
        raise InfraError(
            f"the response from internal to {NEWEST_QUERY} carries no `{PACKAGE_NAME}` row. The "
            f"canary {proved_by} was read from internal moments ago, so an unscoped query cannot "
            "honestly answer with nothing. The query shape or the response is wrong."
        )
    assert isinstance(raw, list)  # `_seam_sdk_rows` refused anything else
    plain = [v for v in (_plain(row.get("version")) for row in raw) if v is not None]
    for higher, lower in zip(plain, plain[1:]):
        if _version_key(lower) > _version_key(higher):
            # Both are plain versions, so both may be printed — they ARE the diagnosis.
            raise InfraError(
                f"the response from internal to {NEWEST_QUERY} is not in descending version "
                f"order ({higher} is followed by {lower}). `sort=-version` was not applied, so "
                "the top of this page is not the newest release. A misspelt sort parameter is "
                "silently ignored by Cloudsmith, which falls back to upload date."
            )
    # `>=`, not `==`: more rows than were asked for means `page_size` itself was ignored, and a
    # response cut at some OTHER size is just as able to split its lowest version. Only a response
    # shorter than the page is known to be the whole list.
    edge = plain[-1] if len(raw) >= PAGE_SIZE and plain else None
    newest, withheld = newest_complete_version(raw, exclude=edge)
    if newest is None:
        raise InfraError(
            f"the response from internal to {NEWEST_QUERY} carries no plain version in both "
            f"formats"
            + (
                f" above the page edge ({edge} is the lowest version on a full page, so its rows "
                "may continue onto the next page and it is never chosen)"
                if edge
                else ""
            )
            + ". There is no newest release to ask partner about."
        )
    if _version_key(newest) < _version_key(proved_by):
        raise InfraError(
            f"the newest complete version in the response from internal to {NEWEST_QUERY} is "
            f"{newest}, below the canary {proved_by} that proved internal this run. The response "
            "is not the top of the list."
        )
    if declared is not None and _version_key(newest) < _version_key(declared):
        raise InfraError(
            f"the newest complete version in the response from internal to {NEWEST_QUERY} is "
            f"{newest}, below {declared}, which internal served in both formats moments ago. The "
            "response is not the top of the list."
        )
    return newest, raw, withheld


def _parse_upload_stamp(value: object) -> datetime:
    """One `uploaded_at`, as an aware UTC datetime. It NEVER prints the value it was given.

    This is response content, and D8 lets no response field but a version reach the output: a
    field echoed in an error is exactly how a body quoting the request header would reach a log.
    So every refusal names the TYPE, or says "not a timestamp", and stops there — including the
    `ValueError` from `fromisoformat` on a well-shaped impossible date (month 13), whose message
    would quote the string, and which is therefore not chained.
    """
    if not isinstance(value, str):
        raise InfraError(
            f"an `uploaded_at` on internal is a {type(value).__name__}, not a timestamp string. "
            "The newest version's clock cannot be read."
        )
    if not UPLOAD_STAMP.fullmatch(value):
        raise InfraError(
            "an `uploaded_at` on internal is not an ISO-8601 timestamp (value withheld). The "
            "newest version's clock cannot be read."
        )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        parsed = None
    if parsed is None:
        raise InfraError(
            "an `uploaded_at` on internal has the shape of a timestamp but is not a real instant "
            "(value withheld). The newest version's clock cannot be read."
        )
    return parsed.astimezone(timezone.utc)


def newest_upload_clock(rows: object, version: str) -> datetime:
    """When the newest version finished landing on internal: the LATEST `uploaded_at` among its
    rows in the required formats.

    The latest, not the earliest: the release is complete only when its last format lands, and
    `promote-partner` cannot start before that. Every such row must carry a readable stamp — one
    unreadable stamp is a clock that cannot be trusted, not one to skip.

    This clock and the declared question's are different on purpose. `main`'s git dates say when
    `main` began claiming a version; they say nothing about a version `main` has moved past. The
    upload is the event `promote-partner` follows, on the same soft and hard windows.
    """
    stamps = [
        _parse_upload_stamp(row.get("uploaded_at"))
        for row in _seam_sdk_rows(rows)
        if row.get("version") == version and row.get("format") in REQUIRED_FORMATS
    ]
    if not stamps:
        raise InfraError(f"no row for {version} on internal carries an `uploaded_at`")
    return max(stamps)


def _load_packages_json(path: Path, flag: str = "--packages-json") -> object:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InfraError(f"{flag} {path} does not exist") from exc
    except OSError as exc:
        raise InfraError(f"{flag} {path} cannot be read: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InfraError(f"{flag} {path} is not valid JSON: {exc}") from exc


def _remediation(version: str, tagged: bool, missing: set[str]) -> str:
    formats = ", ".join(sorted(missing))
    if tagged:
        return (
            f"State B — the tag v{version} EXISTS but the registry does not serve {formats}.\n"
            f"  A publish was attempted and did not land. Look at publish.yml's runs for "
            f"v{version}; `release-outcome` should also have filed an issue, and its silence is "
            f"itself a finding.\n"
            f"  Re-run the publish, or delete and re-push the tag to trigger it again."
        )
    return (
        f"State C — main claims {version} but the tag v{version} DOES NOT EXIST, and the registry "
        f"does not serve {formats}.\n"
        f"  release-on-runtime.yml:180-187 pushes the version commit BEFORE creating and pushing "
        f"the tags, so the commit landing without the tag means the tag step failed. No publish "
        f"was ever triggered, and nothing inside publish.yml can report that.\n"
        f"  Create and push the tags for v{version} (`v{version}` and `go/v{version}`, same "
        f"commit) to trigger the publish."
    )


def _partner_remediation(version: str, missing: set[str]) -> str:
    formats = ", ".join(sorted(missing))
    return (
        f"State P — internal serves {version} in both formats, but `partner` does not serve "
        f"{formats}. A design partner cannot install this release.\n"
        f"  `publish.yml`'s `promote-partner` job copies a release into partner only after "
        f"`registry-smoke` passes, so FIRST confirm that `registry-smoke` was green for "
        f"v{version}: if it was not, the release is broken and must not be promoted — and "
        f"neither tool below re-checks it.\n"
        f"  If it was green, the promotion itself failed (an expired CLOUDSMITH_PARTNER_API_KEY, "
        f"a Cloudsmith outage). Dispatch `promote-partner-backfill.yml` with version={version}, "
        f"or run `./scripts/promote-to-partner.sh {version}` — both check the destination before "
        f"copying, so a re-run is safe."
    )


def _tier(age_minutes: float, soft: int, hard: int) -> str:
    """Which rung of the grace ladder an attempt this old stands on. One ladder, both registries."""
    if age_minutes < soft:
        return "deferred"
    if age_minutes < hard:
        return "warned"
    return "drift"


def _with_newest(code: int, newest_verdict: str | None, newest_error: InfraError | None) -> int:
    """Fold the newest-version question into the declared question's FINAL exit code (D3).

        newest question        declared question                 exit
        drift                  any                               1
        fault                  unsuppressed drift (code 1)       1, with the ::error:: printed
        fault                  clean, grace or suppressed        2
        anything else          —                                 the declared code, unchanged

    A fault keeps a declared drift's 1 for the same reason a partner fault does: the finding is
    real whatever this question's instrument is doing, and turning it into a 2 would hide it. With
    no finding beside it, an unanswerable question is infrastructure, and a green job would make it
    a footnote. `code` 1 means an unsuppressed declared drift and nothing else — both declared
    subjects reach 1 only through a drift tier, and a suppression has already set it to 0.

    `code` 2 arrives from exactly ONE caller, deliberately: `main`'s declared-clock fault path,
    where git could not date the declared version but the newest question had already been
    answered on its own (upload) clock. There a newest drift → 1 (a real finding, which a 2 would
    hide) and a newest fault or no finding → 2. Every other exit-2 path returns WITHOUT calling
    this, because it fires before the newest question has run; one that newly reaches this with 2
    must decide the same thing on purpose, not inherit it.
    """
    if newest_error is not None:
        return 1 if code == 1 else 2
    if newest_verdict == "drift":
        return 1
    return code


def issue_repo() -> str:
    """`owner/name` for the `gh` calls, from the environment rather than from git remotes.

    Deriving it from the checkout would make the reporting target depend on how the checkout was
    made — a fork, a mirror, a `ref:` override — and file issues wherever that pointed. The
    workflow passes `${{ github.repository }}`, which is what the run is actually about.
    """
    repo = os.environ.get(REPO_ENV, "").strip()
    if not repo:
        raise InfraError(
            f"--report needs ${REPO_ENV} (owner/name) and it is unset or empty. Refusing to guess "
            "the repository to file against."
        )
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise InfraError(f"${REPO_ENV} is {repo!r}, which is not `owner/name`.")
    return repo


def _gh(args: list[str], repo: str, *, repo_flag: bool = True) -> str:
    """One `gh` call. Every failure is infrastructure — never a verdict.

    `repo_flag=False` for `gh api`, which has no `--repo` and exits 1 on an unknown flag. The
    repository goes into the API path instead. It stays the same helper rather than growing a
    second one so that every `gh` invocation keeps one timeout, one failure translation, and one
    argv shape — and so the permissions guard, which reads argv literals handed to `_gh`, keeps
    seeing all of them.

    `capture_output` rather than `publish.yml:818-823`'s write-to-a-file-first. That file exists to
    dodge a shell hazard this is not exposed to: `gh … | reader` under `set -o pipefail`, where a
    reader exiting early turns a SIGPIPE into a job failure. There is no pipe here; Python reads
    the child's stdout to EOF.
    """
    try:
        proc = subprocess.run(
            ["gh", *args, *(["--repo", repo] if repo_flag else [])],
            capture_output=True,
            text=True,
            timeout=GH_MAX_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise InfraError("`gh` is not on PATH — cannot report") from exc
    except OSError as exc:
        # FileNotFoundError is only the spelling anyone thought of. Any other OSError — EAGAIN when
        # the machine cannot fork, EMFILE, a broken pipe — escaped to the top-level handler, which
        # correctly exits 2 but prints a traceback for a condition that has a one-line description.
        raise InfraError(f"could not run `gh`: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise InfraError(f"`gh {args[0]} {args[1]}` timed out after {GH_MAX_SECONDS}s") from exc
    if proc.returncode != 0:
        # `gh`'s stderr is echoed: unlike the registry call, nothing secret is passed to it. The
        # token is `GH_TOKEN` in the environment, which `gh` does not print.
        raise InfraError(
            f"`gh {' '.join(args[:2])}` exited {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc.stdout


def fetch_issues(repo: str) -> list[dict]:
    """Every issue, open and closed, as `{number, state, labels, title}`.

    ONE listing serves three questions — this version's drift issue, whether it is suppressed, and
    whether `release-outcome` has an open issue to cross-link — and that is only safe because every
    match below is exact title equality. A substring or prefix match over one listing would let any
    of the three answer for another.
    """
    raw = _gh(
        [
            "issue",
            "list",
            "--state",
            "all",
            "--limit",
            str(ISSUE_LIMIT),
            "--json",
            "number,state,title,labels",
            "--jq",
            # UNIT SEPARATOR, not a comma. GitHub permits a comma inside a label NAME, so
            # join(",") makes `foo,deliberately-unpublished` split into two labels, one of
            # which equals the suppression label exactly — silently suppressing a real
            # drift on an issue nobody ever labelled as suppressed. U+001F cannot be typed
            # into a label name, and @tsv passes it through untouched.
            _ISSUE_LIST_JQ,
        ],
        repo,
    )
    issues = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        # maxsplit=3 so a title containing a tab stays whole rather than losing its tail.
        fields = line.split("\t", 3)
        if len(fields) != 4:
            raise InfraError(f"unreadable row from `gh issue list`: {line!r}")
        number, state, labels, title = fields
        if not number.isdigit():
            raise InfraError(f"`gh issue list` returned a non-numeric issue number: {line!r}")
        issues.append(
            {
                "number": int(number),
                "state": state.strip().upper(),
                "labels": [name for name in labels.split(LABEL_SEP) if name],
                "title": title,
            }
        )
    if len(issues) == ISSUE_LIMIT:
        # Pinning the denominator: at exactly the limit the listing may be a window rather than the
        # whole set, and "no existing issue" would then mean "none in the part I could see".
        print(
            f"::warning::the issue listing came back at exactly --limit {ISSUE_LIMIT}, so it may "
            f"be truncated. An existing drift issue outside the window would be reported as a new "
            f"one. Raise ISSUE_LIMIT."
        )
    return issues


def _exact(issues: list[dict], title: str) -> dict | None:
    """The one issue whose title is EXACTLY this, or None.

    Exact equality, mirroring `publish.yml:824`'s `awk -F'\t' '$2 == t'`. An issue whose title
    merely CONTAINS the drift title — a discussion thread quoting it, say — must not be mistaken
    for the report, or closing that thread with the label would suppress a real drift.
    """
    for issue in issues:
        if issue["title"] == title:
            return issue
    return None


def _partner_cell(
    partner_missing: set[str] | None, missing: set[str], *, partner_unreadable: bool = False
) -> str:
    """Partner's state, for the INTERNAL issue's table. Never blank: blank reads as fine.

    It states only what this run observed. A partner that was queried and failed is "could not be
    read", never "not checked" — the second is reserved for an offline run that never asked. And
    "expected" is claimed only for formats internal is missing too: a format internal SERVES and
    partner does not is a promotion lag of its own, not a consequence of this issue.
    """
    if partner_unreadable:
        return "**could not be read** this run (see the run log)"
    if partner_missing is None:
        return "not checked"
    if not partner_missing:
        return "serves it"
    cell = f"also missing {', '.join(sorted(partner_missing))}"
    own = partner_missing - missing
    if not own:
        return f"{cell} (promotion copies from internal, so expected)"
    return f"{cell} — {', '.join(sorted(own))} is served by internal, so that is a promotion lag too"


def _issue_body(
    version: str,
    tagged: bool,
    missing: set[str],
    age_minutes: float,
    cross_link: dict | None,
    *,
    subject: str = "internal",
    partner_missing: set[str] | None = None,
    partner_unreadable: bool = False,
    question: str = "declared",
    declared: str | None = None,
) -> str:
    """The issue body. `question` says which of the run's questions found this (D4): one title per
    missing version, `PARTNER_DRIFT_TITLE`, whichever question finds it — so the BODY is where a
    reader learns whether `main` still declares this version or has moved past it, and those call
    for different urgency. `declared` is main's version, named in a newest-question lede."""
    formats = ", ".join(sorted(missing))
    age_label = "age of the release attempt"
    if subject == "partner" and question == "newest":
        lede = (
            f"`zer07labs/internal`'s newest release is **{version}**, and it serves it in both "
            f"formats; `zer07labs/partner` — the repository design partners install from — does "
            f"not. `python/pyproject.toml` declares **{declared}**, so the declared-version check "
            f"never asks partner about {version}: this was found by the newest-version check."
        )
        where_row = (
            "| registry | `zer07labs/partner` (internal is complete) |\n"
            f"| found by | the newest-version check (main declares `{declared}`) |"
        )
        # The upload clock, not git: main's dates say nothing about a version it has moved past.
        age_label = "time since it finished uploading to internal"
        remediation = _partner_remediation(version, missing)
    elif subject == "partner":
        lede = (
            f"`python/pyproject.toml` declares **{version}**. `zer07labs/internal` serves it in "
            f"both formats; `zer07labs/partner` — the repository design partners install from — "
            f"does not."
        )
        where_row = (
            "| registry | `zer07labs/partner` (internal is complete) |\n"
            "| found by | the declared-version check |"
        )
        remediation = _partner_remediation(version, missing)
    else:
        lede = f"`python/pyproject.toml` declares **{version}**, and the registry does not serve it."
        where_row = (
            f"| `zer07labs/partner` | "
            f"{_partner_cell(partner_missing, missing, partner_unreadable=partner_unreadable)} |"
        )
        remediation = _remediation(version, tagged, missing)
    lines = [
        lede,
        "",
        "| | |",
        "|---|---|",
        f"| version | `{version}` |",
        f"| missing formats | {formats} |",
        f"| packages | `{PACKAGE_NAME}` (python), `@zer07labs/{PACKAGE_NAME}` (npm) |",
        f"| tag `v{version}` | {'present' if tagged else '**absent**'} |",
        where_row,
        f"| {age_label} | {age_minutes:.0f} minutes |",
        "",
        remediation,
        "",
    ]
    if cross_link:
        lines += [
            f"`release-outcome` also reported this release: #{cross_link['number']}. That issue is "
            f"about the publish RUN; this one is about the registry's state, which stays true "
            f"across re-runs.",
            "",
        ]
    lines += [
        "---",
        "",
        "**This issue does not close itself.** The check only ever adds: it files, comments and "
        "reopens, and never closes. A reporter that can silence itself is a larger authority than "
        "one that can only speak.",
        "",
        "**A re-detection will not comment while this is open.** The check runs every two hours; "
        "re-detecting the same drift is not new information, and a comment per run is how a "
        "reporter gets muted.",
        "",
        f"**If {version} is deliberately staying unpublished**, close this issue AND label it "
        f"`{SUPPRESSION_LABEL}`. Both, and on this issue — that is the suppression path, and it is "
        f"scoped to this version alone. Every suppressed run still prints a `::warning::` naming "
        f"this issue, so a suppression that has outlived its reason stays visible.",
    ]
    return "\n".join(lines)


def report_drift(
    version: str,
    tagged: bool,
    missing: set[str],
    age_minutes: float,
    *,
    issues: list[dict],
    repo: str,
    subject: str = "internal",
    partner_missing: set[str] | None = None,
    partner_unreadable: bool = False,
    question: str = "declared",
    declared: str | None = None,
) -> bool:
    """File, comment, reopen — or recognise a suppression. Returns True if suppressed.

    `issues` is the run's ONE listing, fetched by `main` and handed to every question that reaches
    GitHub (seam-sdk#253): a run can now file for two versions, and two listings could disagree
    about a repository state that never existed at one moment. Every match below is exact title
    equality, which is what makes one listing safe to share.

    The decision table, and note that only the last row changes the exit code:

        no issue                        -> create                      exit 1
        open issue                      -> nothing; it already says so  exit 1
        closed, unlabelled              -> reopen + comment            exit 1
        closed, labelled                -> a ::warning:: naming it     exit 0
    """
    title = (PARTNER_DRIFT_TITLE if subject == "partner" else DRIFT_TITLE).format(version=version)
    existing = _exact(issues, title)
    what = "Partner" if subject == "partner" else "The registry"

    def body_for(cross_link: dict | None) -> str:
        return _issue_body(
            version,
            tagged,
            missing,
            age_minutes,
            cross_link,
            subject=subject,
            partner_missing=partner_missing,
            partner_unreadable=partner_unreadable,
            question=question,
            declared=declared,
        )

    if subject == "partner":
        # Internal serves this version — that is what made this a partner lag. An internal issue
        # still open for it can be closed, and `report_clean` will not say so while partner lags,
        # because this run's verdict is not clean. Same listing, no second read.
        stale = _exact(issues, DRIFT_TITLE.format(version=version))
        if stale and stale["state"] == "OPEN":
            print(
                f"::notice::#{stale['number']} reports drift on {version}, but internal now "
                f"serves it in both formats. That issue can be closed. This check never closes "
                f"one."
            )

    if existing is None:
        # The cross-link matters MORE for a partner lag, not less: `release-outcome` filing for
        # this tag is the signal that `registry-smoke` may have failed, which is exactly when the
        # State P remediation says not to promote.
        cross_link = _exact(issues, RELEASE_NOTICE_TITLE.format(version=version))
        if cross_link and cross_link["state"] != "OPEN":
            cross_link = None
        body = body_for(cross_link)
        _gh(["issue", "create", "--title", title, "--body", body], repo)
        print(f"filed a new drift issue: {title}")
        return False

    if existing["state"] == "OPEN":
        print(f"drift already reported on #{existing['number']} — not commenting again")
        return False

    if SUPPRESSION_LABEL in existing["labels"]:
        # A ::warning::, not a print. The staleness here is symmetric with the curated-file design
        # this was chosen over: if `main` ever returns to this version, a closed labelled issue
        # suppresses just as permanently and just as silently. The warning is what makes that
        # visible in every run summary rather than only in stdout nobody opens.
        print(
            f"::warning::drift on {version} is SUPPRESSED by #{existing['number']}, which is "
            f"closed and labelled `{SUPPRESSION_LABEL}`. {what} still does not serve "
            f"{', '.join(sorted(missing))}. Reopen or unlabel that issue to hear about this again."
        )
        return True

    # COMMENT FIRST, THEN REOPEN. The pair is not atomic and the order decides what a failure
    # between the two costs. Reopening first and failing on the comment leaves the issue OPEN and
    # uncommented — and every later run then takes the `state == "OPEN"` row above ("already
    # reported"), so the "the drift is back" record is never written by any run, ever. Nothing
    # retries it, because nothing can tell that state apart from a normal open report.
    #
    # This order strands nothing: a comment on a CLOSED issue is legal and harmless, so if the
    # reopen then fails the next run still sees CLOSED-and-unlabelled and retries the whole pair.
    # The cost of a failure here is a duplicate comment, which is noise; the other order's cost is
    # silence, which is the thing this check exists to prevent.
    _gh(
        [
            "issue",
            "comment",
            str(existing["number"]),
            "--body",
            body_for(None),
        ],
        repo,
    )
    _gh(["issue", "reopen", str(existing["number"])], repo)
    print(f"commented on and reopened #{existing['number']} — the drift is back")
    return False


def cron_period_minutes(spec: str | None = None) -> int | None:
    """The largest gap between consecutive firings, or `None` if there is no fixed sub-daily one.

    ONE implementation, here, driven by the test suite rather than mirrored in it. Phase 5 grew a
    parser of this shape inside `scripts/test_registry_drift_gate.py` to check that the cron cannot
    step over the warn band; Phase 7 needs the same number at RUNTIME to derive its staleness
    threshold. Writing a second one would have put two readings of the same string in two files,
    free to disagree — and the disagreement would surface as a staleness warning that fires
    constantly or never, both of which end in it being muted. The test now imports this function,
    so its parametrised cases drive the code that actually runs.

    Reading the hour field alone is what let `17 */2 * * 1` through — a weekly cadence wearing a
    two-hourly hour field. So day-of-month, month and day-of-week must all be `*` before the hour
    field means anything at all.

    `*/N` and `A-B/N` are both accepted: `17 1-23/2 * * *` is a correct every-two-hours spelling and
    rejecting it would be a guard enforcing a preferred syntax rather than a property. An explicit
    list (`17 0,12 * * *`) is read as the largest gap between its entries, wrapping at midnight —
    0 and 12 is a twelve-hour period, not a two-hour one.

    `None` rather than an exception: the caller is a warnings-only arm that must never raise, and a
    cron this cannot read is a reason to say so and stop, not to fail a run about the registry.
    """
    # `CRON` is read HERE rather than bound as a default argument. A default is evaluated once, at
    # def time, which would make the constant unpatchable — and therefore make "the threshold is
    # derived from the cron" an untestable claim: a hardcoded 360 satisfies
    # `threshold == period * MULTIPLIER` for as long as the shipped cron happens to be two-hourly.
    # Reading the global lets the test move the cron and watch the threshold follow.
    spec = CRON if spec is None else spec
    fields = spec.split()
    if len(fields) != 5:
        return None
    minute, hours, dom, month, dow = fields
    if (dom, month, dow) != ("*", "*", "*") or not minute.isdigit():
        return None
    if hours == "*":
        return 60
    step_form = re.fullmatch(r"(?:\*|(\d+)-(\d+))/(\d+)", hours)
    if step_form:
        low, high, step = step_form.groups()
        if int(step) == 0:
            return None
        first, last = (int(low), int(high)) if low else (0, 23)
        runs = list(range(first, last + 1, int(step)))
    elif re.fullmatch(r"\d+(?:,\d+)*", hours):
        runs = sorted(int(h) for h in hours.split(","))
    else:
        return None
    if not runs:
        return None
    if len(runs) == 1:
        return 24 * 60
    gaps = [(b - a) * 60 for a, b in zip(runs, runs[1:])]
    gaps.append((runs[0] + 24 - runs[-1]) * 60)  # the wrap past midnight
    return max(gaps)


def staleness_threshold_minutes() -> int | None:
    """How long a SILENCE since the newest COMPLETED scheduled run is worth saying out loud.

    Not "a gap between successful runs" — that was the pre-Phase-7 measurement and both halves of
    it changed. `success` filtered on the VERDICT, so a drift run (exit 1) was invisible; and a gap
    between two past points cannot see a schedule that stopped and never resumed. This docstring
    described the old behaviour for one commit while sitting on the function that produces the
    number, which is the most misleading place for it to be wrong.

    DERIVED, never written down beside the cron as a second number. A hardcoded "360 minutes" goes
    on agreeing with itself after the cron moves to twelve hours, at which point the warning fires
    on every normal run and gets muted — the guard still present, still green, and no longer
    describing anything.
    """
    period = cron_period_minutes()
    return None if period is None else period * STALENESS_MULTIPLIER


def _staleness_heartbeat(now: datetime) -> None:
    """The body of the heartbeat. Warnings only; `warn_if_schedule_is_stale` owns the guarantee.

    A scheduled check can stop existing without anyone noticing — the same class of failure it was
    built to catch, one level up. GitHub drops scheduled runs under load, and the observable signal
    is SILENCE: the newest completed scheduled run is further in the past than the schedule can
    explain.

    **This function cannot change the exit code, and that is a category rule rather than a
    convenience.** A failure here says the watcher could not check on itself; it says nothing about
    whether the registry serves the version. Letting it vote would be exactly the error
    `scripts/probe_framework_coinstall.py:168-170` names — an instrument's own health reported as a
    finding about the thing it measures. Every failure path below is a `::warning::` and a return,
    and the wrapper catches anything that finds a way around them.

    `issue_repo()` is resolved INSIDE this try rather than passed in. Evaluated at the call site it
    sat outside every handler, so an unset `$REPO` — already softened to a warning by `report_clean`
    eleven lines earlier — came back as a traceback and exit 2 on a run that had just PROVED the
    registry healthy. An argument list is the one place a warnings-only arm can still raise.

    `workflow_dispatch` runs are excluded from the HISTORY by the query. Including them would let a
    burst of manual runs — which is what someone does while investigating a dead schedule — mask
    the dead schedule. `now` is this run's own clock whatever triggered it, and that asymmetry is
    the point: a human pressing "Run workflow" because they suspect silence is precisely who needs
    the answer, and a history of past runs alone cannot give it to them.
    """
    try:
        repo = issue_repo()
        raw = _gh(
            [
                "api",
                f"repos/{repo}/actions/workflows/{WORKFLOW_FILENAME}/runs?{HEARTBEAT_QUERY}",
                "--jq",
                ".workflow_runs[].created_at",
            ],
            repo,
            repo_flag=False,
        )
    except InfraError as exc:
        print(f"::warning::could not read this workflow's own run history: {exc}")
        return

    stamps = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            stamps.append(_parse_iso(line, what="a workflow run's created_at"))
        except InfraError as exc:
            print(f"::warning::could not read this workflow's own run history: {exc}")
            return

    if not stamps:
        # Nothing has completed yet: a first run, or the first since the workflow was added. Not a
        # failure and not a warning — there is genuinely nothing to measure, and a warning here
        # would fire once per new workflow forever and teach everyone to ignore this arm.
        return

    threshold = staleness_threshold_minutes()
    if threshold is None:
        print(
            f"::warning::cannot derive a staleness threshold from cron {CRON!r}, so this run "
            f"cannot say whether the schedule has been skipping."
        )
        return

    # SILENCE SINCE THE NEWEST COMPLETED RUN, not the gap between the two newest. A gap compares two
    # points in the PAST, so a schedule that stopped and never resumed leaves its last two runs a
    # nominal cadence apart forever and the gap arm stays quiet about it permanently. Silence
    # reports the same number one cron period EARLIER — on the resuming run rather than the one
    # after it — needs one stamp rather than two, and is the only evidence of ONGOING silence
    # available from inside the thing that went silent.
    silence_minutes = (now - max(stamps)).total_seconds() / 60
    if silence_minutes > threshold:
        print(
            f"::warning::the most recent completed scheduled run of this workflow started "
            f"{silence_minutes:.0f} minutes ago, more than {STALENESS_MULTIPLIER}x the "
            f"{cron_period_minutes()}-minute cron period ({threshold}m). The schedule has been "
            f"skipping. This says nothing about the registry — the verdict above stands on its own."
        )


def warn_if_schedule_is_stale(now: datetime) -> None:
    """The arm's one entry point: it warns, and it CANNOT RAISE.

    Criterion 7 says this arm can never change the exit code, and every handler in the body catches
    `InfraError` — the only failure anyone had so far thought of. `cron_period_minutes` can raise
    `ValueError` on a cron step of zero, a change in GitHub's response shape can raise whatever it
    likes, and the next edit can raise something nobody has named. Any of those escaping reaches the
    top-level handler and exits 2, reporting an instrument's own health as a finding about the
    registry — on a run that may have just proved the registry fine.

    The blanket belongs HERE and nowhere else. Inside the body it would swallow the four named
    diagnostics the `InfraError` handlers exist to print. Around the reporting `try` in `main` it
    would be worse than the bug it fixes: that block `return 2`s, so a crash would become a VERDICT
    instead of a warning — the invariant inverted rather than restored.

    A blanket catch can of course hide a permanently-broken arm. The answer is not to drop it but to
    pin the positive path: three tests require this arm to actually warn on real silence, so an arm
    that always crashes reddens all three.
    """
    try:
        _staleness_heartbeat(now)
    except Exception as exc:  # noqa: BLE001 — deliberate: this arm may not vote, by any route
        print(
            f"::warning::the staleness heartbeat itself failed ({exc!r}) and is being ignored. "
            f"This says nothing about the registry — the verdict above stands on its own."
        )

def report_clean(version: str, issues: list[dict], *, partner_checked: bool) -> None:
    """No drift. If a drift issue for this version is open, say it can be closed — and stop there.

    The check never closes an issue itself. `release-outcome` is write-additive only and this stays
    the same shape: closing is a person's decision, and a reporter that can retract its own reports
    is much harder to trust than one that cannot.

    `issues` is the run's one listing, fetched by `main`; this reads it and writes nothing.
    """
    existing = _exact(issues, DRIFT_TITLE.format(version=version))
    if existing and existing["state"] == "OPEN":
        print(
            f"::notice::#{existing['number']} reports drift on {version}, but the registry now "
            f"serves it in both formats. That issue can be closed. This check never closes one."
        )
    # Same listing, not a second one. And ONLY when partner was actually read this run: an
    # offline run without a partner dump knows nothing about partner, and "can be closed" from it
    # would be an unqueried registry reading as clean.
    if not partner_checked:
        return
    lag = _exact(issues, PARTNER_DRIFT_TITLE.format(version=version))
    if lag and lag["state"] == "OPEN":
        print(
            f"::notice::#{lag['number']} reports {version} missing from partner, but partner now "
            f"serves it in both formats. That issue can be closed. This check never closes one."
        )


def report_newest_clean(newest: str, issues: list[dict]) -> None:
    """Partner now serves the newest version: an open partner issue for it can be closed.

    Advisory only, and given only a listing the run ALREADY holds because the declared question
    reached GitHub. A newest clean never lists for itself: on the runs where the declared version
    is in a grace tier, that read would be the grace window touching GitHub for a courtesy notice,
    which is the exact erosion the grace invariant exists to stop.
    """
    lag = _exact(issues, PARTNER_DRIFT_TITLE.format(version=newest))
    if lag and lag["state"] == "OPEN":
        print(
            f"::notice::#{lag['number']} reports {newest} missing from partner, but partner now "
            f"serves it in both formats. That issue can be closed. This check never closes one."
        )


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < (3, 11):
        # Exit 2, not 1: a wrong interpreter is infrastructure, and 1 is the drift verdict. Same
        # reasoning and same shape as `scripts/probe_framework_coinstall.py:47-56`, which this
        # script already cites as its model. Without it, 3.10 and below fail deep inside date
        # parsing with "cannot parse commit date" — an instrument fault wearing the costume of a
        # malformed repository, and the docs told people to invoke it in exactly the way that
        # produces it.
        print(
            f"::error::this check needs Python 3.11+ (running {sys.version.split()[0]}). Both date "
            f"sources are Z-suffixed — git's `%cI` and GitHub's `created_at` — and "
            f"`datetime.fromisoformat` only learned to accept `Z` in 3.11. Use "
            f"`python/.venv/bin/python scripts/check_registry_drift.py`.",
            file=sys.stderr,
        )
        return 2

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--packages-json",
        type=Path,
        default=None,
        help=(
            "a saved UNSCOPED `?query=seam-sdk` dump (no `version:` qualifier); it must "
            "carry seam-sdk rows at some version. Omit to query the registry live. Its rows "
            "must keep Cloudsmith's `uploaded_at`: with --partner-packages-json beside it, the "
            "newest-version question is timed by that field and refuses (exit 2) without it."
        ),
    )
    parser.add_argument(
        "--partner-packages-json",
        type=Path,
        default=None,
        help=(
            "the same kind of dump, captured from `zer07labs/partner`. Offline only. Without it, "
            "an offline run does NOT check partner, and says so. With it, the newest version in "
            "--packages-json is checked against partner too, timed by that dump's `uploaded_at`."
        ),
    )
    parser.add_argument("--now", default=None, help="ISO 8601; defaults to real UTC now")
    parser.add_argument("--soft-grace-minutes", type=int, default=SOFT_GRACE_MINUTES)
    parser.add_argument("--hard-grace-minutes", type=int, default=HARD_GRACE_MINUTES)
    parser.add_argument(
        "--report",
        action="store_true",
        help=(
            "file, comment on or reopen a GitHub issue for a drift verdict. OFF by default: a "
            "local or manual run is read-only, and a tool with side effects should have to be "
            "asked. Same instinct as yank.yml's `dry_run: true` default."
        ),
    )
    args = parser.parse_args(argv)

    try:
        if args.soft_grace_minutes > args.hard_grace_minutes:
            raise InfraError(
                f"--soft-grace-minutes ({args.soft_grace_minutes}) exceeds "
                f"--hard-grace-minutes ({args.hard_grace_minutes}); the warn band would be empty "
                "and the soft tier would suppress past the hard one."
            )
        now = (
            _parse_iso(args.now, what="--now")
            if args.now
            else datetime.now(timezone.utc)
        )

        version = source_version(args.repo)
        assert_query_safe(version)

        if args.partner_packages_json is not None and args.packages_json is None:
            raise InfraError(
                "--partner-packages-json is an offline input and needs --packages-json beside it. "
                "A live run queries partner itself; mixing a saved partner answer with a live "
                "internal one would compare two different moments."
            )

        proved_by = None
        if args.packages_json is not None:
            rows = _load_packages_json(args.packages_json)
            assert_offline_instrument_healthy(rows, f"--packages-json {args.packages_json}")
        else:
            token = registry_token()
            # Canary FIRST. A failed instrument must abort before the target answer is even
            # computed, so there is no code path on which a target result is interpreted against
            # an unproven instrument.
            proved_by = assert_live_instrument_healthy(version, token)
            rows = fetch_registry(version, token)

        # ── partner ─────────────────────────────────────────────────────────────────────────
        #
        # Asked AFTER internal is fully answered, and its failure is CAPTURED rather than raised.
        # A dead partner canary or a revoked partner scope is infrastructure about partner; it must
        # not turn a real internal drift — the bigger finding, and the one partner's state follows
        # from — into an exit 2. Which exit a captured error produces is decided at the verdict,
        # where internal's answer is known. Same canary-first rule, per registry: no partner target
        # is read through a partner instrument that has not answered.
        #
        # `partner_missing is None` means NOT CHECKED, which is different from "nothing missing".
        # Only an offline run without --partner-packages-json takes that branch, and it prints so.
        partner_missing: set[str] | None = None
        partner_proved_by = None
        partner_error: InfraError | None = None
        try:
            if args.packages_json is not None:
                if args.partner_packages_json is not None:
                    partner_rows = _load_packages_json(
                        args.partner_packages_json, "--partner-packages-json"
                    )
                    assert_offline_instrument_healthy(
                        partner_rows, f"--partner-packages-json {args.partner_packages_json}"
                    )
                    partner_missing = set(REQUIRED_FORMATS) - registry_formats(
                        partner_rows, version
                    )
            else:
                partner_proved_by = assert_live_instrument_healthy(
                    version, token, PARTNER_REGISTRY_URL
                )
                partner_missing = set(REQUIRED_FORMATS) - registry_formats(
                    fetch_registry(version, token, PARTNER_REGISTRY_URL), version
                )
        except InfraError as exc:
            partner_error = exc
        except Exception as exc:  # noqa: BLE001 — see below
            # Anything else from the partner block is still a fault about PARTNER, and letting it
            # escape would reach the top-level exit 2 BEFORE internal's verdict is printed — the
            # exact blinding this block exists to prevent, by a different exception class. It is
            # infrastructure (never a verdict) either way; this only decides where it is reported.
            # The class name only, never the message or repr: an exception raised while reading
            # a response can carry that response, and the response is not ours to print.
            partner_error = InfraError(
                f"unexpected failure reading partner: {type(exc).__name__}"
            )

        # ── the newest version on internal (seam-sdk#253) ───────────────────────────────────
        #
        # Asked AFTER both declared-version answers, and captured the same way partner's is: a
        # fault here is about this question alone and must not pre-empt the declared verdict,
        # which is printed whatever happens below. Which exit a captured error produces is decided
        # at the end, against the declared question's final code (`_with_newest`).
        #
        # PRECONDITION: partner was read this run. The question is "does partner serve V", and a
        # partner whose instrument just failed cannot answer it — so a partner fault makes this
        # question NOT CHECKED, and neither the unscoped GET nor a partner GET at V is made. That
        # also keeps one dead credential from being reported twice.
        #
        # SKIP when V is the declared version: partner was asked about exactly that version above,
        # on the declared clock, and asking again would only print the same answer twice. The
        # unscoped GET is still made and still guarded — the discovery is what can break, so it is
        # exercised on every run, the same rule as the canary's.
        newest: str | None = None
        newest_withheld = 0
        newest_partner_missing: set[str] | None = None
        newest_age = 0.0
        newest_error: InfraError | None = None
        newest_unchecked: str | None = None
        if partner_error is not None:
            newest_unchecked = "partner could not be read"
        elif partner_missing is None:
            newest_unchecked = "offline run without --partner-packages-json"
        else:
            try:
                if args.packages_json is not None:
                    # Offline: the dump is the whole answer, so there is no order to check and no
                    # page edge, and no canary to floor against. The max is order-blind.
                    newest, newest_withheld = newest_complete_version(rows)
                    if newest is None:
                        raise InfraError(
                            f"--packages-json {args.packages_json} carries no plain "
                            f"`{PACKAGE_NAME}` version in both formats, so there is no newest "
                            "release to ask partner about."
                        )
                    newest_rows: object = rows
                else:
                    served = set(REQUIRED_FORMATS) <= registry_formats(rows, version)
                    newest, newest_rows, newest_withheld = fetch_newest(
                        token, proved_by=proved_by, declared=version if served else None
                    )
                if newest != version:
                    # The clock BEFORE the partner read: it is local, and an unreadable stamp is a
                    # fault whatever partner says. Read on every non-skipped run, not only when
                    # partner is short — otherwise a broken stamp would first be noticed on the
                    # one run that needs it, as an exit 2 in place of the lag it was meant to time.
                    try:
                        uploaded = newest_upload_clock(newest_rows, newest)
                    except InfraError as exc:
                        if args.packages_json is None:
                            raise
                        # Offline, the likeliest cause is a dump saved without the field — a
                        # hand-trimmed capture, or one from before this question existed — and
                        # the fix is the operator's, so say which file and what it needs.
                        raise InfraError(
                            f"{exc} --packages-json {args.packages_json} must keep each row's "
                            "`uploaded_at`, as Cloudsmith's list API returns it: with "
                            "--partner-packages-json beside it, the newest-version question is "
                            "timed by that field."
                        ) from None
                    newest_age = (now - uploaded).total_seconds() / 60.0
                    if newest_age < -CLOCK_SKEW_TOLERANCE_MINUTES:
                        # The stamp itself is withheld (D8); the size of the gap is the diagnosis.
                        raise InfraError(
                            f"{newest}'s latest `uploaded_at` on internal is "
                            f"{-newest_age:.0f} minutes AFTER now ({now.isoformat()}), past "
                            f"{CLOCK_SKEW_TOLERANCE_MINUTES} minutes of tolerable skew. Refusing "
                            "to defer: a negative age is below every grace threshold, so this "
                            "would otherwise suppress the newest-version question indefinitely."
                        )
                    newest_age = max(newest_age, 0.0)
                    if args.packages_json is not None:
                        partner_at = registry_formats(partner_rows, newest)
                    else:
                        partner_at = registry_formats(
                            fetch_registry(newest, token, PARTNER_REGISTRY_URL), newest
                        )
                    newest_partner_missing = set(REQUIRED_FORMATS) - partner_at
            except InfraError as exc:
                newest_error = exc
            except Exception as exc:  # noqa: BLE001 — same reasoning as partner's, above
                # The class name only, never the message or repr: this block parses a response.
                newest_error = InfraError(
                    f"unexpected failure answering the newest-version question: "
                    f"{type(exc).__name__}"
                )

    except InfraError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    # ── the newest question's output, as two closures over the facts gathered above ─────────
    #
    # Closures rather than inline blocks because there are TWO places they must run: the normal
    # path below, and the declared clock's own fault path. By the time git is read for the
    # declared clock, the newest question has already been fully answered on its OWN clock (the
    # upload), so a git fault must not swallow it — a computed newest finding is printed on every
    # path that gets this far. Both read the enclosing variables at call time.
    def print_newest_facts(declared_answered: bool = True) -> None:
        # The newest question's facts. Only plain versions and minutes are printed here — never an
        # `uploaded_at` (D8): the age is derived from it, the stamp itself stays inside the process.
        if newest_unchecked is not None:
            print(f"newest on internal: NOT CHECKED ({newest_unchecked})")
        elif newest_error is not None:
            print("newest on internal: COULD NOT BE READ (see the error below)")
        else:
            aside = (
                f" ({newest_withheld} non-version value(s) set aside)" if newest_withheld else ""
            )
            if newest_partner_missing is None:
                # The skip: newest IS the declared version, so its partner answer is the declared
                # question's — which a git-clock fault leaves unanswered, and the line says so.
                answered = "answered above" if declared_answered else "not answered (git failed)"
                print(f"newest on internal: {newest}{aside} — the declared version, {answered}")
            else:
                print(f"newest on internal: {newest}{aside}, uploaded {newest_age:.0f} minutes ago")
                newest_found = set(REQUIRED_FORMATS) - newest_partner_missing
                # Not `partner serves:` — that prefix is the declared version's line, read as such.
                print(f"partner serves {newest}: {', '.join(sorted(newest_found)) or '<nothing>'}")

    def print_newest_verdict() -> str | None:
        newest_verdict: str | None = None
        if newest_error is not None:
            print(
                f"::error::the newest-version question could not be answered: {newest_error}",
                file=sys.stderr,
            )
        elif newest_partner_missing is not None and newest_partner_missing:
            newest_formats = ", ".join(sorted(newest_partner_missing))
            newest_verdict = _tier(newest_age, args.soft_grace_minutes, args.hard_grace_minutes)
            if newest_verdict == "deferred":
                print(
                    f"NEWEST DEFERRED — partner lacks {newest_formats} for {newest}, the newest "
                    f"version on internal (main declares {version}), but it finished uploading only "
                    f"{newest_age:.0f} minutes ago; `promote-partner` is plausibly still running. "
                    f"Escalates at {args.hard_grace_minutes}m."
                )
            elif newest_verdict == "warned":
                print(
                    f"::warning::seam-sdk {newest}, the newest version on internal (main declares "
                    f"{version}), is not on partner ({newest_formats} missing) {newest_age:.0f} "
                    f"minutes after it finished uploading. Past the declared publish ceilings, not "
                    f"yet escalated (hard={args.hard_grace_minutes}m)."
                )
            else:
                print(
                    f"NEWEST DRIFT — seam-sdk {newest}, the newest version on internal, is not on "
                    f"partner {newest_age:.0f} minutes after it finished uploading, past the hard "
                    f"window of {args.hard_grace_minutes}m. Main declares {version}, so the "
                    f"declared-version check above never asks partner about {newest}.\n"
                    + _partner_remediation(newest, newest_partner_missing)
                )
        elif newest_partner_missing is not None:
            print(f"NEWEST CLEAN — partner serves {newest}, the newest version on internal, in both "
                  f"formats.")
        return newest_verdict

    try:
        # The instrument is exercised BEFORE the clock is consulted. The rule that actually has
        # teeth is narrower than "before", and worth stating in the form a future editor can
        # check: NO PATH MAY REACH A VERDICT WITHOUT HAVING RUN THE QUERY. Moving these two lines
        # below the clock changes nothing on its own — everything here is unconditional — but it
        # is the shape from which the tempting optimisation follows: return early inside the soft
        # window and skip the query for a fresh version. That leaves a broken instrument unnoticed
        # on exactly the runs that follow a release, which is when it is needed. The
        # `fresh`-parametrised cases in `scripts/test_registry_drift_gate.py` pin the early return;
        # nothing can pin a pure reorder, because a pure reorder is not observable.
        found = registry_formats(rows, version)
        missing = set(REQUIRED_FORMATS) - found

        landed = version_landed_at(args.repo, version)
        tagged = tag_present(args.repo, version)
        tag_date = tag_created_at(args.repo, version)
        started = max(landed, tag_date) if tag_date else landed
        age_minutes = (now - started).total_seconds() / 60.0
        if age_minutes < -CLOCK_SKEW_TOLERANCE_MINUTES:
            raise InfraError(
                f"the most recent release attempt for {version} is dated "
                f"{started.isoformat()}, which is {-age_minutes:.0f} minutes AFTER now "
                f"({now.isoformat()}). That is past {CLOCK_SKEW_TOLERANCE_MINUTES} minutes of "
                "tolerable skew, so it is not jitter. Refusing to defer: a negative age is below "
                "every grace threshold, so this would otherwise suppress the check silently and "
                "indefinitely."
            )
        age_minutes = max(age_minutes, 0.0)
    except InfraError as exc:
        # The DECLARED question cannot be answered — its clock is git's, and git failed — but the
        # newest question was answered on the upload clock before git was ever read. Print it,
        # then exit by the D3 table with the declared question standing at 2 (infrastructure):
        # a newest DRIFT is a real finding and keeps its 1; anything else leaves the 2. Nothing is
        # reported to GitHub from here, a newest drift included: this checkout cannot be read
        # (the newest issue's own tag row would need it too), and no write leaves a run whose
        # instrument is broken — the rule `test_no_infrastructure_failure_ever_reaches_github`
        # holds. The finding is printed, the exit carries it, and the next healthy run files it.
        print(f"::error::{exc}", file=sys.stderr)
        print_newest_facts(declared_answered=False)
        return _with_newest(2, print_newest_verdict(), newest_error)

    if proved_by:
        print(f"instrument proven by canary {proved_by} (both formats present)")
    if partner_proved_by:
        print(f"partner instrument proven by canary {partner_proved_by} (both formats present)")
    print(f"source version: {version}  (tag v{version} {'present' if tagged else 'ABSENT'})")
    print(f"registry serves: {', '.join(sorted(found)) or '<nothing>'}")
    # Deliberately NOT prefixed `registry serves:` — that line is internal's, and is read as such.
    if partner_error is not None:
        print("partner: COULD NOT BE READ (see the error below)")
    elif partner_missing is None:
        print("partner: NOT CHECKED (offline run without --partner-packages-json)")
    else:
        partner_found = set(REQUIRED_FORMATS) - partner_missing
        print(f"partner serves: {', '.join(sorted(partner_found)) or '<nothing>'}")
    print_newest_facts()
    print(f"most recent release attempt: {started.isoformat()} ({age_minutes:.0f} minutes ago)")

    # ── the verdict, printed BEFORE anything is reported ────────────────────────────────────
    #
    # The order is load-bearing. Reporting talks to GitHub, and GitHub has outages; if the report
    # were computed first, a `gh` failure would exit 2 with the answer never printed. The verdict
    # is this run's product and the issue is a delivery mechanism for it, so the log always carries
    # it even when the delivery fails.
    # `subject` says which registry the verdict is ABOUT, and it is internal whenever internal is
    # short: partner is promoted FROM internal, so a version internal lacks is missing from partner
    # as a consequence, and filing it twice would report one fault as two. Partner becomes the
    # subject only when internal is complete.
    subject = "internal"
    formats = ", ".join(sorted(missing))
    if not missing and partner_error is not None:
        # Internal is clean, so there is no bigger finding for a partner instrument fault to hide.
        # It is exactly what it looks like: partner could not be read. Infrastructure.
        print(f"OK — the registry serves {version} in both formats.")
        print(f"::error::{partner_error}", file=sys.stderr)
        return 2
    if not missing and partner_missing:
        subject = "partner"
        partner_formats = ", ".join(sorted(partner_missing))
        print(f"OK — the registry serves {version} in both formats.")
        tier = _tier(age_minutes, args.soft_grace_minutes, args.hard_grace_minutes)
        if tier == "deferred":
            print(
                f"DEFERRED — partner lacks {partner_formats} for {version}, but the attempt is "
                f"only {age_minutes:.0f} minutes old; `promote-partner` is plausibly still "
                f"running. Escalates at {args.hard_grace_minutes}m."
            )
            verdict, code = "deferred", 0
        elif tier == "warned":
            print(
                f"::warning::seam-sdk {version} is on internal but not on partner "
                f"({partner_formats} missing) {age_minutes:.0f} minutes after the release "
                f"attempt. Past the declared publish ceilings, not yet escalated "
                f"(hard={args.hard_grace_minutes}m)."
            )
            verdict, code = "warned", 0
        else:
            print(
                f"DRIFT — seam-sdk {version} is not on partner {age_minutes:.0f} minutes after "
                f"the release attempt, past the hard window of {args.hard_grace_minutes}m.\n"
                + _partner_remediation(version, partner_missing)
            )
            verdict, code = "drift", 1
    elif not missing:
        if partner_missing is None:
            print(
                f"OK — the registry serves {version} in both formats. Partner was NOT checked "
                f"(offline, no --partner-packages-json)."
            )
        else:
            print(f"OK — the registry serves {version} in both formats, on internal and partner.")
        verdict, code = "clean", 0
    elif age_minutes < args.soft_grace_minutes:
        remaining = args.soft_grace_minutes - age_minutes
        print(
            f"DEFERRED — {formats} missing for {version}, but the attempt is only "
            f"{age_minutes:.0f} minutes old. A publish is plausibly still running. This stops "
            f"deferring silently in {remaining:.0f} minutes (soft={args.soft_grace_minutes}m) and "
            f"escalates at {args.hard_grace_minutes}m."
        )
        verdict, code = "deferred", 0
    elif age_minutes < args.hard_grace_minutes:
        print(
            f"::warning::seam-sdk {version} is not on the registry ({formats} missing) "
            f"{age_minutes:.0f} minutes after the release attempt. That is past the declared "
            f"publish ceilings (soft={args.soft_grace_minutes}m), so something is wrong — but a "
            f"job could still be alive up to {args.hard_grace_minutes}m, so this is not escalated "
            f"yet."
        )
        verdict, code = "warned", 0
    else:
        print(
            f"DRIFT — seam-sdk {version} is not installable {age_minutes:.0f} minutes after the "
            f"release attempt, past the hard window of {args.hard_grace_minutes}m. No publish job "
            f"for it can still be alive.\n" + _remediation(version, tagged, missing)
        )
        verdict, code = "drift", 1

    # ── the newest version's verdict, printed BEFORE anything is reported, like the declared one ──
    #
    # Its own tier on its own clock (the upload, not git), on the same soft and hard windows:
    # `promote-partner` follows the upload in the same publish run either way. Only this question's
    # DRIFT tier votes, and it votes at the end (`_with_newest`), after the declared question's
    # reporting has decided whether that question's drift was suppressed.
    newest_verdict = print_newest_verdict()

    if partner_error is not None:
        # Only reachable with internal SHORT (the clean-internal case returned above). Internal's
        # verdict stands and is printed; the partner fault is reported beside it, never instead of
        # it. A drift keeps its 1 — the finding is real whatever partner's instrument is doing.
        # Inside the grace tiers there is no finding yet, so the instrument fault is the news: 2.
        print(f"::error::partner could not be read: {partner_error}", file=sys.stderr)
        if verdict != "drift":
            return 2

    if not args.report:
        return _with_newest(code, newest_verdict, newest_error)

    # ── reporting ───────────────────────────────────────────────────────────────────────────
    #
    # `deferred` and `warned` reach GitHub not at all — not even the read. The middle tier exists
    # to say "something is wrong and a job could still be alive"; the moment it files anything it
    # has become a reporting tier, and the grace window stops being a grace window. That holds PER
    # QUESTION (seam-sdk#253): each question reaches GitHub only from its own drift (or, for the
    # declared one, its clean) tier, and a question in grace contributes no read.
    #
    # ONE listing per run, fetched LAZILY — on the first question that reaches GitHub — cached,
    # and handed to every later one. Two questions can now file in one run, and two listings
    # could disagree about a repository that never existed at one moment. A FAILED fetch is cached
    # too: a second question must not retry it, or one run could list twice.
    #
    # Lazy rather than up-front because of the newest clean's close notice: it may READ a listing
    # the declared question fetched, and must never be the reason one is fetched. With a getter,
    # that rule is one visible condition at the call site (`declared_reaches`), and dropping it is
    # an observable extra read rather than a no-op.
    listing_cache: list[tuple[list[dict], str] | InfraError] = []

    def listing() -> tuple[list[dict], str]:
        if not listing_cache:
            try:
                target = issue_repo()
                listing_cache.append((fetch_issues(target), target))
            except InfraError as exc:
                listing_cache.append(exc)
        got = listing_cache[0]
        if isinstance(got, InfraError):
            raise got
        return got

    declared_reaches = verdict in ("drift", "clean")
    newest_reaches = newest_verdict == "drift"
    try:
        if verdict == "drift" and subject == "partner":
            # Under PARTNER_DRIFT_TITLE, never DRIFT_TITLE: filing the internal title for a
            # promotion lag would assert the release is not installable from internal, which is
            # a state the registry is not in.
            # `partner_missing` is non-empty here by construction: the subject only becomes
            # partner when partner was read and is short. No `or set()` fallback — an empty set
            # would file an issue whose "missing formats" row is blank, which reads as fine.
            issues, issue_target = listing()
            if report_drift(
                version,
                tagged,
                partner_missing,
                age_minutes,
                issues=issues,
                repo=issue_target,
                subject="partner",
            ):
                code = 0
        elif verdict == "drift":
            issues, issue_target = listing()
            if report_drift(
                version,
                tagged,
                missing,
                age_minutes,
                issues=issues,
                repo=issue_target,
                partner_missing=partner_missing,
                partner_unreadable=partner_error is not None,
            ):
                code = 0
        elif verdict == "clean":
            # BEST EFFORT, AND ONLY HERE. Before reporting existed, a clean run touched nothing;
            # making it read GitHub means a GitHub outage would turn a run that PROVED the
            # registry healthy into a red job. That misreports the answer: red on this workflow
            # has to mean "there is something to look at about the registry", or it gets muted,
            # and a muted workflow is the failure this whole check exists to prevent.
            #
            # Nothing is lost by softening it. This path has no report to lose — its entire
            # output is a courtesy `::notice::` that an already-open issue can now be closed. The
            # drift paths keep exit 2, because there the report IS the product — including a
            # newest drift below, which re-raises this same cached failure.
            #
            # It is not silent: a broken credential still says so on every clean run, one
            # severity down, which is the earliest anyone could learn of it.
            try:
                issues, _ = listing()
                # `partner_error` is None here: a clean internal with a partner fault returned 2
                # above. So "checked" is exactly "a partner answer was read".
                report_clean(version, issues, partner_checked=partner_missing is not None)
            except InfraError as exc:
                if newest_reaches:
                    # The same cached failure is about to fail the newest drift's delivery, and
                    # that is exit 2. Saying "only the advisory notice is missing" first would be
                    # contradicted two lines later, so this says what will actually happen.
                    print(
                        f"::warning::the registry is clean, but GitHub could not be reached: "
                        f"{exc}. The newest-version drift above cannot be filed either, so this "
                        f"run will exit 2."
                    )
                else:
                    print(
                        f"::warning::the registry is clean, but GitHub could not be reached to "
                        f"check for an open drift issue: {exc}. The verdict above stands; only the "
                        f"advisory notice is missing."
                    )

        # The newest question, on the SAME listing. One issue per missing version whichever
        # question finds it (D4): V's partner title is the one the declared question would have
        # filed had `main` still declared V, so an issue it filed then is recognised now, and a
        # suppression on it — closed and labelled, scoped to V alone — mutes this one too.
        if newest_reaches:
            # Non-empty by construction on a drift tier; both checks are for the type checker.
            assert newest is not None and newest_partner_missing
            issues, issue_target = listing()
            if report_drift(
                newest,
                tag_present(args.repo, newest),
                newest_partner_missing,
                newest_age,
                issues=issues,
                repo=issue_target,
                subject="partner",
                question="newest",
                declared=version,
            ):
                # Suppressed: no longer an unsuppressed drift, so it no longer votes (D3).
                newest_verdict = "suppressed"
        elif newest_partner_missing is not None and not newest_partner_missing and declared_reaches:
            # The close notice, ONLY from a listing the declared question already reached GitHub
            # for. `declared_reaches` is the guard: without it a newest clean beside a declared
            # grace tier would fetch a listing for a courtesy notice — the grace window touching
            # GitHub. Best effort like every clean path: a listing that failed is already warned.
            assert newest is not None
            try:
                report_newest_clean(newest, listing()[0])
            except InfraError:
                pass
    except InfraError as exc:
        # A failed listing or write (or the tag read for V) AFTER both verdicts were printed.
        # Whatever was filed before it stands; the run is red because a finding was not
        # delivered. A newest drift beside a gh outage is therefore 2, not 1 — the rule the
        # declared drift has always followed, so an outage reads the same whichever question it
        # interrupts, and "1" keeps meaning "a finding was delivered or is on record".
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    # A partner fault beside an internal drift kept the drift's 1 so the finding could be filed.
    # If that drift turned out to be SUPPRESSED, there is no finding left for the fault to stand
    # beside, and an exit 0 would leave an unreadable partner as a footnote on a green job. 2.
    if partner_error is not None and code == 0:
        code = 2

    # After BOTH questions' reporting, so each suppression has already been applied — the D3
    # table reads the declared question's FINAL code and the newest question's final verdict.
    code = _with_newest(code, newest_verdict, newest_error)

    # ── the watcher's own heartbeat ───────────────────────────────────────────────────────────
    #
    # AFTER the verdicts and after reporting, once, and only on a run that read GitHub — the
    # listing was attempted. A question in grace must reach it not at all — including this read —
    # or the grace window stops being a grace window, which is the invariant
    # `test_neither_grace_tier_touches_github` exists to hold.
    #
    # NOT "if and only if": a `gh` failure on a path that had a finding to deliver (either
    # question's drift) returns 2 from the reporting handler above, before this line, exactly as
    # the declared drift path always has. Only a failed listing wanted solely by a CLEAN declared
    # question is softened, and that run still reaches the heartbeat.
    #
    # `code` is deliberately not reassigned anywhere below this line.
    if listing_cache:
        warn_if_schedule_is_stale(now)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 — deliberate; see "easy to get wrong" #1 above
        print(f"::error::check_registry_drift crashed: {exc!r}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)
