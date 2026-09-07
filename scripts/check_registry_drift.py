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

Usage:  scripts/check_registry_drift.py [--repo DIR] [--packages-json FILE] [--now ISO8601]
                                        [--soft-grace-minutes N] [--hard-grace-minutes N]
        With --packages-json the response is read from that file and nothing is fetched.
        Without it the registry is queried live and SEAM_REGISTRY_TOKEN must be set.
Exit:   0 = the registry serves it, it is younger than the hard window, or the drift is
            suppressed by a closed issue carrying the `deliberately-unpublished` label
        1 = drift
        2 = infrastructure — never a verdict, INCLUDING every unhandled exception
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

#: Versions asserted to be published in BOTH formats. A set rather than a single pin, so one yank
#: does not brick the instrument; three, so two would have to be yanked before this needs an edit.
#: Any entry equal to the target is dropped at runtime — a canary that IS the target proves
#: nothing, and would convert that version's drift into an exit 2, muting the check on exactly the
#: version it is watching.
#:
#: ⚠ UNCONFIRMED AGAINST THE LIVE REGISTRY, and be precise about how weak the evidence is.
#:
#: The rule actually applied is "has a tag, minus the three refusals anyone happened to record".
#: An earlier draft of this comment claimed more: that each entry carries both `vX` and `go/vX`
#: tags, offered as though that excluded a refused release. It does not. `release-on-runtime.yml`
#: creates both tags in one step, BEFORE publish.yml starts — so `go/v0.7.69`, `go/v0.7.70` and
#: `go/v0.7.72` exist too, and the clause has zero discriminating power against exactly the case
#: it was invoked to exclude.
#:
#: Worse, "no recorded refusal" is weakest precisely here. The reason only three refusals are on
#: record (`publish.yml:748-749`) is that nothing was watching — which is the premise of
#: seam-sdk#100 and the reason this file exists. Absence of a refusal record is close to
#: uninformative for this population.
#:
#: So: verify these against the live registry. Query each with the real credential and keep the
#: ones returning BOTH formats. Until then the instrument is unproven — and an unproven instrument
#: exits 2 naming every candidate it tried, which is loud and never a wrong verdict, but that is
#: not the same thing as working.
#:
#: Why a set and not a pin: an entry equal to the target is dropped at runtime (a canary that IS
#: the target cannot distinguish a broken query from a real lag), and `yank.yml` can delete any
#: version, so a single pin is one yank from a permanent exit 2 that everyone learns to scroll
#: past. Three, so two would have to go before this needs an edit.
#:
#: Why the ages are spread: retention. Three of the OLDEST plausible versions would maximise
#: exposure to a cleanup sweep aging all of them out at once. One old, one middle, one recent
#: hedges that.
#:
#: And note what the spread buys on the other side, which is stronger than the drop-if-equal rule
#: needed: every entry is already strictly BELOW the current target (0.7.77), and the target only
#: ever moves upward. So no entry can equal the target again, and the branch that drops one can
#: never actually shrink this roster. That rule stays because it is what makes the roster safe to
#: re-point carelessly — not because this particular roster needs it.
CANARY_VERSIONS = ("0.7.50", "0.7.65", "0.7.75")

#: The list endpoint `yank.yml:69-71` uses. Same request shape deliberately: that is the shape
#: believed to work, and a drift check whose query differs from the one proven in production is
#: testing something else.
REGISTRY_URL = "https://api.cloudsmith.io/v1/packages/zer07labs/internal/"

#: A response carrying exactly this many rows is treated as truncated — see `fetch_registry`.
PAGE_SIZE = 50

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
            raise InfraError(f"a registry row is a {type(row).__name__}, not an object: {row!r}")
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
            "must never look the same."
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


def fetch_registry(version: str, token: str) -> object:
    """GET the rows for one version.

    `curl`, not `urllib`, and that is not stylistic. This repo's hermeticity convention is stub
    executables first on `PATH` (`scripts/test_release_notice_gate.py:62-83`), with the rule "no
    mocks, no cassettes". `urllib` can only be controlled by monkeypatching, which would make this
    the one guard in the repo whose world is a mock. Shelling out also keeps the request
    byte-comparable to `yank.yml:69-71`.

    `-sf` matters: without `-f` a 401 or a 500 returns an error BODY with exit 0, and a body that
    is not a list of packages parses to "no rows" — which reads as drift. Every HTTP failure has
    to arrive as a non-zero exit.
    """
    query = _query_for(version)
    try:
        proc = subprocess.run(
            [
                "curl",
                "-sf",
                "--max-time",
                str(CURL_MAX_SECONDS),
                "-H",
                f"X-Api-Key: {token}",
                f"{REGISTRY_URL}{query}",
            ],
            capture_output=True,
            text=True,
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
            f"curl exited {proc.returncode} querying {query} — the registry could not be read. "
            "22 is an HTTP error (a bad or unscoped credential lands here), 28 a timeout, 6 DNS. "
            "This is infrastructure: an unanswered query says nothing about what is published."
        )
    try:
        rows = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise InfraError(f"the response to {query} is not JSON: {exc}") from exc
    if isinstance(rows, list) and len(rows) == PAGE_SIZE:
        raise InfraError(
            f"the response to {query} carries exactly {PAGE_SIZE} rows, which is the page size. "
            "Treat that as evidence the `version:` qualifier was IGNORED and a first page of "
            "everything came back: a target version outside that page would read as absent, and "
            "the run would report drift for a published version. Raise page_size, or stop "
            "trusting the qualifier."
        )
    return rows


def assert_live_instrument_healthy(target: str, token: str) -> str:
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
        formats = registry_formats(fetch_registry(candidate, token), candidate)
        tried.append(f"{candidate} -> {', '.join(sorted(formats)) or 'nothing'}")
        if set(REQUIRED_FORMATS) <= formats:
            return candidate
    raise InfraError(
        "the registry query returned nothing usable for any canary version ("
        + "; ".join(tried)
        + "). Either the query shape is wrong, or every canary has been yanked and "
        "CANARY_VERSIONS needs re-pointing. Refusing to read the target's answer through an "
        "instrument that has not been shown to work."
    )


def _load_packages_json(path: Path) -> object:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InfraError(f"--packages-json {path} does not exist") from exc
    except OSError as exc:
        raise InfraError(f"--packages-json {path} cannot be read: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InfraError(f"--packages-json {path} is not valid JSON: {exc}") from exc


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


def _issue_body(
    version: str, tagged: bool, missing: set[str], age_minutes: float, cross_link: dict | None
) -> str:
    formats = ", ".join(sorted(missing))
    lines = [
        f"`python/pyproject.toml` declares **{version}**, and the registry does not serve it.",
        "",
        "| | |",
        "|---|---|",
        f"| version | `{version}` |",
        f"| missing formats | {formats} |",
        f"| packages | `{PACKAGE_NAME}` (python), `@zer07labs/{PACKAGE_NAME}` (npm) |",
        f"| tag `v{version}` | {'present' if tagged else '**absent**'} |",
        f"| age of the release attempt | {age_minutes:.0f} minutes |",
        "",
        _remediation(version, tagged, missing),
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
    version: str, tagged: bool, missing: set[str], age_minutes: float
) -> bool:
    """File, comment, reopen — or recognise a suppression. Returns True if suppressed.

    The decision table, and note that only the last row changes the exit code:

        no issue                        -> create                      exit 1
        open issue                      -> nothing; it already says so  exit 1
        closed, unlabelled              -> reopen + comment            exit 1
        closed, labelled                -> a ::warning:: naming it     exit 0
    """
    repo = issue_repo()
    issues = fetch_issues(repo)
    title = DRIFT_TITLE.format(version=version)
    existing = _exact(issues, title)

    if existing is None:
        cross_link = _exact(issues, RELEASE_NOTICE_TITLE.format(version=version))
        if cross_link and cross_link["state"] != "OPEN":
            cross_link = None
        body = _issue_body(version, tagged, missing, age_minutes, cross_link)
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
            f"closed and labelled `{SUPPRESSION_LABEL}`. The registry still does not serve "
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
            _issue_body(version, tagged, missing, age_minutes, None),
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

def report_clean(version: str) -> None:
    """No drift. If a drift issue for this version is open, say it can be closed — and stop there.

    The check never closes an issue itself. `release-outcome` is write-additive only and this stays
    the same shape: closing is a person's decision, and a reporter that can retract its own reports
    is much harder to trust than one that cannot.
    """
    repo = issue_repo()
    existing = _exact(fetch_issues(repo), DRIFT_TITLE.format(version=version))
    if existing and existing["state"] == "OPEN":
        print(
            f"::notice::#{existing['number']} reports drift on {version}, but the registry now "
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
        help="a saved registry response; omit to query the registry live",
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
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    if proved_by:
        print(f"instrument proven by canary {proved_by} (both formats present)")
    print(f"source version: {version}  (tag v{version} {'present' if tagged else 'ABSENT'})")
    print(f"registry serves: {', '.join(sorted(found)) or '<nothing>'}")
    print(f"most recent release attempt: {started.isoformat()} ({age_minutes:.0f} minutes ago)")

    # ── the verdict, printed BEFORE anything is reported ────────────────────────────────────
    #
    # The order is load-bearing. Reporting talks to GitHub, and GitHub has outages; if the report
    # were computed first, a `gh` failure would exit 2 with the answer never printed. The verdict
    # is this run's product and the issue is a delivery mechanism for it, so the log always carries
    # it even when the delivery fails.
    formats = ", ".join(sorted(missing))
    if not missing:
        print(f"OK — the registry serves {version} in both formats.")
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

    if not args.report:
        return code

    # ── reporting ───────────────────────────────────────────────────────────────────────────
    #
    # `deferred` and `warned` reach GitHub not at all — not even the read. The middle tier exists
    # to say "something is wrong and a job could still be alive"; the moment it files anything it
    # has become a reporting tier, and the grace window stops being a grace window.
    try:
        if verdict == "drift":
            if report_drift(version, tagged, missing, age_minutes):
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
            # drift path keeps exit 2, because there the report IS the product.
            #
            # It is not silent: a broken credential still says so on every clean run, one
            # severity down, which is the earliest anyone could learn of it.
            try:
                report_clean(version)
            except InfraError as exc:
                print(
                    f"::warning::the registry is clean, but GitHub could not be reached to "
                    f"check for an open drift issue: {exc}. The verdict above stands; only the "
                    f"advisory notice is missing."
                )
    except InfraError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    # ── the watcher's own heartbeat ───────────────────────────────────────────────────────────
    #
    # AFTER the verdict and after reporting, and only on the tiers that already talked to GitHub.
    # `deferred` and `warned` must reach it not at all — including this read — or the grace window
    # stops being a grace window, which is the invariant
    # `test_neither_grace_tier_touches_github` exists to hold.
    #
    # `code` is deliberately not reassigned anywhere below this line.
    if verdict in ("drift", "clean"):
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
