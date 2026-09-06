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
4. **An empty answer must never read as a clean one.** With `--packages-json` there is no canary to
   prove the query worked, so the response itself has to carry the proof: it must contain at least
   one `seam-sdk` row at SOME version. A file with no `seam-sdk` row in it is not a plausible
   response to a `seam-sdk` query — it is a broken instrument, and it exits 2. (The live path
   answers this differently, with a canary query; see `CANARY` handling there. An empty target
   response is trusted as drift only because a canary returned rows on the same credential in the
   same run.)

Usage:  scripts/check_registry_drift.py [--repo DIR] [--packages-json FILE] [--now ISO8601]
                                        [--soft-grace-minutes N] [--hard-grace-minutes N]
Exit:   0 = the registry serves it, or it is younger than the hard window
        1 = drift
        2 = infrastructure — never a verdict, INCLUDING every unhandled exception
"""

from __future__ import annotations

import argparse
import json
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

#: The version is interpolated into a URL query string (`?query=seam-sdk+version:<v>`), where `+`
#: means SPACE and `#`, `&`, `%` and whitespace are all structural. `yank.yml:64-66` guards its own
#: operator-typed input the same way. The obligation is stronger here: this value is read from
#: `main`, so a refusal means the world is not the world this script models — exit 2, never 1.
SAFE_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*$")

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--packages-json", type=Path, default=None)
    parser.add_argument("--now", default=None, help="ISO 8601; defaults to real UTC now")
    parser.add_argument("--soft-grace-minutes", type=int, default=SOFT_GRACE_MINUTES)
    parser.add_argument("--hard-grace-minutes", type=int, default=HARD_GRACE_MINUTES)
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

        if args.packages_json is None:
            raise InfraError(
                "--packages-json is required: the live registry query is not implemented yet."
            )
        rows = _load_packages_json(args.packages_json)

        # The instrument is exercised BEFORE the clock is consulted. The rule that actually has
        # teeth is narrower than "before", and worth stating in the form a future editor can
        # check: NO PATH MAY REACH A VERDICT WITHOUT HAVING RUN THE QUERY. Moving these two lines
        # below the clock changes nothing on its own — everything here is unconditional — but it
        # is the shape from which the tempting optimisation follows: return early inside the soft
        # window and skip the query for a fresh version. That leaves a broken instrument unnoticed
        # on exactly the runs that follow a release, which is when it is needed. The
        # `fresh`-parametrised cases in `scripts/test_registry_drift_gate.py` pin the early return;
        # nothing can pin a pure reorder, because a pure reorder is not observable.
        assert_offline_instrument_healthy(rows, f"--packages-json {args.packages_json}")
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

    print(f"source version: {version}  (tag v{version} {'present' if tagged else 'ABSENT'})")
    print(f"registry serves: {', '.join(sorted(found)) or '<nothing>'}")
    print(f"most recent release attempt: {started.isoformat()} ({age_minutes:.0f} minutes ago)")

    if not missing:
        print(f"OK — the registry serves {version} in both formats.")
        return 0

    formats = ", ".join(sorted(missing))
    if age_minutes < args.soft_grace_minutes:
        remaining = args.soft_grace_minutes - age_minutes
        print(
            f"DEFERRED — {formats} missing for {version}, but the attempt is only "
            f"{age_minutes:.0f} minutes old. A publish is plausibly still running. This stops "
            f"deferring silently in {remaining:.0f} minutes (soft={args.soft_grace_minutes}m) and "
            f"escalates at {args.hard_grace_minutes}m."
        )
        return 0

    if age_minutes < args.hard_grace_minutes:
        print(
            f"::warning::seam-sdk {version} is not on the registry ({formats} missing) "
            f"{age_minutes:.0f} minutes after the release attempt. That is past the declared "
            f"publish ceilings (soft={args.soft_grace_minutes}m), so something is wrong — but a "
            f"job could still be alive up to {args.hard_grace_minutes}m, so this is not escalated "
            f"yet."
        )
        return 0

    print(
        f"DRIFT — seam-sdk {version} is not installable {age_minutes:.0f} minutes after the "
        f"release attempt, past the hard window of {args.hard_grace_minutes}m. No publish job for "
        f"it can still be alive.\n" + _remediation(version, tagged, missing)
    )
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 — deliberate; see "easy to get wrong" #1 above
        print(f"::error::check_registry_drift crashed: {exc!r}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)
