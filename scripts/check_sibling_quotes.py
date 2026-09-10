#!/usr/bin/env python3
"""Verify `QUOTED`'s sibling-repo claims over the GitHub API, because CI has no sibling checkout.

`QUOTED` in `python/tests/test_compatibility_citations_resolve.py` exists for one job: catching a
claim whose source **changes value in place**. A version constraint on another repo's release
cadence never moves a line, so a line anchor cannot notice it going stale; quoting the sentence is
the only check that fails when it does.

Three of its four entries name sibling repos. In CI none of those siblings are checked out, so the
test hits `pytest.skip(...)` and **the only mechanism that can catch this class of drift never runs
in the only place that gates a merge** (seam-sdk#103). It ran on a workstation that happened to have
the siblings cloned, which is a property of someone's laptop rather than of the repo.

That is this repo's own named failure class — a check whose result is decided by something other
than the property it names — and it had already let one through: `seam-aegis` bumped
`seam-agent-core[sdk]` 0.5 -> 0.6 on 2026-09-05 (`7771f28`). The quote caught it locally. CI was
green throughout and would have stayed green indefinitely.

## Why a script and not a wider test

The test cannot do this itself: it runs in the `python` job, which has no credentials, and these
siblings are private. This runs in its own job holding a `seam-deps-bot` App token scoped to exactly
the repos below, mirroring how `spec-pin` reads `seam-runtime` without checking it out.

## Single source of truth

The table is **not duplicated here.** It is read out of the test module with `ast`, so there is
exactly one `QUOTED` and this script cannot drift from the thing it enforces. `ast` rather than
`import`: importing would pull in pytest and the whole test module's dependencies into a job whose
install list is deliberately tiny, and would run module-level code for no reason.

## Exit codes

    0  every sibling quote still matches its source
    1  DRIFT — a quoted sentence is gone, changed, or no longer unique
    2  INFRASTRUCTURE — no token, `gh` missing, an API failure, an unparseable table, or NO ENTRIES

2 is never a verdict, following `scripts/probe_framework_coinstall.py` and
`scripts/check_registry_drift.py`. **Zero entries is exit 2, not exit 0** — an empty scan is the
vacuous pass this whole mechanism exists to remove, and reporting it as "clean" would rebuild the
bug in the fix for it.

Usage:  scripts/check_sibling_quotes.py [--table PATH] [--repo PATH]
"""

from __future__ import annotations

import argparse
import ast
import shutil
import subprocess
import sys
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TABLE = REPO / "python" / "tests" / "test_compatibility_citations_resolve.py"

#: Sibling repos this script is allowed to reach, and the org that owns them. Kept explicit rather
#: than derived from the path so that adding a repo to `QUOTED` cannot silently widen the App token
#: this job asks for — the workflow's `repositories:` list and this tuple must be changed together,
#: and `scripts/test_sibling_quotes_gate.py` asserts they agree.
OWNER = "zer07labs"
SIBLING_REPOS = ("seam-adapters", "seam-aegis")

DRIFT, INFRA = 1, 2


class InfraError(RuntimeError):
    """A condition that prevents establishing a verdict. Never reported as drift."""


def quoted_table(path: Path) -> list[tuple[str, str, str]]:
    """`QUOTED` from the test module, parsed rather than imported.

    Guard-the-guard: a table that parses to zero rows is an `InfraError`, not an empty pass. The
    same reasoning `table_rows` in `probe_framework_coinstall.py` gives — an empty parse makes every
    assertion below vacuous, which is precisely how a gate stops meaning anything.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InfraError(f"cannot read {path}: {exc}") from exc
    except SyntaxError as exc:
        raise InfraError(f"{path} does not parse: {exc}") from exc

    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "QUOTED" for t in node.targets):
            continue
        try:
            rows = ast.literal_eval(node.value)
        except ValueError as exc:
            raise InfraError(
                f"QUOTED in {path.name} is no longer a literal this can evaluate ({exc}). It was "
                f"a list of plain (doc, path, needle) tuples; if it grew a computed entry, this "
                f"script needs teaching rather than skipping."
            ) from exc
        if not rows:
            raise InfraError(f"QUOTED in {path.name} parsed to ZERO rows")
        return [tuple(r) for r in rows]

    raise InfraError(
        f"no `QUOTED = [...]` assignment in {path.name}. Either it was renamed or the mechanism "
        f"was removed; this script has nothing to check and must not report that as clean."
    )


def sibling_entries(rows: list[tuple[str, str, str]]) -> list[tuple[str, str, str, str]]:
    """(doc, repo, path-within-repo, needle) for every row naming a repo we can reach."""
    out = []
    for doc, path, needle in rows:
        rel = path.removeprefix("../")
        repo = rel.split("/", 1)[0]
        if repo in SIBLING_REPOS:
            out.append((doc, repo, rel.split("/", 1)[1], needle))
    return out


def fetch(repo: str, path: str) -> str:
    """The file's text, read through `gh` so the App token is used and nothing is cloned."""
    if shutil.which("gh") is None:
        raise InfraError("`gh` is not installed")
    proc = subprocess.run(
        [
            "gh", "api",
            f"repos/{OWNER}/{repo}/contents/{path}",
            "-H", "Accept: application/vnd.github.raw",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        # A 404 here is ambiguous on purpose: the file may have been renamed (drift) or the token
        # may not reach this repo (infrastructure). It is reported as infrastructure, because
        # calling a permissions problem a stale claim is the wrong error to be confidently wrong
        # about — it sends someone editing a document that is fine.
        raise InfraError(
            f"gh api failed for {OWNER}/{repo}/{path} (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:400]}"
        )
    return proc.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--table", default=str(TABLE), type=Path)
    ap.add_argument("--repo", default=str(REPO), type=Path)
    args = ap.parse_args()

    try:
        rows = quoted_table(args.table)
        entries = sibling_entries(rows)
    except InfraError as exc:
        print(f"::error::{exc}")
        return INFRA

    if not entries:
        print(
            "::error::QUOTED has rows but NONE of them name a reachable sibling repo "
            f"({', '.join(SIBLING_REPOS)}). This job then checks nothing while reporting success — "
            "the vacuous pass it exists to remove. Either an entry was retired (drop this job in "
            "the same commit) or a repo was added to QUOTED without being added to SIBLING_REPOS "
            "and the workflow's `repositories:` list."
        )
        return INFRA

    print(f"checking {len(entries)} sibling quote(s) against {OWNER}/…")

    drift: list[str] = []
    for doc, repo, path, needle in entries:
        try:
            body = fetch(repo, path)
        except InfraError as exc:
            print(f"::error::{exc}")
            return INFRA

        hits = [i + 1 for i, line in enumerate(body.splitlines()) if needle in line]
        if len(hits) != 1:
            drift.append(
                f"::error::  {doc} quotes {needle!r} from {repo}/{path}, which now contains it "
                f"{len(hits)} time(s) (lines {hits or 'none'}).\n"
                f"::error::    0 means the sentence changed or was dropped — the claim in {doc} is "
                f"now unsupported. Re-source it or delete it; do NOT repoint a line number, there "
                f"isn't one.\n"
                f"::error::    >1 means the needle no longer identifies one sentence: LENGTHEN it "
                f"in QUOTED, never relax the check."
            )
            continue

        local = (args.repo / doc).read_text(encoding="utf-8")
        if needle not in local:
            drift.append(
                f"::error::  {repo}/{path} still says {needle!r}, but {doc} no longer quotes it. "
                f"The entry is checking a claim the document stopped making — drop the entry."
            )
            continue

        print(f"  ok {doc} ← {repo}/{path}: {needle}")

    if drift:
        print("\n::error::a quoted sibling claim no longer matches its source.")
        for item in drift:
            print(item)
        return DRIFT

    print(f"\nall {len(entries)} sibling quote(s) still match.")
    return 0


if __name__ == "__main__":
    # 1 is this script's DRIFT verdict and Python also spends 1 on an uncaught exception, so without
    # this a crash reports itself as "a sibling claim went stale" — the same hole closed in
    # `probe_framework_coinstall.py` for seam-sdk#110. `except SystemExit: raise` is load-bearing:
    # without it the handler swallows the real code from `sys.exit(main())` and every run becomes 2.
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 — deliberate; a crash must not read as a verdict
        print(f"::error::check_sibling_quotes crashed: {exc!r}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(INFRA)
