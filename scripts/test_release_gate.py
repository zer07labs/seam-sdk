"""The framing gate can only gate a release if it runs where the repo exists.

`release-on-runtime.yml` refuses to tag when the runtime's wire framing is not one this SDK
implements — it is the one gate that PREVENTS a 0.7.17 rather than reporting one afterwards. It
does that by reading `contract/wire-framing.json` out of the checkout.

It was originally placed before the token mint, on the correct instinct that a refusal should
leave no commit, no tag, and nothing published. But `actions/checkout` has to follow the mint (it
needs the app token), so "before the mint" also meant "before the repo exists". The gate read a
file into an empty working directory, `set -euo pipefail` killed the job, and every release from
2026-08-24 onward failed — four in a row — without the comparison ever running once.

It failed CLOSED, so nothing wrong was published. That is exactly what made it survive: a gate
that always refuses looks, from the outside, like a gate that is working.

These assertions pin the two constraints that were in tension, so the next reorder cannot satisfy
one by breaking the other:

  * the gate runs AFTER checkout   — otherwise it cannot read its own contract file
  * the gate runs BEFORE the stamp — otherwise a refusal arrives after the damage

Run: `python -m pytest scripts/test_release_gate.py -q`
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
RELEASE = REPO / ".github" / "workflows" / "release-on-runtime.yml"

GATE = "The runtime's wire framing must be one this SDK implements"
CHECKOUT = "actions/checkout"
STAMP = "Bump both packages to the runtime version"
TAG = "Commit + tag (triggers publish.yml)"


def _steps() -> list[dict]:
    return yaml.safe_load(RELEASE.read_text())["jobs"]["release"]["steps"]


def _index(predicate, what: str) -> int:
    for i, step in enumerate(_steps()):
        if predicate(step):
            return i
    raise AssertionError(f"{what} is no longer in release-on-runtime.yml — this guard is stale")


def _gate_index() -> int:
    return _index(lambda s: s.get("name") == GATE, f"the framing gate ({GATE!r})")


def _checkout_index() -> int:
    return _index(lambda s: CHECKOUT in str(s.get("uses", "")), "actions/checkout")


def test_the_framing_gate_runs_after_checkout() -> None:
    """The regression itself: a gate reading a repo file before the repo is cloned."""
    gate, checkout = _gate_index(), _checkout_index()
    assert gate > checkout, (
        f"the framing gate is step {gate}, checkout is step {checkout} — the gate reads "
        "contract/wire-framing.json out of the checkout, so running first means it crashes on a "
        "missing file and fails every release closed, which is what happened on 2026-08-24"
    )


def test_the_framing_gate_runs_before_anything_is_stamped_or_tagged() -> None:
    """The invariant the original ordering was protecting — a refusal must leave nothing behind."""
    gate = _gate_index()
    for name in (STAMP, TAG):
        step = _index(lambda s, n=name: s.get("name") == n, f"the {name!r} step")
        assert gate < step, (
            f"the framing gate is step {gate} but {name!r} is step {step} — a refusal that arrives "
            "after the version is stamped or the tag is pushed is not a gate, it is a report"
        )


def test_the_gate_still_reads_a_file_out_of_the_repo() -> None:
    """Guards the guard: the ordering constraint above only matters while this is true.

    If the gate is ever rewritten to take its inputs entirely from the dispatch payload, the
    after-checkout assertion becomes vacuous rather than false — it would keep passing while
    protecting nothing. Failing here forces that rewrite to revisit this file deliberately.
    """
    script = next(s for s in _steps() if s.get("name") == GATE)["run"]
    assert "contract/wire-framing.json" in script, (
        "the framing gate no longer reads contract/wire-framing.json — if that is intentional, "
        "test_the_framing_gate_runs_after_checkout is now asserting nothing and should be revisited"
    )


def test_every_repo_file_the_gate_reads_actually_exists() -> None:
    """The direct form of the failure: FileNotFoundError, from a path nothing checks."""
    script = next(s for s in _steps() if s.get("name") == GATE)["run"]
    paths = set(re.findall(r"open\('([^']+)'\)", script))
    assert paths, "no open('...') call found in the gate — this guard can no longer see its inputs"
    for rel in sorted(paths):
        assert (REPO / rel).is_file(), (
            f"the framing gate reads {rel!r}, which does not exist in the repo — that is the exact "
            "shape of the 2026-08-24 failure, just from a missing file instead of a missing checkout"
        )
