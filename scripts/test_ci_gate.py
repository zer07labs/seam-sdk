"""`ci-ok` is the single check branch protection requires — so its `needs` list IS the gate.

A job left out of that list still runs, still goes red, and still lets the PR merge, because the
gate reports success on everything it was watching. The omission is invisible in review: the new
job's YAML looks entirely correct.

This repo has a second, sharper version of the problem. `python`, `typescript` and `integration`
are conditional on `preflight` outputs, so a PR where a secret does not resolve **skips the SDK's
core test jobs and still shows green**. The gate therefore distinguishes:

  * REQUIRED — must report `success`. A skip means its assertions never ran.
  * ADVISORY — may skip, must not fail. Only `integration`, which needs a live seam-grpc that a
    PR cannot always reach.

Keeping that list minimal is the whole point, so it is asserted here too.

Run: `python -m pytest scripts/test_ci_gate.py -q`
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

CI = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
GATE = "ci-ok"
ALLOWED_ADVISORY = {"integration"}


def _workflow() -> dict:
    return yaml.safe_load(CI.read_text())


def _gate() -> dict:
    return _workflow()["jobs"][GATE]


def _gate_step() -> dict:
    return next(s for s in _gate()["steps"] if isinstance(s, dict) and "run" in s)


def _advisory() -> set[str]:
    raw = _gate_step().get("env", {}).get("ADVISORY", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


def test_gate_exists() -> None:
    assert GATE in _workflow()["jobs"], (
        f"{GATE} is the required status check; renaming it silently disables branch protection, "
        "because GitHub matches required checks by exact name and an absent one never reports."
    )


def test_gate_needs_every_other_job() -> None:
    jobs = set(_workflow()["jobs"]) - {GATE}
    needs = set(_gate()["needs"])
    missing = jobs - needs
    assert not missing, (
        f"these jobs are not gated: {sorted(missing)} — they can fail while {GATE} reports "
        f"success. Add them to the `needs:` list of {GATE}."
    )
    assert not (needs - jobs), (
        f"{GATE} needs jobs that do not exist: {sorted(needs - jobs)}"
    )


def test_gate_runs_even_when_a_dependency_fails() -> None:
    """Without `if: always()` the gate is skipped when a dep fails, and a skipped required check
    blocks the PR without saying which job broke."""
    assert str(_gate().get("if", "")).strip() == "always()"


def test_advisory_list_stays_minimal() -> None:
    """Every name added here is a job allowed to silently not run.

    `python` or `typescript` appearing in this list would mean the SDK can merge with its core
    test suites never executed — which is the exact failure this gate exists to prevent.
    """
    extra = _advisory() - ALLOWED_ADVISORY
    assert not extra, (
        f"{sorted(extra)} were made advisory — they may now skip without failing the build. "
        f"Only {sorted(ALLOWED_ADVISORY)} is justified (it needs a live runtime). If this is "
        "deliberate, widen ALLOWED_ADVISORY here and say why in the same commit."
    )


def test_advisory_jobs_are_actually_gated_jobs() -> None:
    assert _advisory() <= set(_gate()["needs"]), (
        "an ADVISORY name that is not in `needs` matches nothing and does no work — it reads as "
        "an exemption while granting none"
    )


def _script() -> str:
    return _gate_step()["run"].replace("${{ toJSON(needs) }}", "$NEEDS")


def _run(results: dict[str, str]) -> subprocess.CompletedProcess:
    import json

    needs = json.dumps({k: {"result": v} for k, v in results.items()})
    return subprocess.run(
        ["bash", "-c", _script()],
        env={
            "NEEDS": needs,
            "ADVISORY": ",".join(sorted(_advisory())),
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        },
        capture_output=True,
        text=True,
        check=False,  # a non-zero exit IS the thing under test
    )


@pytest.mark.parametrize(
    ("results", "should_pass"),
    [
        ({"python": "success", "integration": "success"}, True),
        # The case this repo actually produces on every PR today.
        ({"python": "success", "integration": "skipped"}, True),
        # Advisory may skip — it may NOT fail.
        ({"python": "success", "integration": "failure"}, False),
        # A required job skipping is the silent-green failure. It must be red.
        ({"python": "skipped", "integration": "skipped"}, False),
        ({"python": "failure", "integration": "skipped"}, False),
        ({"python": "cancelled", "integration": "skipped"}, False),
        ({}, True),
    ],
    ids=[
        "all-success",
        "advisory-skipped",
        "advisory-failed",
        "required-skipped",
        "required-failed",
        "required-cancelled",
        "empty",
    ],
)
def test_gate_script_executes_correctly(
    results: dict[str, str], should_pass: bool
) -> None:
    """Execute the gate's real shell against synthetic job results.

    Asserting on the YAML proves the text says the right thing, not that it behaves that way.
    A `jq` filter that matches nothing under `set -euo pipefail` is precisely how a correct-looking
    gate exits 1 on a perfectly good PR.
    """
    proc = _run(results)
    passed = proc.returncode == 0
    assert passed is should_pass, (
        f"gate exit={proc.returncode} for {results}\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    if not should_pass:
        assert "not every required job succeeded" in proc.stdout + proc.stderr


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-v"]))
