"""`ci-ok` is the single check branch protection requires — so its `needs` list IS the gate.

A job left out of that list still runs, still goes red, and still lets the PR merge, because the
gate reports success on everything it was watching. The omission is invisible in review: the new
job's YAML looks entirely correct.

This repo has a second, sharper version of the problem. `python`, `typescript` and `integration`
are conditional on `preflight` outputs, so a PR where a secret does not resolve **skips the SDK's
core test jobs and still shows green**. The gate therefore distinguishes:

  * REQUIRED — must report `success`. A skip means its assertions never ran.
  * ADVISORY — may skip, must not fail. `integration` and `spec-pin`, each of which needs a secret
    a fork PR cannot have. Advisory is not tolerance: one of these RUNNING and FAILING still
    blocks the merge.

Keeping that list minimal is the whole point, so it is asserted here too.

Run: `python -m pytest scripts/test_ci_gate.py -q`
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

CI = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"

#: The credential-free lane — the only job that runs without BUF_TOKEN (see seam-sdk#54).
LANE = "workflow-guards"
GATE = "ci-ok"

#: Jobs allowed to SKIP without reddening the gate. Both are here for the same reason and no
#: other: they need a secret a fork PR cannot have, so requiring them outright would block every
#: outside contribution forever. Advisory does NOT mean tolerated — a job in this set that RUNS
#: and FAILS still blocks the merge.
#:
#:   * integration — needs a live seam-grpc, lifted from the published (internal) seamd image via a
#:     scoped seam-deps-bot App token. It had ALWAYS skipped until 2026-08-25, because it gated on a
#:     `RUNTIME_REPO_TOKEN` that was never configured anywhere — a job in every check list that had
#:     never once executed. That is the sharpest argument for this file existing: advisory made the
#:     silence survivable, and nothing else would have noticed.
#:   * spec-pin    — reads the private runtime spec it compares against (via a scoped seam-deps-bot
#:     App token), which a fork PR's secretless run cannot do. It is
#:     the only job that can check the vendored copy at all, because the proof lives in another
#:     repository; drift blocking the merge was a deliberate call, since the copy went stale three
#:     times and a warning would have been ignored a fourth. Its CHECKER is separately exercised
#:     in `workflow-guards`, which needs no credential, so a fork PR still proves the logic.
ALLOWED_ADVISORY = {"integration", "spec-pin"}


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
        f"Only {sorted(ALLOWED_ADVISORY)} are justified, and only because each needs a secret a "
        f"fork PR cannot have. If this is deliberate, widen ALLOWED_ADVISORY here and say why in "
        f"the same commit."
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


def test_credential_free_lane_keeps_what_it_claims_to_prove() -> None:
    """`workflow-guards` is the lane that proves the seam-sdk#54 guard needs nothing but a checkout.

    Its own comment says "the install list is itself the assertion" — which was, until this test,
    an assertion nobody made. Both halves can be dropped while CI stays green, and dropping the
    grpcio install is the quiet one: the import-light guard's two standalone-load tests skip
    themselves as an environment gap, the run still exits 0, and the runtime half of the contract
    silently stops being checked. (Stated as a shape, not a pass/skip count — the count moves every
    time a test is added to that file, and a stale number here would be the same defect this test
    exists to prevent.)

    Deliberately narrow. This pins only that the lane still installs the dependency and still runs
    the file — not how, so `uv pip install` or a different pytest invocation is free to land.
    """
    jobs = _workflow()["jobs"]
    assert LANE in jobs, (
        f"the {LANE!r} job is gone or renamed. It is the only lane that runs without BUF_TOKEN, so "
        f"the seam-sdk#54 guard's credential-independence stops being demonstrated — update this "
        f"test deliberately rather than deleting the lane."
    )
    steps = jobs[LANE]["steps"]
    runs = "\n".join(str(step.get("run", "")) for step in steps)

    # One entry per import-light module's third-party dependency. A missing one does not redden the
    # guard — it makes that module's standalone-load checks SKIP as an environment gap and the lane
    # exits 0, proving less than it claims. That silent degradation is the whole reason this asserts
    # the install list rather than trusting it.
    for dep, module in (("grpcio", "errors.py"), ("cryptography", "crypto.py")):
        assert dep in runs, (
            f"workflow-guards no longer installs {dep}. {module} imports it, so without it "
            f"test_errors_is_import_light.py skips that module's standalone-load checks and exits "
            f"0 — the lane reports success while proving less than it claims (seam-sdk#54)."
        )
    assert "test_errors_is_import_light.py" in runs, (
        "workflow-guards no longer runs the import-light guard. It also runs in the `python` job, "
        "so nothing goes red — but `python` needs BUF_TOKEN and generated code, which is exactly "
        "the coupling this lane exists to disprove (seam-sdk#54)."
    )
    assert any("setup-python" in str(step.get("uses", "")) for step in steps), (
        "workflow-guards no longer pins a Python. The import-light guard skips itself entirely "
        "below 3.10 (sys.stdlib_module_names), so an ambient runner Python can turn this lane "
        "into a green no-op."
    )

    # The negative half, and the one the ci.yml comment is actually about. Asserting what the lane
    # HAS says nothing about what it acquired along the way: `buf` plus a BUF_TOKEN login could be
    # added here and every other assertion above would stay green, while the claim the lane exists
    # to demonstrate — that this guard needs no credential and no generated code — quietly stopped
    # being true.
    body = yaml.safe_dump(jobs[LANE])
    for banned, why in (
        ("BUF_TOKEN", "a credential"),
        ("buf-setup-action", "the contract toolchain"),
        ("make generate", "generated code"),
    ):
        assert banned not in body, (
            f"{LANE} acquired {banned!r} ({why}). This lane's whole claim is that the seam-sdk#54 "
            f"guard runs on a bare checkout — a lane that needs a token proves the opposite of what "
            f"its comment says, and the `python` job already covers the credentialed case."
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


def test_the_pytest_step_sets_seam_require_wheel_build() -> None:
    """Phase 4's whole packaging repair rests on this one workflow cell, and nothing asserted it.

    `test_packaging.py` classifies three distinct outcomes — no builder present, the builder ran and
    failed, the builder exited 0 without producing a `seam_sdk-*.whl` — and locally the first is a
    legitimate SKIP. `SEAM_REQUIRE_WHEEL_BUILD=1` is what turns all three into failures on CI, where
    a skip has no legitimate cause. Delete the env cell and the packaging tests silently go back to
    skipping: measured by the whole-feature verification round, python stayed at 1184 passed and
    `scripts` at 116.

    This is the shape Phase 1 found and closed for the release workflow — unguarded plumbing cells
    that decide whether a gate is a gate — landing one file over without the structural assertion.
    """
    steps = yaml.safe_load(CI.read_text())["jobs"]["python"]["steps"]
    pytest_steps = [s for s in steps if s.get("name") == "pytest"]
    assert len(pytest_steps) == 1, (
        f"expected exactly one step named 'pytest' in ci.yml's `python` job, found "
        f"{len(pytest_steps)}. If it was renamed or split, re-point this assertion."
    )
    env = pytest_steps[0].get("env") or {}
    assert str(env.get("SEAM_REQUIRE_WHEEL_BUILD")) == "1", (
        "ci.yml's `python` -> pytest step no longer sets SEAM_REQUIRE_WHEEL_BUILD: \"1\". Without "
        "it every packaging failure mode degrades to a SKIP on CI, and a skipped packaging test is "
        "indistinguishable from a passing one in the summary — which is how a broken wheel ships."
    )


def test_every_scripts_test_file_runs_in_ci() -> None:
    """The `workflow-guards` job names its test files one by one, so a new one never runs.

    Six `python -m pytest scripts/test_*.py` steps, each a hardcoded filename. The list happens to
    be complete today, which is exactly the state in which nobody notices it is a list: adding
    `scripts/test_whatever.py` gets it collected locally and never on CI, so it can sit red — or
    absent — indefinitely. `python/tests/` is guarded by a directory-scoped run; `scripts/` is not.

    Asserting the set rather than switching the workflow to `pytest scripts/` on purpose: the
    per-file steps give a named check per gate in the PR's check list, which is worth keeping. What
    was missing is anything that fails when the list and the directory disagree.
    """
    on_disk = {p.name for p in (CI.parents[2] / "scripts").glob("test_*.py")}
    steps = yaml.safe_load(CI.read_text())["jobs"][LANE]["steps"]
    run_in_ci = {
        token.split("/")[-1]
        for step in steps
        for token in (step.get("run") or "").split()
        if token.startswith("scripts/test_") and token.endswith(".py")
    }
    assert on_disk == run_in_ci, (
        f"scripts/ holds {sorted(on_disk)} but ci.yml's `{LANE}` job runs {sorted(run_in_ci)}. "
        f"Unrun: {sorted(on_disk - run_in_ci)}. Stale: {sorted(run_in_ci - on_disk)}. A test file "
        "that never runs in CI is not a gate — add a step for it, or delete it."
    )


#: The job that spawns a real `seam-grpc` and runs the suites that need one.
INTEGRATION = "integration"

#: Where the live-suite roster lives. `python/tests/test_live_fixtures_are_isolated.py` already
#: keeps this tuple COMPLETE — `test_no_unregistered_file_spawns_a_server` scans the directory and
#: fails on any unregistered file that spawns a server, with its own anti-vacuity floor. So the set
#: is trustworthy; what nothing checked is whether CI actually RUNS it.
LIVE_ROSTER = (
    Path(__file__).resolve().parents[1]
    / "python"
    / "tests"
    / "test_live_fixtures_are_isolated.py"
)


def _registered_live_suites() -> set[str]:
    """`LIVE_SUITES`, parsed out of the roster module rather than imported.

    Parsed for the same reason the floor tests are: importing it would execute a pytest module from
    a different directory, drag in its fixtures, and make this credential-free lane depend on the
    python package being installed. `ast.literal_eval` on the tuple is exact and needs nothing.
    """
    tree = ast.parse(LIVE_ROSTER.read_text(encoding="utf-8"), filename=str(LIVE_ROSTER))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "LIVE_SUITES" for t in node.targets
        ):
            return set(ast.literal_eval(node.value))
    raise AssertionError(
        f"{LIVE_ROSTER.name} no longer defines LIVE_SUITES at module level. That tuple is the "
        "roster this test joins to ci.yml; if it moved, this guard is now checking nothing and "
        "must be repointed rather than deleted."
    )


def _live_suites_ci_runs() -> set[str]:
    """The test files named by the integration job's pytest step(s).

    Scoped to steps that actually set `SEAM_GRPC_BIN`, because that env var is what turns the
    helper's `pytest.skip` into a real run. A step without it would name the files and still skip
    every one of them — which is the failure being guarded, so it must not count as coverage.
    """
    job = yaml.safe_load(CI.read_text())["jobs"][INTEGRATION]
    found: set[str] = set()
    for step in job["steps"]:
        if "SEAM_GRPC_BIN" not in (step.get("env") or {}):
            continue
        for token in (step.get("run") or "").split():
            if token.startswith("tests/") and token.endswith(".py"):
                found.add(token.rsplit("/", 1)[-1])
    return found


def test_ci_runs_every_registered_live_suite() -> None:
    """The roster and the CI invocation must be the same set.

    This list has ALREADY been wrong once, and the comment above it in `ci.yml` records what that
    cost: it ran two of four, so `test_streamed_decode.py` and `test_verify_attestation.py`
    self-skipped in CI forever while `npm test` ran their TypeScript twins in full. A stale
    `schema_version == 2` assertion survived on the Python side because of it, and was caught only
    because the TS twin happened to disagree. It was then fixed by hand, with nothing added to stop
    a recurrence.

    A grep for `SEAM_GRPC_BIN` would NOT have caught that: `test_streamed_decode.py` never mentions
    the variable. It gates transitively, by calling `live_server.spawn_server` without a `binary=`
    override. Joining to the roster rather than to a text search is what makes this guard see the
    exact file the original bug hid.

    Set equality, not containment, for the reason its sibling `test_every_scripts_test_file_runs_in_ci`
    gives: containment catches only the new-file direction, and a step still naming a deleted file
    is the other half of the same disagreement.
    """
    registered = _registered_live_suites()
    in_ci = _live_suites_ci_runs()
    assert registered == in_ci, (
        f"the live-suite roster and ci.yml's `{INTEGRATION}` job disagree.\n"
        f"  registered in LIVE_SUITES: {sorted(registered)}\n"
        f"  run by CI with SEAM_GRPC_BIN: {sorted(in_ci)}\n"
        f"  NEVER RUN in CI (self-skip forever): {sorted(registered - in_ci)}\n"
        f"  named by CI but not registered: {sorted(in_ci - registered)}\n"
        "A live suite CI does not name is not a gate — it reports pass having spawned nothing."
    )


def test_the_live_suite_join_is_not_vacuous() -> None:
    """Both sides of the equality must be non-empty.

    If the roster parse or the step scan silently returned nothing, the equality above would hold
    as `set() == set()` and this guard would pass while asserting nothing — the exact shape it was
    written to close, one level up. The roster module pins its own count at four; this pins that
    the join actually found files on the CI side too.
    """
    registered = _registered_live_suites()
    in_ci = _live_suites_ci_runs()
    assert registered, "parsed LIVE_SUITES as empty — the roster parse is broken"
    assert in_ci, (
        "found no live-suite files in any integration step that sets SEAM_GRPC_BIN — either the "
        "job was restructured or the env var moved, and this guard can no longer see coverage"
    )
