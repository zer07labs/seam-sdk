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
import re
import subprocess
import sys
from importlib.metadata import packages_distributions
from pathlib import Path

import pytest
import yaml

CI = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
SCRIPTS = Path(__file__).resolve().parent

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

    One `python -m pytest scripts/test_*.py` step per file, each naming its filename literally.
    (Deliberately not stating how many: the count was written as "six" and was eight two commits
    later, which is the same staleness this assertion exists to catch, one level up.) The list
    happens to be complete today, which is exactly the state in which nobody notices it is a list:
    adding
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


# ── Every third-party import in scripts/ is installed by the lane that runs it ────────────────
#
# `python/tests/` has this guard: `test_test_dependencies_are_declared.py` walks each test
# module's AST and fails when an import is not in the `dev` extra. `scripts/` has never had one.
#
# Be precise about what it is worth, because two drafts of this section overstated it. The first
# called it an outage; it is not. `workflow-guards` runs pytest ONCE PER FILE (the `run:` steps
# below `pip install`), so an undeclared import reddens exactly its own step, on the PR that
# introduces it, under a named check. The second draft then claimed the resulting failure carries
# no useful traceback — and that is simply false. Run it: pytest prints the importing line and
# `E ModuleNotFoundError: No module named 'requests'`. What is actually true is narrower, and
# still worth having:
#
#   * It fails LOCALLY, by name, before the push. The local venv carries far more than the lane's
#     install line does, so today that asymmetry surfaces only on the runner.
#   * `ModuleNotFoundError` names the MODULE. Where module and distribution differ — `import yaml`
#     wanting `pyyaml`, `import grpc` wanting `grpcio` — it does not name the thing you have to
#     add to the install line. This guard does, whenever it can resolve one: from
#     `packages_distributions()` if the module is installed locally (the usual case, since whoever
#     added the import has it), or from `_MODULE_ALIASES`. Failing both it falls back to the
#     module name and says no more than `ModuleNotFoundError` would.
#
# That is the whole claim. It is a real improvement and a small one.

#: Module name -> distribution, for the cases where they differ and `packages_distributions()`
#: cannot help (it only knows what is installed in the interpreter running the test, which on a
#: developer's machine is a superset of the lane and on the lane is exactly it).
_MODULE_ALIASES = {"yaml": "pyyaml", "grpc": "grpcio", "_pytest": "pytest"}

#: `pip install` flags that take no value, so whatever follows them is still a distribution.
#: Deliberately an allowlist rather than a "skip anything starting with `-`" rule: a flag that
#: DOES take a value (`-r`, `-c`, `--index-url`) makes the next token a filename or a URL, and
#: reading that as a distribution widens the install set — see `_installs_in` on why widening is
#: the one direction that must never happen quietly.
_VALUELESS_PIP_FLAGS = frozenset(
    {
        "-q",
        "--quiet",
        "-U",
        "--upgrade",
        "--no-deps",
        "--no-cache-dir",
        "--no-input",
        "--pre",
        "--user",
        "--force-reinstall",
        "--disable-pip-version-check",
    }
)

#: A `pip install` argument that is a distribution: a PEP 508 name, optional extras, optional
#: version specifier. A line-continuation `\`, a quoted fragment, a URL and a `$VAR` do not match,
#: and `_installs_in` refuses rather than guessing.
#:
#: It does NOT reject `requirements.txt` — and cannot, because a `.` is legal in a distribution
#: name (`zope.interface`, `ruamel.yaml`), so no regex separates the two. A requirements file is
#: excluded upstream instead: pip only reads one behind `-r`/`-c`, and those are not in
#: `_VALUELESS_PIP_FLAGS`, so the flag raises before the filename is ever looked at.
_DIST_ARG = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(?:[<>=!~][^\s]*)?$")

#: What may legally sit between the start of a shell command and `pip install`. Empty, or the
#: `python -m` form. Anything else — `echo`, `sudo`, half a sentence — means this is not a pip
#: invocation at all, and the words after it are prose rather than distributions.
_PIP_PREFIX = re.compile(r"\s*(?:python3?\s+-m\s+)?")


def _normalize_dist(name: str) -> str:
    """PEP 503 name normalization — `PyYAML`, `pyyaml` and `py_yaml` are one distribution."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _installs_in(steps: list[dict]) -> set[str]:
    """The distributions a job's steps install, read out of their `run:` blocks.

    Split from `_lane_installs` so the shapes this parser must refuse can be handed to it
    directly. Exercising them through the real file would mean editing `ci.yml` to test the guard
    that reads `ci.yml`.

    **This parser fails loudly or not at all.** Every other outcome of a misread is survivable: a
    distribution wrongly dropped makes the guard below fire, noisily, on an import that is in fact
    declared, and a human sorts it out in a minute. The unsurvivable outcome is a set that GREW.
    `installed` is only ever intersected against, so one token wrongly read as a distribution
    makes the guard quietly more permissive — it goes green while a genuinely undeclared import
    sits in the tree, which is precisely the silent-pass this whole file exists to prevent. So an
    unrecognised token raises, and an unrecognised flag raises rather than being assumed
    valueless. Parsing per shell COMMAND, not per `run:` block and not per line, is part of the
    same discipline. Splitting the block on lines was not enough: `echo run pip install requests
    here` contains the substring, and a substring match happily read `requests` and `here` as
    distributions. What identifies a pip invocation is what comes BEFORE `pip install` — nothing,
    or `python -m` — so that is what is checked, and prose is refused for being prose rather than
    for happening to contain a stray quote.
    """
    found: set[str] = set()
    for step in steps:
        for line in str(step.get("run") or "").splitlines():
            for segment in re.split(r"[;&|]+", line):
                before, sep, after = segment.partition("pip install")
                if not sep:
                    continue
                # A `#` to its left makes this a shell comment. `run:` blocks are YAML block
                # scalars, so `safe_load` leaves shell comments in the string for us to skip.
                if "#" in before:
                    continue
                assert _PIP_PREFIX.fullmatch(before), (
                    f"`{segment.strip()}` in {CI.name} contains `pip install` but is not a pip "
                    f"invocation — {before.strip()!r} precedes it. The words after it are prose, "
                    "not distributions, and reading them as distributions would widen the install "
                    "set silently. If this really is an install command, this parser needs to "
                    "learn its shape."
                )
                for tok in re.split(r"[#]", after)[0].split():
                    if tok.startswith("-"):
                        assert tok in _VALUELESS_PIP_FLAGS, (
                            f"`{tok}` appears on a `pip install` line in {CI.name} and this "
                            "parser does not know it. If it takes a value, the token after it is "
                            "a path or a URL rather than a distribution, and reading it as one "
                            "would widen the install set silently. Add it to "
                            "`_VALUELESS_PIP_FLAGS` only if it takes no value."
                        )
                        continue
                    matched = _DIST_ARG.match(tok)
                    assert matched, (
                        f"`{tok}` follows `pip install` in {CI.name} but is not a distribution "
                        "specifier. The `run:` shape changed — a line continuation, a quoted "
                        "fragment, a `$VAR` — and this parser cannot read it. It refuses rather "
                        "than guessing, because a wrong guess here only ever ADDS to the install "
                        "set, which makes the guard below pass when it should not."
                    )
                    found.add(_normalize_dist(matched.group("name")))
    return found


def _lane_installs() -> set[str]:
    """The distributions `workflow-guards` actually installs, read out of `ci.yml`.

    Parsed rather than hardcoded. A copy of `{pyyaml, pytest, grpcio, cryptography}` in this file
    would go stale the day that line changes, and a guard that asserts yesterday's install list
    is worse than none — it would pass while the lane no longer installs what a test imports.
    """
    return _installs_in(yaml.safe_load(CI.read_text())["jobs"][LANE]["steps"])


def _third_party_imports_in(source: str, filename: str = "<source>") -> set[str]:
    """The top-level non-stdlib modules `source` imports, in every form Python offers.

    Split out of the directory scan so the import forms it must catch can be pinned against
    source text rather than against whichever forms `scripts/` happens to use this week. Three of
    the branches below are exercised by no file in the tree today — an untested branch is an
    unprotected one, and the point of a scan is that it keeps working for the import nobody has
    written yet.

    Parsed with `ast`, not grepped: `ast` sees the import whatever the formatting and — unlike a
    regex — cannot be fooled by the word `import` inside a docstring or a string literal, of
    which these files have many. That is load-bearing rather than stylistic. `test_publish_gate.py`
    carries `from google.protobuf import runtime_version` inside a string constant, and a grep
    would report `protobuf` as an undeclared dependency of a file that does not import it.

    `__import__(...)` and `importlib.import_module(...)` are out of contract: a dynamic import is
    invisible to a static walk, here and in the `python/tests/` sibling alike.
    """
    tops: set[str] = set()
    for node in ast.walk(ast.parse(source, filename=filename)):
        if isinstance(node, ast.Import):
            mods = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            # `level > 0` is a relative import — impossible here (`scripts/` is not a package),
            # and first-party by construction anywhere else.
            mods = [node.module] if node.module and node.level == 0 else []
        else:
            continue
        tops |= {
            top
            for top in (m.split(".")[0] for m in mods)
            if top not in sys.stdlib_module_names
        }
    return tops


def _scripts_third_party_imports() -> dict[str, set[str]]:
    """Top-level third-party module -> the `scripts/test_*.py` files importing it.

    There is deliberately **no first-party exemption**. `scripts/` is not a package, and the
    sibling guards load their subject with `importlib.util.spec_from_file_location` rather than
    importing it. So a plain `import check_registry_drift` SHOULD fail here — it would work
    locally, where pytest prepends the test's directory to `sys.path`, and it would fail on the
    lane with exactly the collection error this guard exists to move forward in time.

    Nothing in `scripts/` currently uses the `try: … except ImportError:` optional-dependency
    idiom, so unlike the `python/tests/` sibling this makes no exemption for it. If one is ever
    needed, this guard will flag it — and the answer is to mirror the sibling's exemption
    deliberately, not to widen this scan.
    """
    found: dict[str, set[str]] = {}
    for path in sorted(SCRIPTS.glob("test_*.py")):
        for top in _third_party_imports_in(path.read_text(encoding="utf-8"), str(path)):
            found.setdefault(top, set()).add(path.name)
    return found


def _candidate_dists(mod: str) -> set[str]:
    """Distributions a top-level module could come from.

    `packages_distributions()` is authoritative but only knows what is installed in the
    interpreter running this test. `_MODULE_ALIASES` is the fallback for when it is not — a
    contributor whose venv lacks `grpcio` would otherwise see `import grpc` resolve to a
    distribution literally named `grpc`, which is not on the lane's install line, and get a
    confident failure about a dependency that is in fact declared.
    """
    resolved = _MODULE_ALIASES.get(mod, mod)
    dists = packages_distributions().get(mod) or packages_distributions().get(resolved) or []
    return {_normalize_dist(d) for d in dists} or {_normalize_dist(resolved)}


def _undeclared_imports(third_party: dict[str, set[str]], installed: set[str]) -> list[str]:
    """The verdict, as data: one line per module the lane does not install.

    Returned rather than asserted so that the test proving this can FIRE runs the same predicate
    the real guard runs. A negative test that reimplements the comparison proves only that the
    reimplementation works — and the comparison is the one line here worth protecting, since
    stubbing it out to `if False:` leaves every other assertion in this section green.
    """
    undeclared: list[str] = []
    for mod, importers in sorted(third_party.items()):
        candidates = _candidate_dists(mod)
        if not (candidates & installed):
            undeclared.append(
                f"  `import {mod}` in {', '.join(sorted(importers))} -> distribution "
                f"{sorted(candidates)}, which the `{LANE}` lane does not install"
            )
    return undeclared


def _scan_and_verdict(
    extra: dict[str, set[str]] | None = None,
) -> tuple[dict[str, set[str]], set[str], list[str]]:
    """The scan, the install list, and the verdict — the whole pipeline, in one place.

    The guard, the anti-vacuity floors and the wiring canary all read THIS. With a call site each,
    narrowing or emptying the guard's input left the floors looking at a different, healthy scan
    and every assertion in this section green — `if False:` moved up a level.

    `extra` exists because on a healthy tree the verdict is `[]` no matter what, so no assertion
    over the real result can tell a scan that ran from one that was replaced by `{}`. Injecting a
    known-undeclared module gives the pipeline something it MUST say, which is the only way to
    observe from the outside that the pipeline is still connected. See the canary test below.
    """
    third_party = {**_scripts_third_party_imports(), **(extra or {})}
    installed = _lane_installs()
    return third_party, installed, _undeclared_imports(third_party, installed)


#: A module name no distribution has ever carried, so it resolves through the identity fallback and
#: can never accidentally intersect the lane's install list.
_CANARY_MODULE = "nodistributionisnamedthis"


def test_the_guard_is_wired_to_the_scan_and_not_to_an_empty_one() -> None:
    """Pin the pipeline itself, not just its parts.

    Both halves were already pinned: `_undeclared_imports` fires on a bad module, and the floors
    prove the scan sees seven files. Neither notices if the wiring BETWEEN them is cut — hand the
    comparison `{}` and the verdict is `[]`, which is exactly what a healthy tree produces, so the
    guard passes, the floors pass, and the whole section is decorative.

    Driving one known-undeclared module through the real pipeline is what makes that observable:
    an empty input cannot produce a finding, so silence here means the wiring is cut.
    """
    _, _, verdict = _scan_and_verdict({_CANARY_MODULE: {"test_zz_canary.py"}})
    assert len(verdict) == 1, (
        f"the pipeline was handed a module the lane cannot install and said {verdict!r}. Its "
        "input is not the scan."
    )
    assert _CANARY_MODULE in verdict[0] and "test_zz_canary.py" in verdict[0], verdict[0]


def test_every_scripts_test_import_is_installed_by_the_guards_lane() -> None:
    """An import the lane does not install fails at collection, on the runner, not here.

    It passes locally, where the venv carries far more than the lane's install line does — the
    exact asymmetry that made `python/tests/` need the same guard. This moves it forward to a
    local run, and names the distribution rather than the module.
    """
    _, _, undeclared = _scan_and_verdict()
    assert not undeclared, (
        f"A scripts/ test imports something `{LANE}` does not install:\n"
        + "\n".join(undeclared)
        + "\n\nOn the runner that import fails at COLLECTION, so the step aborts before running "
        f"a single test. Add the distribution to the `pip install` line in {CI.name}'s `{LANE}` "
        "job — or, if the import is of a sibling script, load it with "
        "`importlib.util.spec_from_file_location` as the other gate tests do."
    )


@pytest.mark.parametrize(
    "mod",
    [
        # A real distribution that the lane genuinely does not install. Resolves identically
        # whether or not the developer's venv happens to carry it.
        "requests",
        # And one that exists nowhere, so the identity fallback is the only path to a verdict.
        "nodistributionisnamedthis",
    ],
)
def test_the_undeclared_import_check_fires_on_an_import_the_lane_lacks(mod: str) -> None:
    """The guard above has teeth, and this is the committed proof of it.

    Without this, `if not (candidates & installed):` can be replaced by `if False:` and the whole
    file stays green — the headline assertion would be unfalsifiable, which is the failure this
    repo keeps rediscovering. Red-first by hand does not count: the synthetic file gets deleted
    and the proof leaves with it.
    """
    verdict = _undeclared_imports({mod: {"test_zz_synthetic.py"}}, _lane_installs())
    assert len(verdict) == 1, f"`import {mod}` produced no verdict at all: {verdict}"
    assert mod in verdict[0], f"the verdict names no module: {verdict[0]}"
    assert "test_zz_synthetic.py" in verdict[0], (
        f"the verdict does not say which file to fix: {verdict[0]}"
    )


@pytest.mark.parametrize("mod", ["yaml", "pytest", "grpc", "cryptography"])
def test_the_undeclared_import_check_stays_silent_on_a_declared_import(mod: str) -> None:
    """The other half: it must not fire on the four the lane does install.

    One of these is the whole reason `_MODULE_ALIASES` exists — `yaml` and `grpc` are named
    nothing like the distributions carrying them, and a guard that flagged those would be
    uninstallable noise from its first run.
    """
    assert _undeclared_imports({mod: {"test_ci_gate.py"}}, _lane_installs()) == []


@pytest.mark.parametrize(
    ("label", "source", "expected"),
    [
        ("plain", "import requests", {"requests"}),
        ("dotted", "import requests.adapters", {"requests"}),
        ("aliased", "import requests as r", {"requests"}),
        ("multi-name", "import os, requests, yaml", {"requests", "yaml"}),
        ("from", "from requests import get", {"requests"}),
        ("from-dotted", "from requests.adapters import HTTPAdapter", {"requests"}),
        ("from-multi", "from requests import get, post", {"requests"}),
        ("from-aliased", "from requests import get as g", {"requests"}),
        ("function-level", "def f():\n    import requests\n", {"requests"}),
        ("class-level", "class C:\n    from requests import get\n", {"requests"}),
        ("conditional", "if True:\n    import requests\n", {"requests"}),
        (
            "type-checking",
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import requests\n",
            {"requests"},
        ),
        # No optional-dependency exemption, deliberately — see `_scripts_third_party_imports`.
        (
            "try-except-ImportError",
            "try:\n    import requests\nexcept ImportError:\n    requests = None\n",
            {"requests"},
        ),
        ("stdlib-plain", "import os", set()),
        ("stdlib-dotted", "import os.path", set()),
        ("stdlib-from", "from pathlib import Path", set()),
        ("future", "from __future__ import annotations", set()),
        ("relative-bare", "from . import sibling", set()),
        ("relative-parent", "from .. import cousin", set()),
        ("relative-named", "from .sibling import thing", set()),
        # The reason this is `ast` and not a regex.
        ("string-literal", 'X = "import requests"', set()),
        ("docstring", '"""Never import requests from here."""', set()),
        # Out of contract, asserted so the boundary is written down rather than assumed.
        ("dynamic-dunder", '__import__("requests")', set()),
        ("dynamic-importlib", 'importlib.import_module("requests")', set()),
    ],
)
def test_the_scan_sees_every_static_import_form(
    label: str, source: str, expected: set[str]
) -> None:
    """Each import form, pinned against source text instead of against today's `scripts/`.

    Most of these forms appear in no file in the tree, so the branches handling them carry no
    regression protection from the directory scan alone — `from X import y` for a third-party `X`
    is the sharpest case: deleting its branch entirely changes no real verdict.
    """
    assert _third_party_imports_in(source, filename=f"<{label}>") == expected


def test_the_scripts_import_scan_is_not_vacuous() -> None:
    """Guard the guard: an empty scan satisfies the headline test above for free.

    Every quantity below is derived from what the scan RETURNED, never from an independent
    re-glob of the directory. That distinction is the whole point. An earlier draft floored
    `len(sorted(SCRIPTS.glob("test_*.py")))`, which measures the repository rather than the scan —
    so a filter narrowed to `pytest` (verbatim the case its own docstring claimed to cover) and a
    walk that opened a single file both sailed through, and the no-glob case reported "across 7
    files" while the scan had in fact opened none.
    """
    third_party, installed, verdict = _scan_and_verdict()
    files_seen: set[str] = set().union(*third_party.values()) if third_party else set()

    assert not verdict, f"the real scan should be clean; got {verdict}"
    assert installed, "the lane install list parsed empty"
    assert "pytest" in third_party, (
        f"the scan found no `pytest` import across the {len(files_seen)} files it actually "
        "opened — the glob, the walk, or the filter is returning nothing"
    )
    assert len(third_party) >= 2, (
        f"the scan resolved to {sorted(third_party)}. Two is not headroom, it is the semantic "
        "floor: with only the sentinel surviving there is no way to distinguish a working scan "
        "from one filtered down to `pytest` itself."
    )
    assert len(files_seen) >= 5, (
        f"only {len(files_seen)} scripts/test_*.py files contributed an import (7 at the commit "
        "that added this, all seven of them). The roster is stable and slowly growing, so a drop "
        "below 5 means the glob or the walk broke, not that the tests were deleted."
    )


def test_the_lane_install_list_is_read_not_assumed() -> None:
    """The parse must actually find the install line, or every check above passes vacuously.

    If `_lane_installs()` returned an empty set, `candidates & installed` would be empty for every
    module and the guard above would fail loudly — so this is not protecting against silence. It
    is protecting against the opposite: a parse that returns something plausible but wrong (say,
    the flags rather than the packages) would produce a confusing failure rather than a clean one.
    """
    installed = _lane_installs()
    assert {"pyyaml", "pytest"} <= installed, (
        f"parsed the `{LANE}` install list as {sorted(installed)}, which is missing distributions "
        f"the lane demonstrably installs. The `run:` line shape in {CI.name} changed and this "
        "parser did not follow it."
    )
    assert not any(tok.startswith("-") for tok in installed), (
        f"parsed a flag as a distribution: {sorted(installed)}. The token filter is wrong."
    )


_FOUR = {"pyyaml", "pytest", "grpcio", "cryptography"}
_TWO = {"pyyaml", "pytest"}


@pytest.mark.parametrize(
    ("label", "run_block", "expected"),
    [
        ("the real shape", "pip install --quiet pyyaml pytest grpcio cryptography", _FOUR),
        ("python -m form", "python -m pip install pyyaml pytest", _TWO),
        ("extras and pins", "pip install pyyaml pytest==8.4.2 grpcio[extra] cryptography", _FOUR),
        # The degradation that mattered: a multi-line block contributes only its install line.
        ("multi-line block", "set -euo pipefail\npip install pyyaml pytest\necho done\n", _TWO),
        ("commented-out line", "# pip install requests everywhere\npip install pyyaml pytest", _TWO),
        ("separator ends it", "pip install pyyaml pytest && echo installed requests", _TWO),
        # A `#` anywhere left of `pip install` used to drop the whole line, so a real install
        # sharing a line with a quoted `#` silently vanished from the set. Narrowing is the safe
        # direction, but it is still wrong.
        ("hash left of a real install", 'echo "#1 priority" && pip install pytest', {"pytest"}),
    ],
)
def test_the_parser_reads_the_run_shapes_it_is_meant_to(
    label: str, run_block: str, expected: set[str]
) -> None:
    """Shapes the parser must handle, including the two it used to mis-handle by widening.

    Asserted as an exact set, not a count: the widening bugs produced sets of the right size for
    the wrong reason (`requests` in, `grpcio` out reads as two either way).
    """
    assert _installs_in([{"run": run_block}]) == expected, label


@pytest.mark.parametrize(
    ("label", "run_block"),
    [
        # UNQUOTED prose is the one that matters. The quoted form below was refused even by the
        # substring parser, but only because the closing `"` made a token unparseable — an
        # accident, not detection. Both are here so a regression cannot hide behind the lucky one.
        ("unquoted prose", "echo run pip install requests here"),
        ("a sentence a human would write", "echo If it fails, pip install requests first"),
        ("quoted prose", 'echo "you probably want to pip install requests here"'),
        ("line continuation", "pip install pyyaml \\\n  requests\n"),
        ("requirements file", "pip install -r requirements.txt"),
        ("index url", "pip install --index-url https://example.invalid/simple pytest"),
        ("editable path", "pip install -e ./python[dev]"),
        ("a shell variable", "pip install $EXTRA_DEPS"),
    ],
)
def test_a_run_shape_the_parser_cannot_read_refuses_instead_of_widening(
    label: str, run_block: str
) -> None:
    """An unreadable shape must raise, not quietly contribute whatever it managed to parse.

    This is the asymmetry `_installs_in` documents, made checkable. Each of these previously
    returned a plausible-looking set that was too LARGE — `requests` and `here` from a sentence
    about pip — and `installed` only ever widens the guard. A guard that grew permissive without
    saying so is the same silent pass the section opens by describing.

    The prose cases are refused for the right reason now: what identifies a pip invocation is what
    precedes `pip install` (nothing, or `python -m`), not the presence of the substring. A parser
    that refuses prose only when the prose happens to contain a stray quote is not refusing prose.
    """
    with pytest.raises(AssertionError, match="pip install"):
        _installs_in([{"run": run_block}])


def test_the_alias_map_resolves_modules_whose_distribution_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The alias map only does work when `packages_distributions()` cannot.

    In a venv carrying pyyaml and grpcio — this one, and the lane — the runtime lookup already
    answers correctly, so deleting the map changes nothing and no test notices. It earns its place
    on the machine that does NOT have them, where the fallback is the only thing standing between
    `import grpc` and a false report that grpcio is undeclared. Stubbing the lookup empty is the
    only way to exercise that, so it is stubbed.
    """
    monkeypatch.setitem(globals(), "packages_distributions", dict)
    assert _candidate_dists("yaml") == {"pyyaml"}
    assert _candidate_dists("grpc") == {"grpcio"}
    assert _candidate_dists("cryptography") == {"cryptography"}


def test_the_runtime_lookup_answers_where_the_alias_map_cannot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The converse, and the reason `packages_distributions()` is consulted at all.

    No module in `scripts/` needs it: `pytest` and `cryptography` resolve by identity, `yaml` and
    `grpc` by the alias map. So dropping the lookup entirely changes no real verdict and, without
    this test, nothing goes red. It is load-bearing for the import this repo has not written yet —
    one whose module name matches neither its distribution nor any alias hardcoded above.
    """
    monkeypatch.setitem(globals(), "packages_distributions", lambda: {"cv2": ["OpenCV_Python"]})
    assert _candidate_dists("cv2") == {"opencv-python"}
