"""`check_registry_drift.py` decides whether a release actually landed, so it is driven RED first.

Every guard here is executed, not read. The check's whole value is that it fires on a real lag and
refuses to guess on a broken instrument — and both of those are properties you only have if you
have watched them happen. A green-path-only suite would prove the script runs, which is not the
question.

These build **real git repositories** in `tmp_path` rather than mocking `git`, following
`scripts/test_vendored_spec_gate.py:8-11`. Commit dates, annotated-tag creator dates and the tag
namespace are the subject matter here; a mock of them would only ever assert my model of git, which
is precisely the thing that could be wrong.

The registry response is injected as a file (`--packages-json`), or fetched behind a stubbed `curl`.
Nothing here touches a network — but that is a property of every live-path test passing an EXPLICIT
`env`, not something the file gets for free. One of them did not, and on a machine carrying a real
`SEAM_REGISTRY_TOKEN` it made three real requests to api.cloudsmith.io with the real secret while
still reporting green. Any new live-path test must pass `env=live_env(...)`.

Run: `python -m pytest scripts/test_registry_drift_gate.py -q`
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_registry_drift.py"

def _load_script():
    """Load the checker by path — `scripts/` is not a package, so a plain import will not find it.

    Same loader idiom as `scripts/test_vendored_spec_gate.py:35-47`. Used for the one branch that
    cannot be reached through the CLI: an exhausted canary roster needs `CANARY_VERSIONS` itself to
    be different, and making it settable from the environment would add production surface for a
    test's benefit.
    """
    spec = importlib.util.spec_from_file_location("check_registry_drift", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


#: The canary roster, read from the script rather than restated here. A second copy is a second
#: thing to forget: changing `CANARY_VERSIONS` used to redden four tests that had hardcoded it,
#: which is a maintenance tax with no diagnostic value — the roster's CONTENT is not what these
#: tests are about.
ROSTER = _load_script().CANARY_VERSIONS

#: The moment every fixture repo dates its version commit from, unless it says otherwise. Fixed
#: rather than derived from `datetime.now()` so a failure is reproducible at any hour.
LANDED = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

#: `TAG_FLOOR` is 20, so a fixture repo needs more than that before `tag_present` will answer at
#: all. Deliberately not exactly 20: a fixture sitting on the boundary would turn a future floor
#: change into 40 confusing failures instead of one clear one.
FILLER_TAGS = 25


@pytest.fixture(autouse=True)
def _no_ambient_registry_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make "any new live-path test must pass `env=`" a mechanism instead of a sentence.

    `run()`'s `env` defaults to `None`, which hands the child a copy of this process's environment.
    On a machine carrying a real `SEAM_REGISTRY_TOKEN` that means a live-path test written without
    an explicit `env=` reaches the actual registry with the actual secret — and passes. That has
    already happened here once (three requests to api.cloudsmith.io, suite green); the remedy
    applied was per-test discipline, which is exactly the kind of remedy that decays.

    Removing the variable for the duration of every test makes the omission fail CLOSED: the script
    finds no credential and exits 2, so the test that forgot says so instead of quietly working.

    Phase 5 makes this more likely, not less — it introduces a workflow whose whole job is to put a
    Cloudsmith secret into that variable.
    """
    monkeypatch.delenv("SEAM_REGISTRY_TOKEN", raising=False)


def test_the_ambient_token_scrubber_is_actually_in_effect() -> None:
    """Anti-vacuity for the fixture above, which is invisible when it works.

    An autouse fixture that stopped being applied — renamed, moved to a class, shadowed by a
    conftest — would restore the hazard silently, since every test that passes `env=` explicitly
    stays green either way.
    """
    assert "SEAM_REGISTRY_TOKEN" not in os.environ, (
        "the autouse scrubber is not running, so a live-path test that omits `env=` would inherit "
        "a real credential from this process and query the real registry."
    )


def _git(repo: Path, *args: str, when: datetime | None = None) -> str:
    env = None
    if when is not None:
        stamp = when.isoformat()
        env = {
            **_BASE_ENV,
            "GIT_AUTHOR_DATE": stamp,
            "GIT_COMMITTER_DATE": stamp,
        }
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        env=env if env is not None else _BASE_ENV,
    )
    assert proc.returncode == 0, f"git {args} failed: {proc.stderr}"
    return proc.stdout.strip()


#: A git environment that cannot read the developer's `~/.gitconfig`. Without this a global
#: `commit.gpgsign` or a `init.defaultBranch` hook makes these fixtures behave differently on one
#: machine than on the runner, which is the class of flake that costs an afternoon.
_BASE_ENV = {
    "PATH": "/usr/bin:/bin:/usr/local/bin",
    "HOME": "/nonexistent",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _write_version(repo: Path, version: str, ts_version: str | None = None) -> None:
    (repo / "python").mkdir(parents=True, exist_ok=True)
    (repo / "ts").mkdir(parents=True, exist_ok=True)
    # Two decoys, on purpose. The INDENTED one comes first, so `PYPROJECT_VERSION`'s `^` anchor is
    # what keeps it out — drop the anchor and the parse silently reads `indented-decoy`. The
    # trailing `[tool.*]` one is at column 0, so only "first match wins" excludes it. A fixture
    # with just the second decoy tests the weaker of the two rules.
    (repo / "python" / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["hatchling"]\n  version = "indented-decoy"\n\n'
        f'[project]\nname = "seam-sdk"\nversion = "{version}"\n\n'
        f'[tool.ruff]\nversion = "not-this-one"\n',
        encoding="utf-8",
    )
    (repo / "ts" / "package.json").write_text(
        json.dumps({"name": "@zer07labs/seam-sdk", "version": ts_version or version}) + "\n",
        encoding="utf-8",
    )


def make_repo(
    tmp_path: Path,
    *,
    version: str = "0.7.78",
    ts_version: str | None = None,
    landed: datetime = LANDED,
    tag: bool = True,
    tag_at: datetime | None = None,
    filler_tags: int = FILLER_TAGS,
) -> Path:
    """A real seam-sdk-shaped checkout: two commits, a tag namespace, and a dated version bump.

    Two commits on purpose. `version_landed_at` uses `git log -S`, which dates the commit that
    INTRODUCED the string — so the version has to arrive in a commit of its own, exactly as
    `release-on-runtime.yml` produces it. A single-commit fixture would date the repo's creation
    and quietly pass a test of the wrong thing.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _write_version(repo, "0.0.1")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial", when=landed - timedelta(days=30))

    for i in range(filler_tags):
        _git(repo, "tag", "-a", f"v0.0.{i + 1}", "-m", "filler", when=landed - timedelta(days=30))

    _write_version(repo, version, ts_version)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", f"chore(release): v{version}", when=landed)
    if tag:
        _git(repo, "tag", "-a", f"v{version}", "-m", f"v{version}", when=tag_at or landed)
    return repo


def rows(*specs: tuple[str, str, str]) -> list[dict]:
    """Registry rows as `(name, version, format)` triples."""
    return [{"name": n, "version": v, "format": f} for n, v, f in specs]


def published(version: str) -> list[dict]:
    return rows(
        ("seam-sdk", version, "python"),
        ("@zer07labs/seam-sdk", version, "npm"),
    )


def run(
    repo: Path,
    packages: object | None,
    tmp_path: Path,
    *,
    now: datetime | None = None,
    raw_json: str | None = None,
    packages_json: Path | None = None,
    extra: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [sys.executable, str(SCRIPT), "--repo", str(repo)]
    if packages_json is not None:
        args += ["--packages-json", str(packages_json)]
    elif raw_json is not None or packages is not None:
        path = tmp_path / "packages.json"
        path.write_text(raw_json if raw_json is not None else json.dumps(packages), "utf-8")
        args += ["--packages-json", str(path)]
    args += ["--now", (now or LANDED + timedelta(days=10)).isoformat()]
    args += extra or []
    return subprocess.run(args, capture_output=True, text=True, env=env)


# ── The three states ──────────────────────────────────────────────────────────────────────────


def test_state_a_published_in_both_formats_is_clean(tmp_path: Path) -> None:
    """The registry serves what main claims. Nothing to say."""
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, published("0.7.78"), tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "both formats" in proc.stdout


def test_state_b_tagged_but_unpublished_is_drift(tmp_path: Path) -> None:
    """A tag exists and the registry does not serve it — a publish was attempted and did not land.

    The response deliberately carries seam-sdk rows at ANOTHER version: that is what makes it a
    plausible answer to a scoped query rather than a broken instrument, and it is the difference
    between this case (exit 1) and `test_a_response_with_no_seam_sdk_row_is_infrastructure`.
    """
    repo = make_repo(tmp_path, version="0.7.78", tag=True)
    proc = run(repo, published("0.7.77"), tmp_path)
    assert proc.returncode == 1, proc.stderr
    assert "State B" in proc.stdout
    assert "EXISTS" in proc.stdout


def test_state_c_untagged_is_drift_and_says_the_tag_push_failed(tmp_path: Path) -> None:
    """Main claims the version and no tag exists — the tag push failed, so no publish ever ran.

    This is the half `release-outcome` structurally cannot see: with no tag there is no
    `publish.yml` run, so nothing inside `publish.yml` can report it.
    """
    repo = make_repo(tmp_path, version="0.7.78", tag=False)
    proc = run(repo, published("0.7.77"), tmp_path)
    assert proc.returncode == 1, proc.stderr
    assert "State C" in proc.stdout
    assert "DOES NOT EXIST" in proc.stdout
    assert "release-on-runtime.yml:180-187" in proc.stdout


def test_the_tag_changes_only_the_remediation_never_the_verdict(tmp_path: Path) -> None:
    """Tagged and untagged reach the SAME verdict from the same registry answer.

    The whole reason this check is keyed on the version rather than the tag. If the tag ever starts
    moving the exit code, a tag-push failure (state C) becomes invisible again.
    """
    codes = {}
    for tag in (True, False):
        sub = tmp_path / f"t{int(tag)}"
        sub.mkdir()
        codes[tag] = run(
            make_repo(sub, version="0.7.78", tag=tag), published("0.7.77"), sub
        ).returncode
    assert codes == {True: 1, False: 1}, codes


@pytest.mark.parametrize(
    ("missing_format", "present"),
    [("npm", ("seam-sdk", "0.7.78", "python")), ("python", ("@zer07labs/seam-sdk", "0.7.78", "npm"))],
)
def test_half_a_publish_is_drift_naming_the_missing_format(
    tmp_path: Path, missing_format: str, present: tuple[str, str, str]
) -> None:
    """Both packages are stamped to one version, so half a release is still a broken release."""
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, [*rows(present), *published("0.7.77")], tmp_path)
    assert proc.returncode == 1, proc.stderr
    assert missing_format in proc.stdout


# ── The two-tier grace window ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("age", "expected_code", "expect_warning"),
    [
        (30, 0, False),
        (89, 0, False),
        (91, 0, True),
        (200, 0, True),
        (359, 0, True),
        (361, 1, False),
    ],
)
def test_all_four_grace_boundaries_in_both_directions(
    tmp_path: Path, age: int, expected_code: int, expect_warning: bool
) -> None:
    """89 -> silent, 91 -> warned, 359 -> warned, 361 -> drift.

    The warn band is asserted as exit-0-WITH-warning, not merely exit 0. A future change that
    promotes it to exit 1 would start filing issues an hour and a half early, and would otherwise
    slide past a test that only checked the code.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, published("0.7.77"), tmp_path, now=LANDED + timedelta(minutes=age))
    assert proc.returncode == expected_code, f"age={age}: {proc.stdout}{proc.stderr}"
    out = proc.stdout + proc.stderr
    warned = "::warning::" in out
    assert warned is expect_warning, f"age={age}: warning={warned}, expected {expect_warning}"
    if warned:
        # The criterion says the warning names the age, BOTH thresholds and the missing formats.
        # Asserting only that a warning exists let it collapse to "not on the registry yet" — true,
        # useless, and indistinguishable in a run summary from the message that tells you what to
        # do. A warning nobody can act on is a warning nobody reads.
        warning = next(ln for ln in out.splitlines() if ln.startswith("::warning::"))
        assert str(age) in warning, f"the warning does not say how old it is: {warning}"
        assert "90" in warning and "360" in warning, f"the warning names no thresholds: {warning}"
        assert "npm" in warning and "python" in warning, (
            f"the warning does not say what is missing: {warning}"
        )


def test_the_soft_tier_says_when_it_will_stop_deferring(tmp_path: Path) -> None:
    """Silence is only acceptable if a reader can tell it is deliberate and time-boxed."""
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, published("0.7.77"), tmp_path, now=LANDED + timedelta(minutes=30))
    assert proc.returncode == 0
    assert "DEFERRED" in proc.stdout
    assert "::warning::" not in proc.stdout + proc.stderr
    # Both halves of the criterion, and both are content rather than shape: how old it is, and
    # when it stops. `stops deferring` alone survived a mutation that deleted the number after it,
    # which is the half a reader actually needs.
    assert "30 minutes old" in proc.stdout, proc.stdout
    assert "in 60 minutes" in proc.stdout, proc.stdout
    assert "escalates at 360" in proc.stdout, proc.stdout


def test_the_clock_takes_the_tag_date_when_the_tag_is_newer(tmp_path: Path) -> None:
    """A re-dispatch that tags without committing must still get its grace.

    `release-on-runtime.yml:176-181` has a branch where `git diff --quiet` is true, nothing is
    committed, and `:182`-`:187` tag and push anyway. Keyed on the commit date alone, the retry
    inherits the ORIGINAL bump's date — normally long past the hard window — so the check fires
    against a publish that started ninety seconds ago. `max(commit, tag)` makes the clock mean
    "when did the most recent attempt begin", which is what the window is for.
    """
    repo = make_repo(
        tmp_path,
        version="0.7.78",
        landed=LANDED,
        tag=True,
        tag_at=LANDED + timedelta(days=10) - timedelta(minutes=30),
    )
    proc = run(repo, published("0.7.77"), tmp_path)
    assert proc.returncode == 0, f"the tag date was ignored: {proc.stdout}{proc.stderr}"
    assert "DEFERRED" in proc.stdout


def test_an_old_commit_with_an_equally_old_tag_still_drifts(tmp_path: Path) -> None:
    """The mirror of the test above: `max()` must not become a blanket suppression."""
    repo = make_repo(tmp_path, version="0.7.78", tag=True, tag_at=LANDED)
    proc = run(repo, published("0.7.77"), tmp_path)
    assert proc.returncode == 1, proc.stdout


def test_a_release_attempt_dated_after_now_is_infrastructure_not_silence(tmp_path: Path) -> None:
    """A negative age sits below every threshold, so an unguarded one defers silently forever.

    Not in the plan; found by running the script. Small skew is clamped (see the test below),
    because a tag date a few seconds ahead of the checker is ordinary NTP jitter.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, published("0.7.77"), tmp_path, now=LANDED - timedelta(hours=10))
    assert proc.returncode == 2, proc.stdout
    assert "skew" in (proc.stdout + proc.stderr)


def test_a_few_minutes_of_clock_skew_reads_as_brand_new(tmp_path: Path) -> None:
    """Jitter must not become an infrastructure failure on every run after a release."""
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, published("0.7.77"), tmp_path, now=LANDED - timedelta(minutes=3))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "DEFERRED" in proc.stdout


# ── Never a verdict: the broken instrument must be distinguishable from a clean answer ─────────


@pytest.mark.parametrize("age_minutes", [30, 14400], ids=["fresh", "long past the window"])
@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("an empty list", "[]"),
        ("only unrelated packages", '[{"name":"seam-runtime","version":"0.7.78","format":"python"}]'),
        ("a lookalike name", '[{"name":"@zer07labs/seam-sdk-extra","version":"0.7.78","format":"npm"}]'),
        ("malformed json", "{not json"),
        ("an object rather than a list", '{"results": []}'),
        ("a list of scalars", "[1, 2, 3]"),
    ],
)
def test_a_broken_instrument_is_two_and_never_zero(
    tmp_path: Path, label: str, payload: str, age_minutes: int
) -> None:
    """None of these may exit 0, and none of them may exit 1 — at ANY age.

    A check that silently returns "nothing lagging" because its query broke is this repo's named
    failure class, and it would be a same-shape regression of the very bug this check exists to
    close. `@zer07labs/seam-sdk-extra` is in the list because the name comparison is exact after
    the scope strip — a near-miss must not count as evidence the query worked.

    **The `fresh` age is what pins the ordering rule**, and it was missing. Every case here used to
    run ten days past the release, where the grace window is irrelevant — so moving the clock check
    above the query, or returning early inside soft grace (literally the "cheap implementation" the
    plan rejects), left all 37 tests green. The consequence is precise: a broken query goes
    unreported on exactly the runs following a release, which is when it matters and is the whole
    reason the instrument is exercised first.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, None, tmp_path, raw_json=payload, now=LANDED + timedelta(minutes=age_minutes))
    assert proc.returncode == 2, f"{label}: exit {proc.returncode}\n{proc.stdout}{proc.stderr}"
    assert "::error::" in proc.stderr


def test_a_third_package_format_does_not_satisfy_either_required_one(tmp_path: Path) -> None:
    """`format` is one of the filter's three clauses, and it needs a row that exercises it.

    Cloudsmith carries formats this release does not ship. A `raw` or `docker` artifact at the
    right version under the right name is not the wheel or the tarball, so it must not be counted.

    Asserted on what the run REPORTS, not only on the exit code — because on the verdict alone
    this clause is inert. Dropping it can only put extra formats into `found`, and `missing` is
    `{python, npm} - found`, so a subtraction that gains `raw` still leaves both required formats
    missing and the exit code identical. What it corrupts is the diagnosis: a reader looking at
    `registry serves: docker, raw` while chasing a failed publish is being told the registry has
    something relevant to this release, and it does not.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(
        repo, rows(("seam-sdk", "0.7.78", "raw"), ("seam-sdk", "0.7.78", "docker")), tmp_path
    )
    assert proc.returncode == 1, proc.stdout
    assert "npm" in proc.stdout and "python" in proc.stdout
    served = next(ln for ln in proc.stdout.splitlines() if ln.startswith("registry serves:"))
    assert "raw" not in served and "docker" not in served, (
        f"a format this release does not ship was reported as served: {served!r}"
    )


def test_a_missing_packages_file_is_infrastructure(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, None, tmp_path, packages_json=tmp_path / "nope.json")
    assert proc.returncode == 2
    assert "does not exist" in proc.stderr


def test_a_version_lockstep_mismatch_is_infrastructure_not_drift(tmp_path: Path) -> None:
    """`ci.yml:23-38` makes this impossible on a green main, so it means the world is not modelled.

    There is no single version to check, so there is no verdict to give — guessing one is exactly
    what this file refuses to do.
    """
    repo = make_repo(tmp_path, version="0.7.78", ts_version="0.7.77")
    proc = run(repo, published("0.7.78"), tmp_path)
    assert proc.returncode == 2, proc.stdout
    assert "disagree" in proc.stderr


def test_a_checkout_without_tags_is_infrastructure(tmp_path: Path) -> None:
    """Below the floor every release would be misdiagnosed as 'the tag push failed'."""
    repo = make_repo(tmp_path, version="0.7.78", filler_tags=3, tag=False)
    proc = run(repo, published("0.7.77"), tmp_path)
    assert proc.returncode == 2, proc.stdout
    assert "TAG_FLOOR" in proc.stderr


def test_a_version_that_never_landed_on_this_branch_is_infrastructure(tmp_path: Path) -> None:
    """A shallow clone lands here: the version is real but its commit is not in the history."""
    repo = make_repo(tmp_path, version="0.7.78")
    _write_version(repo, "0.9.99")  # edited in the worktree, never committed
    proc = run(repo, published("0.7.77"), tmp_path)
    assert proc.returncode == 2, proc.stdout
    assert "cannot date" in proc.stderr


@pytest.mark.parametrize(
    "version", ["0.7.78+local", "0.7.78 rc1", "0.7.78&x=1", "0.7.78#frag", "0.7.78%2e"]
)
def test_a_query_unsafe_version_is_two_and_never_one(tmp_path: Path, version: str) -> None:
    """The version is interpolated into a URL query where `+` means space and `&#%` are structural.

    `yank.yml:64-66` guards its own operator-typed input the same way. The obligation is stronger
    here: this value is read from `main`, so a refusal means the world is not the world this script
    models — exit 2. Exit 1 would report a malformed source version as a registry failure.

    The unsafe version is COMMITTED, and the failure MESSAGE is asserted, not merely the exit code.
    An earlier draft edited the worktree without committing, so `version_landed_at` refused first
    with "cannot date this version" — exit 2 for an unrelated reason, and the test passed with the
    query guard deleted outright. Untagged, because git will not accept a ref name containing a
    space, which is itself a hint about the shape of the problem.
    """
    repo = make_repo(tmp_path, version=version, tag=False)
    proc = run(repo, published("0.7.78"), tmp_path)
    assert proc.returncode == 2, f"{version!r}: exit {proc.returncode}\n{proc.stdout}"
    assert "digits-and-dots" in proc.stderr, (
        f"{version!r} was refused for the wrong reason: {proc.stderr}"
    )
    # The criterion says it NAMES the offending character. Without this the whole computation can
    # be replaced by a literal `"?"` and the shared phrase above still matches — the message would
    # tell you the version is malformed without telling you which character made it so, which for
    # a value read out of `main` is most of the diagnosis.
    offender = next(ch for ch in version if not (ch.isdigit() or ch == "."))
    assert repr(offender) in proc.stderr, (
        f"{version!r}: the refusal does not name {offender!r}: {proc.stderr}"
    )


def test_an_empty_version_is_refused_before_the_query_guard_ever_sees_it(tmp_path: Path) -> None:
    """`SAFE_VERSION` rejects the empty string, but nothing can reach it with one.

    Both manifest readers refuse first — the pyproject pattern requires at least one character
    between the quotes, and an empty `package.json` version is caught as a missing one. So the
    empty branch of `assert_query_safe` is defensive, exactly like `yank.yml:65`'s `|""` arm, and
    this test says so rather than letting a parametrised case imply coverage it does not have.
    """
    repo = make_repo(tmp_path, version="0.7.78", tag=False)
    (repo / "ts" / "package.json").write_text(
        json.dumps({"name": "@zer07labs/seam-sdk", "version": ""}) + "\n", encoding="utf-8"
    )
    proc = run(repo, published("0.7.78"), tmp_path)
    assert proc.returncode == 2, proc.stdout
    assert "declares no `version`" in proc.stderr


def test_an_unhandled_exception_exits_two_not_one(tmp_path: Path) -> None:
    """Python exits 1 on an uncaught exception, and 1 is this script's DRIFT verdict.

    Without the handler at the bottom of the script, a typo or an ImportError reports itself as
    "the registry is behind the source" — a confident wrong verdict from a crash.
    `scripts/probe_framework_coinstall.py:265-266` still has this hole; this is the criterion that
    keeps it out of here.

    Injected with a directory where `python/pyproject.toml` should be, so the read raises
    `IsADirectoryError` — an `OSError` subclass that `source_version` deliberately does not catch.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    (repo / "python" / "pyproject.toml").unlink()
    (repo / "python" / "pyproject.toml").mkdir()
    proc = run(repo, published("0.7.78"), tmp_path)
    assert proc.returncode == 2, f"exit {proc.returncode} — a crash was reported as a verdict"
    assert "Traceback" in proc.stderr
    assert "crashed" in proc.stderr


def test_there_is_no_code_path_that_reports_nothing_and_exits_zero(tmp_path: Path) -> None:
    """Anti-vacuity for the suite itself: every exit 0 above must have SAID something.

    A script that printed nothing and returned 0 would satisfy each happy-path assertion's exit
    code while conveying nothing to a reader of the run summary.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    for label, packages, now in (
        ("clean", published("0.7.78"), None),
        ("deferred", published("0.7.77"), LANDED + timedelta(minutes=30)),
        ("warned", published("0.7.77"), LANDED + timedelta(minutes=200)),
    ):
        proc = run(repo, packages, tmp_path, now=now)
        assert proc.returncode == 0, label
        assert proc.stdout.strip(), f"{label}: exited 0 saying nothing"
        assert "0.7.78" in proc.stdout, f"{label}: did not name the version"


def test_omitting_the_registry_response_is_infrastructure_not_a_skip(tmp_path: Path) -> None:
    """There must be no path that shrugs and exits 0, and this is the easiest place to grow one.

    Before the live query existed, omitting the flag was refused outright — and nothing tested it,
    so that refusal could be replaced by `print("cannot determine…"); return 0`, verbatim the
    construct the phase forbids, with the whole suite green. Phase 4 then edited exactly this
    branch, which is why it was worth pinning first.

    It now goes live instead, and with no credential in the environment that is infrastructure.
    The property under test is unchanged and is the one that matters: omitting the response never
    produces a verdict, and never produces silence.

    The environment is supplied explicitly, and that is not tidiness. Passing `env=None` inherits
    the ambient one — so on a machine where `SEAM_REGISTRY_TOKEN` happens to be set, this test made
    three REAL requests to api.cloudsmith.io carrying the real secret, and passed for a different
    reason than the one it names. Phase 5 introduces a workflow where that variable IS in scope.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0])})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir, token=None))
    assert proc.returncode == 2, f"exit {proc.returncode}: {proc.stdout}{proc.stderr}"
    assert "::error::" in proc.stderr
    assert "cannot determine" not in (proc.stdout + proc.stderr).lower()
    assert calls.read_text() == "", "a query was attempted with no credential"


def test_a_repo_that_is_not_a_git_checkout_is_infrastructure(tmp_path: Path) -> None:
    """Named in the phase's edge cases and previously untested."""
    repo = tmp_path / "plain"
    _write_version(repo, "0.7.78")
    proc = run(repo, published("0.7.77"), tmp_path)
    assert proc.returncode == 2, proc.stdout
    assert "::error::" in proc.stderr


def test_a_git_command_that_fails_stops_the_run_rather_than_dropping_its_answer(
    tmp_path: Path,
) -> None:
    """A swallowed git failure does not stay infrastructure — it becomes a false DRIFT.

    `_git` raising on a non-zero exit had no test, and the consequence of removing it is specific
    rather than vague: `for-each-ref` fails, the tag date silently becomes "no tag", the clock
    falls back to the old commit date, and a legitimate re-dispatch — the
    `.github/workflows/release-on-runtime.yml:176-181` path that `max()` exists for — is reported
    as drift. That is exit 1 reached from an infrastructure condition, which is the one thing this
    script's exit-code contract forbids.

    Stubbed as an executable first on `PATH`, per the repo's convention, so the failure is real
    rather than monkeypatched.
    """
    real_git = shutil.which("git")
    assert real_git, "git is not on PATH"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "git"
    stub.write_text(
        f'#!/bin/sh\n# argv is: -C <repo> <subcommand> …\nif [ "$3" = "for-each-ref" ]; then\n'
        f'  echo "simulated git failure" >&2\n  exit 128\nfi\nexec {real_git} "$@"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)

    repo = make_repo(
        tmp_path,
        version="0.7.78",
        landed=LANDED,
        tag=True,
        tag_at=LANDED + timedelta(days=10) - timedelta(minutes=30),
    )
    env = {**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}
    proc = run(repo, published("0.7.77"), tmp_path, env=env)
    assert proc.returncode == 2, (
        f"a failed git call produced exit {proc.returncode} — infrastructure reached a verdict\n"
        f"{proc.stdout}{proc.stderr}"
    )
    assert "for-each-ref" in proc.stderr


def test_the_clock_takes_the_commit_date_when_the_tag_is_older(tmp_path: Path) -> None:
    """The other side of `max()`, which the existing mirror could not see.

    That mirror dates the tag EQUAL to the commit, so `max(commit, tag)` and a plain
    `tag if tag else commit` agree and it cannot tell them apart. A tag older than the commit
    separates them: taking the tag alone would date this release ten days back and report drift on
    a version that landed half an hour ago.
    """
    repo = make_repo(
        tmp_path, version="0.7.78", landed=LANDED, tag=True, tag_at=LANDED - timedelta(days=10)
    )
    proc = run(repo, published("0.7.77"), tmp_path, now=LANDED + timedelta(minutes=30))
    assert proc.returncode == 0, f"the commit date was ignored: {proc.stdout}{proc.stderr}"
    assert "DEFERRED" in proc.stdout


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('{"results": []}', "not a list of packages"),
        ("[1, 2, 3]", "not an object"),
        ('[{"name": "seam-sdk", "version": "0.7.78", "format": "python"}, "x"]', "not an object"),
    ],
)
def test_a_response_of_the_wrong_shape_says_what_shape_it_is(
    tmp_path: Path, payload: str, expected: str
) -> None:
    """These previously passed for the wrong reason, and it matters forward.

    With `_seam_sdk_rows`' type guards removed, the walk returns `[]` and the health check raises
    instead — exit 2 either way, so the guards were unpinned. Phase 4 removes that covering health
    check on the live path, where a non-list error body would then read as drift with nothing red.
    Asserting the message keeps the guards where they are.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, None, tmp_path, raw_json=payload)
    assert proc.returncode == 2, proc.stdout
    assert expected in proc.stderr, proc.stderr


@pytest.mark.parametrize(
    ("value", "expected"),
    [("2026-09-06T12:00:00", "carries no timezone"), ("yesterday", "cannot parse")],
)
def test_an_unusable_now_is_infrastructure(tmp_path: Path, value: str, expected: str) -> None:
    """A naive or unparseable `--now` cannot produce an age, so it cannot produce a verdict."""
    repo = make_repo(tmp_path, version="0.7.78")
    packages = tmp_path / "p.json"
    packages.write_text(json.dumps(published("0.7.78")), encoding="utf-8")
    # Not routed through `run()`: it supplies a well-formed `--now` of its own, which is the value
    # under test here.
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(repo),
            "--packages-json",
            str(packages),
            "--now",
            value,
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, proc.stdout
    assert expected in proc.stderr, proc.stderr


@pytest.mark.parametrize(
    ("break_it", "expected"),
    [
        ("no-pyproject", "does not exist"),
        ("no-package-json", "does not exist"),
        ("indented-version-only", 'no `version = "..."` at column 0'),
        ("bad-package-json", "not valid JSON"),
    ],
)
def test_a_source_manifest_that_cannot_be_read_is_infrastructure(
    tmp_path: Path, break_it: str, expected: str
) -> None:
    """Four ways the version is unreadable, none of which may become a verdict.

    `indented-version-only` is the one that earns its place twice: it also pins the `^` anchor in
    `PYPROJECT_VERSION`. Without the anchor the parse quietly returns the indented decoy, which is
    a wrong version rather than a refusal — and a wrong version asks the registry a question about
    a release that does not exist.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    pyproject = repo / "python" / "pyproject.toml"
    package_json = repo / "ts" / "package.json"
    if break_it == "no-pyproject":
        pyproject.unlink()
    elif break_it == "no-package-json":
        package_json.unlink()
    elif break_it == "indented-version-only":
        pyproject.write_text('[project]\n  version = "0.7.78"\n', encoding="utf-8")
    else:
        package_json.write_text("{not json", encoding="utf-8")
    proc = run(repo, published("0.7.78"), tmp_path)
    assert proc.returncode == 2, f"{break_it}: exit {proc.returncode}\n{proc.stdout}"
    assert expected in proc.stderr, f"{break_it}: {proc.stderr}"


def test_a_soft_window_wider_than_the_hard_one_is_refused(tmp_path: Path) -> None:
    """Otherwise the warn band is empty and the soft tier suppresses past the escalation point.

    A guard added during implementation and, until now, never observed failing — which by this
    plan's own standard is not evidence.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(
        repo,
        published("0.7.77"),
        tmp_path,
        extra=["--soft-grace-minutes", "400", "--hard-grace-minutes", "100"],
    )
    assert proc.returncode == 2, proc.stdout
    assert "exceeds" in proc.stderr


def test_a_packages_path_that_is_not_readable_is_infrastructure(tmp_path: Path) -> None:
    """The `OSError` arm, distinct from the missing-file arm above."""
    repo = make_repo(tmp_path, version="0.7.78")
    as_dir = tmp_path / "adirectory.json"
    as_dir.mkdir()
    proc = run(repo, None, tmp_path, packages_json=as_dir)
    assert proc.returncode == 2, proc.stdout
    assert "cannot be read" in proc.stderr


# ── The live registry query, and the canary that proves the instrument works ───────────────────
#
# `curl` is stubbed as an executable first on `PATH`, per this repo's convention (no mocks, no
# cassettes — `scripts/test_release_notice_gate.py:62-83`). The stub records every invocation and
# answers from pre-rendered files keyed by the version in the query string, so "which versions did
# it ask about, in what order" is observable rather than inferred.

#: Distinctive on purpose: every failure path is grepped for it, so a leak has nowhere to hide.
STUB_TOKEN = "s3cr3t-canary-token-value"



def curl_stub(
    tmp_path: Path,
    responses: dict[str, object],
    *,
    fail_with: int | None = None,
    stderr_text: str | None = None,
) -> tuple[Path, Path]:
    """A `curl` first on PATH. Returns (bin dir, call-log path).

    Two logs are written, not one. `curl-calls` holds `"$*"` — argv joined by spaces, which is what
    almost every assertion here wants. Beside it, `curl-argv` holds `"$@"` one bracketed argument
    per line, because joining destroys the only thing that distinguishes a well-formed header from
    a malformed one: whitespace at an argument's edges survives `$*` invisibly.

    A version with no entry in `responses` answers `[]` — which is what the real registry returns
    for a version it does not carry, and therefore what a genuine drift looks like.

    Assembled line by line rather than with `textwrap.dedent`. A multi-line insertion has no common
    indent, so dedent silently becomes a no-op and leaves the shebang indented — at which point the
    kernel refuses the file, `PATH` falls through, and the REAL curl answers the test. That failed
    loudly here (exit 56 from a network that is not supposed to be reachable) but it is exactly the
    shape of stub bug that otherwise passes quietly.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    calls = tmp_path / "curl-calls"
    calls.write_text("")
    responses_dir = tmp_path / "responses"
    responses_dir.mkdir(exist_ok=True)
    for version, payload in responses.items():
        (responses_dir / version).write_text(
            payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8"
        )
    argv_log = tmp_path / "curl-argv"
    argv_log.write_text("")
    lines = [
        "#!/usr/bin/env bash",
        f"""printf '%s\\n' "$*" >> {calls}""",
        f"""printf '[%s]\\n' "$@" >> {argv_log}""",
    ]
    if stderr_text is not None:
        # Real `curl -sf` does not quote request headers on stderr, but nothing in the script
        # guarantees that stays true of every curl build and proxy — so the script's promise not to
        # echo it has to be testable rather than assumed.
        lines.append(f"""printf '%s\\n' '{stderr_text}' >&2""")
    if fail_with is not None:
        # What `-f` actually does, emulated so the flag is testable rather than decorative: WITH
        # it curl turns an HTTP >= 400 into a non-zero exit and prints no body; WITHOUT it the
        # error BODY is printed and curl exits 0 — which is how a 401 becomes "no rows" and then
        # becomes "drift".
        lines += [
            """if printf '%s' "$*" | grep -q -e '-sf' -e '-f'; then""",
            f"  exit {fail_with}",
            "fi",
            """printf '%s' '{"detail":"Invalid or missing API key."}'""",
            "exit 0",
        ]
    lines += [
        'URL="${@: -1}"',
        'VER="${URL##*version:}"',
        'VER="${VER%%&*}"',
        f'if [ -f "{responses_dir}/$VER" ]; then',
        f'  cat "{responses_dir}/$VER"',
        "else",
        "  echo '[]'",
        "fi",
    ]
    stub = bin_dir / "curl"
    stub.write_text("\n".join(lines) + "\n", encoding="utf-8")
    stub.chmod(0o755)
    assert stub.read_text().startswith("#!"), "the stub shebang must be at column 0"
    return bin_dir, calls


def live_env(bin_dir: Path, *, token: str | None = STUB_TOKEN) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "SEAM_REGISTRY_TOKEN"}
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    if token is not None:
        env["SEAM_REGISTRY_TOKEN"] = token
    return env


def versions_queried(calls: Path) -> list[str]:
    """The versions the stub was asked about, in order."""
    asked = []
    for line in calls.read_text().splitlines():
        if "version:" in line:
            asked.append(line.split("version:")[1].split("&")[0].strip())
    return asked


def test_the_happy_live_path_queries_one_canary_then_the_target(tmp_path: Path) -> None:
    """Two GETs on the common path, in that order, and a clean verdict."""
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(
        tmp_path, {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert versions_queried(calls) == [ROSTER[0], "0.7.78"]
    # And exactly two invocations, counted rather than inferred. `versions_queried` filters on
    # `version:`, so a third request to some URL without that qualifier — a discovery call, a
    # retry against a different endpoint — is invisible to the assertion above. The stub appends
    # one line per invocation, so this counts them.
    assert len(calls.read_text().splitlines()) == 2, (
        f"the run made {len(calls.read_text().splitlines())} requests, not 2:\n{calls.read_text()}"
    )
    assert f"canary {ROSTER[0]}" in proc.stdout
    # `yank.yml` carries no timeout, so this is the one part of the request that is deliberately
    # NOT a mirror of it. A hung GET in a scheduled job is a silent multi-hour burn, and nothing
    # else here would notice the flag disappearing.
    #
    # The VALUE, not just the flag. `--max-time 0` means "no timeout during transfer" to curl, so a
    # present-but-zero argument restores exactly the burn the constant exists to prevent while
    # satisfying any `"--max-time" in line` check. That mutation survived a whole battery.
    ceiling = _load_script().CURL_MAX_SECONDS
    assert isinstance(ceiling, int) and ceiling > 0, (
        f"CURL_MAX_SECONDS is {ceiling!r}. curl reads 0 as 'never time out', which is the state "
        f"this constant exists to make impossible."
    )
    for line in calls.read_text().splitlines():
        args = line.split()
        assert "--max-time" in args, f"the request has no timeout: {line}"
        assert args[args.index("--max-time") + 1] == str(ceiling), (
            f"--max-time carries {args[args.index('--max-time') + 1]!r}, not CURL_MAX_SECONDS "
            f"({ceiling}). The constant documents the ceiling; the request has to use it."
        )
    # F1: the success path prints four lines and none of them may carry the credential. The
    # parametrised leak test below covers only paths that exit 2, so every one of these prints was
    # ungrepped — a token interpolated into "instrument proven by canary …" leaked on every GREEN
    # run, which is the majority of runs, with the whole suite passing.
    assert STUB_TOKEN not in proc.stdout + proc.stderr, "the token leaked on the clean path"


def test_a_dead_instrument_aborts_before_the_target_is_ever_asked(tmp_path: Path) -> None:
    """The ordering proof: with every canary empty the run must exit 2 even though the target
    would have answered.

    This is the case that makes "canary first" a fact rather than a comment. If the target were
    consulted first, a populated target would produce a verdict computed against an instrument
    never shown to work.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(tmp_path, {"0.7.78": published("0.7.78")})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, proc.stdout
    assert "0.7.78" not in versions_queried(calls), (
        f"the target was queried through an unproven instrument: {versions_queried(calls)}"
    )
    for candidate in ROSTER:
        assert candidate in proc.stderr, f"the refusal does not name {candidate}: {proc.stderr}"


@pytest.mark.parametrize(
    ("target_published", "expected"), [(True, 0), (False, 1)], ids=["clean", "drift"]
)
def test_one_yanked_canary_does_not_brick_the_instrument(
    tmp_path: Path, target_published: bool, expected: int
) -> None:
    """The whole reason the roster is a set. Without this it is a single pin wearing a tuple."""
    repo = make_repo(tmp_path, version="0.7.78")
    first, second = ROSTER[0], ROSTER[1]
    responses: dict[str, object] = {second: published(second)}
    if target_published:
        responses["0.7.78"] = published("0.7.78")
    bin_dir, calls = curl_stub(tmp_path, responses)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == expected, proc.stdout + proc.stderr
    assert versions_queried(calls)[:2] == [first, second], (
        "the first candidate must be tried and found wanting before the second"
    )


def test_a_canary_equal_to_the_target_is_dropped_and_the_run_still_reaches_a_verdict(
    tmp_path: Path,
) -> None:
    """The defect the first draft shipped, and the criterion that keeps it fixed.

    With `main` at a roster version, a pinned canary and the target become the SAME query — so a
    genuine drift on that version makes the canary come back empty and the run exits 2, reporting
    "my instrument is broken" for exactly the condition it exists to report as drift. A structural
    mute on the live version, not a corner case. The entry must be dropped, and an empty target
    must then produce **1**, not 2.
    """
    target, backup = ROSTER[0], ROSTER[1]
    repo = make_repo(tmp_path, version=target)
    bin_dir, calls = curl_stub(tmp_path, {backup: published(backup)})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 1, (
        f"exit {proc.returncode} — the target's drift was muted\n{proc.stdout}{proc.stderr}"
    )
    asked = versions_queried(calls)
    assert asked.count(target) == 1, f"{target} was queried as a canary as well: {asked}"
    assert asked[0] == backup, asked


@pytest.mark.parametrize("truncated", [ROSTER[0], "0.7.78"], ids=["canary", "target"])
def test_a_full_page_is_truncation_and_never_a_verdict(tmp_path: Path, truncated: str) -> None:
    """A response of exactly `page_size` rows means the `version:` qualifier was likely ignored.

    A first page of everything would put a published target version outside the window and read as
    absent — drift reported for a release that shipped. This is the one failure the canary alone
    cannot catch: its rows go missing for the same reason, so it degrades to exit 2 only by luck.
    """
    full_page = [
        {"name": "seam-sdk", "version": f"0.0.{i}", "format": "python"} for i in range(50)
    ]
    responses: dict[str, object] = {
        ROSTER[0]: published(ROSTER[0]),
        "0.7.78": published("0.7.78"),
    }
    responses[truncated] = full_page
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, _ = curl_stub(tmp_path, responses)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, f"{truncated}: exit {proc.returncode}\n{proc.stdout}"
    assert "page size" in proc.stderr


def test_a_real_drift_end_to_end_over_the_live_path(tmp_path: Path) -> None:
    """Target empty, canary populated, past the hard tier — the case this whole file exists for."""
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, _ = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0])})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "State B" in proc.stdout


def test_an_http_failure_is_infrastructure_never_drift(tmp_path: Path) -> None:
    """`-sf` is what makes this possible: without `-f`, a 401 body parses as "no rows" -> drift."""
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(tmp_path, {}, fail_with=22)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, proc.stdout
    assert "curl exited 22" in proc.stderr
    # Pin the flag itself. The stub emulates `-f` faithfully, so dropping it makes curl exit 0
    # with an error body — and the run then survives only because the response type guards reject
    # a JSON object. Two independent things would have to break for a 401 to read as drift, and
    # this asserts the first of them rather than relying on the second.
    assert any("-sf" in line or " -f " in line for line in calls.read_text().splitlines()), (
        f"curl was invoked without -f: {calls.read_text()}"
    )


@pytest.mark.parametrize("token", [None, "", "   "], ids=["unset", "empty", "whitespace"])
def test_a_missing_credential_is_two_and_never_one(tmp_path: Path, token: str | None) -> None:
    """Modelled as absent-from-env versus present-but-empty, distinctly.

    A deliberate divergence from `yank.yml:61-63`, which exits 1 for the same condition. There 1
    means "refused"; here 1 means "the registry is behind the source", and a missing secret must
    never be able to say that.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0])})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir, token=token))
    assert proc.returncode == 2, proc.stdout
    assert "SEAM_REGISTRY_TOKEN" in proc.stderr
    assert calls.read_text() == "", "a query was attempted without a credential"


def test_supplying_a_response_file_performs_no_query_at_all(tmp_path: Path) -> None:
    """The offline path Phase 3 shipped must not silently start requiring a network."""
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0])})
    proc = run(repo, published("0.7.78"), tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert calls.read_text() == "", f"curl was invoked on the offline path: {calls.read_text()}"


@pytest.mark.parametrize("verdict", ["clean", "deferred", "warned", "drift"])
def test_the_credential_never_appears_on_a_path_that_reaches_a_verdict(
    tmp_path: Path, verdict: str
) -> None:
    """The four **succeeding** paths, which the failing-path sweep below does not cover.

    That sweep asserts `returncode == 2` on every case, so the four `print()`s that produce an
    actual verdict were ungrepped — and those run far more often than any failure does. A token
    interpolated into `"instrument proven by canary … "` would leak on every GREEN scheduled run,
    forever, with all eighty-odd tests here passing.

    Not hypothetical for this repo: Phase 5 resolves the credential in shell by stripping a
    `Bearer ` prefix, and GitHub masks the registered secret, not a derivative of it. A leaked
    stripped token is a working credential in a run log that nothing redacts.
    """
    # Only the target's age differs: the canary answers in every case, so the certificate line —
    # the one that names a canary and is therefore the likeliest place for a token to be
    # interpolated — is printed on all four.
    age = {"clean": 10, "deferred": 10, "warned": 120, "drift": 14400}[verdict]
    repo = make_repo(tmp_path, version="0.7.78")
    responses: dict[str, object] = {ROSTER[0]: published(ROSTER[0])}
    if verdict == "clean":
        responses["0.7.78"] = published("0.7.78")
    bin_dir, _ = curl_stub(tmp_path, responses)
    proc = run(
        repo, None, tmp_path, now=LANDED + timedelta(minutes=age), env=live_env(bin_dir)
    )
    expected = 1 if verdict == "drift" else 0
    assert proc.returncode == expected, (
        f"{verdict}: exit {proc.returncode}, expected {expected}\n{proc.stdout}{proc.stderr}"
    )
    assert f"canary {ROSTER[0]}" in proc.stdout, (
        f"{verdict}: the certificate line was not printed, so this case is not covering the "
        f"line most likely to interpolate a credential"
    )
    # Three of these four exit 0, so the return code alone cannot tell them apart — without this
    # the parametrisation could silently collapse onto one branch and claim to cover four.
    marker = {"clean": "OK —", "deferred": "DEFERRED", "warned": "::warning::", "drift": "DRIFT —"}
    assert marker[verdict] in proc.stdout, (
        f"{verdict}: expected {marker[verdict]!r} in the output, so this case is not exercising "
        f"the branch it names:\n{proc.stdout}"
    )
    assert STUB_TOKEN not in proc.stdout + proc.stderr, f"{verdict}: the token leaked"


@pytest.mark.parametrize(
    "broken",
    ["all-canaries-empty", "http-failure", "truncated", "not-json", "token-on-curl-stderr"],
)
def test_the_credential_never_appears_in_any_output(tmp_path: Path, broken: str) -> None:
    """Asserted over every failing path, because a token is leaked once and then forever."""
    repo = make_repo(tmp_path, version="0.7.78")
    if broken == "all-canaries-empty":
        bin_dir, _ = curl_stub(tmp_path, {})
    elif broken == "http-failure":
        bin_dir, _ = curl_stub(tmp_path, {}, fail_with=22)
    elif broken == "truncated":
        bin_dir, _ = curl_stub(
            tmp_path,
            {ROSTER[0]: [{"name": "seam-sdk", "version": f"0.0.{i}", "format": "npm"} for i in range(50)]},
        )
    elif broken == "token-on-curl-stderr":
        # The nastiest shape: the credential comes back OUT of the subprocess. If curl's stderr
        # were ever echoed into the error message, the token would land in a public run log.
        bin_dir, _ = curl_stub(
            tmp_path, {}, fail_with=22, stderr_text=f"curl: auth failed for {STUB_TOKEN}"
        )
    else:
        bin_dir, _ = curl_stub(tmp_path, {ROSTER[0]: "<html>error</html>"})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, f"{broken}: exit {proc.returncode}"
    assert STUB_TOKEN not in proc.stdout + proc.stderr, f"{broken}: the token leaked"


def test_a_response_that_is_not_json_is_infrastructure(tmp_path: Path) -> None:
    """An HTML error page from a proxy must not parse as "no rows"."""
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, _ = curl_stub(tmp_path, {ROSTER[0]: "<html>502</html>"})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, proc.stdout
    assert "not JSON" in proc.stderr


def test_curl_absent_from_path_is_infrastructure(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, version="0.7.78")
    empty = tmp_path / "emptybin"
    empty.mkdir()
    env = {"PATH": str(empty), "SEAM_REGISTRY_TOKEN": STUB_TOKEN}
    proc = run(repo, None, tmp_path, env=env)
    assert proc.returncode == 2, proc.stdout
    # Both halves matter. Exit 2 alone is satisfied by the top-level crash handler, and a
    # traceback's rendered source line contains the word `curl` — so the named guard could be
    # deleted entirely and this test would still pass, reporting a crash as a handled condition.
    assert "not on PATH" in proc.stderr, proc.stderr
    assert "Traceback" not in proc.stderr, f"the guard was skipped and this crashed: {proc.stderr}"


@pytest.mark.parametrize(
    "canary_format", ["python", "npm"], ids=["python only", "npm only"]
)
def test_a_half_published_canary_does_not_count_as_a_working_instrument(
    tmp_path: Path, canary_format: str
) -> None:
    """The instrument is healthy only when a canary returns BOTH formats, and nothing pinned that.

    Every canary in this file returned both or nothing, so `set(REQUIRED_FORMATS) <= formats` could
    be weakened to `if formats:` with all 79 tests green — and the failure that hides is a
    confident wrong verdict, not a missed one:

      A credential (or a Cloudsmith entitlement) that can read `python` rows but not `npm` makes
      every query return the python row alone. The weakened check announces "instrument proven by
      canary 0.7.50 (both formats present)" — a falsehood — and then reports DRIFT because npm is
      missing from the target too. An issue filed against a release that shipped perfectly well.

    Half an answer is not a working instrument; it is a systematically wrong one, and the two are
    indistinguishable from the target's answer alone.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    half = [row for row in published(ROSTER[0]) if row["format"] == canary_format]
    bin_dir, _ = curl_stub(tmp_path, {ROSTER[0]: half, "0.7.78": published("0.7.78")})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, (
        f"a canary answering only in {canary_format} was accepted as proof\n"
        f"{proc.stdout}{proc.stderr}"
    )
    assert "nothing usable" in proc.stderr


def test_the_request_is_the_shape_yank_yml_already_proves(tmp_path: Path) -> None:
    """The whole justification for shelling to `curl` is byte-comparability with `yank.yml:69-71`.

    That claim is made in four places in prose and was enforced nowhere, so the URL, the query
    parameter names and `page_size` could all drift with a green suite. `versions_queried()` only
    reads the version substring back out, which is deliberately not the same thing.

    `page_size` is the sharpest of them. The truncation check compares `len(rows)` against
    `PAGE_SIZE`, and that comparison is only meaningful if the request ASKED for that page size.
    Drop the parameter and the server's own default governs — at which point a page-of-everything
    of any other length sails through and the run reports DRIFT for a published version.
    """
    yank = (REPO / ".github" / "workflows" / "yank.yml").read_text(encoding="utf-8")
    matched = re.search(r'"(https://api\.cloudsmith\.io/[^"]*page_size=\d+)"', yank)
    assert matched, (
        "no Cloudsmith list URL found in yank.yml — the shape this mirrors moved, and the "
        "byte-comparability claim needs re-checking by hand"
    )
    expected = matched.group(1).replace("$VERSION", "0.7.78")

    module = _load_script()
    assert module.REGISTRY_URL + module._query_for("0.7.78") == expected, (
        f"the request has drifted from the one yank.yml proves.\n"
        f"  here: {module.REGISTRY_URL + module._query_for('0.7.78')}\n"
        f"  yank: {expected}"
    )
    assert f"page_size={module.PAGE_SIZE}" in expected, (
        f"PAGE_SIZE={module.PAGE_SIZE} is not the page size the request asks for. The truncation "
        "check compares row counts against it, so the two must be the same number or that check "
        "is comparing against nothing."
    )


def test_the_credential_travels_only_in_a_header_never_in_the_url(tmp_path: Path) -> None:
    """A token in a query string is logged by every proxy and server it passes; a header is not.

    Nothing else here could see the difference. The leak tests grep the run's own output, and the
    error messages print only the query string — so moving the credential into the URL leaks it
    everywhere that matters while every assertion stays green. This reads the recorded argv, which
    is where the difference actually shows.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(
        tmp_path, {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    logged = calls.read_text()
    assert logged.strip(), "the stub recorded no invocations"
    for line in logged.splitlines():
        url = next((tok for tok in line.split() if tok.startswith("http")), "")
        assert STUB_TOKEN not in url, f"the credential is in the URL: {url}"
        # Checking the URL alone is too narrow: the token could be added anywhere else in argv —
        # a `-A seam/<token>` user-agent, say — and no assertion here would notice. Exactly once,
        # and only as the X-Api-Key value.
        assert line.count(STUB_TOKEN) == 1, f"the credential appears more than once: {line}"
        assert f"X-Api-Key: {STUB_TOKEN}" in line, f"not sent as the X-Api-Key header: {line}"


def test_a_credential_with_edge_whitespace_reaches_curl_stripped(tmp_path: Path) -> None:
    """Phase 5 resolves this token in shell, where a trailing newline is easy to acquire.

    `$(cat …)`, a secret pasted with a newline, a `${VAR#Bearer }` on a value that had one — all
    produce a token whose edges carry whitespace. Unstripped it builds `X-Api-Key: <tok>\\n`, and
    the run then fails in a way that names the REGISTRY (curl errors, exit 2) rather than the
    credential — recoverable, but for no reason and pointing at the wrong thing.

    Nothing else here can see it. `curl-calls` joins argv with spaces, so an argument's trailing
    newline is indistinguishable from the separator that follows it; every existing assertion stays
    green with the strip removed. This reads the per-argument log instead.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(
        tmp_path, {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir, token=f"  {STUB_TOKEN}\n"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    argv = calls.with_name("curl-argv").read_text().splitlines()
    assert argv, "the stub recorded no arguments"
    headers = [a for a in argv if a.startswith("[X-Api-Key:")]
    assert headers, f"no X-Api-Key argument reached curl at all: {argv}"
    assert set(headers) == {f"[X-Api-Key: {STUB_TOKEN}]"}, (
        f"the header value is not the token with its edges stripped: {headers}. The brackets are "
        f"the point — a value whose whitespace survived shows up either as extra spaces inside "
        f"them or, for a newline, as a line that never closes."
    )


def test_a_canary_answered_at_the_wrong_version_is_not_a_working_instrument(
    tmp_path: Path,
) -> None:
    """The certificate must be earned by the same filter the verdict depends on.

    `registry_formats` takes a version and keeps only rows at it. If the canary's health were
    computed over every `seam-sdk` row in the response instead, the positive control would stop
    exercising the `version:` qualifier — which is precisely the part of the query most likely to
    be silently ignored, and the part the target's empty answer is being trusted against.

    The response here is a plausible page: real `seam-sdk` rows, both formats, just not at the
    version that was asked for. That is what a dropped or misspelled qualifier returns.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    elsewhere: dict[str, object] = {c: published("0.6.1") for c in ROSTER if c != "0.7.78"}
    elsewhere["0.7.78"] = published("0.7.78")
    bin_dir, _ = curl_stub(tmp_path, elsewhere)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, (
        f"a canary whose rows are all at some OTHER version certified the instrument and the run "
        f"reached a verdict anyway: exit {proc.returncode}\n{proc.stdout}{proc.stderr}"
    )
    assert "nothing usable for any canary" in proc.stderr, (
        f"it exited 2, but not through the canary's own refusal: {proc.stderr}"
    )


def test_an_unsafe_version_is_never_put_into_a_request(tmp_path: Path) -> None:
    """`assert_query_safe` runs BEFORE anything is fetched, and only the call log can show that.

    The refusal is reached either way, so the exit code proves nothing about ordering: moved below
    the fetch, the guard still exits 2 — after building
    `?query=seam-sdk+version:0.7.78&admin=1&page_size=50` from a value read out of `main` and
    sending it. Two attacker-chosen parameters reach the registry and every assertion stays green.
    """
    repo = make_repo(tmp_path, version="0.7.78&admin=1")
    bin_dir, calls = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0])})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "&" in proc.stderr, f"the refusal does not name the offending character: {proc.stderr}"
    assert calls.read_text() == "", (
        f"a version the guard rejects was still put on the wire: {calls.read_text()!r}. The guard "
        f"has to run before the request is built, not merely before the verdict."
    )


def test_the_roster_is_deep_enough_to_survive_a_yank(tmp_path: Path) -> None:
    """The comment claims "three, so two would have to go before this needs an edit". Pin it.

    The mechanism (any candidate may answer) is pinned by the tests above; the DEPTH is a separate
    claim and shrinking the tuple to two left every one of them green. Distinctness matters for
    the same reason: three copies of one version is a one-entry roster wearing a three-entry shape,
    and a single yank brings the whole check down to a permanent exit 2 that readers learn to
    scroll past.
    """
    roster = _load_script().CANARY_VERSIONS
    assert len(set(roster)) >= 3, (
        f"CANARY_VERSIONS is {roster}. Fewer than three distinct entries and one yank leaves the "
        f"check unable to prove its own instrument."
    )


def test_a_roster_with_nothing_left_to_probe_names_the_constant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reachable only when the roster shrinks to entries the target already occupies.

    Unreachable through the CLI with three entries, which is exactly why it was written and never
    observed.

    Matched on wording unique to THIS branch, not on `CANARY_VERSIONS`. Deleting the guard drops
    through to the generic all-canaries-failed refusal further down, whose message also names the
    constant — so matching the constant passes either way and pins nothing. The two conditions are
    genuinely different ("there is nothing left to ask" versus "everything I asked came back
    short") and the message a reader gets has to tell them apart.
    """
    module = _load_script()
    monkeypatch.setattr(module, "CANARY_VERSIONS", ("0.7.78",))
    with pytest.raises(module.InfraError, match="no independent probe"):
        module.assert_live_instrument_healthy("0.7.78", "irrelevant")
    # And it must still point at the thing to edit.
    with pytest.raises(module.InfraError, match="CANARY_VERSIONS"):
        module.assert_live_instrument_healthy("0.7.78", "irrelevant")


# ── The script's own dependencies ─────────────────────────────────────────────────────────────


def test_the_script_imports_only_the_standard_library() -> None:
    """The scheduled workflow runs no `pip install`, so a third-party import is a broken job.

    Anti-vacuity is the `>= 4` floor on the scan's own output: an AST walk that returned nothing
    would satisfy an "all imports are stdlib" assertion for free.
    """
    import ast

    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    tops: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            tops |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            tops.add(node.module.split(".")[0])
    assert len(tops) >= 4, f"the import scan found only {sorted(tops)} — it is scanning nothing"
    third_party = sorted(t for t in tops if t not in sys.stdlib_module_names)
    assert not third_party, (
        f"{SCRIPT.name} imports {third_party}, which is not in the standard library. The "
        "registry-drift workflow installs nothing, so this would fail the scheduled run outright."
    )


# ── Phase 5: the scheduled workflow that runs all of the above ────────────────────────────────
#
# The workflow is a second implementation of the credential resolution — the script reads
# `SEAM_REGISTRY_TOKEN`, and something has to put a Cloudsmith secret into it. `yank.yml` shipped
# that same resolution with a bug that made every invocation 401, dry run included, and nothing
# noticed because the failure was CLOSED: it could not delete the wrong thing, it simply never
# worked. The same shape here is worse, not better — a permanently-401ing drift check exits 2 on
# every scheduled run, which reads as "infrastructure is flaky" and gets muted.
#
# So the shell is EXECUTED here, exactly as `scripts/test_yank_gate.py:9-12` argues. Reading it
# would not have caught that bug and will not catch the next one.

WORKFLOW = REPO / ".github" / "workflows" / "registry-drift.yml"


def _workflow() -> dict:
    parsed = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert parsed is not None, f"{WORKFLOW.name} did not parse; every guard below would be vacuous"
    return parsed


def _triggers() -> dict:
    # YAML 1.1 resolves a bare `on:` key to the boolean True, which is why this is not `wf["on"]`.
    # Same handling as `scripts/test_yank_gate.py:222`.
    wf = _workflow()
    return wf[True] if True in wf else wf["on"]


def _job() -> dict:
    jobs = _workflow()["jobs"]
    assert len(jobs) == 1, f"expected one job, got {sorted(jobs)}"
    return next(iter(jobs.values()))


def _drift_step() -> dict:
    return next(s for s in _job()["steps"] if "installable" in str(s.get("name", "")))


def _wf_code() -> list[str]:
    """The step's shell with whole-line comments removed.

    Every static assertion about the step goes through this, never the raw `run`. The step's own
    comments quote `set -euo pipefail` verbatim, so a substring search over the raw body is
    satisfied by prose with the real line deleted — which is how two of `yank.yml`'s guards were
    vacuous (`scripts/test_yank_gate.py:51-62`).

    **It removes whole-line comments only, and that is a real limit rather than an oversight.**
    Stripping everything after a `#` would corrupt the lines that matter most here: `${TOKEN#Bearer }`
    is a parameter expansion, not a comment. So a directive demoted to a TRAILING comment —
    `:  # echo "::add-mask::$TOKEN"` — survives this filter. Any assertion whose mutation looks
    like that must match on the line's SHAPE (does it start with the command?) rather than on the
    needle appearing somewhere in it. `test_the_token_is_masked_before_anything_can_print_it` does.
    """
    return [ln for ln in _drift_step()["run"].splitlines() if not ln.strip().startswith("#")]


def _token_script() -> str:
    """The workflow's own shell, truncated at the call it is setting up for.

    Truncating rather than stubbing `python3` keeps this honest about its subject: the credential
    resolution and the refusal, not the check itself — which has eighty tests of its own above.
    """
    run = _drift_step()["run"]
    marker = "python3 scripts/"
    assert marker in run, (
        "the step no longer invokes the checker with `python3 scripts/…`, which is where this "
        "harness truncates. Re-point the marker rather than deleting the guard."
    )
    assert "CLOUDSMITH_API_KEY" in run[: run.index(marker)], (
        "the truncated region no longer contains the credential resolution — this harness would "
        "be executing an empty script and passing."
    )
    # Read back from a CHILD PROCESS, not with `echo`. The checker is a child, and a bare
    # assignment is fully visible to the rest of the same bash process — so `echo
    # "${SEAM_REGISTRY_TOKEN:-}"` passes identically whether or not `export` is there, and deleting
    # the word `export` left all 126 tests green while the real job handed the script nothing.
    # A python child is the only thing that can tell an exported variable from a shell one.
    return run[: run.index(marker)] + (
        "python3 -c 'import os; print(\"RESOLVED=[%s]\" % os.environ.get"
        '("SEAM_REGISTRY_TOKEN", ""))\'\n'
    )


def _run_token_script(dedicated: str | None, cargo: str | None) -> subprocess.CompletedProcess[str]:
    # `/usr/bin:/bin` gives the step a real `sed`, `tr` and `python3` — the last of which is what
    # reads the exported variable back. Deliberately NOT the ambient PATH: the step must not be
    # able to reach anything this machine happens to have installed.
    env = {"PATH": "/usr/bin:/bin"}
    if dedicated is not None:
        env["CLOUDSMITH_API_KEY"] = dedicated
    if cargo is not None:
        env["CARGO_REGISTRIES_ZER07LABS_TOKEN"] = cargo
    # Plain `bash -c`, NOT `bash -e`. The step sets its own `set -euo pipefail`; running it under
    # an externally imposed `-e` would hide the removal of that line.
    return subprocess.run(
        ["bash", "-c", _token_script()], capture_output=True, text=True, env=env, check=False
    )


def test_the_workflow_runs_on_a_clock_and_on_demand_and_nothing_else() -> None:
    """No `pull_request` trigger, and that is not a noise judgement like `framework-coinstall.yml`'s.

    Secrets are unavailable to a fork-triggered run, so the resolution below would find nothing and
    exit 2 on every external contribution — an infrastructure failure, reported correctly, forever.
    And nothing in a pull request can change this answer: it is a statement about the default
    branch and the registry.
    """
    assert set(_triggers()) == {"schedule", "workflow_dispatch"}, (
        f"triggers are {sorted(_triggers())}. A push/PR trigger cannot see secrets on a fork and "
        f"would exit 2 on every external contribution."
    )
    crons = [entry["cron"] for entry in _triggers()["schedule"]]
    assert crons, "the schedule declares no cron — the check would only ever run on demand"


def _cron_period_minutes(spec: str) -> int | None:
    """The largest gap between consecutive runs, or `None` if there is no fixed sub-daily one.

    Reading the hour field alone is what let `17 */2 * * 1` through — a weekly cadence wearing a
    two-hourly hour field. So day-of-month, month and day-of-week must all be `*` before the hour
    field means anything at all.

    `*/N` and `A-B/N` are both accepted: `17 1-23/2 * * *` is a correct every-two-hours spelling
    and rejecting it would be a guard enforcing a preferred syntax rather than a property. An
    explicit list (`17 0,12 * * *`) is read as the largest gap between its entries, wrapping at
    midnight — 0 and 12 is a twelve-hour period, not a two-hour one.
    """
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


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("17 */2 * * *", 120),
        ("17 1-23/2 * * *", 120),   # the same cadence, spelled out
        ("17 */6 * * *", 360),
        ("17 0,12 * * *", 720),     # a list, read as its largest gap
        ("17 3 * * *", 1440),       # once a day
        ("17 */2 * * 1", None),     # Mondays only — weekly, wearing a two-hourly hour field
        ("17 */2 1 * *", None),     # the 1st of the month
        ("*/5 * * * *", None),      # the minute field is not a fixed minute
        ("17 nonsense * * *", None),
    ],
)
def test_the_cron_period_reader_is_not_fooled_by_the_hour_field(spec, expected) -> None:
    """The parser the guard below depends on, driven directly.

    It is the piece that was wrong — reading `c.split()[1]` and calling it the period — so it gets
    its own cases rather than being exercised only through the one cron the workflow happens to
    carry. `1-23/2` and `0,12` are the two shapes that separate "reads the syntax" from "matches
    a prefix".
    """
    assert _cron_period_minutes(spec) == expected


def test_the_cron_cannot_step_over_the_warn_band() -> None:
    """The middle tier is the one that has to be *observed*; the soft tier only has to suppress.

    Worth being precise, because the obvious version of this test is wrong. A first draft asserted
    the period must be narrower than `SOFT_GRACE_MINUTES`, and the shipped 120-minute cron fails
    that against a 90-minute soft window — correctly, because the soft tier's job is to say nothing
    while a publish may still be running. Whether any run happens to land inside it is luck, and
    nothing depends on that luck.

    The warn band is different. It exists so that "something is wrong, but a job could still be
    alive" is stated once before anything escalates. If the period exceeded the band's WIDTH
    (`HARD - SOFT`), a release could go from too-fresh to escalated with no run in between, and the
    middle tier would be decoration — present in the code, never reachable in production.
    """
    module = _load_script()
    crons = [entry["cron"] for entry in _triggers()["schedule"]]
    band = module.HARD_GRACE_MINUTES - module.SOFT_GRACE_MINUTES
    periods = {c: _cron_period_minutes(c) for c in crons}
    tight = [c for c, minutes in periods.items() if minutes is not None and minutes < band]
    assert tight, (
        f"no cron entry runs often enough: {periods}. The warn band is {band} minutes wide "
        f"({module.SOFT_GRACE_MINUTES}m to {module.HARD_GRACE_MINUTES}m), and a release that "
        f"crosses it between two runs escalates with the middle tier never printed — code that "
        f"exists and never executes. `None` means the entry does not run at a fixed sub-daily "
        f"cadence on every day, which is the shape `17 */2 * * 1` hides in."
    )


@pytest.mark.parametrize(
    ("dedicated", "cargo", "expected"),
    [
        ("cs-key", "", "cs-key"),
        ("", "Bearer cargo-tok", "cargo-tok"),
        ("", "cargo-tok", "cargo-tok"),
        ("Bearer cs-key", "", "cs-key"),
        ("cs-key", "Bearer cargo-tok", "cs-key"),
        ("Bearer ", "Bearer cargo-tok", "cargo-tok"),
        # Beyond the ten `scripts/test_yank_gate.py:93-140` covers. `yank.yml` tests the RAW value
        # with `-z`, so a secret that is a single space is not empty: the fallback is never
        # consulted and a perfectly good Cargo token in scope is discarded. That is a permanent
        # exit 2 whose log says the credential is missing while the repository can see one.
        ("   ", "Bearer cargo-tok", "cargo-tok"),
        ("\n", "cargo-tok", "cargo-tok"),
        # And a usable value with whitespace around it must arrive trimmed rather than being
        # refused or sent malformed. `Bearer` followed by more than one space is the same case:
        # `${TOKEN#Bearer }` eats exactly one and leaves the rest leading the header value.
        ("  cs-key  ", "", "cs-key"),
        ("Bearer   cs-key", "", "cs-key"),
        # The rule the shell's comment promises: `Bearer` is a prefix only when something separates
        # it from the value. Without these two, `s/^Bearer[[:space:]]*//` (zero-or-more) and
        # `s/^Bearer  *//` (literal spaces only) both pass — the first eats six characters off a
        # token that merely starts with those letters, the second stops handling a tab.
        ("BearerTok123", "", "BearerTok123"),
        ("Bearer\ttok", "", "tok"),
        # A secret pasted from Windows, and one pasted with a stray second line. The second is the
        # one that mattered: `::add-mask::` registers one line, so an unhandled multi-line token
        # printed its tail into the run log as ordinary text.
        ("cs-key\r", "", "cs-key"),
        # A CR in the MIDDLE, which neither trim can reach — and the only shape that distinguishes
        # `tr -d '\r'` from the trailing-whitespace rule. It matters because the value goes into
        # `X-Api-Key: <token>`, where a bare CR is a header-splitting shape.
        ("cs\rkey", "", "cskey"),
        ("cs-key\nrubbish", "", "cs-key"),
    ],
    ids=[
        "dedicated-only",
        "cargo-with-bearer",
        "cargo-without-bearer",
        "dedicated-with-bearer",
        "both-set",
        "prefix-only-dedicated-falls-through",
        "whitespace-only-dedicated-falls-through",
        "newline-only-dedicated-falls-through",
        "dedicated-surrounded-by-whitespace",
        "bearer-followed-by-several-spaces",
        "bearer-with-no-separator-is-not-a-prefix",
        "bearer-separated-by-a-tab",
        "carriage-return-from-a-windows-paste",
        "carriage-return-inside-the-value",
        "only-the-first-line-is-the-credential",
    ],
)
def test_the_credential_reaches_the_checker_by_the_name_it_reads(
    dedicated: str, cargo: str, expected: str
) -> None:
    """The same six shapes `scripts/test_yank_gate.py:93-113` covers, asserted on the export.

    `cargo-with-bearer` is the shape that was broken in `yank.yml`: the org Cargo token carries the
    prefix, and a token still wearing `Bearer ` arrives as `X-Api-Key: Bearer …` and authenticates
    as nothing. Here that is not a closed failure — every run exits 2 and the check is dead.
    """
    p = _run_token_script(dedicated, cargo)
    assert p.returncode == 0, f"the step refused a usable credential: {p.stdout}{p.stderr}"
    assert f"RESOLVED=[{expected}]" in p.stdout, (
        f"SEAM_REGISTRY_TOKEN is not {expected!r} — got {p.stdout.strip()!r}. The checker reads "
        f"that variable and nothing else; a token resolved into a name it does not read is the "
        f"same as no token."
    )


@pytest.mark.parametrize(
    ("dedicated", "cargo"),
    [
        ("", ""),
        (None, None),
        ("", "Bearer "),
        ("Bearer ", ""),
        # Whitespace is not a credential, in either source or after the prefix comes off.
        ("   ", "  "),
        ("\n", ""),
        ("Bearer   ", ""),
        ("", "Bearer \t"),
    ],
    ids=[
        "both-empty",
        "both-unset",
        "cargo-is-only-the-prefix",
        "dedicated-is-only-the-prefix",
        "both-are-whitespace",
        "dedicated-is-a-newline",
        "dedicated-is-prefix-plus-spaces",
        "cargo-is-prefix-plus-a-tab",
    ],
)
def test_a_missing_credential_is_infrastructure_and_exits_2_not_1(
    dedicated: str | None, cargo: str | None
) -> None:
    """**Exit 2, and the digit is the whole point.**

    `yank.yml` exits 1 here and is right to — it is a destructive tool where 1 means "refused".
    In this workflow 1 already means *the registry is behind the source*. A repository that has
    lost its Cloudsmith secret would then file a drift verdict about a release that published
    perfectly well, and the verdict would be indistinguishable from a real one.

    `both-unset` is the case `set -u` decides: a bare `${VAR#Bearer }` on an absent variable
    aborts the step with bash's own status, not with the refusal.
    """
    p = _run_token_script(dedicated, cargo)
    assert p.returncode == 2, (
        f"an unusable credential exited {p.returncode}, not 2. 1 is the drift verdict; a missing "
        f"secret reported as drift is a wrong answer, not a loud one. Output: {p.stdout}{p.stderr}"
    )
    assert "No Cloudsmith credential" in p.stdout + p.stderr, (
        "the step failed, but not with its own refusal — so it failed for some other reason and "
        f"this test is not proving what it claims: {p.stdout}{p.stderr}"
    )


def test_the_token_is_masked_before_anything_can_print_it() -> None:
    """`::add-mask::` only masks output that comes AFTER it, so its position is the guarantee.

    Read from the comment-stripped body: the comment beside this line says the word `add-mask`,
    and a substring search over the raw `run` is satisfied by that comment with the real directive
    deleted.
    """
    code = _wf_code()
    # Three separate things, because each was defeated on its own:
    #   * it must EMIT, not mention — `_wf_code()` drops whole-line comments only (it cannot drop
    #     trailing ones without corrupting `${TOKEN#Bearer }`), so `:  # echo "::add-mask::$TOKEN"`
    #     kept the needle, the index and the ordering while running nothing;
    #   * the argument must be THE TOKEN — `echo "::add-mask::"` registers an empty mask and
    #     `echo "::add-mask::x"` masks a literal, both silently;
    #   * the output must reach the runner — `echo "::add-mask::$TOKEN" > /dev/null` is a mask
    #     nobody receives.
    # `printf` is accepted as well as `echo`: it is a correct way to emit the directive and
    # rejecting it would be a guard dictating style rather than behaviour.
    emitters = re.compile(r"^(?:echo|printf)\s")
    masks = [
        i
        for i, ln in enumerate(code)
        if emitters.match(ln.strip()) and "::add-mask::" in ln
    ]
    assert masks, (
        "the step never EMITS `::add-mask::` — a line mentioning it is not the same as a line "
        f"running it. Lines seen: {[ln for ln in code if '::add-mask::' in ln]}. Without the "
        "directive the token appears in plain text in the Actions log the first time anything "
        "echoes it, and the value here is a trimmed derivative that Actions does not redact on "
        "its own."
    )
    for i in masks:
        line = code[i]
        assert re.search(r"\$\{?TOKEN\b", line), (
            f"the mask directive does not carry the token: {line.strip()!r}. `::add-mask::` with "
            f"a literal or an empty argument registers a mask for something that is not the "
            f"credential, and nothing else here would notice."
        )
        assert not re.search(r"[>|]", line), (
            f"the mask directive's output is redirected: {line.strip()!r}. The runner reads "
            f"workflow commands off the step's stdout; a mask it never sees masks nothing."
        )
    users = [
        i
        for i, ln in enumerate(code)
        if "SEAM_REGISTRY_TOKEN" in ln or "python3 scripts/" in ln
    ]
    assert users and min(masks) < min(users), (
        f"the mask is emitted at line {min(masks)} but the token is first used at {min(users)}. "
        f"`::add-mask::` does not redact output that was already written."
    )
    # Ordering relative to the two known consumers is not enough. `::add-mask::` cannot redact what
    # was already printed, so ANY line that writes the token before it is a leak — and the step's
    # own comment names `set -x` as the scenario while nothing enforced against it.
    for i, ln in enumerate(code[: min(masks)]):
        assert not re.match(r"^\s*(?:echo|printf|cat|tee)\b", ln) or "$TOKEN" not in ln, (
            f"line {i} prints the token before the mask is registered: {ln.strip()!r}"
        )
    assert not any(re.match(r"^\s*set\s+[-+][a-z]*x", ln) for ln in code), (
        "the step enables shell tracing. Every command — including the assignments that build the "
        "token — is echoed to the log, and the trace of the assignment runs before `::add-mask::` "
        "can register anything."
    )


def test_the_checkers_exit_status_is_the_steps_exit_status() -> None:
    """The verdict travels out of this job as an exit code and nothing else.

    So anything that decouples the two turns a drift into a green job, and none of it appears on
    the invocation line where the guard above looks. All three of these survived:

        trap 'exit 0' ERR      one line, anywhere after `set -euo pipefail`
        set +e                 plus any trailing command
        <invocation>; echo ok  the step's status becomes the last command's

    `exit 2` does not fire an ERR trap and `if [ … ]` conditions are exempt from `-e`, so the
    credential tests stay green throughout — the refusal path is untouched. Only the verdict is
    lost.
    """
    code = [ln for ln in _wf_code() if ln.strip()]
    for pattern, why in (
        (r"^\s*trap\b", "a trap can convert a failing command into a successful step"),
        (r"^\s*set\s+\+", "`set +e` disarms the errexit the rest of this step relies on"),
    ):
        offenders = [ln.strip() for ln in code if re.match(pattern, ln)]
        assert not offenders, f"{offenders}: {why}"
    assert "python3 scripts/" in code[-1], (
        f"the last command in the step is {code[-1].strip()!r}, not the checker. The step's exit "
        f"status is its last command's, so anything after the invocation replaces the verdict "
        f"with its own success."
    )


def test_the_token_resolution_does_not_rely_on_an_and_list() -> None:
    """`publish.yml` resolves with `[ -z … ] && TOKEN=…`; that step has no `set -e`, this one does.

    The AND-list is safe by a rule about AND-OR exit status that most readers do not hold, and it
    becomes the step's exit status if it is ever moved last. The explicit `if` is immune to both.
    """
    offenders = [ln for ln in _wf_code() if "&&" in ln and "TOKEN=" in ln]
    assert not offenders, (
        f"the token resolution uses an AND-list under `set -euo pipefail`: {offenders}. Use the "
        f"explicit `if`, as `yank.yml:54-62` does."
    )
    # EXACT line match, not a substring of the step: the comment above the resolution contains
    # this literal, and `in run` was satisfied by prose in `yank.yml` with the real line deleted.
    assert any(ln.strip() == "set -euo pipefail" for ln in _wf_code()), (
        "the step lost `set -euo pipefail`. Without it an unset secret no longer aborts, and the "
        "refusal below is reached with a variable that silently expanded to nothing."
    )


def test_the_checkout_asks_for_tags_explicitly() -> None:
    """`fetch-depth: 0` is *believed* to bring tags. That is behaviour, not a contract.

    A tag-less checkout here is not a loud failure. `tag_present()` answers "absent" for every
    version, which selects state C's remediation — *"the version commit landed but the tag push
    failed"* — for what is really state B. Every release would be misdiagnosed, confidently and in
    the same direction. `TAG_FLOOR` catches it as an exit 2; this is the belt to that braces, and
    it is asserted here because the two are independent and either alone is a single point.
    """
    checkout = next(s for s in _job()["steps"] if "checkout" in str(s.get("uses", "")))
    with_ = checkout.get("with") or {}
    # WHAT is checked out, not only how much of it. `ref: v0.1.0` freezes the check on a commit
    # whose version the registry does serve, so it prints OK forever while `main` drifts;
    # `repository: someone/else` answers about a different repository entirely. Both are one
    # `with:` key and both left every other assertion green. The plan's "scheduled runs execute on
    # the default branch — which is exactly what the source says" is the claim being enforced here.
    assert set(with_) <= {"fetch-depth", "fetch-tags"}, (
        f"the checkout takes {sorted(set(with_) - {'fetch-depth', 'fetch-tags'})}. `ref:` and "
        f"`repository:` change which source the verdict is about; the check is a statement about "
        f"this repository's default branch and nothing else."
    )
    assert with_.get("fetch-depth") == 0, (
        f"the checkout does not set `fetch-depth: 0` (got {with_.get('fetch-depth')!r}). "
        f"`version_landed_at` uses `git log -S` over the whole history and a shallow clone "
        f"truncates it."
    )
    assert with_.get("fetch-tags") is True, (
        "the checkout does not set `fetch-tags: true`. Without tags, every release is diagnosed "
        "as 'the tag push failed' regardless of what actually happened."
    )


def test_the_job_is_bounded_and_cannot_be_told_to_ignore_itself() -> None:
    """A scheduled job with no ceiling is a silent multi-hour burn; `continue-on-error` is a mute."""
    timeout = _job().get("timeout-minutes")
    assert isinstance(timeout, int), (
        "the job declares no `timeout-minutes`. A hung request in a scheduled job burns until "
        "GitHub's six-hour default, every two hours, with nobody watching."
    )
    # A NUMBER, not merely a declaration. `timeout-minutes: 360` is GitHub's own default written
    # out longhand — it satisfies "is an int" and changes nothing. The job makes at most a handful
    # of HTTP requests, each already capped by `CURL_MAX_SECONDS`.
    assert 0 < timeout <= 30, (
        f"`timeout-minutes: {timeout}` is not a ceiling. The job does a checkout and a few capped "
        f"requests; anything near GitHub's six-hour default means a hang is indistinguishable "
        f"from a slow day for hours at a time."
    )
    assert "continue-on-error" not in WORKFLOW.read_text(encoding="utf-8"), (
        "`continue-on-error` appears in the workflow. This check's only output is whether the job "
        "is red; a job that cannot go red reports nothing at all."
    )


def test_the_job_installs_nothing() -> None:
    """The other end of the checker's stdlib-only obligation, seen from the workflow.

    `scripts/check_registry_drift.py` shells out to `curl` instead of importing `requests`
    precisely so this job needs no dependency resolution. A `pip install` appearing here would
    mean that obligation had been dropped somewhere in the script, and this is the assertion that
    notices — the script itself cannot tell you what it is no longer allowed to import.
    """
    for step in _job()["steps"]:
        # An action can install too. `uses: BSFishy/pip-action@v1` runs pip without the word
        # appearing in any `run:` body, and the shell-only scan never saw it.
        action = str(step.get("uses", ""))
        assert "pip" not in action.lower(), (
            f"step uses {action!r}, which installs packages without a `run:` line to notice."
        )
        body = "\n".join(
            ln for ln in str(step.get("run") or "").splitlines() if not ln.strip().startswith("#")
        )
        # `pip3`, `python -m pip`, and any flags in between — `python3 -m pip --quiet install`
        # evaded the tighter pattern. Each of those is the same act with different spelling.
        assert not re.search(r"\b(?:python3?\s+-m\s+)?pip3?\s+(?:-\S+\s+)*install\b", body), (
            f"step {step.get('name') or step.get('uses')!r} installs packages. The checker is "
            f"stdlib-only by design; if it now needs a dependency, that is the thing to revisit."
        )


def test_the_declared_permissions_are_exactly_what_the_job_uses() -> None:
    """Both directions, so this survives Phases 6 and 7 without being rewritten.

    A `permissions:` block grants ONLY what it lists — an undeclared scope is `none`, not
    inherited. So the staleness arm (`gh api …/actions/…/runs`) 403s unless `actions: read` travels
    in the same commit, and the issue arm 403s without `issues: write`. The reverse direction
    matters too: a scope declared for work that was later removed is standing authority nothing
    needs, on a job that reads a production credential.
    """
    # Job-level if present, else top-level — because job permissions REPLACE top-level rather
    # than extend them, so whichever is nearest the job is the one that decides. Reading only the
    # top level would have made this test red the moment Phase 6 moves the block down, which is
    # the plan's own instruction; a guard that forces its own rewrite at the next phase is a guard
    # that gets rewritten into something weaker.
    perms = _job().get("permissions", _workflow().get("permissions"))
    assert isinstance(perms, dict), (
        f"`permissions:` is {perms!r}. It must be an explicit mapping — omitting it inherits the "
        f"repository default, which may be read/write for everything."
    )
    assert not any("permissions" in step for step in _job()["steps"]), "steps cannot take permissions"

    # THE SURFACE IS THE SCRIPT, AND ONLY THE SCRIPT. The workflow's `run:` text is deliberately
    # NOT part of it, and that exclusion is a fix rather than an oversight.
    #
    # Phase 6 rebuilt this guard because prose was justifying `issues: write` — but it hardened
    # only the script half and left the workflow half as raw text with whole-line comments
    # stripped. A TRAILING comment survives that filter, which `_wf_code()`'s docstring already
    # warned about in this very file. So
    #     python3 scripts/check_registry_drift.py --report  # replaces the `gh issue create` runbook
    # justified `issues: write` with a sentence, on a script where no issue write existed at all.
    # An `echo "...gh issue create..."` did it too. The hole had moved, not closed.
    #
    # It is excluded rather than filtered because no scope needs it: the whole design of this
    # phase is that the `gh` calls live in the script, so the `run:` line contains no `gh` call
    # and no `api` call to find. A surface that cannot help can only hurt.
    body = _script_argv() + "\n" + _script_code()

    # `PERMISSION_NEEDLES` is module-level so the control test below searches the SAME regexes
    # this guard enforces. Anything outside that mapping is standing authority nobody has argued
    # for, on a job that holds a production credential.
    justifiable = PERMISSION_NEEDLES
    unknown = set(perms) - set(justifiable)
    assert not unknown, (
        f"`permissions:` declares {sorted(unknown)}, which nothing here accounts for. Add the "
        f"scope to `justifiable` together with the needle that proves the job uses it — an "
        f"unexplained scope is standing authority for work nobody can point at."
    )
    assert perms.get("contents") == "read", "the job checks out the repository"
    for scope, (needle, why) in justifiable.items():
        if needle is None:
            continue
        uses = re.search(needle, body) is not None
        declared = scope in perms
        assert uses == declared, (
            f"the job {'does' if uses else 'does not'} do {why}, but `{scope}` is "
            f"{'declared' if declared else 'not declared'} in `permissions:`. An undeclared scope "
            f"is `none` rather than inherited and the call 403s; a declared-but-unused one is "
            f"standing authority for nothing."
        )

    # BELT, over every declared scope rather than over `issues` alone. The loop above searches
    # argv AND blanked code; this one insists the justification appear in the ARGV specifically —
    # the surface that can only be built by handing a list literal to a call.
    #
    # It is a loop and not a hardcoded line because the hardcoded version protected `issues` and
    # left `actions` bare, so the scope Phase 7 adds would have landed with no belt at all on the
    # day the assertion naming it gets deleted. A belt that covers only the scope that already has
    # one is not a belt.
    argv = _script_argv()
    for scope in perms:
        needle, why = justifiable[scope]
        if needle is None:
            continue
        assert re.search(needle, argv), (
            f"`{scope}` is declared, but no ARGV in the script does {why} — only the wider "
            f"surface says so. A permission has to be earned by a call, not by anything a "
            f"sentence can imitate."
        )


#: scope -> (regex proving the job uses it, what needs it). ONE copy, shared by the guard that
#: enforces it and by the control that proves the guard is not vacuous. A second copy would be a
#: second thing to forget, and being satisfied by the wrong thing is this needle's entire failure
#: mode — see `test_a_permission_cannot_be_justified_by_prose_about_the_code`.
#:
#: The `issues` needle names WRITE verbs only. `gh issue list` needs `issues: read`; it must not be
#: what argues for `write`.
PERMISSION_NEEDLES = {
    "contents": (None, "checking out the repository"),
    "issues": (
        r"\bissue\s+(?:create|comment|reopen|edit|close|delete|lock)\b",
        "filing, commenting on or reopening an issue",
    ),
    "actions": (r"/actions/", "reading the Actions API for this workflow's own run history"),
}


def _script_tree(src: str | None = None) -> ast.Module:
    """`check_registry_drift.py` parsed, with every docstring deleted from the tree."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8") if src is None else src)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body.pop(0)
            if not node.body:
                node.body.append(ast.Pass())
    return tree


def _argv_words(node: ast.List | ast.Tuple) -> list[str]:
    words = []
    for element in node.elts:
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            words.append(element.value)
        elif isinstance(element, ast.JoinedStr):
            # An f-string in an argv slot is still an argv word: Phase 7's Actions read is
            # `f"repos/{repo}/actions/runs"`, and dropping it would hide the call it is.
            words.append(
                "".join(
                    part.value
                    for part in element.values
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
            )
    return words


#: Callees whose first positional argument IS an argv. An allowlist, not a denylist, and the
#: direction matters: an unlisted spawn helper makes a needle stop matching, which trips the guard
#: loudly, while an unlisted PROSE builder would silently re-admit exactly the sentences this
#: surface exists to exclude. `run` covers `subprocess.run`; `_gh` is this script's own wrapper.
ARGV_CALLEES = frozenset({"_gh", "run"})


def _callee_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _script_argv(src: str | None = None) -> str:
    """Every list/tuple literal handed as the FIRST POSITIONAL argument to a SPAWN callee.

    This is the surface that proves the script SPAWNS something, as distinct from the surface that
    merely talks about spawning it.

    **The callee filter is load-bearing and was added after review.** Taking the first positional
    slot of *any* call makes the separation "assignment vs call" rather than "prose vs argv", and
    those come apart under an ordinary refactor: `_issue_body` builds its markdown as
    `lines = [...]` then `"\n".join(lines)`, which is excluded only because the list is bound to a
    name first. Inline it to `return "\n".join([...])` — a pure-style change nobody would question
    in review — and a bullet reading ``Run `gh issue create` by hand to refile.`` lands in the argv
    surface and justifies `issues: write` on its own. Verified: that exact spelling satisfied the
    write needle before this filter existed.
    """
    lines = []
    for node in ast.walk(_script_tree(src)):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if not isinstance(node.args[0], (ast.List, ast.Tuple)):
            continue
        if _callee_name(node) not in ARGV_CALLEES:
            continue
        lines.append(" ".join(_argv_words(node.args[0])))
    return "\n".join(lines)


class _BlankStrings(ast.NodeTransformer):
    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        if isinstance(node.value, str):
            return ast.copy_location(ast.Constant(value=""), node)
        return node


def _script_code(src: str | None = None) -> str:
    r"""`check_registry_drift.py` as structure and names only — every string literal blanked.

    **The blanking is the fix for a real defect this phase found, not tidiness.** Before it, the
    needle for `issues` was `\bgh\b\W{1,8}issue\b`, and the only things in the whole script that
    matched it were two ERROR MESSAGES: ``f"unreadable row from `gh issue list`"`` and ``f"`gh
    issue list` returned a non-numeric issue number"``. The actual calls are spelled
    `_gh(["issue", "create", …], repo)` — `"gh"` lives inside `_gh`'s own argv and is never
    adjacent to `"issue"` — so the permission was being justified by prose ABOUT the code while the
    code itself went unread. A mutation that deleted those two messages (leaving every `gh issue`
    call intact) turned the guard red, which is how it surfaced.

    Prose can no longer reach the surface at all: strings survive only via `_script_argv`, which
    keeps them exclusively where they are an argv. Docstrings are deleted from the tree first,
    since `ast.unparse` would otherwise emit them.
    """
    tree = _BlankStrings().visit(_script_tree(src))
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def _permission_surface(source: str) -> str:
    """The exact surface the guard searches, built from an arbitrary script instead of the real one.

    Parameterising the builders is what makes the control below a control. The previous version of
    this test asserted the needle against hand-written spellings — including
    `subprocess.run(["gh", "issue", "create"])`, which this codebase does not use anywhere — and
    passed while the real file satisfied the needle only through two error messages.
    """
    return _script_argv(source) + "\n" + _script_code(source)


def test_a_permission_cannot_be_justified_by_prose_about_the_code() -> None:
    """The control that would have caught the defect `_script_code` now documents.

    A script that only TALKS about `gh issue create` — in an exception message, in a `print`, in a
    markdown body it assembles — must not be able to justify `issues: write`. A script that
    actually spawns it must. Both halves are asserted, because either alone is satisfiable by a
    needle that is simply always-false or always-true.
    """
    needle, _why = PERMISSION_NEEDLES["issues"]

    talks_about_it = """
def f(repo):
    body = ["Close this issue and label it.", "Run `gh issue create` by hand to refile."]
    print(f"filing with `gh issue create` on {repo}")
    raise RuntimeError(f"`gh issue create` exited non-zero")
"""
    assert not re.search(needle, _permission_surface(talks_about_it)), (
        "prose about `gh issue create` satisfies the issues needle. A permission would then be "
        "justified by a comment-shaped string rather than by a call, which is the defect this "
        "control exists for."
    )

    does_it = """
def f(repo):
    _gh(["issue", "create", "--title", title, "--body", body], repo)
"""
    assert re.search(needle, _permission_surface(does_it)), (
        "the codebase's own spelling of a `gh issue create` does not satisfy the issues needle, "
        "so the guard would demand `issues: write` be REMOVED at the moment it became necessary."
    )

    reads_only = """
def f(repo):
    _gh(["issue", "list", "--state", "all"], repo)
"""
    assert not re.search(needle, _permission_surface(reads_only)), (
        "`gh issue list` satisfies the WRITE needle. Listing needs `issues: read`; it must not be "
        "what argues for `write`."
    )

    # An argv-shaped list handed to a STRING BUILDER is prose wearing an argv's clothes. This is
    # the refactor `_script_argv`'s callee filter exists for: `_issue_body` is one inlining away
    # from this shape, and the bullet is the kind of remediation text it genuinely contains.
    prose_in_a_list = """
def f():
    return "\\n".join(["Run `gh issue create` by hand to refile."])
"""
    assert not re.search(needle, _permission_surface(prose_in_a_list)), (
        "a markdown bullet passed to `join` satisfies the issues needle. The separation has to be "
        "prose-vs-argv, not assignment-vs-call — those come apart under an ordinary refactor."
    )

    # And the real file must be on the right side of that line — this is the assertion that went
    # green for the wrong reason before the surface was rebuilt.
    assert re.search(needle, _script_argv()), (
        "no `gh issue <write verb>` appears in any argv in the script, yet `issues: write` is "
        "declared. Either the call moved or the needle stopped describing it."
    )

    # The blanking must remove prose without removing code.
    code = _script_code()
    assert "#:" not in code and '"""' not in code, "comments or docstrings survived the stripper"
    assert "REGISTRY_URL" in code, "the stripper removed code, not just prose"
    assert "unreadable row" not in code, "a string literal survived the blanker"
    assert "Registry drift" not in code, "a string literal survived the blanker"


def test_the_workflow_shell_cannot_argue_for_a_permission() -> None:
    """A trailing comment on the `run:` line justified `issues: write` with a sentence.

    Phase 6 rebuilt the script half of this surface and left the workflow half as raw text with
    only WHOLE-LINE comments stripped — a filter `_wf_code()`'s own docstring, in this file,
    already warned is defeated by a trailing comment. So

        python3 scripts/check_registry_drift.py --report  # replaces the `gh issue create` runbook

    earned the scope while the script contained no issue write at all, and an `echo` of the same
    sentence did it too. The needle was never the problem; the surface was.

    The fix is exclusion rather than a better filter, because no scope can be earned there: every
    `gh` call lives in the script by design, so the `run:` block has nothing to contribute and can
    only be imitated.
    """
    needle, _why = PERMISSION_NEEDLES["issues"]

    # FLOOR: the sentence really does satisfy the needle. Without this the test could pass because
    # the needle stopped matching anything at all, which is the failure it is meant to detect.
    imitation = "python3 scripts/check_registry_drift.py --report  # the `gh issue create` runbook"
    assert re.search(needle, imitation), (
        "the imitation no longer matches the needle, so this control proves nothing. Re-word it "
        "until it does — the point is that a MATCHING sentence must still not reach the surface."
    )

    surface = _script_argv() + "\n" + _script_code()
    run_text = "\n".join(str(step.get("run") or "") for step in _job()["steps"])
    assert "add-mask" in run_text, "floor: the credential shell is where this test thinks it is"
    assert "add-mask" not in surface, (
        "the workflow's shell is back in the permissions surface. Every scope must be earned by "
        "the script's own argv; a `run:` line can say anything."
    )


def test_the_actions_needle_is_ready_for_the_phase_that_needs_it() -> None:
    """`actions: read` is not declared yet, so its needle is unexercised until Phase 7 lands.

    An unexercised regex is an unverified one, and the direction it fails in is silent: a needle
    that never matches makes the guard demand the scope be REMOVED on the day the heartbeat starts
    reading the Actions API. Same failure the `issues` needle actually had, caught one phase early.
    """
    needle, _why = PERMISSION_NEEDLES["actions"]
    heartbeat = """
def f(repo, workflow):
    _gh(["api", f"repos/{repo}/actions/workflows/{workflow}/runs"], repo)
"""
    assert re.search(needle, _permission_surface(heartbeat)), (
        "the Actions-API call Phase 7 will make does not satisfy the actions needle."
    )
    assert "actions" not in (_job().get("permissions") or {}), (
        "`actions: read` is declared. Phase 7 grants it in the commit that uses it; if that has "
        "landed, this assertion is the one to delete."
    )


def test_the_secrets_are_actually_wired_into_the_step() -> None:
    """The credential tests inject their own env, so they prove the shell and nothing upstream of it.

    `_run_token_script()` sets `CLOUDSMITH_API_KEY` itself. That is right for testing the
    resolution, and it means deleting the step's whole `env:` block — or misspelling one
    `secrets.` reference — leaves every one of those ten cases green while the real job receives
    nothing and exits 2 on every scheduled run, forever, at a cadence that reads as flaky
    infrastructure and gets muted. That is verbatim the failure this block exists to prevent, one
    level up from where it was being checked.
    """
    # Job-level and step-level are equivalent here; requiring the step's own `env:` would redden
    # on a purely cosmetic move.
    env = {**(_job().get("env") or {}), **(_drift_step().get("env") or {})}
    for name in ("CLOUDSMITH_API_KEY", "CARGO_REGISTRIES_ZER07LABS_TOKEN"):
        assert name in env, (
            f"the step does not receive {name}. The shell below resolves it correctly and finds "
            f"nothing there, which is a permanent exit 2 with the secret sitting in scope."
        )
        assert env[name].strip() == "${{ secrets.%s }}" % name, (
            f"{name} is wired to {env[name]!r}, not to the secret of the same name. A misspelt "
            f"`secrets.` reference expands to the empty string — GitHub does not error on it."
        )


def test_nothing_can_switch_the_job_off_without_reddening_a_test() -> None:
    """`if: false` on the job or the step is the cheapest way to delete this check.

    One line, no code removed, 113 tests still testifying that the workflow works. There is no
    conditional logic in this job and no reason for one to appear; if a real condition is ever
    needed, this assertion is the place to argue for it.
    """
    job = _job()
    assert "if" not in job, f"the job carries `if: {job['if']!r}` — it can be switched off silently"
    for step in job["steps"]:
        assert "if" not in step, (
            f"step {step.get('name') or step.get('uses')!r} carries `if: {step['if']!r}`. A step "
            f"that does not run is a check that does not run, and the job still reports success."
        )


def test_the_job_runs_where_its_shell_actually_works() -> None:
    """`runs-on: windows-latest` makes `set -euo pipefail` a syntax error, invisibly to every test.

    Every assertion here executes the step's shell under `bash` on this machine. None of them can
    see which interpreter GitHub would hand it. The same goes for an explicit `shell:` override.
    """
    runner = _job()["runs-on"]
    assert isinstance(runner, str) and runner.startswith("ubuntu-"), (
        f"the job runs on {runner!r}. Every guard in this file executes the step under bash; on a "
        f"Windows runner the default shell is PowerShell and `set -euo pipefail` is not a "
        f"statement it has."
    )
    for step in _job()["steps"]:
        assert "shell" not in step, (
            f"step {step.get('name') or step.get('uses')!r} overrides `shell:` to "
            f"{step['shell']!r}. These tests run it under bash regardless."
        )
    # `defaults: run: shell:` does the same thing one level up, at either the workflow or the job,
    # and the per-step check above cannot see it. Both survived.
    for scope, holder in (("workflow", _workflow()), ("job", _job())):
        shell = ((holder.get("defaults") or {}).get("run") or {}).get("shell")
        assert shell is None, (
            f"{scope}-level `defaults.run.shell` is {shell!r}. It applies to every `run:` step "
            f"exactly as a per-step override would, and nothing here executes the step under it."
        )


def test_the_actions_the_job_depends_on_are_pinned_where_their_inputs_exist() -> None:
    """`fetch-tags` did not exist before `actions/checkout` v4.1.0, and an unknown `with:` key is
    silently IGNORED rather than an error.

    So downgrading to `@v3` leaves `test_the_checkout_asks_for_tags_explicitly` green — it reads the
    YAML — while tags stop being fetched and every release is misdiagnosed as "the tag push
    failed". `TAG_FLOOR` still catches it as exit 2, so the braces hold; this is the belt.
    """
    uses = {str(step.get("uses", "")).split("@")[0]: str(step.get("uses", "")) for step in _job()["steps"]}
    assert uses.get("actions/checkout") == "actions/checkout@v4", (
        f"checkout is pinned to {uses.get('actions/checkout')!r}. `fetch-tags:` is a v4.1.0+ input "
        f"and older versions ignore it without complaining."
    )
    setup = next(
        (s for s in _job()["steps"] if str(s.get("uses", "")).startswith("actions/setup-python")),
        None,
    )
    assert setup is not None, (
        "the setup-python step is gone. `ubuntu-latest` happens to ship a python3, so the job "
        "would still run — on whatever version the image drifts to next."
    )
    pinned = str((setup.get("with") or {}).get("python-version", ""))
    assert tuple(int(part) for part in pinned.split(".")) >= (3, 11), (
        f"python-version is pinned to {pinned!r}. The checker is written against 3.11+ and this is "
        f"the only place the interpreter is chosen."
    )


def test_no_run_can_be_cancelled_by_the_next_one() -> None:
    """The plan rejected `concurrency:` explicitly; nothing enforced the rejection.

    Cancelling a run mid-flight produces a missing answer that looks exactly like a passing one —
    the job ends without a verdict, and the schedule moves on. At a ~1-minute job against a 2-hour
    period there is nothing to de-duplicate anyway.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "concurrency" not in text, (
        "the workflow declares `concurrency:`. A cancelled run is an unanswered question that "
        "reports as a finished one."
    )


def test_the_workflow_runs_the_checker_this_file_is_about() -> None:
    """Anti-vacuity for the whole block: everything above tests a shell that must call the script.

    A rename that left this workflow pointing at a path that no longer exists would keep every
    assertion above green — the credential still resolves, the mask is still emitted — while the
    scheduled run does nothing but `python3: can't open file`, every two hours, forever.
    """
    invocations = [ln.strip() for ln in _wf_code() if "python3 scripts/" in ln]
    assert len(invocations) == 1, f"expected exactly one checker invocation, got {invocations}"
    tokens = invocations[0].split()
    # THE WHOLE LINE, token by token — not just the `.py` argument. Reading only the script path
    # left every one of these green while the check was disabled or answered a different question:
    #
    #   … check_registry_drift.py || true     the job can never go red
    #   … check_registry_drift.py &           backgrounded; the status is discarded
    #   … check_registry_drift.py > /dev/null the verdict never reaches the log
    #   … --hard-grace-minutes 100000         exit 1 becomes unreachable; DEFERRED forever
    #   … --repo /tmp                         a verdict about a directory that is not this repo
    #
    # Every one is a one-line diff with 100-odd tests testifying that the workflow works.
    assert tokens[0] == "python3", f"the invocation does not start with python3: {invocations[0]!r}"
    assert (REPO / tokens[1]).resolve() == SCRIPT.resolve(), (
        f"the workflow runs {tokens[1]}, which is not {SCRIPT.relative_to(REPO)}."
    )
    # Flags are allowlisted rather than pattern-matched, so adding one is a deliberate edit HERE
    # as well as there. Phase 6 adds `--report`; that is the moment to decide it belongs, not a
    # thing to discover afterwards.
    # `--report` is here because Phase 6 implemented it, in the same commit — it was on this list
    # once BEFORE that, "ready for Phase 6", while the script had no such flag. Adding it to the
    # workflow then would have passed this test and produced `unrecognized arguments: --report`,
    # argparse exit 2, on every scheduled run. The cross-check below is what would have caught it,
    # and it is the reason a flag never joins this set speculatively.
    allowed = {"--report"}
    declared = set(re.findall(r'add_argument\(\s*"(--[a-z-]+)"', SCRIPT.read_text(encoding="utf-8")))
    assert len(declared) >= 4, (
        f"only {sorted(declared)} parsed out of the script's argparse setup — the cross-check "
        f"below would be comparing against almost nothing."
    )
    unknown_to_script = [tok for tok in tokens[2:] if tok.startswith("--") and tok not in declared]
    assert not unknown_to_script, (
        f"the workflow passes {unknown_to_script}, which `{SCRIPT.name}` does not declare. "
        f"argparse exits 2 on an unrecognised argument, so this is a permanent infrastructure-red "
        f"at a cadence that gets muted — not a loud failure."
    )
    extra = [tok for tok in tokens[2:] if tok not in allowed]
    assert not extra, (
        f"the invocation carries {extra}. Arguments change the question the check asks — a grace "
        f"override makes the drift verdict unreachable, a `--repo` override asks about somewhere "
        f"else. Add the flag to `allowed` here in the same change that adds it there."
    )
    for operator in ("||", "&&", "&", ">", ">>", "|", ";", "`", "$("):
        assert operator not in invocations[0], (
            f"the invocation line contains {operator!r}: {invocations[0]!r}. The step's exit "
            f"status IS the verdict; anything that redirects, backgrounds or swallows it turns a "
            f"drift into a green job."
        )


def test_the_check_is_not_also_a_job_in_ci_yml() -> None:
    """It is a scheduled sibling, for `framework-coinstall.yml:5-8`'s reason and one of its own.

    That file's argument — the answer changes when a third party changes, so `ci-ok` stays a
    statement about the diff — holds here. The sharper reason is that this check exists to catch a
    release that was never dispatched, and a job that runs on a push cannot see that: the failure
    mode is precisely that nothing ran.
    """
    # Comment-stripped `run:` bodies, not the raw file. `ci.yml:680` *mentions* this script in a
    # comment explaining why the drift question is not asked there — which is the argument this
    # test enforces, so matching on it would fail for saying the right thing.
    hosts = []
    for suffix in ("*.yml", "*.yaml"):
        for candidate in (REPO / ".github" / "workflows").glob(suffix):
            parsed = yaml.safe_load(candidate.read_text(encoding="utf-8"))
            body = "\n".join(
                ln
                for job in (parsed.get("jobs") or {}).values()
                for step in (job.get("steps") or [])
                for ln in str(step.get("run") or "").splitlines()
                if not ln.strip().startswith("#")
            )
            if SCRIPT.name in body:
                hosts.append(candidate.name)
    hosts = sorted(hosts)
    assert hosts == [WORKFLOW.name], (
        f"{SCRIPT.name} is invoked from {hosts}. Running it on a push cannot observe a release "
        f"that was never dispatched, and holding unrelated merges hostage to registry uptime is "
        f"what `framework-coinstall.yml:5-8` argues against."
    )


def test_the_scheduled_run_never_passes_a_saved_response() -> None:
    """`--packages-json` is the one way to reach a clean verdict without querying anything.

    Offline mode exists for the tests and for a human reproducing a run by hand, and it carries its
    own health check — but a saved file cannot go stale in a way that check can see. A workflow
    pointed at a captured response would print `OK` on a schedule, forever, describing a registry
    it never contacted. The script cannot prevent that; this is where it gets prevented.
    """
    body = "\n".join(
        ln
        for step in _job()["steps"]
        for ln in str(step.get("run") or "").splitlines()
        if not ln.strip().startswith("#")
    )
    assert "--packages-json" not in body, (
        "the scheduled job passes `--packages-json`, so it reads a file instead of the registry. "
        "The verdict would then be a statement about that file's age, not about the registry."
    )


# ── Phase 6: reporting, suppression, and provable non-collision ───────────────────────────────
#
# `gh` is stubbed as an executable first on PATH, in the shape `scripts/test_release_notice_gate.py`
# uses: it logs every argv and answers `issue list` with a pre-rendered TSV. No mocks and no
# monkeypatching — the script builds a real argv and a real process reads it, so a change to the
# flags, to the `--jq` expression, or to the ORDER of the calls is visible from here.
#
# The property this block cares about most is not what the check files. It is what it does NOT
# file. An infrastructure failure must reach exit 2 with the `gh` log EMPTY, and both grace tiers
# must reach exit 0 with the `gh` log empty. A reporter that files on a broken instrument is worse
# than no reporter at all: the issue it opens is indistinguishable from a real one, and the only
# way to tell them apart is to redo by hand the work the check exists to do.

_SCRIPT_MODULE = _load_script()
DRIFT_TITLE = _SCRIPT_MODULE.DRIFT_TITLE
RELEASE_NOTICE_TITLE = _SCRIPT_MODULE.RELEASE_NOTICE_TITLE
SUPPRESSION_LABEL = _SCRIPT_MODULE.SUPPRESSION_LABEL
ISSUE_LIMIT = _SCRIPT_MODULE.ISSUE_LIMIT

#: The repository the stubbed `gh` is told it is filing against. Deliberately the real one: `REPO`
#: env resolution refuses anything that is not `owner/name`, and a fixture value that happened to
#: be malformed would pass every test here for the wrong reason.
STUB_REPO = "zer07labs/seam-sdk"

#: The version every reporting fixture drifts on. One constant so a test that asserts on a title
#: and a test that asserts on a listing cannot disagree about which release they are describing.
DRIFTING = "0.7.78"


#: The intra-field label separator, one copy, shared by the stub and by the script's `--jq`.
#: U+001F because GitHub permits a comma inside a label NAME and forbids nothing that would
#: collide with a unit separator.
LABEL_SEP = "\x1f"


def gh_stub(
    tmp_path: Path,
    listing: list[tuple[int, str, list[str], str]],
    *,
    fail_on: tuple[str, str] | None = None,
) -> tuple[Path, Path]:
    """A `gh` first on PATH. Returns (bin dir, argv-log path).

    `listing` rows are `(number, state, labels, title)` — exactly the four fields the script's own
    `--jq` projects, so the parser is exercised rather than bypassed.

    The log is NUL-delimited, not line-delimited, and that is not fussiness: the issue BODY is
    multi-line, so a `printf '[%s]\\n'` log of the kind `curl_stub` uses would split one argument
    across many lines and make the argv unrecoverable. Each invocation is preceded by a literal
    `CALL` record, which is why argv can be grouped per call rather than flattened into one stream
    where the ORDER of `reopen` and `comment` would be unobservable.

    `fail_on` makes one verb pair fail the way a GitHub outage does — non-zero with a message on
    stderr — so the promise that a delivery failure never becomes a verdict is testable.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "gh-argv"
    log.write_bytes(b"")
    tsv = tmp_path / "issues.tsv"
    # Labels joined by U+001F, mirroring the script's `--jq ... join("\u001f")`. A comma here
    # would make the stub disagree with the real projection on exactly the input that matters —
    # a label whose NAME contains a comma — so the parser would be exercised against a shape
    # GitHub never produces.
    tsv.write_text(
        "".join(
            f"{number}\t{state}\t{LABEL_SEP.join(labels)}\t{title}\n"
            for number, state, labels, title in listing
        ),
        encoding="utf-8",
    )
    lines = [
        "#!/usr/bin/env bash",
        f"""printf 'CALL\\0' >> {log}""",
        f"""printf '%s\\0' "$@" >> {log}""",
    ]
    if fail_on is not None:
        lines += [
            f"""if [ "$1" = "{fail_on[0]}" ] && [ "$2" = "{fail_on[1]}" ]; then""",
            """  echo 'gh: HTTP 503 — the GitHub API is unavailable' >&2""",
            "  exit 1",
            "fi",
        ]
    lines += [
        """if [ "$1" = "issue" ] && [ "$2" = "list" ]; then""",
        # The stub HONOURS `--state`, and that is load-bearing rather than fidelity for its own
        # sake. `--state all` narrowed to `--state open` is otherwise an invisible edit: a closed
        # suppressed issue drops out of the listing, the check files a duplicate every two hours
        # forever, and every suppression test stays green because the stub answered regardless of
        # what it was asked.
        """  case "$*" in""",
        f"""    *"--state open"*) awk -F'\t' '$2 == "OPEN"' {tsv} ;;""",
        f"""    *"--state closed"*) awk -F'\t' '$2 == "CLOSED"' {tsv} ;;""",
        f"""    *) cat {tsv} ;;""",
        """  esac""",
        "fi",
        "exit 0",
    ]
    stub = bin_dir / "gh"
    stub.write_text("\n".join(lines) + "\n", encoding="utf-8")
    stub.chmod(0o755)
    assert stub.read_text().startswith("#!"), "the stub shebang must be at column 0"
    return bin_dir, log


def gh_calls(log: Path) -> list[list[str]]:
    """Every `gh` invocation, argv-exact and in order."""
    calls: list[list[str]] = []
    for part in log.read_bytes().split(b"\0"):
        token = part.decode("utf-8")
        if token == "CALL":
            calls.append([])
        elif token:
            assert calls, f"argv {token!r} arrived before any CALL marker — the stub is broken"
            calls[-1].append(token)
    return calls


def gh_verbs(log: Path) -> list[str]:
    """`issue list`, `issue create`, … in the order they were invoked."""
    return [" ".join(call[:2]) for call in gh_calls(log)]


def gh_writes(log: Path) -> list[str]:
    """Every call that is not the read. This is what must be empty on every non-drift path."""
    return [verb for verb in gh_verbs(log) if verb != "issue list"]


def gh_flag(log: Path, verb: str, flag: str) -> str:
    """The value of `--title` / `--body` on the one call with this verb."""
    matches = [call for call in gh_calls(log) if " ".join(call[:2]) == verb]
    assert len(matches) == 1, f"expected exactly one `{verb}`, saw {len(matches)}"
    argv = matches[0]
    assert flag in argv, f"`{verb}` was invoked without {flag}: {argv}"
    return argv[argv.index(flag) + 1]


def report_env(
    bin_dir: Path, *, repo: str | None = STUB_REPO, token: str | None = None
) -> dict[str, str]:
    """The environment a reporting run sees. `REPO` and `GH_TOKEN` are wiped first, then set.

    Wiped rather than merely overwritten: an ambient `REPO` on the developer's machine would make
    the `REPO`-is-unset test pass by filing against whatever that named, which is the one outcome
    it exists to forbid.
    """
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("SEAM_REGISTRY_TOKEN", "REPO", "GH_TOKEN")
    }
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["GH_TOKEN"] = "stub-gh-token"
    if repo is not None:
        env["REPO"] = repo
    if token is not None:
        env["SEAM_REGISTRY_TOKEN"] = token
    return env


def report_run(
    repo: Path,
    packages: object | None,
    tmp_path: Path,
    *,
    listing: list[tuple[int, str, list[str], str]] | None = None,
    now: datetime | None = None,
    extra: list[str] | None = None,
    gh_bin: Path | None = None,
    gh_log: Path | None = None,
    env_repo: str | None = STUB_REPO,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the checker with `--report` against a stubbed `gh`. Returns (proc, argv log)."""
    if gh_bin is None or gh_log is None:
        gh_bin, gh_log = gh_stub(tmp_path, listing or [])
    proc = run(
        repo,
        packages,
        tmp_path,
        now=now,
        extra=["--report", *(extra or [])],
        env=report_env(gh_bin, repo=env_repo),
    )
    return proc, gh_log


def drift_listing(number: int, state: str, labels: list[str]) -> list[tuple[int, str, list[str], str]]:
    return [(number, state, labels, DRIFT_TITLE.format(version=DRIFTING))]


def test_the_gh_stub_records_a_multiline_argument_without_losing_it(tmp_path: Path) -> None:
    """The instrument for this whole block, proved before anything is measured with it.

    Every assertion below about a body reads it back through `gh_calls`. If the log could not
    survive an embedded newline — and the real body is a markdown table, so it is full of them —
    every one of those assertions would be measuring the truncation instead of the body.
    """
    bin_dir, log = gh_stub(tmp_path, [])
    body = "line one\nline two\n\n| a | b |"
    subprocess.run(
        [str(bin_dir / "gh"), "issue", "create", "--title", "t", "--body", body], check=True
    )
    assert gh_calls(log) == [["issue", "create", "--title", "t", "--body", body]]


# ── The decision table ────────────────────────────────────────────────────────────────────────


def test_a_first_drift_files_exactly_one_issue_that_says_what_is_wrong(tmp_path: Path) -> None:
    """Criterion 1. Nothing has been reported yet, so the check reports it — once."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(repo, published("0.7.77"), tmp_path, listing=[])

    assert proc.returncode == 1, proc.stderr
    assert gh_verbs(log) == ["issue list", "issue create"], gh_calls(log)
    assert gh_flag(log, "issue create", "--title") == DRIFT_TITLE.format(version=DRIFTING)

    body = gh_flag(log, "issue create", "--body")
    # The body has to stand on its own: whoever opens the issue is not holding the run log.
    for needle in (
        DRIFTING,
        "seam-sdk",
        "@zer07labs/seam-sdk",
        "npm",
        "python",
        "present",
        "minutes",
        SUPPRESSION_LABEL,
    ):
        assert needle in body, f"the filed body never mentions {needle!r}:\n{body}"


def test_the_body_names_the_format_that_is_actually_missing(tmp_path: Path) -> None:
    """Criterion 1's "names the missing format(s)", pinned where it can actually fail.

    The both-missing case above CANNOT check this. Its `"npm"` and `"python"` needles are already
    satisfied by the packages row — ``| packages | `seam-sdk` (python), `@zer07labs/seam-sdk`
    (npm) |`` — which names both ecosystems on every body ever filed. So replacing the verdict's
    `sorted(missing)` with `sorted(REQUIRED_FORMATS)`, making every issue claim BOTH formats are
    missing, left all 184 tests green. A half-published release would then file a body that
    misstates what is broken, and the person acting on it would go looking for the wrong failure.

    Half-published is not hypothetical here: `publish.yml` uploads the wheel and the npm package
    in separate steps, so one landing without the other is an ordinary outcome.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    # The npm package IS served at the drifting version; the wheel is not.
    proc, log = report_run(
        repo,
        rows(("seam-sdk", "0.7.77", "python"), ("@zer07labs/seam-sdk", DRIFTING, "npm")),
        tmp_path,
        listing=[],
    )
    assert proc.returncode == 1, proc.stderr
    body = gh_flag(log, "issue create", "--body")

    missing_row = next(
        (ln for ln in body.splitlines() if "missing" in ln.lower() and "|" in ln), None
    )
    assert missing_row is not None, f"no row names what is missing:\n{body}"
    assert "python" in missing_row, f"the missing format is not named:\n{missing_row}"
    assert "npm" not in missing_row, (
        f"the body claims npm is missing when the registry serves it. A body that names both "
        f"formats regardless of which one failed is indistinguishable from one that names "
        f"neither:\n{missing_row}"
    )


def test_a_drift_already_reported_does_not_report_it_again(tmp_path: Path) -> None:
    """Criterion 2. The check runs every two hours; re-detection is not new information.

    A comment per run is precisely how a reporter gets muted by the people it reports to.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo, published("0.7.77"), tmp_path, listing=drift_listing(42, "OPEN", [])
    )
    assert proc.returncode == 1, proc.stderr
    assert gh_writes(log) == [], gh_calls(log)
    assert "#42" in proc.stdout


def test_a_drift_that_came_back_comments_then_reopens(tmp_path: Path) -> None:
    """Criterion 3. Closed and unlabelled means someone believed it fixed. It is not fixed.

    THE ORDER IS PINNED, AND IT IS COMMENT-THEN-REOPEN. The two calls are not atomic, and the
    order decides what a failure between them costs. Reopen-then-comment, failing on the comment,
    leaves the issue OPEN and uncommented — and every later run then matches the `state == "OPEN"`
    row ("already reported, not commenting again"), so the "the drift is back" record is never
    written by any run, ever, and nothing retries because nothing can distinguish that state from
    a normal open report.

    Comment-then-reopen strands nothing: commenting on a closed issue is legal, so a failed reopen
    leaves CLOSED-and-unlabelled and the next run retries the pair. Its worst case is a duplicate
    comment; the other order's worst case is silence.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo, published("0.7.77"), tmp_path, listing=drift_listing(42, "CLOSED", [])
    )
    assert proc.returncode == 1, proc.stderr
    assert gh_verbs(log) == ["issue list", "issue comment", "issue reopen"], gh_calls(log)
    assert gh_calls(log)[2][:3] == ["issue", "reopen", "42"]
    assert DRIFTING in gh_flag(log, "issue comment", "--body")


def test_a_failed_reopen_leaves_the_issue_retryable(tmp_path: Path) -> None:
    """The reason the order above is what it is, exercised rather than merely asserted.

    `gh` dies on the reopen, after the comment landed. The run must exit 2 (infrastructure), and
    the issue must still be CLOSED — which is what makes the NEXT run take the reopen row again
    instead of the "already reported" one. An order assertion alone would still pass if the
    recovery reasoning behind it were wrong.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    gh_bin, gh_log = gh_stub(
        tmp_path, drift_listing(42, "CLOSED", []), fail_on=("issue", "reopen")
    )
    proc, log = report_run(
        repo, published("0.7.77"), tmp_path, gh_bin=gh_bin, gh_log=gh_log
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "issue comment" in gh_verbs(log), gh_calls(log)
    # The comment is on the issue; the state never moved. A rerun sees CLOSED and tries again.
    assert gh_verbs(log) == ["issue list", "issue comment", "issue reopen"], gh_calls(log)


def test_a_comma_in_some_other_label_cannot_suppress_a_drift(tmp_path: Path) -> None:
    """GitHub permits a comma inside a label NAME. The projection must not treat one as a delimiter.

    With `join(",")`, an issue carrying the single label `wontfix,deliberately-unpublished` — one
    label, one comma, entirely legal — splits into two, the second of which equals the suppression
    label exactly. A real drift would then be suppressed by an issue nobody ever labelled as
    suppressed, and the `::warning::` would name a label the repository does not have, so the
    person reading it could not even find what was silencing them.

    The direction is what makes this worth a test: splitting only ever ADDS label entries, so the
    failure is always toward false SILENCE, never toward noise.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=drift_listing(42, "CLOSED", [f"wontfix,{SUPPRESSION_LABEL}"]),
    )
    # Not suppressed: exit 1, and the issue is reopened and commented like any other recurrence.
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "SUPPRESSED" not in proc.stdout, proc.stdout
    assert gh_verbs(log) == ["issue list", "issue comment", "issue reopen"], gh_calls(log)


def test_a_github_outage_on_a_clean_run_does_not_redden_a_healthy_registry(
    tmp_path: Path,
) -> None:
    """The clean path's GitHub read is BEST EFFORT. Everywhere else, a `gh` failure is exit 2.

    Before reporting existed, a clean run touched nothing. Making it read GitHub means a GitHub
    outage would turn a run that PROVED the registry healthy into a red job — and red on this
    workflow has to keep meaning "there is something to look at about the registry", or it gets
    muted, which is the exact failure this check exists to prevent.

    Softening costs nothing here because this path has no report to lose: its whole output is a
    courtesy notice that an already-open issue can be closed. It stays audible one severity down,
    so a broken credential still announces itself on every clean run — earlier than it otherwise
    would, since the drift path only speaks when there is drift.
    """
    repo = make_repo(tmp_path, version="0.7.77", tag=True)
    gh_bin, gh_log = gh_stub(tmp_path, [], fail_on=("issue", "list"))
    proc, log = report_run(
        repo, published("0.7.77"), tmp_path, gh_bin=gh_bin, gh_log=gh_log
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "::warning::" in proc.stdout, proc.stdout
    assert "clean" in proc.stdout.lower()
    # It really did try — otherwise this passes for the wrong reason on a run that never called.
    assert gh_verbs(log) == ["issue list"], gh_calls(log)


def test_a_github_outage_on_a_drift_run_is_still_exit_two(tmp_path: Path) -> None:
    """The floor under the softening above: only the CLEAN path is best-effort.

    Without this, widening the `except InfraError` to cover both branches would leave the clean
    test green while a real drift silently exited 0 with nobody told — the reporter's single worst
    outcome, reached by a change that looks like consistency.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    gh_bin, gh_log = gh_stub(tmp_path, [], fail_on=("issue", "create"))
    proc, log = report_run(
        repo, published("0.7.77"), tmp_path, gh_bin=gh_bin, gh_log=gh_log
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "DRIFT" in proc.stdout, "the verdict must still be printed before the delivery failed"


def test_a_deliberate_non_publish_is_suppressed_but_never_silent(tmp_path: Path) -> None:
    """Criterion 4. Closed AND labelled: exit 0, no writes, and a warning that names all three.

    Named rather than merely emitted. A suppression is a standing decision, and the only thing that
    keeps a standing decision reviewable is that every run says which issue is making it.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=drift_listing(42, "CLOSED", [SUPPRESSION_LABEL]),
    )
    assert proc.returncode == 0, proc.stderr
    assert gh_writes(log) == [], gh_calls(log)
    assert "::warning::" in proc.stdout
    for needle in ("#42", DRIFTING, SUPPRESSION_LABEL):
        assert needle in proc.stdout, f"the suppression warning never names {needle!r}"
    # And it still says the registry is wrong — a suppressed drift is a drift.
    assert "still does not serve" in proc.stdout


def test_reopening_a_labelled_issue_stops_the_suppression(tmp_path: Path) -> None:
    """Criterion 4b. The label alone must not suppress; the state is half the key.

    Reopening is how a person says "I want to hear about this again", and it is the cheaper of the
    two undo gestures — cheaper than hunting down a label. If it did not work, the suppression
    would be one-way.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=drift_listing(42, "OPEN", [SUPPRESSION_LABEL]),
    )
    assert proc.returncode == 1, proc.stderr
    assert gh_writes(log) == [], gh_calls(log)


@pytest.mark.parametrize(
    ("age", "band", "marker"),
    [(10, "soft", "DEFERRED"), (200, "warn", "::warning::")],
)
def test_neither_grace_tier_touches_github(
    tmp_path: Path, age: int, band: str, marker: str
) -> None:
    """Criterion 4c, both tiers. Grace means grace — not even the read.

    The moment a grace tier files anything it has stopped being a grace window and become a
    reporting tier with a softer adjective. The read is included in that: `gh issue list` is
    harmless, but allowing it is what makes the write one edit away.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=[],
        now=LANDED + timedelta(minutes=age),
    )
    assert proc.returncode == 0, proc.stderr
    assert marker in proc.stdout, f"the {band} tier did not announce itself:\n{proc.stdout}"
    assert gh_calls(log) == [], f"the {band} tier called GitHub: {gh_calls(log)}"


def test_a_recovered_registry_says_the_issue_can_be_closed_and_closes_nothing(
    tmp_path: Path,
) -> None:
    """Criterion 5. The check only ever adds. Closing is a person's decision.

    A reporter that can retract its own reports is a much larger authority than one that can only
    speak, and the failure mode is far worse: a bug in the clean path would erase the record of a
    real outage rather than merely add noise to it.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo, published(DRIFTING), tmp_path, listing=drift_listing(42, "OPEN", [])
    )
    assert proc.returncode == 0, proc.stderr
    assert gh_writes(log) == [], gh_calls(log)
    assert "::notice::" in proc.stdout
    assert "#42" in proc.stdout
    assert "never closes" in proc.stdout


def test_a_clean_run_with_nothing_outstanding_says_nothing_to_github(tmp_path: Path) -> None:
    """The ordinary case — most runs. One read, no writes, no notice."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(repo, published(DRIFTING), tmp_path, listing=[])
    assert proc.returncode == 0, proc.stderr
    assert gh_writes(log) == [], gh_calls(log)
    assert "::notice::" not in proc.stdout


# ── Exact-title matching: three questions, one listing ────────────────────────────────────────


@pytest.mark.parametrize(
    ("state", "labels"),
    [("CLOSED", [SUPPRESSION_LABEL]), ("OPEN", []), ("CLOSED", [])],
)
def test_an_issue_that_merely_quotes_the_title_is_not_the_report(
    tmp_path: Path, state: str, labels: list[str]
) -> None:
    """Criterion 6. Containment is not identity, in any of the three ways it could matter.

    One listing answers three questions — is this reported, is it suppressed, is there a release
    notice to link — and that is only safe while every match is exact equality. A substring match
    would let a discussion thread that quotes the title answer any of the three: closed with the
    label it would suppress a real drift, open it would swallow the first report entirely.
    """
    exact = DRIFT_TITLE.format(version=DRIFTING)
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=[(99, state, labels, f"Re: {exact} — is this still happening?")],
    )
    assert proc.returncode == 1, proc.stderr
    assert gh_verbs(log) == ["issue list", "issue create"], gh_calls(log)
    assert gh_flag(log, "issue create", "--title") == exact


def test_a_drift_issue_for_another_version_does_not_answer_for_this_one(tmp_path: Path) -> None:
    """The title carries the version, so suppression is scoped to one release and never to all."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=[(7, "CLOSED", [SUPPRESSION_LABEL], DRIFT_TITLE.format(version="0.7.77"))],
    )
    assert proc.returncode == 1, proc.stderr
    assert gh_verbs(log) == ["issue list", "issue create"], gh_calls(log)


# ── The cross-link to the merged half of #100 ─────────────────────────────────────────────────


def test_an_open_release_notice_is_linked_from_the_filed_issue(tmp_path: Path) -> None:
    """Criterion 9. Both halves of #100 can fire on one release; they should not read as two bugs.

    `release-outcome` reports the publish RUN; this reports the registry's STATE. When both have
    something to say they are saying it about the same release, and a reader arriving at either one
    should be able to reach the other.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=[(7, "OPEN", [], RELEASE_NOTICE_TITLE.format(version=DRIFTING))],
    )
    assert proc.returncode == 1, proc.stderr
    body = gh_flag(log, "issue create", "--body")
    assert "#7" in body, f"the release notice was not linked:\n{body}"


def test_a_closed_release_notice_is_not_linked(tmp_path: Path) -> None:
    """A closed notice is a resolved run. Linking it would point a live issue at a dead lead."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=[(7, "CLOSED", [], RELEASE_NOTICE_TITLE.format(version=DRIFTING))],
    )
    assert proc.returncode == 1, proc.stderr
    assert "#7" not in gh_flag(log, "issue create", "--body")


def _release_outcome_title_template() -> str:
    """The `TITLE=` literal from `publish.yml`'s `release-outcome` job, read out of the workflow.

    Extracted rather than restated. The whole point of the test below is that these two titles can
    never collide, and a hand-copied second version of the other side's template would keep
    agreeing with itself long after `publish.yml` had moved.
    """
    publish = REPO / ".github" / "workflows" / "publish.yml"
    job = yaml.safe_load(publish.read_text(encoding="utf-8"))["jobs"]["release-outcome"]
    body = "\n".join(str(step.get("run") or "") for step in job["steps"])
    found = re.findall(r'TITLE="([^"]*)"', body)
    assert len(found) == 1, (
        f"expected exactly one TITLE= assignment in release-outcome, found {found}. The "
        f"non-collision proof below is only as good as its knowledge of what the other side files."
    )
    return found[0]


def _release_outcome_tag_expr() -> str:
    """The `TAG=` right-hand side from the same job, extracted rather than assumed.

    THIS IS THE FRAGILE HALF, and the test used to supply it itself with `.replace("${TAG}",
    f"v{version}")`. That hardcodes the one thing most likely to move: three other jobs in the same
    file spell it `${GITHUB_REF_NAME#v}`, so "make release-outcome consistent with its neighbours"
    is a plausible, well-intentioned edit. It would make `publish.yml` file `Release 0.7.78 did not
    publish` while this script hunts for `Release v0.7.78 did not publish`, and the cross-link would
    silently stop matching — with the test that claims to prove the equality still green, because
    it was rendering through its own assumption rather than through the workflow's.
    """
    publish = REPO / ".github" / "workflows" / "publish.yml"
    job = yaml.safe_load(publish.read_text(encoding="utf-8"))["jobs"]["release-outcome"]
    body = "\n".join(str(step.get("run") or "") for step in job["steps"])
    found = re.findall(r'TAG="([^"]*)"', body)
    assert len(found) == 1, (
        f"expected exactly one TAG= assignment in release-outcome, found {found}."
    )
    return found[0]


def test_the_two_reporters_can_never_file_the_same_issue() -> None:
    """Criterion 10. Non-collision by construction, pinned against the other side's real template.

    Two mechanisms file issues about the same release. If their titles could ever coincide, each
    would find the other's issue by exact-title match and take it for its own: this check would
    "already reported" a `release-outcome` issue and never file, and a `deliberately-unpublished`
    label meant for one would silence the other.

    Substring, not just inequality. Both matchers are exact-equality today, so inequality alone is
    enough — but that is a property of the current implementation, and a future editor relaxing
    either matcher to `contains` should be caught by this test rather than by an outage.
    """
    other = _release_outcome_title_template()
    assert other, "release-outcome's TITLE= extracted empty"
    assert "did not publish" in other, (
        f"the extracted template {other!r} does not look like the release notice title — the "
        f"regex is matching something else in the job's shell."
    )

    # The tag binding comes out of the workflow too. `GITHUB_REF_NAME` is the pushed tag, so an
    # UNSTRIPPED `${GITHUB_REF_NAME}` is what puts the `v` into the filed title — and
    # `RELEASE_NOTICE_TITLE` carries that `v` in its own literal. Asserting the expression rather
    # than rendering through a hardcoded `f"v{version}"` is what makes the neighbour-consistency
    # edit (`${GITHUB_REF_NAME#v}`, as at `.github/workflows/publish.yml:163`) fail HERE, in the
    # test that claims to own this equality, instead of incidentally in the sibling suite.
    tag_expr = _release_outcome_tag_expr()
    assert tag_expr == "${GITHUB_REF_NAME}", (
        f"release-outcome now derives its tag as {tag_expr!r}. If the `v` is stripped there, "
        f"publish.yml files `Release 0.7.78 did not publish` while this script looks for "
        f"`Release v0.7.78 did not publish`, and the cross-link dies silently. Either restore it "
        f"or drop the `v` from RELEASE_NOTICE_TITLE — they have to move together."
    )

    for version in ("0.7.69", "0.7.72", "0.7.77", DRIFTING, "0.8.0", "1.0.0"):
        # Rendered through the workflow's OWN tag expression, not through this test's idea of it.
        rendered_other = other.replace("${TAG}", tag_expr.replace("${GITHUB_REF_NAME}", f"v{version}"))
        # The cross-link finds that issue by exact title, so our copy of it must render identically
        # to what `publish.yml` actually files.
        assert RELEASE_NOTICE_TITLE.format(version=version) == rendered_other, (
            f"RELEASE_NOTICE_TITLE renders {RELEASE_NOTICE_TITLE.format(version=version)!r} but "
            f"publish.yml files {rendered_other!r} — the cross-link can never match."
        )
        mine = DRIFT_TITLE.format(version=version)
        assert mine != rendered_other
        assert mine not in rendered_other
        assert rendered_other not in mine

    # Criterion 10 asks that BOTH sides match exactly. This script's half is pinned by
    # `test_an_issue_that_merely_quotes_the_title_is_not_the_report`; publish.yml's half is this.
    # Without it the criterion is half-implemented: `release-outcome` relaxing its `awk` to a
    # substring test would make it adopt a discussion thread quoting its title, and the sibling
    # suite's fixtures do not contain the notice title so they would not notice either.
    publish_body = "\n".join(
        str(step.get("run") or "")
        for step in yaml.safe_load(
            (REPO / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        )["jobs"]["release-outcome"]["steps"]
    )
    assert "$2 == t" in publish_body, (
        "release-outcome no longer selects its issue by EXACT title. Both reporters match by "
        "equality; if either relaxes to a substring the two can adopt each other's issues, which "
        "is the collision this whole test exists to rule out."
    )


# ── Reporting is opt-in, and never speaks for a broken instrument ─────────────────────────────


def test_without_the_flag_a_drift_is_printed_and_nothing_is_filed(tmp_path: Path) -> None:
    """Criterion 7. A local or manual run is read-only.

    `gh` is on PATH and would work. Off by default is a choice, not an accident of the environment:
    same instinct as `.github/workflows/yank.yml`'s `dry_run: true` default.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    bin_dir, log = gh_stub(tmp_path, drift_listing(42, "CLOSED", []))
    proc = run(
        repo,
        published("0.7.77"),
        tmp_path,
        env=report_env(bin_dir),
    )
    assert proc.returncode == 1, proc.stderr
    assert "DRIFT —" in proc.stdout
    assert gh_calls(log) == [], gh_calls(log)


def test_reporting_is_off_in_the_parser_and_not_merely_in_how_it_is_called() -> None:
    """`--report` defaults off where it is DECLARED, not only where the workflow invokes it.

    The test above proves a run without the flag files nothing. This proves the flag is what is
    missing, rather than the absence being an accident of that invocation — a `default=True` would
    keep that test green while making every local run a reporting run.
    """
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    declarations = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "--report"
    ]
    assert len(declarations) == 1, f"expected one --report declaration, found {len(declarations)}"
    kwargs = {kw.arg: kw.value for kw in declarations[0].keywords}
    assert isinstance(kwargs.get("action"), ast.Constant)
    assert kwargs["action"].value == "store_true", ast.unparse(declarations[0])
    default = kwargs.get("default")
    assert default is None or (isinstance(default, ast.Constant) and default.value is False), (
        f"--report carries a default: {ast.unparse(declarations[0])}"
    )


@pytest.mark.parametrize(
    "broken",
    ["no-canary", "http-401", "no-token", "no-tags", "no-repo-env", "empty-response"],
)
def test_no_infrastructure_failure_ever_reaches_github(tmp_path: Path, broken: str) -> None:
    """Criterion 8. Exit 2 with an EMPTY `gh` log, on every way the instrument can be broken.

    This is the single most important assertion in the block. An issue filed because the credential
    expired is indistinguishable, to whoever opens it, from an issue filed because a release did
    not publish — and the only way to tell them apart is to redo by hand exactly the work this
    check exists to do. A reporter that files on a broken instrument is worse than no reporter.
    """
    version = DRIFTING
    packages: object | None = published("0.7.77")
    env_repo: str | None = STUB_REPO
    filler = FILLER_TAGS
    curl_bin: Path | None = None
    token: str | None = None

    if broken == "no-canary":
        curl_bin, _ = curl_stub(tmp_path, {})
        packages, token = None, STUB_TOKEN
    elif broken == "http-401":
        curl_bin, _ = curl_stub(tmp_path, {}, fail_with=22)
        packages, token = None, STUB_TOKEN
    elif broken == "no-token":
        curl_bin, _ = curl_stub(tmp_path, {v: published(v) for v in ROSTER})
        packages, token = None, None
    elif broken == "no-tags":
        filler = 0
    elif broken == "no-repo-env":
        env_repo = None
    elif broken == "empty-response":
        packages = []

    repo = make_repo(tmp_path, version=version, tag=True, filler_tags=filler)
    gh_bin, log = gh_stub(tmp_path, [])
    # One bin dir holds both stubs, so `curl` and `gh` are resolved by the same PATH entry and a
    # test cannot accidentally reach the real one while stubbing the other.
    assert curl_bin is None or curl_bin == gh_bin

    env = report_env(gh_bin, repo=env_repo, token=token)
    proc = run(repo, packages, tmp_path, extra=["--report"], env=env)

    assert proc.returncode == 2, f"{broken} exited {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    assert "::error::" in proc.stderr
    assert gh_calls(log) == [], f"{broken} reached GitHub: {gh_calls(log)}"


def test_a_github_outage_never_becomes_a_verdict(tmp_path: Path) -> None:
    """`gh` failing is infrastructure — exit 2 — and the verdict is still in the log.

    The order inside `main` is load-bearing and this is what pins it. Reporting talks to GitHub and
    GitHub has outages; if the report were computed before the verdict were printed, an outage
    would exit 2 with the answer never printed at all, and the run would be a total loss rather
    than an undelivered one. The verdict is the run's product; the issue is a delivery mechanism.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    gh_bin, log = gh_stub(tmp_path, [], fail_on=("issue", "create"))
    proc, _ = report_run(
        repo, published("0.7.77"), tmp_path, gh_bin=gh_bin, gh_log=log
    )
    assert proc.returncode == 2, proc.stdout
    assert "DRIFT —" in proc.stdout, "the verdict was lost to the delivery failure"
    assert "::error::" in proc.stderr
    assert "503" in proc.stderr


# ── The listing itself has to be trustworthy ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("row", "why"),
    [
        ("42\tOPEN\n", "a row with too few fields"),
        ("not-a-number\tOPEN\t\tRegistry drift\n", "a non-numeric issue number"),
    ],
)
def test_an_unreadable_listing_is_infrastructure_not_an_empty_listing(
    tmp_path: Path, row: str, why: str
) -> None:
    """A listing that cannot be parsed must not read as "no issue exists" and file a duplicate."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    gh_bin, log = gh_stub(tmp_path, [])
    (tmp_path / "issues.tsv").write_text(row, encoding="utf-8")
    proc = run(
        repo,
        published("0.7.77"),
        tmp_path,
        extra=["--report"],
        env=report_env(gh_bin),
    )
    assert proc.returncode == 2, f"{why} exited {proc.returncode}: {proc.stdout}"
    assert gh_writes(log) == [], gh_calls(log)


@pytest.mark.parametrize(
    ("count", "warns"),
    [
        pytest.param(ISSUE_LIMIT, True, id="at-the-limit-warns"),
        pytest.param(ISSUE_LIMIT - 1, False, id="one-below-stays-quiet"),
    ],
)
def test_a_listing_at_exactly_the_limit_says_it_may_be_a_window(
    tmp_path: Path, count: int, warns: bool
) -> None:
    """Pinning the denominator. At exactly `--limit` the listing may not be the whole set.

    "No existing issue" would then mean "none in the part I could see", and the check would file a
    duplicate every two hours forever. It still files — the alternative is going silent on a real
    drift — but it says why the answer may be wrong.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    filler = [
        (n, "CLOSED", [], f"unrelated issue {n}") for n in range(1, count + 1)
    ]
    proc, log = report_run(repo, published("0.7.77"), tmp_path, listing=filler)
    assert proc.returncode == 1, proc.stderr
    if warns:
        assert "truncated" in proc.stdout
        assert str(ISSUE_LIMIT) in proc.stdout
    else:
        # THE FLOOR. Without this the guard is unfalsifiable in the direction that will actually
        # happen: replacing the `len(issues) == ISSUE_LIMIT` test with `if True` makes every run
        # cry truncation forever, and the at-the-limit case above stays green. A warning that
        # cannot be observed NOT firing is a warning nobody will believe by the third week.
        assert "truncated" not in proc.stdout, proc.stdout
    assert gh_verbs(log) == ["issue list", "issue create"], gh_verbs(log)


def test_one_listing_answers_every_question_the_run_asks(tmp_path: Path) -> None:
    """Exactly one read per run, whatever the verdict.

    Not efficiency — blast radius. Three separate `gh issue list` calls could disagree with each
    other if an issue changed state between them, and the check would then reason about a
    repository state that never existed at any single moment.
    """
    for verdict, packages in (("drift", published("0.7.77")), ("clean", published(DRIFTING))):
        sub = tmp_path / verdict
        sub.mkdir()
        repo = make_repo(sub, version=DRIFTING, tag=True)
        _, log = report_run(repo, packages, sub, listing=drift_listing(42, "OPEN", []))
        assert gh_verbs(log).count("issue list") == 1, f"{verdict}: {gh_verbs(log)}"


@pytest.mark.parametrize("bad", ["", "   ", "seam-sdk", "zer07labs/seam-sdk/extra", "a b/c"])
def test_a_repo_that_is_not_owner_slash_name_is_refused_before_any_call(
    tmp_path: Path, bad: str
) -> None:
    """The reporting target comes from `${{ github.repository }}`, and is validated anyway.

    Deriving it from the checkout's git remotes would make the target depend on how the checkout
    was made — a fork, a mirror, a `ref:` override — and file issues wherever that pointed.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    gh_bin, log = gh_stub(tmp_path, [])
    env = report_env(gh_bin, repo=None)
    if bad:
        env["REPO"] = bad
    proc = run(
        repo, published("0.7.77"), tmp_path, extra=["--report"], env=env
    )
    assert proc.returncode == 2, f"REPO={bad!r} exited {proc.returncode}: {proc.stdout}"
    assert gh_calls(log) == [], gh_calls(log)


# ── The workflow declares the write it performs ───────────────────────────────────────────────


def test_the_job_declares_the_issue_write_it_now_performs() -> None:
    """Criterion 12, the falsifiable half.

    `test_the_declared_permissions_are_exactly_what_the_job_uses` already refuses a scope nothing
    uses; this refuses a use nothing declares. Together they are an equality, and neither direction
    alone is one — a job can be broken by an over-grant or by an under-grant, and only the second
    fails at runtime with a 403 that reads like a GitHub problem.

    `actions: read` is deliberately NOT here. The plan grants it in this phase, but nothing in this
    phase reads the Actions API, and the exactness guard above correctly refuses it. Phase 7 adds
    the heartbeat and the scope in the same commit — recorded as this phase's divergence.
    """
    perms = _job().get("permissions") or {}
    # Deliberately NOT an exact-dict assertion. Pinning the whole mapping would duplicate
    # `test_the_declared_permissions_are_exactly_what_the_job_uses` and force its own rewrite in
    # Phase 7 — a guard that has to be edited to add a legitimate scope is a guard that gets edited
    # into something weaker. What that guard cannot see is the LEVEL: it checks a scope's presence,
    # so `issues: read` on a job that files issues would satisfy it and 403 at runtime.
    assert perms.get("issues") == "write", (
        f"`issues` is {perms.get('issues')!r}. The job creates, comments on and reopens an issue; "
        f"a read grant 403s on all three, and the failure arrives as a GitHub-shaped error rather "
        f"than as a workflow-shaped one."
    )


def test_the_scheduled_run_actually_reports() -> None:
    """`--report` is what makes this phase exist, and it lives in one word of one line.

    Deleting it leaves every test in this file green — the script still reaches the right verdict,
    the workflow still runs, the permissions are still correct — and the check goes permanently
    silent: a red job in a tab nobody opens. That is the whole unfalsifiable-green class in a
    single-token diff, so it gets its own assertion rather than riding on the allowlist above,
    which only says the flag is *permitted*.
    """
    invocations = [
        line
        for line in _wf_code()
        if SCRIPT.name in line
    ]
    assert invocations, f"the workflow never invokes {SCRIPT.name}"
    assert all("--report" in line for line in invocations), (
        f"the scheduled run does not pass --report, so it computes a verdict and tells nobody: "
        f"{invocations}"
    )


def test_the_reporting_credentials_are_wired_into_the_step() -> None:
    """`gh` needs `GH_TOKEN`, and the reporting target comes from `REPO`.

    Same reasoning as the registry secrets one row up, and the same failure: the reporting tests
    inject both themselves, so dropping either from the step leaves them green while every real
    drift exits 2 with "cannot report" — an infrastructure failure caused by the workflow, at a
    cadence that reads as flaky and gets muted.
    """
    env = {**(_job().get("env") or {}), **(_drift_step().get("env") or {})}
    assert env.get("GH_TOKEN", "").strip() == "${{ github.token }}", (
        f"GH_TOKEN is {env.get('GH_TOKEN')!r}. `gh` reads it from the environment and has no "
        f"other credential in a job."
    )
    assert env.get("REPO", "").strip() == "${{ github.repository }}", (
        f"REPO is {env.get('REPO')!r}. It must be the repository the run is about — deriving it "
        f"from the checkout would follow a fork or a `ref:` override and file issues there."
    )


def test_every_call_names_the_repository_it_is_talking_about() -> None:
    """`--repo` on every `gh` call, from `$REPO` rather than from the checkout.

    `gh` falls back to the current directory's git remote when `--repo` is absent, so dropping it
    is invisible in CI on the happy path and wrong in exactly the cases `issue_repo()` exists for:
    a fork, a mirror, or a `ref:` override. Asserted over the argv rather than over the source, so
    a call added later without the flag is caught by the same assertion.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo = make_repo(root, version=DRIFTING, tag=True)
        proc, log = report_run(
            repo, published("0.7.77"), root, listing=drift_listing(42, "CLOSED", [])
        )
        assert proc.returncode == 1, proc.stderr
        calls = gh_calls(log)
        assert len(calls) == 3, calls
        for call in calls:
            assert "--repo" in call, f"a `gh` call without --repo: {call}"
            assert call[call.index("--repo") + 1] == STUB_REPO, call


def test_the_listing_asks_for_closed_issues_too(tmp_path: Path) -> None:
    """`--state all`. Suppression lives on a CLOSED issue, so an open-only listing cannot see it.

    The failure is not a crash: the suppressed issue simply is not there, the check reads that as
    "nothing reported yet", and files a fresh duplicate every two hours — while the person who
    suppressed it sees their closed, labelled issue sitting exactly where they left it.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    _, log = report_run(repo, published("0.7.77"), tmp_path, listing=[])
    listing = [call for call in gh_calls(log) if call[:2] == ["issue", "list"]]
    assert len(listing) == 1, listing
    argv = listing[0]
    assert "--state" in argv, argv
    assert argv[argv.index("--state") + 1] == "all", argv


def test_the_stub_would_notice_an_open_only_listing(tmp_path: Path) -> None:
    """The behavioural half of the assertion above, through a stub that honours `--state`.

    A static argv pin says what was asked; this says what happens when the wrong thing is asked.
    Together they mean neither a changed flag nor a changed stub can quietly restore the green.
    """
    bin_dir, log = gh_stub(tmp_path, drift_listing(42, "CLOSED", [SUPPRESSION_LABEL]))
    listed = subprocess.run(
        [str(bin_dir / "gh"), "issue", "list", "--state", "open"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert listed.stdout.strip() == "", (
        "the stub answered an open-only listing with a CLOSED issue, so `--state all` narrowed to "
        "`--state open` would be unobservable from here."
    )
