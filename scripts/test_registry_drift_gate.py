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
    """The step's shell with comment lines removed.

    Every static assertion about the step goes through this, never the raw `run`. The comments in
    this step quote the strings the guards look for — `set -euo pipefail`, `::add-mask::` and
    `pip install` all appear in prose beside the code that does or does not do them. That is not
    hypothetical: two of `yank.yml`'s guards were vacuous for exactly this reason
    (`scripts/test_yank_gate.py:51-62`), and one of them stayed green with the real line deleted.
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
    # The EXPORTED name, not the local. What the checker actually reads is `SEAM_REGISTRY_TOKEN`;
    # a resolution that gets `TOKEN` right and then fails to export it leaves the script with no
    # credential, which is exit 2 forever.
    return run[: run.index(marker)] + 'echo "RESOLVED=[${SEAM_REGISTRY_TOKEN:-}]"\n'


def _run_token_script(dedicated: str | None, cargo: str | None) -> subprocess.CompletedProcess[str]:
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
    (hours,) = {c.split()[1] for c in crons}
    assert hours.startswith("*/"), f"cannot read a period out of the cron hour field {hours!r}"
    period = int(hours[2:]) * 60
    band = module.HARD_GRACE_MINUTES - module.SOFT_GRACE_MINUTES
    assert 0 < period < band, (
        f"the workflow runs every {period} minutes and the warn band is only {band} minutes wide "
        f"({module.SOFT_GRACE_MINUTES}m to {module.HARD_GRACE_MINUTES}m). A release can cross the "
        f"whole band between two runs, so the warn tier would never be printed and escalation "
        f"would arrive with no prior notice."
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
    ],
    ids=[
        "dedicated-only",
        "cargo-with-bearer",
        "cargo-without-bearer",
        "dedicated-with-bearer",
        "both-set",
        "prefix-only-dedicated-falls-through",
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
    [("", ""), (None, None), ("", "Bearer "), ("Bearer ", "")],
    ids=[
        "both-empty",
        "both-unset",
        "cargo-is-only-the-prefix",
        "dedicated-is-only-the-prefix",
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
    masks = [i for i, ln in enumerate(code) if "::add-mask::" in ln]
    assert masks, (
        "the step never emits `::add-mask::`. The token would appear in plain text in the Actions "
        "log the first time anything echoes it — including a future `set -x` added while debugging."
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
    assert isinstance(_job().get("timeout-minutes"), int), (
        "the job declares no `timeout-minutes`. A hung request in a scheduled job burns until "
        "GitHub's six-hour default, every two hours, with nobody watching."
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
        body = "\n".join(
            ln for ln in str(step.get("run") or "").splitlines() if not ln.strip().startswith("#")
        )
        assert "pip install" not in body, (
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
    perms = _workflow().get("permissions")
    assert isinstance(perms, dict), (
        f"top-level `permissions:` is {perms!r}. It must be an explicit mapping — omitting it "
        f"inherits the repository default, which may be read/write for everything."
    )
    assert not any("permissions" in step for step in _job()["steps"]), "steps cannot take permissions"
    assert perms.get("contents") == "read", "the job checks out the repository"
    body = "\n".join(
        ln
        for step in _job()["steps"]
        for ln in str(step.get("run") or "").splitlines()
        if not ln.strip().startswith("#")
    )
    for scope, needle, why in (
        ("issues", "gh issue", "filing or updating an issue"),
        ("actions", "/actions/", "reading the Actions API"),
    ):
        uses = needle in body
        declared = scope in perms
        assert uses == declared, (
            f"the job {'does' if uses else 'does not'} do {why}, but `{scope}` is "
            f"{'declared' if declared else 'not declared'} in `permissions:`. An undeclared scope "
            f"is `none` and the call 403s; a declared-but-unused one is standing authority for "
            f"nothing."
        )


def test_the_workflow_runs_the_checker_this_file_is_about() -> None:
    """Anti-vacuity for the whole block: everything above tests a shell that must call the script.

    A rename that left this workflow pointing at a path that no longer exists would keep every
    assertion above green — the credential still resolves, the mask is still emitted — while the
    scheduled run does nothing but `python3: can't open file`, every two hours, forever.
    """
    invocations = [ln.strip() for ln in _wf_code() if "python3 scripts/" in ln]
    assert len(invocations) == 1, f"expected exactly one checker invocation, got {invocations}"
    (called,) = [tok for tok in invocations[0].split() if tok.endswith(".py")]
    assert (REPO / called).resolve() == SCRIPT.resolve(), (
        f"the workflow runs {called}, which is not {SCRIPT.relative_to(REPO)}."
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
