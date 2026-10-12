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
import contextlib
import importlib.util
import io
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


#: The checker, loaded ONCE. Everything below that needs a constant or a function out of it reads
#: it from here rather than re-loading, so the whole suite is talking about a single module object.
_SCRIPT_MODULE = _load_script()

#: The canary roster, read from the script rather than restated here. A second copy is a second
#: thing to forget: changing `CANARY_VERSIONS` used to redden four tests that had hardcoded it,
#: which is a maintenance tax with no diagnostic value — the roster's CONTENT is not what these
#: tests are about.
ROSTER = _SCRIPT_MODULE.CANARY_VERSIONS

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


def upload_stamp(when: datetime) -> str:
    """`when` spelled exactly as Cloudsmith spells `uploaded_at` (observed 2026-10-12):
    microseconds and a `Z`, e.g. `2026-10-11T04:43:28.896556Z`."""
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


#: Every fixture row's `uploaded_at` unless it says otherwise: the same instant the fixture repo
#: dates its version commit from, so a test that never thinks about the upload clock gets an age
#: equal to the git age it already chose, and never a stamp in its future.
UPLOADED = upload_stamp(LANDED)


def rows(*specs: tuple[str, str, str], uploaded_at: str = UPLOADED) -> list[dict]:
    """Registry rows as `(name, version, format)` triples, each carrying `uploaded_at` — the
    field the newest-version question's clock is read from (seam-sdk#253)."""
    return [
        {"name": n, "version": v, "format": f, "uploaded_at": uploaded_at} for n, v, f in specs
    ]


def published(version: str, *, uploaded_at: str = UPLOADED) -> list[dict]:
    return rows(
        ("seam-sdk", version, "python"),
        ("@zer07labs/seam-sdk", version, "npm"),
        uploaded_at=uploaded_at,
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

#: Where each `curl_stub` records a request it must never receive: an UNSCOPED query to partner.
#: The newest question asks partner only about one version (`fetch_registry(V, …)`); an unscoped
#: partner read would be a second discovery against a second repository, and nothing in the plan
#: answers that question. The stub refuses it (exit 97) AND writes it here, and the autouse
#: fixture below fails any test whose stub saw one — so the refusal cannot be laundered by the
#: script capturing the stub's exit as a newest fault and the test asserting a 2 it expected.
_UNSCOPED_PARTNER_LOGS: list[Path] = []

#: The stub's exit code for that refusal. Not a code real curl uses for anything this script names.
UNSCOPED_PARTNER_REFUSAL = 97


@pytest.fixture(autouse=True)
def _partner_is_never_asked_an_unscoped_query():
    """Fail any test during which partner received an unscoped query, whatever it asserted."""
    _UNSCOPED_PARTNER_LOGS.clear()
    yield
    seen = [(p, p.read_text()) for p in _UNSCOPED_PARTNER_LOGS if p.exists() and p.read_text()]
    _UNSCOPED_PARTNER_LOGS.clear()
    assert not seen, f"partner was asked an unscoped query: {seen}"


def _version_sort_key(row: object) -> tuple[int, tuple[int, ...]]:
    """Descending-version order for the stub's unscoped answer. Plain versions by number, the way
    `sort=-version` was observed to order them; anything else after every plain one."""
    version = row.get("version") if isinstance(row, dict) else None
    if isinstance(version, str) and re.fullmatch(r"[0-9]+(\.[0-9]+)*", version):
        return (1, tuple(int(p) for p in version.split(".")))
    return (0, ())



def _write_payload(path: Path, payload: object) -> None:
    """`bytes` verbatim (a body that is not UTF-8 is a case to test), `str` as-is, else JSON."""
    if isinstance(payload, bytes):
        path.write_bytes(payload)
    else:
        path.write_text(
            payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8"
        )


def curl_stub(
    tmp_path: Path,
    responses: dict[str, object],
    *,
    fail_with: int | None = None,
    stderr_text: str | None = None,
    partner_responses: dict[str, object] | None = None,
    partner_fail_with: int | None = None,
    unscoped: object | None = None,
) -> tuple[Path, Path]:
    """A `curl` first on PATH. Returns (bin dir, call-log path).

    UNSCOPED queries (no `version:` — the newest question's `NEWEST_QUERY`, seam-sdk#253) are
    answered, for internal only, with what a sorted registry holding exactly `responses` would
    return: the union of every list payload in it, sorted by version descending, cut at the page
    size. So a test written before the newest question existed gets a newest version consistent
    with the per-version answers it already chose, and no test has to describe the same registry
    twice. Non-list payloads (an HTML error page, raw bytes) are a statement about ONE request and
    are left out of the union. `unscoped=` overrides the union with any payload at all — a list in
    the wrong order, `[]`, bytes — for the tests that are about the unscoped answer itself.
    Partner is NEVER asked an unscoped query: the stub refuses it, and the autouse fixture above
    fails the test.

    `zer07labs/partner` MIRRORS `responses` unless `partner_responses` is given, and is routed by
    the `/zer07labs/partner/` path segment. Mirroring is the default because every test written
    before the partner check is a statement about internal, and a partner that answered `[]` there
    would turn each of them into a partner-canary exit 2 — testing nothing they claim to.
    `partner_fail_with` makes ONLY partner requests exit with that code, the way `-f` would.

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
        _write_payload(responses_dir / version, payload)
    partner_dir = responses_dir
    if partner_responses is not None:
        partner_dir = tmp_path / "partner-responses"
        partner_dir.mkdir(exist_ok=True)
        for version, payload in partner_responses.items():
            _write_payload(partner_dir / version, payload)
    if unscoped is None:
        union = [
            row for payload in responses.values() if isinstance(payload, list) for row in payload
        ]
        # `sorted` is stable, so rows at one version keep the order the test wrote them in.
        unscoped = sorted(union, key=_version_sort_key, reverse=True)[
            : _SCRIPT_MODULE.PAGE_SIZE
        ]
    # A name no version can take, so it cannot collide with a per-version response file.
    unscoped_file = tmp_path / "unscoped-response"
    _write_payload(unscoped_file, unscoped)
    violations = tmp_path / "curl-unscoped-partner"
    violations.write_text("")
    _UNSCOPED_PARTNER_LOGS.append(violations)
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
        # Unscoped first, ahead of partner's own routing and `partner_fail_with`, so a partner
        # unscoped query is recorded as the violation it is whatever else the test configured.
        'case "$URL" in',
        "  *version:*) ;;",
        "  */zer07labs/partner/*)",
        f"""    printf '%s\\n' "$URL" >> {violations}""",
        f"    exit {UNSCOPED_PARTNER_REFUSAL} ;;",
        "  *)",
        f'    cat "{unscoped_file}"',
        "    exit 0 ;;",
        "esac",
        'VER="${URL##*version:}"',
        'VER="${VER%%&*}"',
        f'DIR="{responses_dir}"',
        'case "$URL" in',
        f'  */zer07labs/partner/*) DIR="{partner_dir}"'
        + (f"; exit {partner_fail_with}" if partner_fail_with is not None else "")
        + " ;;",
        "esac",
        'if [ -f "$DIR/$VER" ]; then',
        '  cat "$DIR/$VER"',
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


#: What `registries_queried` reports for the newest question's unscoped GET, in place of a
#: version. Not a string any version can be, so it cannot be confused with one.
NEWEST = "<newest>"


def registries_queried(calls: Path) -> list[tuple[str, str]]:
    """`(repository slug, version)` per request, in order — which registry was asked, not only what.
    An unscoped request reads `(slug, NEWEST)`, and only if it is EXACTLY `NEWEST_QUERY`: any other
    request without a `version:` is something this file has no name for, and fails here."""
    asked = []
    for line in calls.read_text().splitlines():
        url = line.split()[-1]
        slug = url.split("/packages/zer07labs/")[1].split("/")[0]
        if "version:" not in url:
            assert url.endswith("/" + _SCRIPT_MODULE.NEWEST_QUERY), f"unrecognised request: {url}"
            asked.append((slug, NEWEST))
            continue
        asked.append((slug, url.split("version:")[1].split("&")[0].strip()))
    return asked


def versions_queried(calls: Path) -> list[str]:
    """The versions the stub was asked about, in order."""
    asked = []
    for line in calls.read_text().splitlines():
        if "version:" in line:
            asked.append(line.split("version:")[1].split("&")[0].strip())
    return asked


def test_the_happy_live_path_queries_one_canary_then_the_target(tmp_path: Path) -> None:
    """Five GETs on the common path — canary then target, internal then partner, then internal's
    newest (seam-sdk#253) — and a clean verdict.

    #253 acceptance 1: the newest version IS the declared one here, and partner was already asked
    about it, so the newest question is answered without a sixth GET. The unscoped GET is still
    made: the discovery is what can break, so it runs on every run."""
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(
        tmp_path, {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert registries_queried(calls) == [
        ("internal", ROSTER[0]),
        ("internal", "0.7.78"),
        ("partner", ROSTER[0]),
        ("partner", "0.7.78"),
        ("internal", NEWEST),
    ]
    # And exactly five invocations, counted rather than inferred. `versions_queried` filters on
    # `version:`, so a sixth request to some URL without that qualifier — a second discovery call,
    # a retry against a different endpoint — is invisible to it. The stub appends one line per
    # invocation, so this counts them.
    logged = calls.read_text().splitlines()
    assert len(logged) == 5, f"the run made {len(logged)} requests, not 5:\n{calls.read_text()}"
    # The fifth URL, byte for byte: `registries_queried` recognises it by suffix, which a URL on
    # the wrong repository with the right query would also satisfy.
    assert logged[4].split()[-1] == _SCRIPT_MODULE.REGISTRY_URL + _SCRIPT_MODULE.NEWEST_QUERY
    assert "newest on internal: 0.7.78 — the declared version, answered above" in proc.stdout
    assert "on internal and partner" in proc.stdout
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
    # Per registry: the target is asked exactly once OF EACH, as a target, never as a canary.
    asked = registries_queried(calls)
    for registry in ("internal", "partner"):
        mine = [v for r, v in asked if r == registry]
        assert mine.count(target) == 1, f"{target} was queried as a {registry} canary as well: {asked}"
        assert mine[0] == backup, asked
    assert asked[0] == ("internal", backup), asked
    # The whole sequence (seam-sdk#253): the newest on internal is the backup canary, which is not
    # the declared version, so partner is asked about it once more — as the NEWEST, after the
    # unscoped read, never as a second canary probe.
    assert asked == [
        ("internal", backup),
        ("internal", target),
        ("partner", backup),
        ("partner", target),
        ("internal", NEWEST),
        ("partner", backup),
    ], asked


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


def test_rows_at_other_versions_only_means_the_qualifier_was_ignored(tmp_path: Path) -> None:
    """The server-side positive control, and the only check that can see the filter not applied.

    The truncation guard above catches an ignored `version:` qualifier ONLY when the response comes
    back at exactly PAGE_SIZE. A server that caps pages below 50 makes that equality permanently
    silent — and then the target sits outside a window of everything, reads as absent, and exits 1
    for a published version. Here the window is 6 rows: far under the page size, so truncation
    cannot fire, and without this guard the run would report drift.
    """
    window = rows(
        ("seam-sdk", "0.7.20", "python"),
        ("@zer07labs/seam-sdk", "0.7.20", "npm"),
        ("seam-sdk", "0.7.21", "python"),
        ("@zer07labs/seam-sdk", "0.7.21", "npm"),
        ("seam-sdk", "0.7.22", "python"),
        ("@zer07labs/seam-sdk", "0.7.22", "npm"),
    )
    assert len(window) < _SCRIPT_MODULE.PAGE_SIZE, "the truncation guard must not be what fires"
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, _ = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0]), "0.7.78": window})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, (
        f"a window over everything read as a verdict: exit {proc.returncode}\n"
        f"{proc.stdout}{proc.stderr}"
    )
    assert "was not applied" in proc.stderr, proc.stderr
    assert "0.7.20" in proc.stderr, "the message must carry the versions that came back"


def test_an_empty_response_is_still_drift_and_not_a_broken_filter(tmp_path: Path) -> None:
    """The guard must stay silent on zero rows, or the check could never report drift at all.

    This is the failure direction that would matter most: `[]` is what a genuine lag looks like on
    the live path, and a positive control that fired on it would convert every true positive into
    exit 2 — a check that can only ever say "infrastructure".
    """
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, _ = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0])})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 1, f"an empty answer stopped reading as drift: {proc.stdout}{proc.stderr}"
    assert "was not applied" not in proc.stderr


def test_a_superset_carrying_the_target_is_not_refused(tmp_path: Path) -> None:
    """Over-inclusion is harmless and must stay harmless.

    Cloudsmith may rank matches to the top of a superset rather than filtering hard; nothing in the
    recorded evidence excludes that. `registry_formats` re-filters, so a superset CONTAINING the
    target is a correct answer — and this guard must not turn it into exit 2.
    """
    superset = published("0.7.78") + rows(
        ("seam-sdk", "0.7.20", "python"),
        ("@zer07labs/seam-sdk", "0.7.20", "npm"),
    )
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, _ = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0]), "0.7.78": superset})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 0, f"a superset carrying the target was refused: {proc.stdout}{proc.stderr}"


def test_a_yanked_canary_still_falls_through_to_the_next(tmp_path: Path) -> None:
    """A yanked canary answers `[]`, so the positive control must not fire on it either.

    Otherwise the guard added to protect the roster would be the thing that breaks it: one yank
    would exit 2 at the first candidate instead of trying the rest, which is precisely the single
    point of failure the roster exists to remove.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(tmp_path, {ROSTER[1]: published(ROSTER[1])})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 1, f"the roster did not survive a yanked first entry: {proc.stdout}{proc.stderr}"
    asked = versions_queried(calls)
    assert asked[:2] == [ROSTER[0], ROSTER[1]], asked


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

    The diagnosis moved, deliberately. This used to assert the canary loop's own refusal
    ("nothing usable for any canary"), which blames the ROSTER — the weaker reading of this
    evidence. `fetch_registry`'s server-side positive control now fires first and names the actual
    cause: a query scoped to one version answered with other versions. Same exit 2, better
    sentence. The loop's refusal is still reachable and still pinned, by the all-yanked case below.

    Because that guard would now fire here whatever `registry_formats` does, this test alone no
    longer pins the version clause — `test_registry_formats_keeps_only_rows_at_that_version` does,
    directly, where no earlier guard can launder it.
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
    assert "was not applied" in proc.stderr, (
        f"it exited 2, but not with the qualifier diagnosis this shape warrants: {proc.stderr}"
    )


def test_registry_formats_keeps_only_rows_at_that_version() -> None:
    """The three clauses of `registry_formats`, driven red one at a time, as a unit.

    This exists because the end-to-end above can no longer pin the version clause: the server-side
    positive control in `fetch_registry` refuses a wrong-version response before the loop ever
    computes formats, so that test now passes with or without the clause. A guard that is only
    observed through a stricter guard in front of it is not observed at all.
    """
    fmt = _SCRIPT_MODULE.registry_formats
    assert fmt(published("0.7.77"), "0.7.77") == {"python", "npm"}
    # version clause
    assert fmt(published("0.6.1"), "0.7.77") == set()
    # format clause — a format this release does not ship is not a published format
    assert fmt(rows(("seam-sdk", "0.7.77", "cargo")), "0.7.77") == set()
    # name clause — a longer name that merely starts with the package name is a different package
    assert fmt(rows(("@zer07labs/seam-sdk-extra", "0.7.77", "npm")), "0.7.77") == set()


def test_every_canary_empty_is_still_the_rosters_own_refusal(tmp_path: Path) -> None:
    """The loop's refusal branch, kept pinned now that the wrong-version shape routes elsewhere.

    Every canary answering `[]` is the all-yanked case: no rows at all, so the positive control is
    silent by design, and the roster is genuinely out of candidates. That must still name the
    roster and say it may need re-pointing.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, _ = curl_stub(tmp_path, {"0.7.78": published("0.7.78")})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, f"exit {proc.returncode}\n{proc.stdout}{proc.stderr}"
    assert "nothing usable for any canary" in proc.stderr, proc.stderr
    assert "was not applied" not in proc.stderr, (
        f"the positive control fired on empty responses, which would break roster fallthrough: "
        f"{proc.stderr}"
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


# ── seam-sdk#203: partner — the repository a design partner actually installs from ─────────────
#
# `internal` serving a release says nothing about whether a partner can install it: the two are
# separate Cloudsmith repositories, and #203 is the record of `partner` lagging for twenty
# releases while every check here stayed green. These pin that partner is asked, through its own
# proven instrument, on the same clock — and that a partner fault never hides an internal finding.


def test_partner_url_differs_from_internal_only_in_the_repository_slug() -> None:
    """Same endpoint, same query; one path segment apart. Anything else is a different question."""
    module = _load_script()
    assert module.PARTNER_REGISTRY_URL != module.REGISTRY_URL
    assert module.PARTNER_REGISTRY_URL == module.REGISTRY_URL.replace(
        "/zer07labs/internal/", "/zer07labs/partner/"
    )
    assert module.PARTNER_REGISTRY_URL.endswith("/packages/zer07labs/partner/")
    assert module.registry_name(module.PARTNER_REGISTRY_URL) == "partner"
    assert module.registry_name(module.REGISTRY_URL) == "internal"


@pytest.mark.parametrize(
    ("age", "expected_code", "marker"),
    [(30, 0, "DEFERRED"), (200, 0, "::warning::"), (361, 1, "DRIFT")],
    ids=["soft", "warn", "hard"],
)
def test_a_partner_lag_walks_the_same_grace_ladder(
    tmp_path: Path, age: int, expected_code: int, marker: str
) -> None:
    """Internal serves it, partner does not. One clock: `promote-partner` is in the same run."""
    repo = make_repo(tmp_path, version="0.7.78")
    full = {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    bin_dir, _ = curl_stub(
        tmp_path, full, partner_responses={ROSTER[0]: published(ROSTER[0])}
    )
    proc = run(
        repo, None, tmp_path, now=LANDED + timedelta(minutes=age), env=live_env(bin_dir)
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == expected_code, out
    assert marker in out, out
    assert "partner" in out
    assert "partner serves: <nothing>" in proc.stdout
    assert STUB_TOKEN not in out


def test_a_partner_drift_names_state_p_and_both_promotion_tools(tmp_path: Path) -> None:
    """The remediation must route to promotion — and warn against promoting a smoke-failed build."""
    repo = make_repo(tmp_path, version="0.7.78")
    full = {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    bin_dir, _ = curl_stub(
        tmp_path,
        full,
        partner_responses={ROSTER[0]: published(ROSTER[0]), "0.7.78": rows(("seam-sdk", "0.7.78", "python"))},
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "State P" in proc.stdout
    assert "promote-partner-backfill.yml" in proc.stdout
    assert "./scripts/promote-to-partner.sh 0.7.78" in proc.stdout
    assert "registry-smoke" in proc.stdout
    # Half a promotion is still a lag, and the missing half is named.
    assert "partner serves: python" in proc.stdout
    assert "does not serve npm" in proc.stdout
    # Not internal's states: the tag and the publish are fine.
    assert "State B" not in proc.stdout and "State C" not in proc.stdout


def test_internal_short_is_reported_as_internal_even_with_partner_short_too(tmp_path: Path) -> None:
    """Partner is promoted FROM internal: one fault, reported once, at its source."""
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, _ = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0])})
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "State B" in proc.stdout
    assert "State P" not in proc.stdout
    assert "partner serves: <nothing>" in proc.stdout


@pytest.mark.parametrize("fault", ["canaries-empty", "http-failure"])
def test_a_broken_partner_instrument_is_infrastructure_when_internal_is_clean(
    tmp_path: Path, fault: str
) -> None:
    """Internal clean, partner unreadable: exit 2, and the message says WHICH registry."""
    repo = make_repo(tmp_path, version="0.7.78")
    full = {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    if fault == "canaries-empty":
        bin_dir, calls = curl_stub(tmp_path, full, partner_responses={"0.7.78": published("0.7.78")})
    else:
        bin_dir, calls = curl_stub(tmp_path, full, partner_fail_with=22)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "partner" in proc.stderr
    assert "partner: COULD NOT BE READ" in proc.stdout
    # The clean-internal line must not ALSO claim partner was merely skipped: it was tried.
    assert "NOT checked" not in proc.stdout
    assert STUB_TOKEN not in proc.stdout + proc.stderr
    if fault == "canaries-empty":
        # Canary first, per registry: partner's target is never read through a dead instrument.
        assert ("partner", "0.7.78") not in registries_queried(calls), registries_queried(calls)


@pytest.mark.parametrize(
    ("age", "expected_code"), [(30, 2), (200, 2), (361, 1)], ids=["soft", "warn", "hard"]
)
def test_a_broken_partner_instrument_never_hides_an_internal_drift(
    tmp_path: Path, age: int, expected_code: int
) -> None:
    """Internal short: a drift keeps its 1 with the partner fault beside it; inside the grace
    tiers there is no finding yet, so the instrument fault is the news — 2."""
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, _ = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0])}, partner_fail_with=22)
    proc = run(
        repo, None, tmp_path, now=LANDED + timedelta(minutes=age), env=live_env(bin_dir)
    )
    assert proc.returncode == expected_code, proc.stdout + proc.stderr
    assert "::error::partner could not be read" in proc.stderr
    if expected_code == 1:
        assert "State B" in proc.stdout


def test_offline_without_a_partner_dump_says_partner_was_not_checked(tmp_path: Path) -> None:
    """Not checked is not clean. The clean line must say which registries it speaks for."""
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, published("0.7.78"), tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "partner: NOT CHECKED" in proc.stdout
    assert "Partner was NOT checked" in proc.stdout
    assert "on internal and partner" not in proc.stdout


@pytest.mark.parametrize(
    ("partner", "expected_code", "needle"),
    [
        ("full", 0, "on internal and partner"),
        ("short", 1, "State P"),
        ("unrelated", 2, "--partner-packages-json"),
    ],
)
def test_offline_with_a_partner_dump_checks_partner_by_the_offline_rule(
    tmp_path: Path, partner: str, expected_code: int, needle: str
) -> None:
    """The offline instrument rule applies to the partner file too: no `seam-sdk` row at ANY
    version is a broken capture, never an absence."""
    repo = make_repo(tmp_path, version="0.7.78")
    payload = {
        "full": published("0.7.78"),
        "short": published("0.7.77"),
        "unrelated": rows(("other-thing", "1.0.0", "python")),
    }[partner]
    pfile = tmp_path / "partner.json"
    pfile.write_text(json.dumps(payload), "utf-8")
    proc = run(
        repo, published("0.7.78"), tmp_path, extra=["--partner-packages-json", str(pfile)]
    )
    assert proc.returncode == expected_code, proc.stdout + proc.stderr
    assert needle in proc.stdout + proc.stderr


@pytest.mark.parametrize("payload", ["[]", None], ids=["empty-list", "missing-file"])
def test_an_empty_or_missing_partner_dump_is_infrastructure_named_by_its_own_flag(
    tmp_path: Path, payload: str | None
) -> None:
    """`[]` is not a plausible unscoped capture; a missing file is not a capture at all. Both are
    exit 2, and the message names the flag the operator actually passed."""
    repo = make_repo(tmp_path, version="0.7.78")
    pfile = tmp_path / "partner.json"
    if payload is not None:
        pfile.write_text(payload, "utf-8")
    proc = run(
        repo, published("0.7.78"), tmp_path, extra=["--partner-packages-json", str(pfile)]
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert f"--partner-packages-json {pfile}" in proc.stderr, proc.stderr


def test_a_non_json_partner_response_names_partner(tmp_path: Path) -> None:
    """Every partner-side refusal must say partner — the operator otherwise debugs internal."""
    repo = make_repo(tmp_path, version="0.7.78")
    full = {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    bin_dir, _ = curl_stub(
        tmp_path, full, partner_responses={ROSTER[0]: published(ROSTER[0]), "0.7.78": "<html>"}
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "the response from partner to" in proc.stderr, proc.stderr
    assert "is not JSON" in proc.stderr


def test_a_partner_dump_without_an_internal_one_is_refused(tmp_path: Path) -> None:
    """A saved partner answer beside a LIVE internal one compares two moments. Exit 2, no query."""
    repo = make_repo(tmp_path, version="0.7.78")
    bin_dir, calls = curl_stub(tmp_path, {ROSTER[0]: published(ROSTER[0])})
    pfile = tmp_path / "partner.json"
    pfile.write_text(json.dumps(published("0.7.78")), "utf-8")
    proc = run(
        repo,
        None,
        tmp_path,
        extra=["--partner-packages-json", str(pfile)],
        env=live_env(bin_dir),
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "needs --packages-json" in proc.stderr
    assert calls.read_text() == ""


# ── The script's own dependencies ─────────────────────────────────────────────────────────────


def test_a_non_utf8_partner_body_is_a_named_fault_that_never_prints_its_bytes(
    tmp_path: Path,
) -> None:
    """A body that is not UTF-8 is "not JSON" from partner: exit 2, partner named. It is never a
    UnicodeDecodeError, whose repr carries the raw bytes, and here those bytes quote the token."""
    repo = make_repo(tmp_path, version="0.7.78")
    full = {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    hostile = b"\xff X-Api-Key: " + STUB_TOKEN.encode() + b" \xfe"
    bin_dir, _ = curl_stub(
        tmp_path, full, partner_responses={ROSTER[0]: published(ROSTER[0]), "0.7.78": hostile}
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    assert "partner" in out and "not JSON" in out, out
    assert STUB_TOKEN not in out, out
    assert "UnicodeDecodeError" not in out and "Traceback" not in out, out


def test_an_unexpected_partner_exception_cannot_blind_an_internal_drift(tmp_path: Path) -> None:
    """The non-InfraError capture, driven for real. A pathologically nested partner body raises
    RecursionError inside `json.loads` — not JSONDecodeError, so not an InfraError. Captured, the
    internal drift still reaches its verdict (exit 1, State B printed); escaping, it would hit the
    top-level handler and exit 2 with no verdict at all. Only the class name is printed."""
    repo = make_repo(tmp_path, version="0.7.78", tag=True)
    nested = "[" * 200_000 + "]" * 200_000
    bin_dir, _ = curl_stub(
        tmp_path,
        {ROSTER[0]: published(ROSTER[0])},
        partner_responses={ROSTER[0]: published(ROSTER[0]), "0.7.78": nested},
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "State B" in proc.stdout, proc.stdout
    # The whole line, so "the class name only" is pinned — a repr would append its message.
    assert re.search(
        r"unexpected failure reading partner: RecursionError$", proc.stderr, re.MULTILINE
    ), proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr


@pytest.mark.parametrize(
    ("body", "marker"),
    [
        (["X-Api-Key: " + STUB_TOKEN], "not an object"),
        ([{"name": "seam-sdk", "version": "tok=" + STUB_TOKEN, "format": "python"}], "was not applied"),
    ],
    ids=["string-row", "version-field"],
)
def test_a_hostile_partner_body_is_diagnosed_without_being_echoed(
    tmp_path: Path, body: object, marker: str
) -> None:
    """The two diagnoses that describe a malformed response — a non-object row, and rows at other
    versions — name its shape, never its content. Partner reaches both now."""
    repo = make_repo(tmp_path, version="0.7.78")
    full = {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    bin_dir, _ = curl_stub(
        tmp_path, full, partner_responses={ROSTER[0]: published(ROSTER[0]), "0.7.78": body}
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    assert marker in out and "partner" in out, out
    assert STUB_TOKEN not in out, out


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


#: NOT a second implementation — the script's own, so the parametrised cases below drive the code
#: that actually runs in production. Phase 5 wrote this parser here, in the test, because only the
#: test needed it; Phase 7 needs the same number at RUNTIME to derive its staleness threshold from
#: the cron rather than writing "360 minutes" beside it. Two readings of one string in two files
#: are free to disagree, and the disagreement would surface as a staleness warning that fires
#: always or never — muted either way. Moved to `scripts/check_registry_drift.py`; this alias keeps
#: the existing cases pointed at it.
_cron_period_minutes = _SCRIPT_MODULE.cron_period_minutes


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("17 */2 * * *", 120),
        # A step of zero. `range(0, 24, 0)` raises `ValueError`, which is not an `InfraError`, so
        # without the guard it escapes the warnings-only arm and exits 2. Both spellings, because
        # the bare `*/N` and the `A-B/N` forms reach the same `int(step)`.
        ("17 */0 * * *", None),
        ("17 0-23/0 * * *", None),
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
    # OVER THE PARSED YAML, not over the file's text. A substring search also matches the word
    # inside a COMMENT — and this workflow's header now explains that `continue-on-error` is
    # deliberately absent, which would trip a text search and force the explanation to be deleted
    # to keep the guard green. That is the same prose-vs-structure confusion this phase already
    # fixed in the permissions guard, running in the opposite direction: there prose could satisfy
    # a guard, here prose could break one. Both are answered by reading structure.
    holders = [("job", _job())] + [
        (f"step {i}", step) for i, step in enumerate(_job().get("steps") or [])
    ]
    for where, node in holders:
        assert "continue-on-error" not in node, (
            f"`continue-on-error` is set on the {where}. This check's only output is whether the "
            f"job is red; a job that cannot go red reports nothing at all."
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


def test_the_actions_needle_matches_the_call_that_earned_the_scope() -> None:
    """`actions: read` is declared, and its needle must go on matching the call that authorises it.

    An unexercised regex is an unverified one, and the direction it fails in is silent: a needle
    that never matches makes the guard demand the scope be REMOVED, which would switch the arm off
    while leaving every structural test green. Same failure the `issues` needle actually had.

    The name and the first line of this docstring both used to say "not declared yet ... until
    Phase 7 lands". Phase 7 landed in this same diff and inverted the assertion, and only the prose
    was left behind — the exact drift class this file exists to catch, in the file that catches it.
    """
    needle, _why = PERMISSION_NEEDLES["actions"]
    heartbeat = """
def f(repo, workflow):
    _gh(["api", f"repos/{repo}/actions/workflows/{workflow}/runs"], repo)
"""
    assert re.search(needle, _permission_surface(heartbeat)), (
        "the Actions-API call Phase 7 will make does not satisfy the actions needle."
    )
    # Phase 7 has landed, so the "not declared yet" assertion that used to stand here is gone —
    # this test named it as the line to delete and it was deleted in that commit. What remains is
    # the half that keeps mattering: the needle must go on matching the call it authorises. The
    # coupling in the other direction is not lost — it is enforced better, by
    # `test_the_declared_permissions_are_exactly_what_the_job_uses`, which fails if the scope is
    # declared without the call OR the call is made without the scope.
    assert "actions" in (_job().get("permissions") or {}), (
        "the heartbeat reads the Actions API but `actions: read` is not declared. An undeclared "
        "scope is `none` rather than inherited, so the call 403s and the staleness arm is off."
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

DRIFT_TITLE = _SCRIPT_MODULE.DRIFT_TITLE
RELEASE_NOTICE_TITLE = _SCRIPT_MODULE.RELEASE_NOTICE_TITLE
PARTNER_DRIFT_TITLE = _SCRIPT_MODULE.PARTNER_DRIFT_TITLE
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
#: DERIVED from the script, never restated. This literal used to be a third independent copy of a
#: value the script also wrote twice, and three copies that happen to agree are not one value —
#: `join(",")` in the projection passed every test in this file while suppressing real drift.
LABEL_SEP = _SCRIPT_MODULE.LABEL_SEP


def gh_stub(
    tmp_path: Path,
    listing: list[tuple[int, str, list[str], str]],
    *,
    fail_on: tuple[str, str] | None = None,
    runs: list[str] | None = None,
    fail_create_titled: str | None = None,
) -> tuple[Path, Path]:
    """A `gh` first on PATH. Returns (bin dir, argv-log path).

    `fail_create_titled` fails ONLY the `issue create` whose `--title` is exactly that, the way an
    outage landing between two creates would — so "the first create succeeded, the second did
    not" is observable rather than collapsed into `fail_on`'s every-create failure.

    `listing` rows are `(number, state, labels, title)` — exactly the four fields the script's own
    `--jq` projects, so the parser is exercised rather than bypassed.

    The log is NUL-delimited, not line-delimited, and that is not fussiness: the issue BODY is
    multi-line, so a `printf '[%s]\\n'` log of the kind `curl_stub` uses would split one argument
    across many lines and make the argv unrecoverable. Each invocation is preceded by a literal
    `CALL` record, which is why argv can be grouped per call rather than flattened into one stream
    where the ORDER of `reopen` and `comment` would be unobservable.

    `fail_on` makes one verb pair fail the way a GitHub outage does — non-zero with a message on
    stderr — so the promise that a delivery failure never becomes a verdict is testable.

    `runs` is the heartbeat's answer: the `created_at` timestamps `gh api --jq` would emit, newest
    first, one per line.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "gh-argv"
    log.write_bytes(b"")
    runs_file = tmp_path / "workflow-runs.txt"
    runs_file.write_text("".join(f"{r}\n" for r in (runs or [])), encoding="utf-8")
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
    if fail_create_titled is not None:
        title_file = tmp_path / "gh-fail-title"
        title_file.write_text(fail_create_titled, encoding="utf-8")
        lines += [
            f"""if [ "$1" = "issue" ] && [ "$2" = "create" ] && [ "$4" = "$(cat {title_file})" ]; then""",
            """  echo 'gh: HTTP 503 — the GitHub API is unavailable' >&2""",
            "  exit 1",
            "fi",
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
        # Phase 7's heartbeat. `runs=None` answers with NOTHING rather than with a plausible
        # history, so every test written before the heartbeat existed keeps exercising the
        # fewer-than-two-stamps path — which is the honest default for a stub that was never told
        # about run history, and keeps those tests silent rather than accidentally asserting a
        # staleness verdict they never meant to express.
        """if [ "$1" = "api" ]; then""",
        # FIDELITY, and load-bearing in the same way `--state` is. Real `gh api` has no `--repo`
        # and exits 1 on it. Without this the stub tolerates a flag production rejects, so flipping
        # `repo_flag=False` to `True` stays invisible here while the heartbeat would be dead on
        # every real run, behind a `::warning::` nobody reads — the "off but still present" state
        # this arm exists to make impossible.
        """  for a in "$@"; do""",
        """    if [ "$a" = "--repo" ]; then echo "unknown flag: --repo" >&2; exit 1; fi""",
        """  done""",
        f"""  cat {runs_file}""",
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


#: Phase 7's heartbeat, as it appears in the argv log. Built from the script's own constant so a
#: rename shows up here rather than as a mysteriously absent call.
def heartbeat_verb(repo: str = STUB_REPO) -> str:
    return (
        f"api repos/{repo}/actions/workflows/{_SCRIPT_MODULE.WORKFLOW_FILENAME}/runs"
        f"?{_SCRIPT_MODULE.HEARTBEAT_QUERY}"
    )


def heartbeat_argv(repo: str = STUB_REPO) -> list[str]:
    """The ONE `gh api` argv this check may ever emit, word for word.

    Built from the script's own constants, so it answers "did anything get ADDED to the call" and
    not "is the call right" — that second question is a different test, and it has to compare
    against a literal or it would be asking the constant to confirm itself.
    """
    return ["api", heartbeat_verb(repo).split(" ", 1)[1], "--jq", ".workflow_runs[].created_at"]


def issue_list_argv(repo: str = STUB_REPO) -> list[str]:
    """The ONE `gh issue list` argv this check may ever emit, word for word.

    `--state all` was pinned; its neighbours were not, and each is load-bearing. Dropping `labels`
    from `--json` makes real `gh` error, so the check exits 2 forever. Dropping `--limit` falls back
    to gh's default of 30 on a repository already past issue #100 — an existing drift issue outside
    that window is re-filed every two hours, and the truncation warning could never fire.
    """
    return [
        "issue", "list",
        "--state", "all",
        "--limit", str(_SCRIPT_MODULE.ISSUE_LIMIT),
        "--json", "number,state,title,labels",
        "--jq", _SCRIPT_MODULE._ISSUE_LIST_JQ,
        "--repo", repo,
    ]


def gh_writes(log: Path) -> list[str]:
    """Every call that MUTATES. This is what must be empty on every non-drift path.

    There are two READS — `issue list` and Phase 7's `gh api` heartbeat — and the second is
    recognised explicitly rather than by "it is an api call, so it must be safe". `gh api` can
    POST perfectly well; classifying a whole subcommand as read-only would mean a future write
    smuggled through it counts as no write at all, on the exact assertion that exists to catch
    writes.
    """
    writes = []
    for call in gh_calls(log):
        verb = " ".join(call[:2])
        if verb == "issue list":
            continue
        if call[0] == "api":
            assert call == heartbeat_argv(), (
                f"an unrecognised `gh api` call reached the log: {call!r}. Exactly ONE `gh api` "
                f"argv is classified read-only here, word for word, because a DENYLIST of write "
                f"flags cannot do this job: `-XPOST` and `--method=POST` are one argv token each "
                f"so membership never sees them, and `-F`/`--raw-field` are as much a write as "
                f"`-f`/`--field`. Five of the seven real write spellings evaded the list this "
                f"replaced. An allowlist has no next spelling to miss."
            )
            continue
        writes.append(verb)
    return writes


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
    assert gh_verbs(log) == ["issue list", "issue create", heartbeat_verb()], gh_calls(log)
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
    assert gh_verbs(log) == ["issue list", "issue comment", "issue reopen", heartbeat_verb()], gh_calls(log)
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
    assert gh_verbs(log) == ["issue list", "issue comment", "issue reopen", heartbeat_verb()], gh_calls(log)


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
    assert gh_verbs(log) == ["issue list", heartbeat_verb()], gh_calls(log)


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


def _partner_dump(tmp_path: Path, payload: object) -> list[str]:
    pfile = tmp_path / "partner.json"
    pfile.write_text(json.dumps(payload), "utf-8")
    return ["--partner-packages-json", str(pfile)]


def _partner_lag_run(
    tmp_path: Path, listing: list[tuple[int, str, list[str], str]], **kw: object
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Internal complete, partner empty for DRIFTING, past the hard window, with --report."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    return report_run(
        repo,
        published(DRIFTING),
        tmp_path,
        listing=listing,
        extra=_partner_dump(tmp_path, published("0.7.77")),
        **kw,
    )


def partner_listing(
    number: int, state: str, labels: list[str]
) -> list[tuple[int, str, list[str], str]]:
    return [(number, state, labels, PARTNER_DRIFT_TITLE.format(version=DRIFTING))]


def test_a_partner_lag_files_one_issue_under_its_own_title(tmp_path: Path) -> None:
    """One listing, one create, PARTNER_DRIFT_TITLE — never DRIFT_TITLE, which would assert that
    the release is not installable from internal, a state the registry is not in."""
    proc, log = _partner_lag_run(tmp_path, [])
    assert proc.returncode == 1, proc.stdout + proc.stderr
    calls = gh_calls(log)
    assert sum(1 for c in calls if c[:2] == ["issue", "list"]) == 1, calls
    creates = [c for c in calls if c[:2] == ["issue", "create"]]
    assert len(creates) == 1, calls
    title = creates[0][creates[0].index("--title") + 1]
    body = creates[0][creates[0].index("--body") + 1]
    assert title == PARTNER_DRIFT_TITLE.format(version=DRIFTING)
    for call in calls:
        assert DRIFT_TITLE.format(version=DRIFTING) not in call, call
    assert "State P" in body
    assert "`zer07labs/partner`" in body
    assert "promote-partner-backfill.yml" in body
    assert "registry-smoke" in body
    # Reporting is followed by the watcher's heartbeat on a partner verdict too: a partner lag
    # that outlasts the schedule must not also silence the check on its own schedule.
    assert [c for c in calls if c[0] == "api"] == [heartbeat_argv()], calls


@pytest.mark.parametrize(
    ("state", "labels", "expected_code", "writes"),
    [
        ("OPEN", [], 1, []),
        ("CLOSED", [], 1, ["comment", "reopen"]),
        ("CLOSED", [SUPPRESSION_LABEL], 0, []),
    ],
    ids=["open", "closed", "suppressed"],
)
def test_the_partner_issue_walks_the_same_decision_table(
    tmp_path: Path, state: str, labels: list[str], expected_code: int, writes: list[str]
) -> None:
    proc, log = _partner_lag_run(tmp_path, partner_listing(11, state, labels))
    assert proc.returncode == expected_code, proc.stdout + proc.stderr
    assert [c[1] for c in gh_calls(log) if c[0] == "issue" and c[1] != "list"] == writes
    if labels:
        assert "::warning::" in proc.stdout and "#11" in proc.stdout
        assert "Partner still does not serve" in proc.stdout
    if "comment" in writes:
        # The reopen comment is the partner body, not the internal one: an internal body here
        # would tell the reader the release is not installable and send them to re-publish.
        comment = next(c for c in gh_calls(log) if c[:2] == ["issue", "comment"])
        text = comment[comment.index("--body") + 1]
        assert "State P" in text and "`zer07labs/partner` (internal is complete)" in text, text
        assert "the registry does not serve it" not in text, text


@pytest.mark.parametrize("age", [30, 200], ids=["soft", "warn"])
def test_a_partner_lag_inside_grace_touches_no_github(tmp_path: Path, age: int) -> None:
    """The grace invariant holds for the partner subject too: with --report, a deferred or
    warned partner lag reaches GitHub not at all — not even the listing."""
    proc, log = _partner_lag_run(tmp_path, [], now=LANDED + timedelta(minutes=age))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert gh_calls(log) == [], gh_calls(log)


def test_a_partner_lag_says_an_open_internal_issue_can_be_closed(tmp_path: Path) -> None:
    """Internal serving the version is what makes this a partner lag, so an open internal issue
    for it is stale. `report_clean` cannot say so — the verdict is not clean — so the partner
    path does, from the same listing, and closes nothing."""
    listing = drift_listing(4, "OPEN", [])
    proc, log = _partner_lag_run(tmp_path, listing)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "::notice::#4" in proc.stdout and "can be closed" in proc.stdout, proc.stdout
    calls = gh_calls(log)
    assert sum(1 for c in calls if c[:2] == ["issue", "list"]) == 1, calls
    assert not any(c[:2] in (["issue", "close"], ["issue", "edit"]) for c in calls), calls


def test_an_internal_suppression_does_not_suppress_a_partner_lag(tmp_path: Path) -> None:
    """Suppression is scoped to one title. Closing the INTERNAL issue for this version with the
    label says nothing about partner, and must not mute it."""
    listing = [
        (5, "CLOSED", [SUPPRESSION_LABEL], DRIFT_TITLE.format(version=DRIFTING)),
    ]
    proc, log = _partner_lag_run(tmp_path, listing)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert any(c[:2] == ["issue", "create"] for c in gh_calls(log)), gh_calls(log)


def test_a_partner_issue_cross_links_an_open_release_notice(tmp_path: Path) -> None:
    """An open `release-outcome` issue is the signal that registry-smoke may have failed —
    exactly when State P says not to promote. The body must point at it."""
    listing = [(9, "OPEN", [], RELEASE_NOTICE_TITLE.format(version=DRIFTING))]
    proc, log = _partner_lag_run(tmp_path, listing)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    create = next(c for c in gh_calls(log) if c[:2] == ["issue", "create"])
    assert "#9" in create[create.index("--body") + 1]


def test_internal_and_partner_both_short_file_one_internal_issue_naming_partner(
    tmp_path: Path,
) -> None:
    """One fault, at its source. The internal body records partner's state; no partner issue."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=[],
        extra=_partner_dump(tmp_path, published("0.7.77")),
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    creates = [c for c in gh_calls(log) if c[:2] == ["issue", "create"]]
    assert len(creates) == 1, gh_calls(log)
    assert creates[0][creates[0].index("--title") + 1] == DRIFT_TITLE.format(version=DRIFTING)
    body = creates[0][creates[0].index("--body") + 1]
    assert "| `zer07labs/partner` | also missing npm, python (promotion copies" in body, body


@pytest.mark.parametrize(
    ("internal", "partner", "cell"),
    [
        (published("0.7.77"), None, "| `zer07labs/partner` | not checked |"),
        (published("0.7.77"), "serving", "| `zer07labs/partner` | serves it |"),
        (
            "python-only",
            "empty",
            "| `zer07labs/partner` | also missing npm, python — python is served by internal, "
            "so that is a promotion lag too |",
        ),
    ],
    ids=["not-checked", "serves-it", "own-lag"],
)
def test_the_internal_issue_states_partner_as_observed(
    tmp_path: Path, internal: object, partner: str | None, cell: str
) -> None:
    """Every branch of the partner row in the INTERNAL issue, read back from the filed body.
    "Expected" is claimed only for formats internal is missing too."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    if internal == "python-only":
        internal = [*published("0.7.77"), *rows(("seam-sdk", DRIFTING, "python"))]
    extra = None
    if partner == "serving":
        extra = _partner_dump(tmp_path, published(DRIFTING))
    elif partner == "empty":
        extra = _partner_dump(tmp_path, published("0.7.77"))
    proc, log = report_run(repo, internal, tmp_path, listing=[], extra=extra)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    create = next(c for c in gh_calls(log) if c[:2] == ["issue", "create"])
    assert create[create.index("--title") + 1] == DRIFT_TITLE.format(version=DRIFTING)
    assert cell in create[create.index("--body") + 1], create


@pytest.mark.parametrize(
    ("partner_dump", "expect_notice"), [(True, True), (False, False)], ids=["checked", "unchecked"]
)
def test_a_recovered_partner_says_its_issue_can_be_closed_only_when_partner_was_read(
    tmp_path: Path, partner_dump: bool, expect_notice: bool
) -> None:
    """An offline run with no partner dump knows nothing about partner. "Can be closed" from it
    would be an unqueried registry reading as clean."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published(DRIFTING),
        tmp_path,
        listing=partner_listing(12, "OPEN", []),
        extra=_partner_dump(tmp_path, published(DRIFTING)) if partner_dump else None,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert ("#12" in proc.stdout) is expect_notice, proc.stdout
    assert gh_writes(log) == [], gh_calls(log)
    assert sum(1 for c in gh_calls(log) if c[:2] == ["issue", "list"]) == 1, gh_calls(log)


def test_no_title_is_a_prefix_of_another() -> None:
    """Three exact-title matchers over three shapes. None may contain another, in either
    direction, at any version — or one mechanism could find, comment on, or suppress another's
    issue."""
    titles = {
        "internal": DRIFT_TITLE,
        "partner": PARTNER_DRIFT_TITLE,
        "release-outcome": RELEASE_NOTICE_TITLE,
    }
    for version in ("0.7.78", "0.45.0", "1.0.0"):
        rendered = {k: t.format(version=version) for k, t in titles.items()}
        assert len(set(rendered.values())) == 3, rendered
        for a, ta in rendered.items():
            for b, tb in rendered.items():
                if a != b:
                    assert not tb.startswith(ta) and ta not in tb, (a, b, ta, tb)


def test_the_internal_close_notice_on_a_partner_lag_is_for_open_issues_only(
    tmp_path: Path,
) -> None:
    """A CLOSED internal issue — a suppression like #250, or one already resolved — gets no
    "can be closed" note: it is closed."""
    proc, _ = _partner_lag_run(tmp_path, drift_listing(4, "CLOSED", [SUPPRESSION_LABEL]))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "can be closed" not in proc.stdout, proc.stdout


def test_a_partner_suppression_does_not_suppress_an_internal_drift(tmp_path: Path) -> None:
    """The reverse of the internal-suppression test: a closed, labelled PARTNER issue says
    nothing about internal. Internal short files its own issue."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=partner_listing(11, "CLOSED", [SUPPRESSION_LABEL]),
        extra=_partner_dump(tmp_path, published("0.7.77")),
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    create = next(c for c in gh_calls(log) if c[:2] == ["issue", "create"])
    assert create[create.index("--title") + 1] == DRIFT_TITLE.format(version=DRIFTING)
    assert "SUPPRESSED" not in proc.stdout


def test_a_live_partner_lag_end_to_end_with_report(tmp_path: Path) -> None:
    """The seam between the phases, with no offline dump: curl and gh stubs together. Five GETs in
    order — the fifth is the newest question's unscoped read, answered without a partner GET
    because the newest version is the declared one — then one listing, one create under the
    partner title, then the heartbeat — and the token in no argv handed to gh and in no output."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    bin_dir, curl_log = curl_stub(
        tmp_path,
        {ROSTER[0]: published(ROSTER[0]), DRIFTING: published(DRIFTING)},
        partner_responses={ROSTER[0]: published(ROSTER[0])},
    )
    _, gh_log = gh_stub(tmp_path, [])
    proc = run(
        repo,
        None,
        tmp_path,
        extra=["--report"],
        env=report_env(bin_dir, token=STUB_TOKEN),
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert registries_queried(curl_log) == [
        ("internal", ROSTER[0]),
        ("internal", DRIFTING),
        ("partner", ROSTER[0]),
        ("partner", DRIFTING),
        ("internal", NEWEST),
    ]
    calls = gh_calls(gh_log)
    assert [c[:2] for c in calls] == [["issue", "list"], ["issue", "create"], ["api", calls[2][1]]]
    assert calls[1][calls[1].index("--title") + 1] == PARTNER_DRIFT_TITLE.format(version=DRIFTING)
    assert calls[2] == heartbeat_argv(), calls
    assert STUB_TOKEN not in out
    for call in calls:
        assert not any(STUB_TOKEN in arg for arg in call), call


@pytest.mark.parametrize("age", [30, 200], ids=["soft", "warn"])
def test_a_partner_fault_inside_internal_grace_exits_2_and_touches_no_github(
    tmp_path: Path, age: int
) -> None:
    """No finding yet, so the instrument fault is the news — and grace still means grace."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=[],
        now=LANDED + timedelta(minutes=age),
        extra=_partner_dump(tmp_path, rows(("other-thing", "1.0.0", "python"))),
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "::error::partner could not be read" in proc.stderr
    assert gh_calls(log) == [], gh_calls(log)


@pytest.mark.parametrize(
    ("labels", "state", "expected"),
    [(None, None, 1), ([SUPPRESSION_LABEL], "CLOSED", 2)],
    ids=["filed", "suppressed"],
)
def test_a_partner_fault_beside_an_internal_drift(
    tmp_path: Path, labels: list[str] | None, state: str | None, expected: int
) -> None:
    """Filed: the drift's 1 stands, the fault is printed beside it. Suppressed: there is no
    finding left to stand beside, so the fault must not ride out on a green job — 2."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    listing = drift_listing(7, state, labels) if labels is not None else []
    proc, log = report_run(
        repo,
        published("0.7.77"),
        tmp_path,
        listing=listing,
        extra=_partner_dump(tmp_path, rows(("other-thing", "1.0.0", "python"))),
    )
    assert proc.returncode == expected, proc.stdout + proc.stderr
    assert "::error::partner could not be read" in proc.stderr
    assert "State B" in proc.stdout
    if labels is None:
        create = next(c for c in gh_calls(log) if c[:2] == ["issue", "create"])
        # Queried and failed is not "not checked": the body states what this run observed.
        body = create[create.index("--body") + 1]
        assert "| `zer07labs/partner` | **could not be read**" in body, body
        assert "not checked" not in body, body


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
    assert gh_verbs(log) == ["issue list", "issue create", heartbeat_verb()], gh_calls(log)
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
    assert gh_verbs(log) == ["issue list", "issue create", heartbeat_verb()], gh_calls(log)


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
    assert gh_verbs(log) == ["issue list", "issue create", heartbeat_verb()], gh_verbs(log)


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
def test_a_repo_that_is_not_owner_slash_name_is_refused_before_any_call_on_the_drift_path(
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
        assert len(calls) == 4, calls
        for call in calls:
            if call[0] == "api":
                # `gh api` HAS NO `--repo` and exits 1 on an unknown flag, so it names the
                # repository in the path instead. The obligation is unchanged — the call must not
                # be able to resolve against the checkout's remote — so it is asserted, not
                # exempted. `$REPO` is where the value comes from in both shapes.
                assert f"repos/{STUB_REPO}/" in call[1], (
                    f"a `gh api` call that does not name the repository in its path: {call}"
                )
                continue
            assert "--repo" in call, f"a `gh` call without --repo: {call}"
            assert call[call.index("--repo") + 1] == STUB_REPO, call
        assert [c[0] for c in calls].count("api") == 1, calls


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


# ── Phase 7: the watcher's own heartbeat ──────────────────────────────────────────────────────
#
# A scheduled check can stop existing without anyone noticing, which is the failure it was built to
# catch, one level up. These are the PR-time layer: they make deletion or detuning impossible to
# land quietly. They can say nothing about a schedule that stops firing for GitHub's own reasons —
# that is the runtime arm below, and the residual after both is written into the workflow header.


def test_the_check_still_runs_on_a_schedule() -> None:
    """Criterion 1. Without `schedule:` the check exists and never runs.

    That is the worst of the failure modes available here, because every other guard in this file
    keeps passing: the workflow is present, the script is correct, the permissions are right, and
    the answer is never computed. `workflow_dispatch` alone would leave a tool nobody remembers to
    invoke, which is indistinguishable from not having one.
    """
    triggers = _triggers()
    assert "schedule" in triggers, (
        "the workflow has no `schedule:` trigger, so this check runs only when a human remembers "
        "to press the button. It exists to catch a release that was NEVER DISPATCHED — a failure "
        "whose whole character is that nobody noticed — so a trigger nobody notices is no trigger."
    )
    entries = triggers["schedule"]
    assert isinstance(entries, list) and entries, f"`schedule:` is empty: {entries!r}"
    assert all("cron" in e for e in entries), entries


def test_the_cron_is_the_one_the_threshold_is_derived_from() -> None:
    """Criterion 2. The workflow's cron and the script's `CRON` are the same string.

    They have to be, because the staleness threshold is DERIVED from `CRON` at runtime. If the
    workflow moved to a twelve-hour cadence and the constant did not, the threshold would stay at
    3x two hours and every ordinary run would warn that the schedule is skipping — a warning that
    is wrong every time is muted within a week, and the arm is then off while still present.

    The derivation itself is asserted here too, rather than the number: pinning "360" would be a
    second hardcoded value agreeing with the first, which is the thing being prevented.
    """
    crons = [e["cron"] for e in _triggers()["schedule"]]
    assert crons == [_SCRIPT_MODULE.CRON], (
        f"the workflow runs on {crons} but `check_registry_drift.CRON` is "
        f"{_SCRIPT_MODULE.CRON!r}. The staleness threshold is derived from the constant, so the "
        f"two drifting apart silently mistunes the heartbeat."
    )
    period = _SCRIPT_MODULE.cron_period_minutes()
    assert period is not None, f"the shipped cron {_SCRIPT_MODULE.CRON!r} has no fixed period"
    assert _SCRIPT_MODULE.staleness_threshold_minutes() == (
        period * _SCRIPT_MODULE.STALENESS_MULTIPLIER
    ), "the threshold is not derived from the cron period"

    # THE DERIVATION, WATCHED MOVING. The assertion above is satisfied by a hardcoded 360 for as
    # long as the shipped cron is two-hourly — which is exactly the mistuning being guarded
    # against, so it cannot be the only check. Move the cron and the threshold must follow it.
    original = _SCRIPT_MODULE.CRON
    try:
        _SCRIPT_MODULE.CRON = "17 */12 * * *"
        assert _SCRIPT_MODULE.cron_period_minutes() == 720
        assert _SCRIPT_MODULE.staleness_threshold_minutes() == 720 * (
            _SCRIPT_MODULE.STALENESS_MULTIPLIER
        ), (
            "the threshold did not follow the cron. It is written down beside it rather than "
            "derived from it, so a cadence change silently mistunes the heartbeat."
        )
    finally:
        _SCRIPT_MODULE.CRON = original


def test_the_check_never_grows_a_pull_request_trigger() -> None:
    """Criterion 3. Secrets are unavailable to a fork-PR-triggered workflow.

    The credential resolution would find nothing and the job would exit 2 on every external
    contribution — an infrastructure failure, reported correctly as one, permanently. And nothing
    in a pull request can change this answer anyway: it is a statement about the default branch and
    the registry, not about the diff.
    """
    assert "pull_request" not in _triggers(), (
        "the workflow gained a `pull_request:` trigger. Secrets are not available to workflows "
        "triggered by a fork PR, so this job would exit 2 on every external contribution forever, "
        "and the answer it computes has nothing to do with the diff in any case."
    )


def test_the_on_demand_trigger_survives() -> None:
    """Its own test, because it is the design's escape hatch rather than a detail of the PR guard.

    `workflow_dispatch` is the on-demand answer a human gets in about a minute, and it is what the
    staleness arm's silence measurement exists to serve: a dispatch run is the one run that can
    report a schedule which stopped and never resumed. Deleting it used to fail a test named after
    pull-request triggers, which misdirects the reader at exactly the moment the escape hatch
    disappears.
    """
    assert "workflow_dispatch" in _triggers(), (
        "`workflow_dispatch` is gone. It is the on-demand answer a human gets in about a minute, "
        "and after the heartbeat learned to measure silence it is the only run that can report a "
        "schedule which stopped and never resumed."
    )


def test_the_workflow_filename_constant_is_the_real_filename() -> None:
    """Criterion 6. The heartbeat asks the Actions API about a file by name.

    Rename the workflow without the constant and the API answers 404: the heartbeat degrades to a
    `::warning::` that nobody reads, and the staleness arm is off permanently while every other
    test stays green.
    """
    assert _SCRIPT_MODULE.WORKFLOW_FILENAME == WORKFLOW.name
    assert WORKFLOW.exists()


#: The clock every heartbeat fixture runs at, and the anchor its run histories are written
#: against. It is deliberately the SAME value `run()` already defaults `--now` to, so naming it
#: shifts nothing — but once the arm measures silence as `now - newest`, an unstated clock stops
#: being harmless: the histories below were dated five days before that default, which would have
#: made every one of them warn, including the fixtures whose whole job is to assert silence.
HEARTBEAT_NOW = LANDED + timedelta(days=10)


def _stale_run(tmp_path: Path, runs: list[str] | None, *, now: datetime = HEARTBEAT_NOW):
    """A clean reporting run whose heartbeat sees `runs`. Returns (proc, log)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    repo = make_repo(tmp_path, version="0.7.77", tag=True)
    gh_bin, gh_log = gh_stub(tmp_path, [], runs=runs)
    return report_run(repo, published("0.7.77"), tmp_path, now=now, gh_bin=gh_bin, gh_log=gh_log)


def _arm_says(monkeypatch, *, cron: str, stamps: list[str], now: datetime) -> str:
    """Run the heartbeat arm IN-PROCESS with `CRON` moved, and return everything it printed.

    In-process because `CRON` is a module constant: a subprocess cannot be told to move it, so no
    out-of-process test can tell `staleness_threshold_minutes()` apart from a literal `360`. That
    is the whole of the gap this exists to close — the derivation was pinned where it is DEFINED
    and never where it is USED, and 120 x 3 happens to equal 360 for the shipped cron, so the two
    agree on every value the suite ever looked at.

    `_SCRIPT_MODULE` is the same loaded module the cron parser tests already drive, so this adds no
    new mechanism. Nothing here reads a wall clock: `now` and every stamp are literals.
    """
    monkeypatch.setattr(_SCRIPT_MODULE, "CRON", cron)
    monkeypatch.setattr(_SCRIPT_MODULE, "issue_repo", lambda: STUB_REPO)
    monkeypatch.setattr(_SCRIPT_MODULE, "_gh", lambda *a, **k: "\n".join(stamps))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _SCRIPT_MODULE.warn_if_schedule_is_stale(now)
    return buf.getvalue()


def _stamp(now: datetime, *, minutes_ago: float) -> str:
    return (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_a_schedule_that_has_been_skipping_says_so_and_changes_nothing(tmp_path: Path) -> None:
    """Criterion 4. A 40-hour gap warns, and the exit code is identical to the no-gap run.

    The comparison is the point. Asserting only that a warning appears would leave the arm free to
    also change the verdict — and a heartbeat that can turn a healthy registry red is worse than no
    heartbeat, because it makes the check's own red untrustworthy. So the same scenario runs twice,
    differing only in the run history, and the return codes are compared to each other rather than
    to a constant.
    """
    stale = ["2026-09-09T20:00:00Z", "2026-09-09T18:00:00Z"]   # newest is 40h before the clock
    healthy = ["2026-09-11T11:00:00Z", "2026-09-11T09:00:00Z"]  # newest is 1h before it

    warned, _ = _stale_run(tmp_path / "a", stale)
    quiet, _ = _stale_run(tmp_path / "b", healthy)

    assert "::warning::" in warned.stdout, warned.stdout
    assert "2400" in warned.stdout, f"the silence is not named in minutes:\n{warned.stdout}"
    # The FULL sentence, not the word. The derive-failure message — "cannot derive a staleness
    # threshold ... whether the schedule has been skipping" — also contains "skipping", so the
    # short needle cannot tell "it skipped" from "I have no idea whether it skipped", and those
    # are opposite claims. A test that accepts either is not reading the answer.
    assert "The schedule has been skipping" in warned.stdout, warned.stdout
    assert "::warning::" not in quiet.stdout, quiet.stdout
    assert warned.returncode == quiet.returncode, (
        f"the staleness arm changed the exit code ({warned.returncode} vs {quiet.returncode}). It "
        f"is diagnostics about the watcher, never evidence about the registry."
    )


def test_a_heartbeat_that_cannot_be_read_changes_nothing(tmp_path: Path) -> None:
    """Criterion 5. `gh api` fails: a warning, and the exit code is untouched.

    This is the path that decides whether the arm is safe to have at all. An Actions API that 403s
    — which is exactly what a missing `actions: read` produces — must not be able to fail a run
    about the registry.
    """
    repo = make_repo(tmp_path, version="0.7.77", tag=True)
    # The path is derived from the same constant the script builds it from, so a change to the
    # query shape cannot leave this test silently failing to fail.
    gh_bin, gh_log = gh_stub(
        tmp_path, [], fail_on=("api", heartbeat_verb().split(" ", 1)[1])
    )
    broken, log = report_run(repo, published("0.7.77"), tmp_path, gh_bin=gh_bin, gh_log=gh_log)

    healthy, _ = _stale_run(tmp_path / "ok", ["2026-09-06T12:00:00Z", "2026-09-06T10:00:00Z"])
    assert "::warning::" in broken.stdout, broken.stdout
    assert "run history" in broken.stdout
    assert broken.returncode == healthy.returncode, (
        f"a failed heartbeat changed the exit code ({broken.returncode} vs "
        f"{healthy.returncode}). A broken instrument about the instrument is not a verdict."
    )
    assert [c[0] for c in gh_calls(log)].count("api") == 1, gh_calls(log)


def test_an_unreadable_timestamp_is_a_warning_and_not_a_crash(tmp_path: Path) -> None:
    """The `--jq` could answer with something that is not a timestamp. That is still not a verdict.

    Without this the arm's parse sits on the happy path only, and a GitHub response shape change
    would surface as an uncaught exception — which the top-level handler turns into exit 2, making
    a schedule diagnostic fail a run about the registry after all.
    """
    proc, _ = _stale_run(tmp_path, ["2026-09-06T12:00:00Z", "not-a-timestamp"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "::warning::" in proc.stdout


def test_too_little_history_is_silent_but_a_single_ancient_run_is_not(tmp_path: Path) -> None:
    """No completed run at all is not evidence. ONE RECENT run is not either. One ANCIENT run IS.

    A warning on a newly added workflow would fire once for every new workflow and teach its first
    reader that this arm cries wolf, which is the failure mode being guarded against. But the rule
    that bought that — `len(stamps) < 2` — exempted the single-stamp case wholesale, so a workflow
    whose one and only completed run was days ago read identically to one added a minute ago.

    Measuring silence needs one stamp rather than two, so the exemption shrinks to exactly what it
    was always meant to cover: nothing to measure at all. The third case is what stops this test
    passing by simply never warning.
    """
    for name, history, quiet in (
        ("none", [], True),
        ("one-recent", ["2026-09-11T11:00:00Z"], True),
        ("one-ancient", ["2026-09-09T20:00:00Z"], False),
    ):
        proc, _ = _stale_run(tmp_path / name, history)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert ("The schedule has been skipping" in proc.stdout) is not quiet, (
            f"[{name}] expected {'silence' if quiet else 'a warning'}:\n{proc.stdout}"
        )


def test_the_heartbeat_asks_whether_the_schedule_fired_not_whether_it_was_green(
    tmp_path: Path,
) -> None:
    """`event=schedule`, and `status=completed` — never `status=success`.

    `event=schedule` is the half that was always right: pressing "Run workflow" is precisely what
    someone does while investigating a check that has gone quiet, so counting manual runs would
    make the arm blindest exactly when it is being consulted.

    `status` is the half that was wrong. The runs API filters on a check run's STATUS OR
    CONCLUSION, so `success` selects on the VERDICT rather than on whether the schedule fired.
    This check exits 1 on drift, so every run of a real incident is invisible under `success`, and
    the first green run afterwards measures across the whole incident and reports a schedule that
    never missed a beat as skipping — crying wolf immediately after the arm's subject did the one
    thing it exists to report.

    This asserts against LITERALS on purpose. `heartbeat_argv()` is built from the script's own
    constants, so comparing to it would only ask the constant to agree with itself.
    """
    _, log = _stale_run(tmp_path, ["2026-09-11T11:00:00Z", "2026-09-11T09:00:00Z"])
    api = [c for c in gh_calls(log) if c[0] == "api"]
    assert len(api) == 1, gh_calls(log)
    assert "event=schedule" in api[0][1], api[0]
    assert "status=completed" in api[0][1], api[0]
    assert "status=success" not in api[0][1], (
        f"the heartbeat is filtering its own run history to SUCCESSFUL runs: {api[0][1]!r}. A "
        f"drift verdict exits 1, so every run that reported drift is invisible here, and the "
        f"first clean run after an incident measures a span covering the whole incident and "
        f"announces that the schedule has been skipping when it never missed a beat."
    )
    assert "--repo" not in api[0], (
        f"`gh api` has no `--repo` and exits 1 on it, so this heartbeat would be dead on every "
        f"real run behind a warning nobody reads: {api[0]!r}"
    )


def _fabricated_log(tmp_path: Path, name: str, calls: list[list[str]]) -> Path:
    """An argv log the stub could have written. NUL-delimited, `CALL` before each invocation."""
    parts: list[str] = []
    for call in calls:
        parts.append("CALL")
        parts.extend(call)
    log = tmp_path / f"{name}.log"
    log.write_bytes(b"\0".join(p.encode("utf-8") for p in parts) + b"\0")
    return log


@pytest.mark.parametrize(
    "repo_value",
    [None, "", "   ", "seam-sdk", "a b/c"],
    ids=["unset", "empty", "whitespace", "no-slash", "spaces"],
)
def test_a_broken_reporting_target_cannot_redden_a_clean_run(
    tmp_path: Path, repo_value: str | None
) -> None:
    """Criterion 7, on the path that actually broke. A bad `$REPO` must not fail a healthy run.

    `report_clean` resolves `issue_repo()` inside a best-effort handler precisely so a GitHub
    problem cannot redden a run that PROVED the registry healthy. The heartbeat then resolved the
    same value again as an ARGUMENT AT THE CALL SITE — outside every handler — so the identical
    `InfraError`, already softened to a `::warning::` eleven lines earlier, came back as a
    traceback and exit 2. The same failure, softened once and then fatal.

    The exit code is compared to the healthy run rather than to a literal `0`, so this cannot pass
    by both runs being broken in the same new way.
    """
    broken_dir = tmp_path / "broken"
    broken_dir.mkdir(parents=True, exist_ok=True)
    repo = make_repo(broken_dir, version="0.7.77", tag=True)
    gh_bin, gh_log = gh_stub(broken_dir, [], runs=["2026-09-11T11:00:00Z"])
    broken, _ = report_run(
        repo,
        published("0.7.77"),
        broken_dir,
        now=HEARTBEAT_NOW,
        gh_bin=gh_bin,
        gh_log=gh_log,
        env_repo=repo_value,
    )
    healthy, _ = _stale_run(tmp_path / "healthy", ["2026-09-11T11:00:00Z"])

    assert "Traceback" not in broken.stderr, broken.stderr
    assert broken.returncode == healthy.returncode, (
        f"a reporting target the heartbeat cannot use changed the exit code "
        f"({broken.returncode} vs {healthy.returncode}) on a run whose registry verdict was "
        f"clean. Diagnostics about the watcher are not evidence about the registry."
    )
    assert "run history" in broken.stdout, broken.stdout


def test_the_staleness_arm_cannot_raise_whatever_goes_wrong_inside_it(monkeypatch) -> None:
    """Criterion 7 as a CLASS, not as the list of failures somebody happened to think of.

    Every handler inside the body catches `InfraError`. `cron_period_minutes` can raise
    `ValueError` on a cron step of zero, a change in GitHub's response shape can raise anything,
    and the next edit can raise something nobody has named — all of which reach the top-level
    handler and exit 2, reporting the instrument's own health as a finding about the registry.
    """
    def boom(_now):
        raise ZeroDivisionError("boom")

    monkeypatch.setattr(_SCRIPT_MODULE, "_staleness_heartbeat", boom)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _SCRIPT_MODULE.warn_if_schedule_is_stale(HEARTBEAT_NOW)  # must not raise
    out = buf.getvalue()
    assert "::warning::" in out, out
    assert "ZeroDivisionError" in out, out


@pytest.mark.parametrize(
    ("cron", "silence_minutes", "warns"),
    [
        ("17 */2 * * *", 500, True),
        ("17 */12 * * *", 500, False),
        ("17 */12 * * *", 2500, True),
        # This row pins the multiplier's VALUE, which the three above do not. They constrain it
        # only to (0.694, 3.47), so 1 and 2 both pass — and at 1 the arm warns whenever a single
        # cron period slips, which the workflow's own cron comment says GitHub does routinely. A
        # warning that is wrong every time is the muted-guard failure this design argues against.
        # 300 minutes is quiet only when the multiplier is at least 2.5, so 1 and 2 both redden it.
        ("17 */2 * * *", 300, False),
    ],
    ids=["two-hourly-warns", "twelve-hourly-stays-quiet", "twelve-hourly-warns-later",
         "two-hourly-quiet-below-threshold"],
)
def test_the_threshold_the_heartbeat_uses_moves_with_the_cron(
    monkeypatch, cron: str, silence_minutes: int, warns: bool
) -> None:
    """The ARM's threshold, not the helper's. This is the gap the helper's own test cannot see.

    `test_the_cron_is_the_one_the_threshold_is_derived_from` proves
    `staleness_threshold_minutes()` follows `CRON`. Nothing proved the arm CALLS it — and since
    120 x 3 == 360 for the shipped cron, a literal `threshold = 360` agrees with the derivation on
    every value the suite ever looked at, leaving the helper as unreachable dead code.

    Falsifiable in both directions, which is what makes it more than a second copy of the helper
    test: a hardcoded 360 makes the twelve-hourly case warn, and a hardcoded 2160 makes the
    two-hourly case go quiet. No single constant satisfies all three rows.
    """
    out = _arm_says(
        monkeypatch,
        cron=cron,
        stamps=[_stamp(HEARTBEAT_NOW, minutes_ago=silence_minutes)],
        now=HEARTBEAT_NOW,
    )
    assert ("The schedule has been skipping" in out) is warns, out


def test_a_cron_the_arm_cannot_read_warns_and_changes_nothing(monkeypatch) -> None:
    """The `threshold is None` branch, which no test had ever executed.

    Reached when the cron is not a fixed sub-daily cadence. Without the step-of-zero guard in the
    parser this same input raises `ValueError` instead — which is not an `InfraError`, so it would
    escape to the top level and exit 2 from an arm whose contract is warnings-only.

    The needle is `cron period`, not `skipping`: the derive-failure message ends "...cannot say
    whether the schedule has been SKIPPING", so the short needle cannot tell it apart from the
    warning that says the schedule HAS been skipping. They are opposite claims.
    """
    out = _arm_says(
        monkeypatch,
        cron="17 */0 * * *",
        stamps=[_stamp(HEARTBEAT_NOW, minutes_ago=5000)],
        now=HEARTBEAT_NOW,
    )
    assert "cannot derive a staleness threshold" in out, out
    assert "cron period" not in out, f"it claimed to measure a cadence it cannot read:\n{out}"


def test_the_heartbeat_call_is_argv_exact(tmp_path: Path) -> None:
    """Exactly one `gh api` call, and exactly the argv the script's constants describe."""
    _, log = _stale_run(tmp_path, ["2026-09-11T11:00:00Z", "2026-09-11T09:00:00Z"])
    assert [c for c in gh_calls(log) if c[0] == "api"] == [heartbeat_argv()], gh_calls(log)


def test_the_write_classifier_notices_a_write_smuggled_through_gh_api(tmp_path: Path) -> None:
    """Guard the guard. `gh_writes` claims no write reaches GitHub through `gh api`.

    It used to claim that by denying a hand-written list of flags — `-X`, `--method`, `-f`,
    `--field` — which took the SHORT form of one pair and the LONG form of the other, and tested
    membership on whole argv tokens. Five of the seven real spellings below walked straight past
    it, on the assertion whose whole purpose is catching a write.

    This is the control that stops the allowlist becoming vacuous: it pins that the classifier
    accepts the real call and rejects every one of those spellings.
    """
    assert gh_writes(_fabricated_log(tmp_path, "clean", [heartbeat_argv()])) == []
    for name, extra in (
        ("dash-x-split", ["-X", "POST"]),
        ("dash-x-glued", ["-XPOST"]),
        ("method-equals", ["--method=POST"]),
        ("upper-f", ["-F", "ref=main"]),
        ("raw-field", ["--raw-field", "ref=main"]),
        ("input", ["--input", "-"]),
    ):
        with pytest.raises(AssertionError):
            gh_writes(_fabricated_log(tmp_path, name, [heartbeat_argv() + extra]))


def test_a_roster_entry_that_could_alter_the_request_is_refused(monkeypatch) -> None:
    """The canary roster reaches the SAME URL interpolation as the source version.

    Only the source version was ever validated. `_query_for` builds `?query=seam-sdk+version:<v>`
    for roster entries too, so an entry carrying `&` appends a parameter to the request instead of
    failing — and the roster constant's own comment says values of this class must be checked. The
    refusal must be an `InfraError`, so it exits 2 rather than reading as a verdict.
    """
    # Both halves are load-bearing, and the first draft of this test had neither. Asserting only
    # that an InfraError comes out passes with the guard DELETED: execution falls through to
    # `fetch_registry`, which raises InfraError of its own and quotes the version in the message.
    # A mutation run caught that — the test was green against its own removal.
    reached: list[str] = []

    def must_not_run(version: str, token: str) -> object:
        reached.append(version)
        raise AssertionError(f"fetch_registry was reached with {version!r} before validation")

    monkeypatch.setattr(_SCRIPT_MODULE, "CANARY_VERSIONS", ("0.7.50&admin=1", "0.7.65"))
    monkeypatch.setattr(_SCRIPT_MODULE, "fetch_registry", must_not_run)
    with pytest.raises(_SCRIPT_MODULE.InfraError) as caught:
        _SCRIPT_MODULE.assert_live_instrument_healthy("0.7.77", "stub-token")
    assert "not plain digits-and-dots" in str(caught.value), caught.value
    assert reached == [], f"the entry reached the request path before being validated: {reached}"


def test_an_interpreter_older_than_the_dates_it_must_parse_is_refused(monkeypatch) -> None:
    """3.10 and below fail deep inside date parsing, which reads as a broken repository.

    Both date sources are Z-suffixed — git's `%cI` and GitHub's `created_at` — and
    `datetime.fromisoformat` only accepts `Z` from 3.11. The docs tell a reader to run this with
    `python3`, which on a stock macOS is 3.9, and the failure they got named the commit date rather
    than the interpreter. Exit 2, because a wrong interpreter is infrastructure and 1 is drift.
    """
    monkeypatch.setattr(_SCRIPT_MODULE.sys, "version_info", (3, 10, 4, "final", 0))
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        code = _SCRIPT_MODULE.main([])
    assert code == 2, code
    assert "3.11" in buf.getvalue(), buf.getvalue()


def test_the_issue_listing_call_is_argv_exact(tmp_path: Path) -> None:
    """`--state all` was pinned; `--limit`, `--json` and `--jq` were not, and each is load-bearing."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    _, log = report_run(repo, published("0.7.60"), tmp_path)
    listings = [c for c in gh_calls(log) if c[:2] == ["issue", "list"]]
    assert listings == [issue_list_argv()], listings


def test_the_label_projection_survives_a_real_jq(tmp_path: Path) -> None:
    """The `--jq` program is EXECUTED here, not merely quoted — and that is the whole point.

    The stub hand-writes the TSV, so until this test the projection had never once run. Mutating
    `join("\u001f")` to `join(",")` left every test in this file green, while in production a label
    like `foo,deliberately-unpublished` split into two, one of them exactly equal to the suppression
    label, and a real drift was silently suppressed and never reported again.

    jq is preinstalled on GitHub's ubuntu runners, so this does not skip: a skipped guard is the
    same hole wearing a different colour. The program is taken from the ARGV the script actually
    sent, not from the constant, so this is behaviour rather than a constant agreeing with itself.
    """
    jq = shutil.which("jq")
    assert jq, (
        "jq is required by this test, which executes the real `--jq` projection. It is preinstalled "
        "on GitHub ubuntu runners; skipping instead would restore the hole this test closes."
    )
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    _, log = report_run(repo, published("0.7.60"), tmp_path)
    listing = next(c for c in gh_calls(log) if c[:2] == ["issue", "list"])
    program = listing[listing.index("--jq") + 1]

    payload = json.dumps([{ "number": 7, "state": "CLOSED", "title": "t",
                            "labels": [{"name": "area:ci,urgent"},
                                       {"name": _SCRIPT_MODULE.SUPPRESSION_LABEL}]}])
    out = subprocess.run([jq, "-r", program], input=payload, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    fields = out.stdout.rstrip("\n").split("\t", 3)
    assert len(fields) == 4, fields
    assert fields[2].split(_SCRIPT_MODULE.LABEL_SEP) == ["area:ci,urgent",
                                                         _SCRIPT_MODULE.SUPPRESSION_LABEL]


def test_two_labels_on_one_issue_are_read_as_two(tmp_path: Path) -> None:
    """No listing row anywhere in this file carried more than one label before this one.

    The only comma case was a SINGLE label containing a comma, for which a comma join and a
    unit-separator join produce identical output — so even a stub that ran jq would have missed it.
    A closed drift issue carrying an unrelated label alongside the suppression label must still
    suppress, and must still say so.
    """
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    listing = [(7, "CLOSED", ["area:ci,urgent", SUPPRESSION_LABEL],
                DRIFT_TITLE.format(version=DRIFTING))]
    proc, log = report_run(repo, published("0.7.60"), tmp_path, listing=listing)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "::warning::" in proc.stdout, proc.stdout
    assert gh_writes(log) == [], gh_writes(log)


def test_the_gh_stub_refuses_a_repo_flag_on_api_the_way_gh_does(tmp_path: Path) -> None:
    """Instrument fidelity, and load-bearing in the same way honouring `--state` is.

    Real `gh api` has no `--repo` and exits 1 on it. While the stub tolerated it, flipping
    `repo_flag=False` to `True` was invisible to all 201 tests, and the heartbeat would have been
    dead on every real run behind a `::warning::` nobody reads — present, green, and off.

    The `issue list` half of the assertion keeps this targeted: `--repo` is correct there, and a
    stub that banned it everywhere would be a different bug.
    """
    gh_bin, _ = gh_stub(tmp_path, [(1, "OPEN", [], "t")], runs=["2026-09-11T11:00:00Z"])
    env = report_env(gh_bin)
    refused = subprocess.run(
        [str(gh_bin / "gh"), "api", "some/path", "--repo", STUB_REPO],
        capture_output=True, text=True, env=env,
    )
    assert refused.returncode == 1, refused
    assert "unknown flag: --repo" in refused.stderr, refused.stderr
    allowed = subprocess.run(
        [str(gh_bin / "gh"), "issue", "list", "--repo", STUB_REPO, "--state", "all"],
        capture_output=True, text=True, env=env,
    )
    assert allowed.returncode == 0, allowed


def test_a_schedule_that_stopped_dead_is_named_by_the_run_a_human_presses(tmp_path: Path) -> None:
    """The case the pairwise gap provably cannot see, and the reason `now` is a parameter.

    A gap compares two points in the PAST. A schedule that stopped and never resumed leaves its
    last two runs a nominal cadence apart forever, so the gap arm is permanently silent about it —
    and permanent silence is the residual the workflow header names, whose stated mitigation is
    `workflow_dispatch`. Until now that dispatch run's heartbeat said nothing at all.

    The two runs differ ONLY in `now`, so this cannot pass with `now` ignored.
    """
    healthy = ["2026-09-11T11:00:00Z", "2026-09-11T09:00:00Z"]
    dead, _ = _stale_run(tmp_path / "dead", healthy, now=HEARTBEAT_NOW + timedelta(days=3))
    alive, _ = _stale_run(tmp_path / "alive", healthy)

    assert "The schedule has been skipping" in dead.stdout, dead.stdout
    assert "The schedule has been skipping" not in alive.stdout, alive.stdout
    assert dead.returncode == alive.returncode == 0


def test_a_dense_history_through_an_incident_is_not_a_skipping_schedule(tmp_path: Path) -> None:
    """48 hours of runs every two hours, the newest an hour old. The schedule never missed.

    This is what `status=completed` buys and what `status=success` could not: during a real
    incident every run exits 1, so under `success` this history would be empty of everything but
    the pre-incident runs, and the arm would announce a skipping schedule about a schedule firing
    perfectly. It also pins that measuring silence is not oversensitive — a dense history stays
    quiet, so the warnings above are about absence rather than about volume.
    """
    history = [_stamp(HEARTBEAT_NOW, minutes_ago=m) for m in range(60, 60 + 24 * 120, 120)]
    proc, _ = _stale_run(tmp_path, history)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "The schedule has been skipping" not in proc.stdout, proc.stdout


def test_neither_grace_tier_reaches_the_heartbeat_either(tmp_path: Path) -> None:
    """The grace tiers touch GitHub not at all, and the heartbeat is a GitHub call.

    Phase 6 pinned this for reporting; Phase 7 adds a second call on the same code path, so the
    invariant needs re-asserting against the thing that could newly break it. A grace window that
    makes any request has stopped being a grace window.
    """
    for minutes, expect in ((10, "DEFERRED"), (200, "::warning::")):
        (tmp_path / f"g{minutes}").mkdir(parents=True, exist_ok=True)
        repo = make_repo(tmp_path / f"g{minutes}", version=DRIFTING, tag=True)
        gh_bin, gh_log = gh_stub(tmp_path / f"g{minutes}", [], runs=["2026-09-06T12:00:00Z"])
        proc, log = report_run(
            repo,
            published("0.7.77"),
            tmp_path / f"g{minutes}",
            gh_bin=gh_bin,
            gh_log=gh_log,
            now=LANDED + timedelta(minutes=minutes),
        )
        assert expect in proc.stdout, proc.stdout
        assert gh_calls(log) == [], gh_calls(log)


# ── seam-sdk#253: partner serves the NEWEST release on internal ─────────────────────────────────
#
# The declared-version question cannot see a release `main` has already moved past: with 0.45.0 on
# internal and `main` declaring 0.45.1, nothing above asks partner about 0.45.0. These pin the one
# extra question — the newest version internal serves in both formats, and whether partner serves
# it — through one unscoped GET whose answer is proved before it is used, on the upload clock, with
# the D3 exit table, and with nothing from the response but plain versions reaching the output.

#: A newest version ABOVE the declared one (`DRIFTING`). That is the only shape in which the newest
#: question can disagree with a clean declared one: when internal serves the declared version, the
#: newest is floored at it, so "newest lags while declared is clean" means newest > declared.
AHEAD = "0.7.80"

NEWEST_FAULT = "::error::the newest-version question could not be answered"


def newest_stub(
    tmp_path: Path,
    *,
    now: datetime,
    declared_served: bool = True,
    ahead_minutes_ago: float | None = None,
    ahead_rows: list[dict] | None = None,
    partner_ahead: object | None = None,
    unscoped: object | None = None,
) -> tuple[Path, Path]:
    """Internal and partner both serve the canary, and — when `declared_served` — `DRIFTING`.
    Internal ALSO serves `AHEAD` when `ahead_minutes_ago` (uploaded that long before `now`) or
    `ahead_rows` is given; partner serves `AHEAD` only as `partner_ahead` says. The unscoped answer
    is the stub's sorted union unless `unscoped` overrides it."""
    internal: dict[str, object] = {ROSTER[0]: published(ROSTER[0])}
    partner: dict[str, object] = {ROSTER[0]: published(ROSTER[0])}
    if declared_served:
        internal[DRIFTING] = published(DRIFTING)
        partner[DRIFTING] = published(DRIFTING)
    if ahead_rows is not None:
        internal[AHEAD] = ahead_rows
    elif ahead_minutes_ago is not None:
        internal[AHEAD] = published(
            AHEAD, uploaded_at=upload_stamp(now - timedelta(minutes=ahead_minutes_ago))
        )
    if partner_ahead is not None:
        partner[AHEAD] = partner_ahead
    return curl_stub(tmp_path, internal, partner_responses=partner, unscoped=unscoped)


def test_the_newest_query_is_pinned_word_for_word() -> None:
    """The request shape, against a LITERAL — a constant compared with itself pins nothing.

    Observed live (2026-10-12): `sort=-bogus` is HTTP 400, but a wrong parameter NAME
    (`ordering=-version`) is silently ignored and the server falls back to `-date`. So a typo here
    would not fail; it would quietly change which release is "newest". `fetch_newest` also checks
    the order it gets back — this pins what is asked, that proves what was answered.
    """
    assert _SCRIPT_MODULE.NEWEST_QUERY == "?query=seam-sdk&sort=-version&page_size=50"
    assert (
        _SCRIPT_MODULE.REGISTRY_URL + _SCRIPT_MODULE.NEWEST_QUERY
        == "https://api.cloudsmith.io/v1/packages/zer07labs/internal/"
        "?query=seam-sdk&sort=-version&page_size=50"
    )
    # Same `page_size` as the version-scoped query: the page-edge rule reads "full" against it.
    assert f"page_size={_SCRIPT_MODULE.PAGE_SIZE}" in _SCRIPT_MODULE.NEWEST_QUERY


def test_the_curl_stub_answers_unscoped_from_a_sorted_union_and_refuses_partner(
    tmp_path: Path,
) -> None:
    """The instrument for this block, proved before anything is measured with it.

    If the union were unsorted, every ordering test below would be testing the stub; if partner's
    refusal were not recorded, a script asking partner an unscoped query would merely see a curl
    failure, capture it as a newest fault, and pass any test that expected a 2."""
    bin_dir, _ = curl_stub(
        tmp_path,
        {
            ROSTER[0]: published(ROSTER[0]),
            "0.7.9": published("0.7.9"),
            "0.7.100": published("0.7.100"),
            "html": "<html>not a list</html>",
        },
    )
    base = _SCRIPT_MODULE.REGISTRY_URL + _SCRIPT_MODULE.NEWEST_QUERY
    got = subprocess.run([str(bin_dir / "curl"), base], capture_output=True, text=True)
    assert got.returncode == 0, got.stderr
    versions = [row["version"] for row in json.loads(got.stdout)]
    # Numeric, not lexical: 0.7.100 > 0.7.71 > 0.7.9.
    assert versions == ["0.7.100", "0.7.100", ROSTER[0], ROSTER[0], "0.7.9", "0.7.9"], versions

    partner = _SCRIPT_MODULE.PARTNER_REGISTRY_URL + _SCRIPT_MODULE.NEWEST_QUERY
    refused = subprocess.run([str(bin_dir / "curl"), partner], capture_output=True, text=True)
    assert refused.returncode == UNSCOPED_PARTNER_REFUSAL
    log = tmp_path / "curl-unscoped-partner"
    assert log.read_text().strip() == partner
    # Cleared, because the autouse fixture would — correctly — fail this test for it otherwise.
    log.write_text("")


def test_a_newest_version_partner_serves_is_a_sixth_get_beside_a_declared_drift(
    tmp_path: Path,
) -> None:
    """#253 acceptance 2, unsuppressed. `main` declares 0.7.79, internal never got it; the newest
    on internal is 0.7.78 and partner serves it. Exit 1 is the DECLARED drift's, and the sixth GET
    asks partner about 0.7.78 — the question nothing asked before."""
    repo = make_repo(tmp_path, version="0.7.79")
    bin_dir, calls = curl_stub(
        tmp_path, {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    )
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert registries_queried(calls) == [
        ("internal", ROSTER[0]),
        ("internal", "0.7.79"),
        ("partner", ROSTER[0]),
        ("partner", "0.7.79"),
        ("internal", NEWEST),
        ("partner", "0.7.78"),
    ]
    assert "DRIFT — seam-sdk 0.7.79 is not installable" in proc.stdout, proc.stdout
    assert "newest on internal: 0.7.78, uploaded" in proc.stdout, proc.stdout
    assert "partner serves 0.7.78: npm, python" in proc.stdout, proc.stdout
    assert "NEWEST CLEAN — partner serves 0.7.78" in proc.stdout, proc.stdout
    assert STUB_TOKEN not in out


def test_a_suppressed_declared_drift_beside_a_clean_newest_is_zero(tmp_path: Path) -> None:
    """#253 acceptance 2, suppressed. The declared drift's own suppression applies, and a newest
    version partner serves adds nothing to vote with: exit 0, still six GETs."""
    repo = make_repo(tmp_path, version="0.7.79")
    bin_dir, calls = curl_stub(
        tmp_path, {ROSTER[0]: published(ROSTER[0]), "0.7.78": published("0.7.78")}
    )
    _, gh_log = gh_stub(
        tmp_path, [(7, "CLOSED", [SUPPRESSION_LABEL], DRIFT_TITLE.format(version="0.7.79"))]
    )
    proc = run(repo, None, tmp_path, extra=["--report"], env=report_env(bin_dir, token=STUB_TOKEN))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "SUPPRESSED by #7" in proc.stdout, proc.stdout
    assert registries_queried(calls)[4:] == [("internal", NEWEST), ("partner", "0.7.78")]
    assert len(registries_queried(calls)) == 6, registries_queried(calls)
    assert gh_writes(gh_log) == [], gh_calls(gh_log)
    assert STUB_TOKEN not in out


@pytest.mark.parametrize(
    ("uploaded_ago", "git_age", "expected", "marker"),
    [
        (30, 14400, 0, "NEWEST DEFERRED —"),
        (200, 14400, 0, f"::warning::seam-sdk {AHEAD}, the newest version on internal"),
        (14400, 10, 1, "NEWEST DRIFT —"),
    ],
    ids=["soft", "warn", "hard"],
)
def test_a_newest_lag_walks_the_ladder_on_the_upload_clock_never_git(
    tmp_path: Path, uploaded_ago: int, git_age: int, expected: int, marker: str
) -> None:
    """#253 acceptance 3. Declared 0.7.78 is clean on both; internal also serves 0.7.80, partner
    does not. Each case puts git's age on the OPPOSITE side of the ladder from the upload's — 30
    minutes after upload but two weeks after the version commit, and the reverse — so a tier read
    from git instead of `uploaded_at` lands on the wrong rung in every case."""
    now = LANDED + timedelta(minutes=git_age)
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, calls = newest_stub(tmp_path, now=now, ahead_minutes_ago=uploaded_ago)
    proc = run(repo, None, tmp_path, now=now, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == expected, out
    assert marker in out, out
    assert f"OK — the registry serves {DRIFTING} in both formats, on internal and partner." in out
    assert f"newest on internal: {AHEAD}, uploaded {uploaded_ago} minutes ago" in proc.stdout
    assert f"partner serves {AHEAD}: <nothing>" in proc.stdout
    assert registries_queried(calls)[4:] == [("internal", NEWEST), ("partner", AHEAD)]
    assert len(registries_queried(calls)) == 6, registries_queried(calls)
    if expected == 1:
        # State P for the NEWEST version, naming both it and the declared one.
        assert "State P" in proc.stdout and f"promote-to-partner.sh {AHEAD}" in proc.stdout
        assert f"Main declares {DRIFTING}" in proc.stdout
    # D8: the age is printed, the stamp it came from never is.
    stamp = upload_stamp(now - timedelta(minutes=uploaded_ago))
    assert stamp not in out and stamp[:19] not in out, out
    assert STUB_TOKEN not in out


def _full_page_of_one_version() -> list[dict]:
    return [
        row
        for _ in range(_SCRIPT_MODULE.PAGE_SIZE // 2)
        for row in published(DRIFTING)
    ]


@pytest.mark.parametrize(
    ("case", "needle"),
    [
        ("empty", "carries no `seam-sdk` row"),
        ("ascending", f"({ROSTER[0]} is followed by {DRIFTING})"),
        ("full-page-of-one-version", f"{DRIFTING} is the lowest version on a full page"),
        ("below-the-proving-canary", f"below the canary {ROSTER[0]}"),
        ("below-a-served-declared-version", f"below {DRIFTING}, which internal served"),
        ("uploaded-at-missing", "is a NoneType, not a timestamp string"),
        ("uploaded-at-garbage", "is not an ISO-8601 timestamp (value withheld)"),
        ("uploaded-at-impossible", "is not a real instant (value withheld)"),
        ("uploaded-at-in-the-future", "minutes AFTER now"),
    ],
)
def test_an_unprovable_newest_answer_is_two_with_the_declared_verdict_printed(
    tmp_path: Path, case: str, needle: str
) -> None:
    """#253 acceptance 4. Every guard on the newest answer, driven red. Each exits 2 — the declared
    question is clean (or, for the canary floor, still in grace), so there is no finding for the
    fault to stand beside — and the declared verdict is printed first regardless.

    The canary-floor case runs with the declared version ABSENT and young, so the declared floor
    cannot fire in its place: each floor is observed alone, never through the other."""
    now = LANDED + timedelta(days=10)
    declared_served = True
    kw: dict[str, object] = {}
    garbage = "yesterday"
    if case == "empty":
        kw["unscoped"] = []
    elif case == "ascending":
        kw["unscoped"] = published(ROSTER[0]) + published(DRIFTING)
    elif case == "full-page-of-one-version":
        kw["unscoped"] = _full_page_of_one_version()
    elif case == "below-the-proving-canary":
        declared_served = False
        now = LANDED + timedelta(minutes=10)
        kw["unscoped"] = published("0.7.50")
    elif case == "below-a-served-declared-version":
        kw["unscoped"] = published("0.7.75") + published(ROSTER[0])
    elif case == "uploaded-at-missing":
        kw["ahead_rows"] = [
            {k: v for k, v in row.items() if k != "uploaded_at"} for row in published(AHEAD)
        ]
    elif case == "uploaded-at-garbage":
        kw["ahead_rows"] = published(AHEAD, uploaded_at=garbage)
    elif case == "uploaded-at-impossible":
        garbage = "2026-13-01T00:00:00.000000Z"
        kw["ahead_rows"] = published(AHEAD, uploaded_at=garbage)
    else:
        garbage = upload_stamp(now + timedelta(minutes=60))
        kw["ahead_rows"] = published(AHEAD, uploaded_at=garbage)
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, calls = newest_stub(tmp_path, now=now, declared_served=declared_served, **kw)
    proc = run(repo, None, tmp_path, now=now, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    assert NEWEST_FAULT in proc.stderr and needle in proc.stderr, out
    assert "newest on internal: COULD NOT BE READ" in proc.stdout, proc.stdout
    if declared_served:
        assert f"OK — the registry serves {DRIFTING} in both formats" in proc.stdout, proc.stdout
    else:
        assert "DEFERRED —" in proc.stdout, proc.stdout
    if case.startswith("uploaded-at"):
        # The clock is read before partner is asked, so a broken stamp costs no partner GET.
        assert ("partner", AHEAD) not in registries_queried(calls), registries_queried(calls)
        assert garbage not in out and garbage[:19] not in out, out
    assert "Traceback" not in out and STUB_TOKEN not in out, out


@pytest.mark.parametrize(
    ("newest", "declared", "expected"),
    [
        ("drift", "clean", 1),
        ("drift", "deferred", 1),
        ("drift", "warned", 1),
        ("drift", "drift", 1),
        ("drift", "suppressed", 1),
        ("fault", "drift", 1),
        ("fault", "clean", 2),
        ("fault", "deferred", 2),
        ("fault", "warned", 2),
        ("fault", "suppressed", 2),
    ],
)
def test_the_d3_exit_table_row_by_row(
    tmp_path: Path, newest: str, declared: str, expected: int
) -> None:
    """#253 acceptance 5. A newest drift is 1 beside ANY declared state, a suppressed one included
    (the suppression is the declared version's, not the newest's). A newest fault keeps an
    unsuppressed declared drift's 1 and prints the error beside it; with no such finding, the fault
    is the news: 2."""
    git_age = {"clean": 14400, "deferred": 10, "warned": 200, "drift": 14400, "suppressed": 14400}
    now = LANDED + timedelta(minutes=git_age[declared])
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, calls = newest_stub(
        tmp_path,
        now=now,
        declared_served=declared == "clean",
        ahead_minutes_ago=14400,
        unscoped=[] if newest == "fault" else None,
    )
    if declared == "suppressed":
        _, gh_log = gh_stub(
            tmp_path, [(7, "CLOSED", [SUPPRESSION_LABEL], DRIFT_TITLE.format(version=DRIFTING))]
        )
        env = report_env(bin_dir, token=STUB_TOKEN)
        proc = run(repo, None, tmp_path, now=now, extra=["--report"], env=env)
        assert "SUPPRESSED by #7" in proc.stdout, proc.stdout
        # One listing, shared. The suppression is the DECLARED version's, so a newest drift is
        # still filed — under AHEAD's partner title — and a newest fault files nothing. (Flipped
        # in Phase 2 from "files nothing" for the newest-drift row.)
        if newest == "drift":
            assert_filed_newest_only(gh_log, AHEAD)
        else:
            assert gh_calls(gh_log) == [issue_list_argv(), heartbeat_argv()], gh_calls(gh_log)
    else:
        proc = run(repo, None, tmp_path, now=now, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == expected, out
    declared_marker = {
        "clean": "OK — the registry serves",
        "deferred": "DEFERRED — npm, python missing",
        "warned": f"::warning::seam-sdk {DRIFTING} is not on the registry",
        "drift": "DRIFT — seam-sdk",
        "suppressed": "DRIFT — seam-sdk",
    }[declared]
    assert declared_marker in out, out
    if newest == "drift":
        assert "NEWEST DRIFT —" in proc.stdout, proc.stdout
        assert NEWEST_FAULT not in proc.stderr
    else:
        assert NEWEST_FAULT in proc.stderr, out
        assert "NEWEST DRIFT" not in proc.stdout
    assert STUB_TOKEN not in out


@pytest.mark.parametrize("fault", ["canaries-empty", "http-failure"])
def test_a_partner_fault_leaves_the_newest_question_not_checked(
    tmp_path: Path, fault: str
) -> None:
    """#253 acceptance 6. The newest question asks partner, so a partner that could not be read
    cannot answer it: NOT CHECKED, and neither the unscoped GET nor a partner GET at the newest
    version is made. Exact sequences, so a newest GET anywhere in them is visible."""
    repo = make_repo(tmp_path, version=DRIFTING)
    full = {ROSTER[0]: published(ROSTER[0]), DRIFTING: published(DRIFTING), AHEAD: published(AHEAD)}
    if fault == "canaries-empty":
        bin_dir, calls = curl_stub(tmp_path, full, partner_responses={DRIFTING: published(DRIFTING)})
        partner_asked = [("partner", c) for c in ROSTER]
    else:
        bin_dir, calls = curl_stub(tmp_path, full, partner_fail_with=22)
        partner_asked = [("partner", ROSTER[0])]
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    assert registries_queried(calls) == [
        ("internal", ROSTER[0]),
        ("internal", DRIFTING),
        *partner_asked,
    ]
    assert "newest on internal: NOT CHECKED (partner could not be read)" in proc.stdout
    assert NEWEST_FAULT not in proc.stderr, "one dead partner credential reported twice"
    assert STUB_TOKEN not in out


def test_offline_without_a_partner_dump_leaves_the_newest_question_not_checked(
    tmp_path: Path,
) -> None:
    """#253 acceptance 7a. Offline, partner is known only through its dump; without one there is
    no partner to ask about any version."""
    repo = make_repo(tmp_path, version=DRIFTING)
    proc = run(repo, published(DRIFTING) + published(AHEAD), tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (
        "newest on internal: NOT CHECKED (offline run without --partner-packages-json)"
        in proc.stdout
    )


def test_offline_the_newest_version_does_not_depend_on_the_dumps_order(tmp_path: Path) -> None:
    """#253 acceptance 7b. Offline there is no server sort to prove, so the newest version must be
    the numeric max, whatever order the dump is in. Run end to end on the sorted dump and on its
    reverse, and the newest line must be identical — and must be the numeric max, not the lexical
    one (`0.7.100` > `0.7.80`)."""
    internal = published("0.7.100") + published(AHEAD) + published(DRIFTING) + published("0.7.9")
    lines = []
    for order, dump in (("sorted", internal), ("reversed", list(reversed(internal)))):
        (tmp_path / order).mkdir()
        repo = make_repo(tmp_path / order, version=DRIFTING)
        proc = run(
            repo, dump, tmp_path / order, extra=_partner_dump(tmp_path / order, internal)
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        lines.append([ln for ln in proc.stdout.splitlines() if ln.startswith("newest on internal")])
    assert lines[0] == lines[1], lines
    assert lines[0][0].startswith("newest on internal: 0.7.100, uploaded"), lines


def test_offline_non_plain_versions_are_set_aside_counted_and_never_printed(
    tmp_path: Path,
) -> None:
    """#253 acceptance 7c. A pre-release and a field that is not a version at all are both
    excluded from "newest" — the pre-release would otherwise win, `0.8.0-rc.1` beating 0.7.80 —
    and both are counted, never echoed."""
    internal = (
        published(DRIFTING)
        + published(AHEAD)
        + rows(("seam-sdk", "0.8.0-rc.1", "python"), ("@zer07labs/seam-sdk", "0.8.0-rc.1", "npm"))
        + rows(("seam-sdk", "tok=" + STUB_TOKEN, "python"))
    )
    repo = make_repo(tmp_path, version=DRIFTING)
    proc = run(repo, internal, tmp_path, extra=_partner_dump(tmp_path, internal))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert f"newest on internal: {AHEAD} (2 non-version value(s) set aside), uploaded" in out, out
    assert "0.8.0-rc.1" not in out and STUB_TOKEN not in out, out


def test_newest_complete_version_is_order_blind_and_wants_both_formats() -> None:
    """The pure core, every clause at once: numeric max, both formats required, `exclude` honoured,
    non-plain counted (a trailing newline included — `fullmatch`, not `match`), and the answer
    invariant under every permutation tried."""
    import itertools

    fn = _SCRIPT_MODULE.newest_complete_version
    data = (
        published("0.7.9")
        + rows(("seam-sdk", "0.7.200", "python"))  # half a release: never newest
        + published("0.7.100")
        + rows(("seam-sdk", "0.7.300\n", "python"), ("@zer07labs/seam-sdk", "0.7.300\n", "npm"))
    )
    for perm in itertools.islice(itertools.permutations(data), 0, 5040, 37):
        assert fn(list(perm)) == ("0.7.100", 1)
    assert fn(data, exclude="0.7.100") == ("0.7.9", 1)
    assert fn(rows(("seam-sdk", "0.7.9", "python"))) == (None, 0)


@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        ("2026-10-11T04:43:28.896556Z", True),  # exactly as observed on 2026-10-12
        ("2026-10-11T04:43:28Z", True),
        ("2026-10-11T06:43:28.896556+02:00", True),
        ("2026-10-11T04:43:28.896556", False),  # naive: no instant at all
        ("2026-10-11 04:43:28Z", False),
        (" 2026-10-11T04:43:28Z", False),
        ("2026-10-11T04:43:28Z\n", False),
        ("2026-13-11T04:43:28Z", False),
        (1760157808, False),
        (None, False),
    ],
)
def test_an_upload_stamp_is_parsed_strictly_and_never_echoed(value: object, accepted: bool) -> None:
    """`_parse_upload_stamp` accepts the observed format and its offset spelling, refuses anything
    else, and its refusal never carries the value — the field is response content (D8)."""
    parse = _SCRIPT_MODULE._parse_upload_stamp
    if accepted:
        assert parse(value) == datetime(2026, 10, 11, 4, 43, 28, 896556 if "." in value else 0,
                                        tzinfo=timezone.utc)
        return
    with pytest.raises(_SCRIPT_MODULE.InfraError) as raised:
        parse(value)
    message = str(raised.value)
    if isinstance(value, str) and value.strip():
        assert value.strip() not in message and value.strip()[:10] not in message, message
    # Never chained to a ValueError whose message would quote the value.
    assert raised.value.__cause__ is None


@pytest.mark.parametrize(
    ("body", "code", "needle"),
    [
        (["X-Api-Key: " + STUB_TOKEN], 2, "not an object"),
        (
            [{"name": "seam-sdk", "version": "tok=" + STUB_TOKEN, "format": "python",
              "uploaded_at": UPLOADED}] + published(DRIFTING) + published(ROSTER[0]),
            0,
            f"newest on internal: {DRIFTING} (1 non-version value(s) set aside)",
        ),
        (published(AHEAD, uploaded_at="X-Api-Key: " + STUB_TOKEN) + published(DRIFTING), 2,
         "value withheld"),
        (b"\xff X-Api-Key: " + STUB_TOKEN.encode() + b" \xfe", 2, "is not JSON"),
    ],
    ids=["string-row", "version-field", "uploaded-at", "non-utf8"],
)
def test_a_hostile_unscoped_body_is_diagnosed_without_being_echoed(
    tmp_path: Path, body: object, code: int, needle: str
) -> None:
    """#253 acceptance 8, the unscoped fetch. The token planted in each place a response can carry
    it — a string row, a version field, `uploaded_at`, a body that is not even UTF-8 — and in none
    of them may it reach the output. Declared is clean, so a 2 here is the newest fault alone."""
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, _ = newest_stub(tmp_path, now=LANDED + timedelta(days=10), unscoped=body)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == code, out
    assert needle in out, out
    assert STUB_TOKEN not in out, out
    assert "Traceback" not in out and "UnicodeDecodeError" not in out, out


@pytest.mark.parametrize(
    ("body", "code", "needle"),
    [
        (["X-Api-Key: " + STUB_TOKEN], 2, "not an object"),
        (
            [{"name": "seam-sdk", "version": "tok=" + STUB_TOKEN, "format": "python"}],
            2,
            "1 non-version value(s)",
        ),
        # Partner's `uploaded_at` is never read — the clock is internal's — so a hostile one is
        # inert: partner serves the version, and the run is clean with nothing echoed.
        (published(AHEAD, uploaded_at="X-Api-Key: " + STUB_TOKEN), 0, f"NEWEST CLEAN — partner "
         f"serves {AHEAD}"),
        (b"\xff X-Api-Key: " + STUB_TOKEN.encode() + b" \xfe", 2, "the response from partner to"),
    ],
    ids=["string-row", "version-field", "uploaded-at", "non-utf8"],
)
def test_a_hostile_partner_body_at_the_newest_version_is_diagnosed_without_being_echoed(
    tmp_path: Path, body: object, code: int, needle: str
) -> None:
    """#253 acceptance 8, the newest-partner fetch: the same four plantings, in partner's answer
    about the newest version."""
    now = LANDED + timedelta(days=10)
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, calls = newest_stub(tmp_path, now=now, ahead_minutes_ago=14400, partner_ahead=body)
    proc = run(repo, None, tmp_path, now=now, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == code, out
    assert needle in out, out
    assert registries_queried(calls)[-1] == ("partner", AHEAD), registries_queried(calls)
    assert STUB_TOKEN not in out, out
    assert "Traceback" not in out and "UnicodeDecodeError" not in out, out


@pytest.mark.parametrize(
    "path",
    ["skipped", "clean", "deferred", "warned", "drift", "fault", "not-checked", "offline"],
)
def test_the_credential_never_appears_on_any_newest_path(tmp_path: Path, path: str) -> None:
    """#253 acceptance 8, swept: every way the newest question can end, each grepped for the
    token. The certificate line, the newest line and each tier's message are all new prints, and
    the sweep over the declared question's paths above covers none of them."""
    now = LANDED + timedelta(days=10)
    repo = make_repo(tmp_path, version=DRIFTING)
    extra: list[str] = []
    marker = {
        "skipped": "the declared version, answered above",
        "clean": "NEWEST CLEAN —",
        "deferred": "NEWEST DEFERRED —",
        "warned": f"::warning::seam-sdk {AHEAD}, the newest version on internal",
        "drift": "NEWEST DRIFT —",
        "fault": "COULD NOT BE READ",
        "not-checked": "NOT CHECKED (partner could not be read)",
        "offline": "newest on internal: 0.7.80",
    }[path]
    if path == "skipped":
        bin_dir, _ = newest_stub(tmp_path, now=now)
    elif path == "clean":
        bin_dir, _ = newest_stub(
            tmp_path, now=now, ahead_minutes_ago=14400, partner_ahead=published(AHEAD)
        )
    elif path in ("deferred", "warned", "drift"):
        ago = {"deferred": 30, "warned": 200, "drift": 14400}[path]
        bin_dir, _ = newest_stub(tmp_path, now=now, ahead_minutes_ago=ago)
    elif path == "fault":
        bin_dir, _ = newest_stub(tmp_path, now=now, unscoped=[])
    elif path == "not-checked":
        bin_dir, _ = curl_stub(
            tmp_path, {ROSTER[0]: published(ROSTER[0]), DRIFTING: published(DRIFTING)},
            partner_fail_with=22,
        )
    else:
        bin_dir, _ = curl_stub(tmp_path, {})
        dump = published(DRIFTING) + published(AHEAD)
        extra = ["--packages-json", str(tmp_path / "dump.json"), *_partner_dump(tmp_path, dump)]
        (tmp_path / "dump.json").write_text(json.dumps(dump), "utf-8")
    proc = run(repo, None, tmp_path, now=now, extra=extra, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert marker in out, f"{path}: not exercising the branch it names\n{out}"
    assert STUB_TOKEN not in out, f"{path}: the token leaked"


def test_an_unexpected_newest_exception_is_captured_by_class_name_only(tmp_path: Path) -> None:
    """The newest block's catch-all, driven for real: a pathologically nested unscoped body raises
    RecursionError inside `json.loads`, not an InfraError. Captured, the declared verdict stands and
    the line carries the class name and nothing else."""
    repo = make_repo(tmp_path, version=DRIFTING)
    nested = "[" * 200_000 + "]" * 200_000
    bin_dir, _ = newest_stub(tmp_path, now=LANDED + timedelta(days=10), unscoped=nested)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert f"OK — the registry serves {DRIFTING}" in proc.stdout, proc.stdout
    assert re.search(
        r"unexpected failure answering the newest-version question: RecursionError$",
        proc.stderr,
        re.MULTILINE,
    ), proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr


def test_the_exit_composition_is_the_d3_table_as_a_unit() -> None:
    """`_with_newest` alone, over every input it can see — the end-to-end table above reaches it
    only through the cases that can be staged."""
    compose = _SCRIPT_MODULE._with_newest
    fault = _SCRIPT_MODULE.InfraError("x")
    for code in (0, 1, 2):
        assert compose(code, "drift", None) == 1
        assert compose(code, None, fault) == (1 if code == 1 else 2)
        for quiet in (None, "deferred", "warned"):
            assert compose(code, quiet, None) == code


# ── #253 Phase 1, verifier gaps: the clock, the page edge, skew, --report, git faults, offline ────


@pytest.mark.parametrize("later", ["npm", "python"])
def test_the_newest_clock_is_the_latest_required_upload_not_the_earliest(
    tmp_path: Path, later: str
) -> None:
    """D2's "latest". The release is complete only when its LAST format lands, so that is when
    `promote-partner` can start. One format uploaded 14400 minutes ago and the other 30: the tier
    must be DEFERRED (30). The earliest would say DRIFT. Both orders, so "whichever row comes last"
    cannot pass for "latest"."""
    now = LANDED + timedelta(days=10)
    early, late = upload_stamp(now - timedelta(minutes=14400)), upload_stamp(now - timedelta(minutes=30))
    ahead = [
        {"name": "seam-sdk", "version": AHEAD, "format": "python",
         "uploaded_at": late if later == "python" else early},
        {"name": "@zer07labs/seam-sdk", "version": AHEAD, "format": "npm",
         "uploaded_at": late if later == "npm" else early},
    ]
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, _ = newest_stub(tmp_path, now=now, ahead_rows=ahead)
    proc = run(repo, None, tmp_path, now=now, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "NEWEST DEFERRED —" in proc.stdout and "NEWEST DRIFT" not in proc.stdout, out
    assert f"newest on internal: {AHEAD}, uploaded 30 minutes ago" in proc.stdout, out


def test_a_format_this_release_does_not_ship_never_feeds_the_clock(tmp_path: Path) -> None:
    """The clock's format filter. A `cargo` row at the newest version uploaded 30 minutes ago is
    not part of this release; the python and npm rows, 14400 minutes old, are. DRIFT, not DEFERRED.
    """
    now = LANDED + timedelta(days=10)
    ahead = published(AHEAD, uploaded_at=upload_stamp(now - timedelta(minutes=14400))) + rows(
        ("seam-sdk", AHEAD, "cargo"), uploaded_at=upload_stamp(now - timedelta(minutes=30))
    )
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, _ = newest_stub(tmp_path, now=now, ahead_rows=ahead)
    proc = run(repo, None, tmp_path, now=now, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "NEWEST DRIFT —" in proc.stdout, out
    assert f"newest on internal: {AHEAD}, uploaded 14400 minutes ago" in proc.stdout, out


def test_the_page_edge_excludes_the_LOWEST_version_and_still_chooses_the_highest(
    tmp_path: Path,
) -> None:
    """A full page holding two versions: `AHEAD` on top, `DRIFTING` filling the rest down to the
    edge. The edge is the lowest — `DRIFTING`, which may continue onto the next page — and the
    newest is `AHEAD`, which is whole. Excluding the HIGHEST instead would make the newest the
    declared version and silently skip the question."""
    page = published(AHEAD) + [
        row for _ in range((_SCRIPT_MODULE.PAGE_SIZE - 2) // 2) for row in published(DRIFTING)
    ]
    assert len(page) == _SCRIPT_MODULE.PAGE_SIZE
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, calls = newest_stub(tmp_path, now=LANDED + timedelta(days=10), unscoped=page)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert f"newest on internal: {AHEAD}, uploaded" in proc.stdout, out
    assert registries_queried(calls)[-1] == ("partner", AHEAD), registries_queried(calls)


def test_a_response_longer_than_the_page_is_still_a_page_with_an_edge(tmp_path: Path) -> None:
    """`>=`, not `==`. A server that ignored `page_size` and sent 51 rows cut its answer at a size
    nobody asked for, and its lowest version is no more trustworthy than at 50. Fifty-one rows of
    one version has no candidate above the edge: exit 2."""
    page = _full_page_of_one_version() + published(DRIFTING)[:1]
    assert len(page) == _SCRIPT_MODULE.PAGE_SIZE + 1
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, _ = newest_stub(tmp_path, now=LANDED + timedelta(days=10), unscoped=page)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    assert f"{DRIFTING} is the lowest version on a full page" in proc.stderr, out


@pytest.mark.parametrize(
    ("ahead_by", "expected"),
    [(3, 0), (5, 0), (6, 2)],
    ids=["jitter", "at-the-tolerance", "past-the-tolerance"],
)
def test_an_upload_stamp_slightly_in_the_future_is_jitter_and_further_is_a_fault(
    tmp_path: Path, ahead_by: int, expected: int
) -> None:
    """The newest clock's skew guard, at its boundary. Up to `CLOCK_SKEW_TOLERANCE_MINUTES` (5) in
    the future is NTP jitter: clamped to zero minutes, so a lag reads as DEFERRED. One minute past
    it is a clock that cannot be trusted: exit 2, never a silent defer."""
    assert _SCRIPT_MODULE.CLOCK_SKEW_TOLERANCE_MINUTES == 5
    now = LANDED + timedelta(days=10)
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, _ = newest_stub(
        tmp_path,
        now=now,
        ahead_rows=published(AHEAD, uploaded_at=upload_stamp(now + timedelta(minutes=ahead_by))),
    )
    proc = run(repo, None, tmp_path, now=now, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == expected, out
    if expected == 0:
        assert f"newest on internal: {AHEAD}, uploaded 0 minutes ago" in proc.stdout, out
        assert "NEWEST DEFERRED —" in proc.stdout, out
    else:
        assert NEWEST_FAULT in proc.stderr and f"{ahead_by} minutes AFTER now" in proc.stderr, out


def test_the_order_check_reads_every_row_not_only_seam_sdk_rows(tmp_path: Path) -> None:
    """The judgement call, pinned: `sort=-version` orders the WHOLE response, so a row of another
    package out of order is as much evidence the sort was ignored as a `seam-sdk` row would be.
    Checking only `seam-sdk` rows would accept this page and answer from it."""
    page = (
        published(AHEAD)
        + rows(("other-thing", "9.9.9", "python"))
        + published(DRIFTING)
        + published(ROSTER[0])
    )
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, _ = newest_stub(tmp_path, now=LANDED + timedelta(days=10), unscoped=page)
    proc = run(repo, None, tmp_path, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    assert f"({AHEAD} is followed by 9.9.9)" in proc.stderr, out


def assert_filed_newest_only(log: Path, version: str) -> None:
    """The exact `gh` sequence of a run whose ONLY GitHub business is filing a newest drift for
    `version`: one listing, one create under V's partner title, the heartbeat. Nothing else."""
    calls = gh_calls(log)
    assert [c[:2] for c in calls] == [["issue", "list"], ["issue", "create"], ["api", calls[-1][1]]], calls
    assert calls[0] == issue_list_argv(), calls[0]
    assert calls[1][2:4] == ["--title", PARTNER_DRIFT_TITLE.format(version=version)], calls[1]
    assert calls[1][-2:] == ["--repo", STUB_REPO] and len(calls[1]) == 8, calls[1]
    assert calls[2] == heartbeat_argv(), calls[2]


# ── --report: a newest finding is filed (Phase 2; these were Phase 1's "files nothing" tests) ──


def test_with_report_a_newest_drift_beside_a_clean_declared_files_one_partner_issue(
    tmp_path: Path,
) -> None:
    """Exit 1 for the newest drift, and its issue filed: one listing (shared with the clean
    declared question), one create under the NEWEST version's partner title, the heartbeat.

    Flipped in Phase 2 from "...files_nothing", which pinned [list, heartbeat] as the interim."""
    now = LANDED + timedelta(days=10)
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, _ = newest_stub(tmp_path, now=now, ahead_minutes_ago=14400)
    _, gh_log = gh_stub(tmp_path, [])
    proc = run(repo, None, tmp_path, now=now, extra=["--report"],
               env=report_env(bin_dir, token=STUB_TOKEN))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "NEWEST DRIFT —" in proc.stdout, out
    assert_filed_newest_only(gh_log, AHEAD)


@pytest.mark.parametrize(
    ("declared_minutes", "newest_ago", "expected"),
    [
        (10, 14400, 1),
        (200, 14400, 1),
        (10, 30, 0),
        (10, 200, 0),
        (200, 30, 0),
        (200, 200, 0),
    ],
    ids=[
        "declared-deferred+newest-drift",
        "declared-warned+newest-drift",
        "declared-deferred+newest-deferred",
        "declared-deferred+newest-warned",
        "declared-warned+newest-deferred",
        "declared-warned+newest-warned",
    ],
)
def test_with_report_a_declared_grace_tier_reaches_github_only_for_a_newest_drift(
    tmp_path: Path, declared_minutes: int, newest_ago: int, expected: int
) -> None:
    """Grace is per question, live. With the declared version in a grace tier it contributes no
    read; a newest version in ITS grace adds none either, so those runs make no `gh` call at all.
    A newest DRIFT is a finding of its own and files it: exactly list, create, heartbeat.

    Flipped in Phase 2 from "...reaches_no_github_whatever_the_newest_says", whose two
    newest-drift cases pinned zero gh calls as the interim."""
    now = LANDED + timedelta(minutes=declared_minutes)
    repo = make_repo(tmp_path, version=DRIFTING)
    bin_dir, _ = newest_stub(
        tmp_path, now=now, declared_served=False, ahead_minutes_ago=newest_ago
    )
    _, gh_log = gh_stub(tmp_path, [])
    proc = run(repo, None, tmp_path, now=now, extra=["--report"],
               env=report_env(bin_dir, token=STUB_TOKEN))
    out = proc.stdout + proc.stderr
    assert proc.returncode == expected, out
    assert f"newest on internal: {AHEAD}, uploaded {newest_ago} minutes ago" in proc.stdout, out
    if newest_ago == 14400:
        assert_filed_newest_only(gh_log, AHEAD)
    else:
        assert gh_calls(gh_log) == [], gh_calls(gh_log)


# ── The two named invariants, re-run on paths where the newest question is CHECKED ─────────────


@pytest.mark.parametrize("newest_ago", [30, 200, 14400], ids=["deferred", "warned", "drift"])
@pytest.mark.parametrize(
    ("age", "band", "marker"),
    [(10, "soft", "DEFERRED"), (200, "warn", "::warning::")],
)
def test_neither_grace_tier_touches_github_with_the_newest_question_checked(
    tmp_path: Path, age: int, band: str, marker: str, newest_ago: int
) -> None:
    """`test_neither_grace_tier_touches_github`, offline WITH a partner dump, so the newest
    question is asked (0.7.77, which partner lacks) and lands on each of its own tiers. Grace on
    the declared version contributes no `gh` call of any kind; a newest version in its own grace
    adds none. A newest DRIFT files for itself — exactly list, create, heartbeat — and that is the
    only way GitHub is reached (the drift case flipped in Phase 2 from zero calls)."""
    now = LANDED + timedelta(minutes=age)
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    internal = published("0.7.77", uploaded_at=upload_stamp(now - timedelta(minutes=newest_ago)))
    proc, log = report_run(
        repo,
        internal,
        tmp_path,
        listing=[],
        now=now,
        extra=_partner_dump(tmp_path, published("0.7.76")),
    )
    assert proc.returncode == (1 if newest_ago == 14400 else 0), proc.stdout + proc.stderr
    assert marker in proc.stdout, f"the {band} tier did not announce itself:\n{proc.stdout}"
    assert f"newest on internal: 0.7.77, uploaded {newest_ago} minutes ago" in proc.stdout
    if newest_ago == 14400:
        assert_filed_newest_only(log, "0.7.77")
    else:
        assert gh_calls(log) == [], f"the {band} tier called GitHub: {gh_calls(log)}"


@pytest.mark.parametrize(
    ("declared_served", "newest_served"),
    [(False, True), (False, False), (True, True), (True, False)],
    ids=["drift+newest-clean", "drift+newest-drift", "clean+newest-clean", "clean+newest-drift"],
)
def test_one_listing_answers_every_question_with_the_newest_question_checked(
    tmp_path: Path, declared_served: bool, newest_served: bool
) -> None:
    """`test_one_listing_answers_every_question_the_run_asks`, offline WITH a partner dump, so a
    third question — the newest version — is answered in the same run. Still exactly one
    `gh issue list`, whichever way each question comes out."""
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    internal = published(AHEAD) + (published(DRIFTING) if declared_served else [])
    partner = published(DRIFTING) + (published(AHEAD) if newest_served else [])
    proc, log = report_run(
        repo,
        internal,
        tmp_path,
        listing=drift_listing(42, "OPEN", []),
        extra=_partner_dump(tmp_path, partner),
    )
    out = proc.stdout + proc.stderr
    assert f"newest on internal: {AHEAD}, uploaded" in proc.stdout, out
    assert ("NEWEST DRIFT —" in proc.stdout) is (not newest_served), out
    assert gh_verbs(log).count("issue list") == 1, gh_verbs(log)


# ── A declared-clock fault must not swallow a newest answer already computed ───────────────────


@pytest.mark.parametrize(
    ("newest", "expected", "marker"),
    [("drift", 1, "NEWEST DRIFT —"), ("clean", 2, "NEWEST CLEAN —"), ("fault", 2, NEWEST_FAULT)],
)
def test_a_git_clock_fault_still_prints_the_newest_answer_and_exits_by_d3(
    tmp_path: Path, newest: str, expected: int, marker: str
) -> None:
    """A checkout without tags makes the DECLARED clock unreadable (exit 2) — but by then the
    newest question has been answered on the upload clock, which git does not touch. Its answer
    is printed, and the exit follows D3 with the declared question at 2: a newest drift is a real
    finding and keeps 1; a clean or failed newest leaves the 2."""
    now = LANDED + timedelta(days=10)
    repo = make_repo(tmp_path, version=DRIFTING, filler_tags=0, tag=False)
    if newest == "fault":
        bin_dir, _ = newest_stub(tmp_path, now=now, unscoped=[])
    else:
        bin_dir, _ = newest_stub(
            tmp_path,
            now=now,
            ahead_minutes_ago=14400,
            partner_ahead=published(AHEAD) if newest == "clean" else None,
        )
    proc = run(repo, None, tmp_path, now=now, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == expected, out
    assert "below TAG_FLOOR" in proc.stderr, out
    assert marker in out, out
    if newest != "fault":
        assert f"newest on internal: {AHEAD}, uploaded 14400 minutes ago" in proc.stdout, out
    assert "Traceback" not in out and STUB_TOKEN not in out, out


def test_a_git_clock_fault_never_claims_the_declared_question_was_answered(tmp_path: Path) -> None:
    """Newest IS the declared version (the skip), and git fails: the declared question has no
    answer, so the newest line must not say "answered above" — it says it was not answered."""
    now = LANDED + timedelta(days=10)
    repo = make_repo(tmp_path, version=DRIFTING, filler_tags=0, tag=False)
    bin_dir, _ = newest_stub(tmp_path, now=now)
    proc = run(repo, None, tmp_path, now=now, env=live_env(bin_dir))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    assert "below TAG_FLOOR" in proc.stderr, out
    assert f"newest on internal: {DRIFTING} — the declared version, not answered (git failed)" in (
        proc.stdout
    ), out
    assert "answered above" not in out, out


# ── Offline: the dump must carry `uploaded_at` for the newest question ──────────────────────────


def test_an_offline_dump_without_uploaded_at_is_refused_naming_the_file(tmp_path: Path) -> None:
    """Exit 2 — a clock that cannot be read is never a defer — and the refusal says WHICH file and
    WHAT it needs, because offline the fix is the operator's: re-capture keeping the field."""
    repo = make_repo(tmp_path, version=DRIFTING)
    internal = [
        {k: v for k, v in row.items() if k != "uploaded_at"}
        for row in published(AHEAD) + published(DRIFTING)
    ]
    proc = run(repo, internal, tmp_path, extra=_partner_dump(tmp_path, published(DRIFTING)))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    dump = tmp_path / "packages.json"
    assert f"--packages-json {dump} must keep each row's `uploaded_at`" in proc.stderr, out
    assert f"OK — the registry serves {DRIFTING}" in proc.stdout, out


def test_the_offline_help_says_the_newest_question_needs_uploaded_at() -> None:
    """The help text is where an operator capturing a dump finds out what it must keep."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    # One block per option: argparse starts each at a line beginning `  --`, and continuation
    # lines are indented further, so a mention of another flag inside a help text cannot end it.
    blocks: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if line.startswith("  --"):
            current = line.split()[0]
            blocks[current] = line
        elif line.startswith("   ") and blocks:
            blocks[current] += " " + line.strip()
    for flag in ("--packages-json", "--partner-packages-json"):
        assert "uploaded_at" in blocks.get(flag, ""), f"{flag}: {blocks.get(flag)!r}"


# ── #253 Phase 2: reporting a newest-version lag ───────────────────────────────────────────────
#
# A newest drift files, comments and reopens under `PARTNER_DRIFT_TITLE.format(V)` — the same
# title the declared question would use for V, so there is one issue per missing version whichever
# question finds it (D4). One listing per run, fetched lazily and shared; the heartbeat whenever
# GitHub was read, except a gh failure on a drift path, which exits 2 first; a newest clean's close
# notice only from a listing the declared question fetched.

#: The suppression issue every "declared drift is suppressed" fixture carries.
DECLARED_SUPPRESSED = (7, "CLOSED", [SUPPRESSION_LABEL], DRIFT_TITLE.format(version=DRIFTING))


def newest_report_run(
    tmp_path: Path,
    *,
    declared: str = "clean",
    newest: str = "drift",
    listing: list[tuple[int, str, list[str], str]] | None = None,
    fail_on: tuple[str, str] | None = None,
    fail_create_titled: str | None = None,
    tag_newest: bool = False,
    filler_tags: int = FILLER_TAGS,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """A live `--report` run with curl and gh stubbed in one bin dir.

    `declared`: clean (served, two weeks old), drift / suppressed (absent, two weeks old; the
    latter with `DECLARED_SUPPRESSED` in the listing), deferred / warned (absent, 10 / 200 minutes).
    `newest`: drift (AHEAD on internal 14400 minutes ago, absent from partner), clean (partner
    serves AHEAD), deferred (AHEAD uploaded 30 minutes ago, absent from partner)."""
    git_age = {"clean": 14400, "drift": 14400, "suppressed": 14400, "deferred": 10, "warned": 200}
    now = LANDED + timedelta(minutes=git_age[declared])
    repo = make_repo(tmp_path, version=DRIFTING, tag=filler_tags > 0, filler_tags=filler_tags)
    if tag_newest:
        _git(repo, "tag", "-a", f"v{AHEAD}", "-m", f"v{AHEAD}", when=LANDED)
    bin_dir, _ = newest_stub(
        tmp_path,
        now=now,
        declared_served=declared == "clean",
        ahead_minutes_ago=30 if newest == "deferred" else 14400,
        partner_ahead=published(AHEAD) if newest == "clean" else None,
    )
    full_listing = list(listing or [])
    if declared == "suppressed":
        full_listing.append(DECLARED_SUPPRESSED)
    _, gh_log = gh_stub(
        tmp_path, full_listing, fail_on=fail_on, fail_create_titled=fail_create_titled
    )
    proc = run(
        repo, None, tmp_path, now=now, extra=["--report"], env=report_env(bin_dir, token=STUB_TOKEN)
    )
    return proc, gh_log


def newest_partner_listing(number: int, state: str, labels: list[str]):
    return [(number, state, labels, PARTNER_DRIFT_TITLE.format(version=AHEAD))]


def test_a_suppressed_declared_drift_beside_a_newest_lag_files_the_newest_issue(
    tmp_path: Path,
) -> None:
    """#253 Phase 2 acceptance 1. The declared version's suppression is its own; the newest lag is
    a separate version's finding: one listing, one create under V's partner title whose body names
    V and D and carries State P for V, then the heartbeat, and exit 1."""
    proc, log = newest_report_run(tmp_path, declared="suppressed", newest="drift")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "SUPPRESSED by #7" in proc.stdout, out
    assert_filed_newest_only(log, AHEAD)
    body = gh_flag(log, "issue create", "--body")
    assert body.startswith(
        f"`zer07labs/internal`'s newest release is **{AHEAD}**"
    ), body
    assert f"declares **{DRIFTING}**" in body, body
    assert "found by the newest-version check" in body, body
    assert f"| found by | the newest-version check (main declares `{DRIFTING}`) |" in body, body
    assert f"State P — internal serves {AHEAD}" in body, body
    assert f"./scripts/promote-to-partner.sh {AHEAD}" in body, body
    assert "| time since it finished uploading to internal | 14400 minutes |" in body, body
    assert STUB_TOKEN not in out


def test_an_open_partner_issue_for_the_newest_version_gets_no_write(tmp_path: Path) -> None:
    """#253 Phase 2 acceptance 2. The partner issue for V is open — filed earlier by the declared
    question, when `main` still declared V. Same title, so it is recognised: no write, exit 1."""
    proc, log = newest_report_run(tmp_path, listing=newest_partner_listing(11, "OPEN", []))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert gh_calls(log) == [issue_list_argv(), heartbeat_argv()], gh_calls(log)
    assert "drift already reported on #11" in proc.stdout, out


@pytest.mark.parametrize(
    ("labels", "expected", "writes"),
    [([SUPPRESSION_LABEL], 0, []), ([], 1, ["comment", "reopen"])],
    ids=["closed-labelled", "closed-unlabelled"],
)
def test_a_closed_partner_issue_for_the_newest_version_walks_the_decision_table(
    tmp_path: Path, labels: list[str], expected: int, writes: list[str]
) -> None:
    """#253 Phase 2 acceptance 3. Closed and labelled on V's partner title: suppressed, a
    `::warning::` naming it, exit 0 (the suppression is V's, so the drift no longer votes). Closed
    and unlabelled: comment THEN reopen, in that order, with the newest body, exit 1."""
    proc, log = newest_report_run(tmp_path, listing=newest_partner_listing(11, "CLOSED", labels))
    out = proc.stdout + proc.stderr
    assert proc.returncode == expected, out
    calls = gh_calls(log)
    assert [c[1] for c in calls if c[0] == "issue" and c[1] != "list"] == writes, calls
    assert calls[0] == issue_list_argv() and calls[-1] == heartbeat_argv(), calls
    if labels:
        assert f"::warning::drift on {AHEAD} is SUPPRESSED by #11" in proc.stdout, out
        assert "Partner still does not serve" in proc.stdout, out
    else:
        assert [c[2] for c in calls if c[:2] in (["issue", "comment"], ["issue", "reopen"])] == [
            "11",
            "11",
        ], calls
        text = gh_flag(log, "issue comment", "--body")
        assert "found by the newest-version check" in text and f"**{AHEAD}**" in text, text


def test_a_declared_drift_and_a_newest_drift_share_one_listing_and_file_two_issues(
    tmp_path: Path,
) -> None:
    """#253 Phase 2 acceptance 4. Two versions, two findings, two titles — one listing, read once
    and shared, then the heartbeat once."""
    proc, log = newest_report_run(tmp_path, declared="drift", newest="drift")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    calls = gh_calls(log)
    assert [c[:2] for c in calls] == [
        ["issue", "list"],
        ["issue", "create"],
        ["issue", "create"],
        ["api", calls[-1][1]],
    ], calls
    assert calls[0] == issue_list_argv() and calls[-1] == heartbeat_argv(), calls
    assert [c[3] for c in calls[1:3]] == [
        DRIFT_TITLE.format(version=DRIFTING),
        PARTNER_DRIFT_TITLE.format(version=AHEAD),
    ], calls


@pytest.mark.parametrize("declared", ["deferred", "warned"])
@pytest.mark.parametrize(
    "open_partner_issue", [True, False], ids=["open-partner-issue-for-V", "no-issue"]
)
def test_a_declared_grace_tier_beside_a_newest_clean_makes_no_github_call(
    tmp_path: Path, declared: str, open_partner_issue: bool
) -> None:
    """#253 Phase 2 acceptance 5, the clean half (the drift half is
    `test_with_report_a_declared_grace_tier_reaches_github_only_for_a_newest_drift`). The declared
    question is in grace and the newest is clean: zero `gh` calls — even with an OPEN partner issue
    for V that a close notice could point at. A newest clean never lists for itself."""
    listing = newest_partner_listing(11, "OPEN", []) if open_partner_issue else []
    proc, log = newest_report_run(tmp_path, declared=declared, newest="clean", listing=listing)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "NEWEST CLEAN —" in proc.stdout, out
    assert gh_calls(log) == [], gh_calls(log)
    assert "can be closed" not in proc.stdout, out


def test_a_newest_clean_says_its_issue_can_be_closed_when_the_declared_question_listed(
    tmp_path: Path,
) -> None:
    """The other side of the guard: the declared question is clean, so it listed — and from that
    same listing an open partner issue for V gets the close notice. No write, one listing."""
    proc, log = newest_report_run(
        tmp_path, declared="clean", newest="clean", listing=newest_partner_listing(11, "OPEN", [])
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert f"::notice::#11 reports {AHEAD} missing from partner" in proc.stdout, out
    assert gh_calls(log) == [issue_list_argv(), heartbeat_argv()], gh_calls(log)


@pytest.mark.parametrize("newest", ["drift", "suppressed", "clean", "deferred"])
@pytest.mark.parametrize("declared", ["clean", "drift", "suppressed", "deferred"])
def test_exactly_one_listing_and_one_heartbeat_iff_github_was_read(
    tmp_path: Path, declared: str, newest: str
) -> None:
    """#253 Phase 2 acceptance 6, plus the heartbeat rule, over every combination of the two
    questions' GitHub-relevant states. A run reads GitHub iff the declared question is clean or a
    drift (suppressed included — it had to list to learn that) or the newest is a drift (likewise).
    When it does: exactly one listing and exactly one heartbeat. When it does not: no call at all."""
    listing = newest_partner_listing(12, "CLOSED", [SUPPRESSION_LABEL]) if newest == "suppressed" else []
    proc, log = newest_report_run(
        tmp_path,
        declared=declared,
        newest="drift" if newest == "suppressed" else newest,
        listing=listing,
    )
    out = proc.stdout + proc.stderr
    reads = declared in ("clean", "drift", "suppressed") or newest in ("drift", "suppressed")
    verbs = gh_verbs(log)
    assert verbs.count("issue list") == (1 if reads else 0), verbs
    assert verbs.count(heartbeat_verb()) == (1 if reads else 0), verbs
    if reads:
        assert verbs[0] == "issue list" and verbs[-1] == heartbeat_verb(), verbs
    expected = 1 if declared == "drift" or newest == "drift" else 0
    assert proc.returncode == expected, out


@pytest.mark.parametrize("outage", [("issue", "list"), ("issue", "create")], ids=["list", "create"])
def test_a_github_outage_beside_a_newest_drift_is_two_with_both_verdicts_printed(
    tmp_path: Path, outage: tuple[str, str]
) -> None:
    """#253 Phase 2 acceptance 7. GitHub fails while a newest drift is being delivered: exit 2 —
    a finding that could not be delivered is infrastructure, the declared drift's rule — and both
    verdicts are already in the log, because they are printed before anything is reported. The
    listing is never retried by a second question."""
    proc, log = newest_report_run(tmp_path, declared="clean", newest="drift", fail_on=outage)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    assert f"OK — the registry serves {DRIFTING} in both formats" in proc.stdout, out
    assert "NEWEST DRIFT —" in proc.stdout, out
    assert "503" in proc.stderr, out
    assert gh_verbs(log).count("issue list") == 1, gh_verbs(log)
    # The clean declared question's own outage warning is printed too when it was the listing.
    if outage == ("issue", "list"):
        # Reworded when a newest drift is pending: it must not promise a green run it won't have.
        assert "The newest-version drift above cannot be filed either" in proc.stdout, out
        assert "only the advisory notice is missing" not in proc.stdout, out


def test_a_listing_outage_with_only_clean_questions_stays_green(tmp_path: Path) -> None:
    """The contrast to acceptance 7: nothing to deliver, so a listing outage is a warning and the
    healthy run stays 0 — the declared clean path's rule, unchanged by the newest question."""
    proc, log = newest_report_run(
        tmp_path, declared="clean", newest="clean", fail_on=("issue", "list")
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert gh_verbs(log).count("issue list") == 1, gh_verbs(log)


def test_no_token_reaches_gh_and_the_gh_verbs_are_unchanged(tmp_path: Path) -> None:
    """#253 Phase 2 acceptance 8, on the widest reporting path: a declared drift filed, and a
    newest drift commented and reopened. No argv handed to `gh` carries the registry token, nor
    does any output; and every `gh` call is one of the verbs this check has always used — plus the
    one allowlisted read (`gh_writes` refuses any other `gh api`)."""
    proc, log = newest_report_run(
        tmp_path, declared="drift", newest="drift", listing=newest_partner_listing(11, "CLOSED", [])
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    calls = gh_calls(log)
    for call in calls:
        assert not any(STUB_TOKEN in arg for arg in call), call
    assert set(gh_writes(log)) <= {"issue create", "issue comment", "issue reopen"}, gh_writes(log)
    assert gh_writes(log) == ["issue create", "issue comment", "issue reopen"], gh_writes(log)
    assert STUB_TOKEN not in out


def test_a_suppression_is_scoped_to_its_own_version_and_title(tmp_path: Path) -> None:
    """Per-version suppression. Closed-and-labelled issues for every OTHER thing — the partner
    title of the DECLARED version, and the internal title of V — say nothing about V on partner.
    The newest drift is filed."""
    listing = [
        (21, "CLOSED", [SUPPRESSION_LABEL], PARTNER_DRIFT_TITLE.format(version=DRIFTING)),
        (22, "CLOSED", [SUPPRESSION_LABEL], DRIFT_TITLE.format(version=AHEAD)),
    ]
    proc, log = newest_report_run(tmp_path, listing=listing)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "SUPPRESSED" not in proc.stdout, out
    assert_filed_newest_only(log, AHEAD)


def test_a_declared_partner_lag_body_says_the_declared_question_found_it(tmp_path: Path) -> None:
    """D4's other half: the shared title means the BODY says which question found it, so an
    issue filed by the declared question says so too."""
    proc, log = _partner_lag_run(tmp_path, [])
    assert proc.returncode == 1, proc.stdout + proc.stderr
    body = gh_flag(log, "issue create", "--body")
    assert "| found by | the declared-version check |" in body, body
    assert "newest-version" not in body, body


# ── #253 Phase 2, verifier gaps ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("tagged", "cell"), [(True, "present"), (False, "**absent**")])
def test_the_newest_issue_states_the_newest_versions_own_tag(
    tmp_path: Path, tagged: bool, cell: str
) -> None:
    """The newest body's tag row is V's, read from git for V — not the declared version's (which
    is tagged here in both cases), and not a constant."""
    proc, log = newest_report_run(tmp_path, tag_newest=tagged)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    body = gh_flag(log, "issue create", "--body")
    assert f"| tag `v{AHEAD}` | {cell} |" in body, body


@pytest.mark.parametrize(
    ("notice_for", "linked"), [(AHEAD, True), (DRIFTING, False)], ids=["for-V", "only-for-D"]
)
def test_the_newest_issue_cross_links_release_outcome_for_V_only(
    tmp_path: Path, notice_for: str, linked: bool
) -> None:
    """An open `release-outcome` issue for V is linked from V's issue — it is the sign V's
    `registry-smoke` may have failed, exactly when State P says not to promote. One open only for
    the DECLARED version is about a different release and is not linked."""
    listing = [(9, "OPEN", [], RELEASE_NOTICE_TITLE.format(version=notice_for))]
    proc, log = newest_report_run(tmp_path, listing=listing)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    body = gh_flag(log, "issue create", "--body")
    assert ("`release-outcome` also reported this release: #9" in body) is linked, body


def test_a_declared_drift_beside_a_newest_clean_still_gets_the_close_notice(
    tmp_path: Path,
) -> None:
    """The close-notice guard's other half: the declared question reached GitHub through a DRIFT,
    not a clean — its listing is just as much in hand, so the open partner issue for V gets the
    notice from it. One listing, the declared create, the heartbeat; nothing for V."""
    proc, log = newest_report_run(
        tmp_path, declared="drift", newest="clean", listing=newest_partner_listing(11, "OPEN", [])
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert f"::notice::#11 reports {AHEAD} missing from partner" in proc.stdout, out
    calls = gh_calls(log)
    assert [c[:2] for c in calls] == [["issue", "list"], ["issue", "create"], ["api", calls[-1][1]]]
    assert calls[1][3] == DRIFT_TITLE.format(version=DRIFTING), calls[1]


def test_a_git_clock_fault_with_report_reaches_no_github_even_beside_a_newest_drift(
    tmp_path: Path,
) -> None:
    """The git-clock fault path files nothing: the checkout cannot be read, and no write leaves a
    run whose instrument is broken. The newest drift is printed and votes 1 — and `gh` is never
    called, not even to list."""
    proc, log = newest_report_run(tmp_path, newest="drift", filler_tags=0)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "below TAG_FLOOR" in proc.stderr and "NEWEST DRIFT —" in proc.stdout, out
    assert gh_calls(log) == [], gh_calls(log)


def test_a_listing_outage_beside_two_drifts_is_two_with_both_verdicts_and_no_retry(
    tmp_path: Path,
) -> None:
    """Declared drift and newest drift, the listing fails: exit 2, both verdicts in the log, ONE
    listing attempt (the failure is cached, never retried by the second question), no write, and
    no heartbeat — the drift path's handler returns before it."""
    proc, log = newest_report_run(
        tmp_path, declared="drift", newest="drift", fail_on=("issue", "list")
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    assert f"DRIFT — seam-sdk {DRIFTING} is not installable" in proc.stdout, out
    assert "NEWEST DRIFT —" in proc.stdout and "503" in proc.stderr, out
    assert gh_calls(log) == [issue_list_argv()], gh_calls(log)


def test_a_newest_create_failing_after_the_declared_create_is_two_and_keeps_the_first(
    tmp_path: Path,
) -> None:
    """The declared issue is filed, then the outage lands on the newest create: exit 2 (a finding
    went undelivered), the declared issue stands — exactly one create succeeded — the newest one
    was attempted once and failed, and the heartbeat is not reached."""
    v_title = PARTNER_DRIFT_TITLE.format(version=AHEAD)
    proc, log = newest_report_run(
        tmp_path, declared="drift", newest="drift", fail_create_titled=v_title
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out
    calls = gh_calls(log)
    assert [c[:2] for c in calls] == [["issue", "list"], ["issue", "create"], ["issue", "create"]]
    assert [c[3] for c in calls[1:]] == [DRIFT_TITLE.format(version=DRIFTING), v_title], calls
    filed = [ln for ln in proc.stdout.splitlines() if ln.startswith("filed a new drift issue:")]
    assert filed == [f"filed a new drift issue: {DRIFT_TITLE.format(version=DRIFTING)}"], filed
    assert "503" in proc.stderr, out


# ── Final verify: the seams between the declared and newest questions under --report ────────────
#
# Each phase's tests staged one question at a time. These stage BOTH, with --report, on the cells
# the whole-feature verify found uncovered: a declared PARTNER lag beside a newest question on another
# version (two partner titles from one listing), and a newest fault or grace tier beside a clean or
# drifting declared question.

SEAM_NOW = LANDED + timedelta(minutes=14400)


def _seam_run(
    tmp_path: Path,
    *,
    internal: dict,
    partner: dict,
    listing: list | tuple = (),
    unscoped: object | None = None,
) -> tuple[subprocess.CompletedProcess, Path]:
    repo = make_repo(tmp_path, version=DRIFTING, tag=True)
    bin_dir, _ = curl_stub(tmp_path, internal, partner_responses=partner, unscoped=unscoped)
    _, gh_log = gh_stub(tmp_path, list(listing))
    proc = run(
        repo,
        None,
        tmp_path,
        now=SEAM_NOW,
        extra=["--report"],
        env=report_env(bin_dir, token=STUB_TOKEN),
    )
    return proc, gh_log


def _ahead(minutes_ago: float) -> list[dict]:
    return published(AHEAD, uploaded_at=upload_stamp(SEAM_NOW - timedelta(minutes=minutes_ago)))


def _canary() -> dict:
    return {ROSTER[0]: published(ROSTER[0])}


def _creates(log: Path) -> list[str]:
    return [c[3] for c in gh_calls(log) if c[:2] == ["issue", "create"]]


def test_a_declared_partner_lag_and_a_newest_drift_file_two_partner_issues_from_one_listing(
    tmp_path: Path,
) -> None:
    """Internal serves D and V; partner serves neither. Both questions are partner lags, on two
    different versions and so two different titles: D's issue first, then V's, from ONE listing."""
    internal = {**_canary(), DRIFTING: published(DRIFTING), AHEAD: _ahead(14400)}
    proc, log = _seam_run(tmp_path, internal=internal, partner=_canary())
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert _creates(log) == [
        PARTNER_DRIFT_TITLE.format(version=DRIFTING),
        PARTNER_DRIFT_TITLE.format(version=AHEAD),
    ], gh_calls(log)
    assert gh_verbs(log).count("issue list") == 1, gh_calls(log)
    assert gh_calls(log)[-1] == heartbeat_argv(), gh_calls(log)
    assert STUB_TOKEN not in out


def test_a_suppressed_declared_partner_lag_does_not_suppress_the_newest_versions_lag(
    tmp_path: Path,
) -> None:
    """Suppression is per version: D's closed+labelled partner issue silences D, never V."""
    internal = {**_canary(), DRIFTING: published(DRIFTING), AHEAD: _ahead(14400)}
    listing = [(7, "CLOSED", [SUPPRESSION_LABEL], PARTNER_DRIFT_TITLE.format(version=DRIFTING))]
    proc, log = _seam_run(tmp_path, internal=internal, partner=_canary(), listing=listing)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert_filed_newest_only(log, AHEAD)


def test_both_partner_lags_suppressed_is_green_and_writes_nothing(tmp_path: Path) -> None:
    internal = {**_canary(), DRIFTING: published(DRIFTING), AHEAD: _ahead(14400)}
    listing = [
        (7, "CLOSED", [SUPPRESSION_LABEL], PARTNER_DRIFT_TITLE.format(version=DRIFTING)),
        (8, "CLOSED", [SUPPRESSION_LABEL], PARTNER_DRIFT_TITLE.format(version=AHEAD)),
    ]
    proc, log = _seam_run(tmp_path, internal=internal, partner=_canary(), listing=listing)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert gh_writes(log) == [], gh_calls(log)


def test_a_declared_partner_lag_beside_a_newest_clean_still_gets_the_close_notice(
    tmp_path: Path,
) -> None:
    internal = {**_canary(), DRIFTING: published(DRIFTING), AHEAD: _ahead(14400)}
    partner = {**_canary(), AHEAD: published(AHEAD)}
    listing = [(11, "OPEN", [], PARTNER_DRIFT_TITLE.format(version=AHEAD))]
    proc, log = _seam_run(tmp_path, internal=internal, partner=partner, listing=listing)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"::notice::#11 reports {AHEAD} missing from partner" in proc.stdout
    assert _creates(log) == [PARTNER_DRIFT_TITLE.format(version=DRIFTING)], gh_calls(log)


def test_with_report_a_newest_fault_beside_a_clean_declared_is_two_after_one_listing(
    tmp_path: Path,
) -> None:
    """The declared question is clean and reached GitHub (its close-notice listing); the newest
    question could not be answered. Nothing to file — exit 2, after exactly list + heartbeat."""
    internal = {**_canary(), DRIFTING: published(DRIFTING)}
    proc, log = _seam_run(tmp_path, internal=internal, partner=dict(internal), unscoped=[])
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert gh_calls(log) == [issue_list_argv(), heartbeat_argv()], gh_calls(log)


def test_with_report_a_newest_fault_beside_a_declared_drift_files_the_drift_and_exits_one(
    tmp_path: Path,
) -> None:
    """D3: a fault never hides an unsuppressed drift — the declared drift is filed and stands at 1."""
    proc, log = _seam_run(tmp_path, internal=_canary(), partner=_canary(), unscoped=[])
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert gh_calls(log)[0] == issue_list_argv(), gh_calls(log)
    assert _creates(log) == [DRIFT_TITLE.format(version=DRIFTING)], gh_calls(log)
    assert gh_calls(log)[-1] == heartbeat_argv(), gh_calls(log)


@pytest.mark.parametrize("minutes_ago", [30, 200], ids=["deferred", "warned"])
def test_with_report_a_newest_grace_tier_beside_a_clean_declared_files_nothing(
    tmp_path: Path, minutes_ago: float
) -> None:
    internal = {**_canary(), DRIFTING: published(DRIFTING), AHEAD: _ahead(minutes_ago)}
    partner = {**_canary(), DRIFTING: published(DRIFTING)}
    proc, log = _seam_run(tmp_path, internal=internal, partner=partner)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert gh_calls(log) == [issue_list_argv(), heartbeat_argv()], gh_calls(log)


def test_with_report_a_newest_warned_tier_beside_a_declared_drift_files_only_the_drift(
    tmp_path: Path,
) -> None:
    proc, log = _seam_run(tmp_path, internal={**_canary(), AHEAD: _ahead(200)}, partner=_canary())
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert _creates(log) == [DRIFT_TITLE.format(version=DRIFTING)], gh_calls(log)

