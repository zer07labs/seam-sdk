"""`check_registry_drift.py` decides whether a release actually landed, so it is driven RED first.

Every guard here is executed, not read. The check's whole value is that it fires on a real lag and
refuses to guess on a broken instrument — and both of those are properties you only have if you
have watched them happen. A green-path-only suite would prove the script runs, which is not the
question.

These build **real git repositories** in `tmp_path` rather than mocking `git`, following
`scripts/test_vendored_spec_gate.py:8-11`. Commit dates, annotated-tag creator dates and the tag
namespace are the subject matter here; a mock of them would only ever assert my model of git, which
is precisely the thing that could be wrong.

The registry response is injected as a file (`--packages-json`). Phase 4 adds the live query behind
a stubbed `curl`; nothing in this file touches a network.

Run: `python -m pytest scripts/test_registry_drift_gate.py -q`
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_registry_drift.py"

#: The moment every fixture repo dates its version commit from, unless it says otherwise. Fixed
#: rather than derived from `datetime.now()` so a failure is reproducible at any hour.
LANDED = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

#: `TAG_FLOOR` is 20, so a fixture repo needs more than that before `tag_present` will answer at
#: all. Deliberately not exactly 20: a fixture sitting on the boundary would turn a future floor
#: change into 40 confusing failures instead of one clear one.
FILLER_TAGS = 25


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
    (repo / "python" / "pyproject.toml").write_text(
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
    return subprocess.run(args, capture_output=True, text=True)


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
    warned = "::warning::" in proc.stdout + proc.stderr
    assert warned is expect_warning, f"age={age}: warning={warned}, expected {expect_warning}"


def test_the_soft_tier_says_when_it_will_stop_deferring(tmp_path: Path) -> None:
    """Silence is only acceptable if a reader can tell it is deliberate and time-boxed."""
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, published("0.7.77"), tmp_path, now=LANDED + timedelta(minutes=30))
    assert proc.returncode == 0
    assert "DEFERRED" in proc.stdout
    assert "stops deferring" in proc.stdout
    assert "::warning::" not in proc.stdout + proc.stderr


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
def test_a_broken_instrument_is_two_and_never_zero(tmp_path: Path, label: str, payload: str) -> None:
    """None of these may exit 0, and none of them may exit 1.

    A check that silently returns "nothing lagging" because its query broke is this repo's named
    failure class, and it would be a same-shape regression of the very bug this check exists to
    close. `@zer07labs/seam-sdk-extra` is in the list because the name comparison is exact after
    the scope strip — a near-miss must not count as evidence the query worked.
    """
    repo = make_repo(tmp_path, version="0.7.78")
    proc = run(repo, None, tmp_path, raw_json=payload)
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
