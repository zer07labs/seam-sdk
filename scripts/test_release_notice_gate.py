"""`publish.yml`'s gates all worked; the refusals told nobody, which is why the registry lagged.

v0.7.69, v0.7.70 and v0.7.72 were each refused correctly by `ci-green`. Each refusal was found by
hand, days later — the registry sat five days behind a source tree, a tag and a runtime that all
said 0.7.72 existed. A failed workflow run is a red dot on a page nobody opens.

`release-outcome` exists to make that arrive somewhere. It is a REPORTER, not a gate, and the
properties worth pinning are the ones that make a reporter useless when they rot:

  * it runs when its dependencies FAILED (`if: always()`) — the default is "only if needs
    succeeded", which is silent in precisely the case it was written for;
  * it stays quiet on a real success, or it trains everyone to ignore it;
  * it treats `registry-smoke` — not npm/python — as the proof of a landed release, because
    "uploaded" and "installable" are different claims and this repo has already been bitten by
    the gap;
  * it does not open a second issue for a tag that already has one.

These execute the real step script out of the workflow against a stubbed `gh`, for the reason
`test_publish_gate.py` gives: a gate whose logic is only read and never run is how the ordering bug
in `release-on-runtime.yml` survived a day.

Run: `python -m pytest scripts/test_release_notice_gate.py -q`
"""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
PUBLISH = REPO / ".github" / "workflows" / "publish.yml"
JOB = "release-outcome"

#: Every job whose result the notice reads. Kept here so a job added to `needs:` without being
#: reported is a test failure rather than a silently missing row in the issue body.
REPORTED = ["ci-green", "version-check", "npm", "python", "registry-smoke"]


def _job() -> dict:
    return yaml.safe_load(PUBLISH.read_text())["jobs"][JOB]


def _script() -> str:
    return _job()["steps"][0]["run"]


def _run(
    tmp_path: Path,
    *,
    smoke: str = "success",
    ci_green: str = "success",
    version_check: str = "success",
    npm: str = "success",
    python: str = "success",
    open_issues: list[dict] | None = None,
) -> tuple[subprocess.CompletedProcess, list[list[str]]]:
    """Run the notice script with a stubbed `gh`; return the process and every `gh` argv it made."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "gh-calls"
    calls.write_text("")
    listing = tmp_path / "issues.tsv"
    listing.write_text(
        "".join(f"{i['number']}\t{i['title']}\n" for i in (open_issues or []))
    )

    # The stub answers `issue list` with a pre-rendered TSV — exactly the shape the script's
    # `--jq '.[] | "\(.number)\t\(.title)"'` produces — and records every invocation.
    (bin_dir / "gh").write_text(
        textwrap.dedent(f"""\
        #!/usr/bin/env bash
        printf '%s\\n' "$*" >> {calls}
        if [ "$1" = "issue" ] && [ "$2" = "list" ]; then
          cat {listing}
        fi
        exit 0
        """)
    )
    (bin_dir / "gh").chmod(0o755)

    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/local/bin",
        "GH_TOKEN": "stub",
        "CI_GREEN": ci_green,
        "VERSION_CHECK": version_check,
        "NPM": npm,
        "PYTHON": python,
        "SMOKE": smoke,
        "GITHUB_REF_NAME": "v0.7.72",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "zer07labs/seam-sdk",
        "GITHUB_RUN_ID": "12345",
    }
    proc = subprocess.run(
        ["bash", "-c", _script()],
        env=env,
        capture_output=True,
        text=True,
    )
    argv = [line.split() for line in calls.read_text().splitlines() if line.strip()]
    return proc, argv


def _verbs(argv: list[list[str]]) -> list[str]:
    return [" ".join(a[:2]) for a in argv]


# ── it reports when the release did not land ───────────────────────────────────────────────────


def test_a_refused_release_opens_an_issue(tmp_path: Path) -> None:
    proc, argv = _run(tmp_path, ci_green="failure", npm="skipped", python="skipped", smoke="skipped")
    assert proc.returncode == 0, proc.stderr
    assert "issue create" in _verbs(argv), f"nothing was filed; gh saw {_verbs(argv)}"


@pytest.mark.parametrize("failed", REPORTED)
def test_any_job_short_of_a_landed_release_reports(failed: str, tmp_path: Path) -> None:
    """Not just `ci-green`. A half-published release — npm up, python down — is still a failure.

    The three real incidents all failed at `ci-green`, so a guard written only against them would
    pass while staying blind to the partial-publish case, which is the worse one: the registry then
    holds an npm package with no matching wheel.
    """
    kwargs = {"ci_green": "success", "version_check": "success", "npm": "success", "python": "success", "smoke": "success"}
    kwargs["smoke" if failed == "registry-smoke" else failed.replace("-", "_")] = "failure"
    if failed != "registry-smoke":
        kwargs["smoke"] = "skipped"
    proc, argv = _run(tmp_path, **kwargs)
    assert proc.returncode == 0, proc.stderr
    assert "issue create" in _verbs(argv), f"{failed} failing filed nothing"


def test_the_issue_names_the_tag(tmp_path: Path) -> None:
    proc, argv = _run(tmp_path, ci_green="failure", smoke="skipped")
    create = next(a for a in argv if a[:2] == ["issue", "create"])
    assert "v0.7.72" in " ".join(create), (
        "the issue title does not carry the tag, so two failed releases collapse into one thread"
    )


# ── it stays quiet when the release actually landed ────────────────────────────────────────────


def test_a_landed_release_files_nothing(tmp_path: Path) -> None:
    proc, argv = _run(tmp_path, smoke="success")
    assert proc.returncode == 0, proc.stderr
    assert argv == [], f"a successful release still called gh: {_verbs(argv)}"


def test_npm_and_python_succeeding_is_not_enough(tmp_path: Path) -> None:
    """`registry-smoke` is the proof, not the upload jobs.

    npm and python report the PUSH succeeded. registry-smoke installs the artifact back out of
    Cloudsmith and runs the vectors against it. A release that uploads and never becomes
    installable passes the first two and fails the third — and that exact failure is why
    registry-smoke exists, so the notice must read it and not them.
    """
    proc, argv = _run(tmp_path, npm="success", python="success", smoke="failure")
    assert "issue create" in _verbs(argv), (
        "an uploaded-but-not-installable release reported nothing"
    )


# ── it does not spam ───────────────────────────────────────────────────────────────────────────


def test_a_tag_that_already_has_an_issue_gets_a_comment(tmp_path: Path) -> None:
    proc, argv = _run(
        tmp_path,
        ci_green="failure",
        smoke="skipped",
        open_issues=[{"number": 101, "title": "Release v0.7.72 did not publish"}],
    )
    assert proc.returncode == 0, proc.stderr
    verbs = _verbs(argv)
    assert "issue comment" in verbs, f"re-run did not comment; gh saw {verbs}"
    assert "issue create" not in verbs, "a second issue was opened for the same tag"


def test_an_unrelated_open_issue_does_not_suppress_the_report(tmp_path: Path) -> None:
    """Title matching must be exact.

    A substring match against a busy issue list is how a reporter goes quiet for reasons nobody
    can reconstruct later — the failure class this whole job was written against.
    """
    proc, argv = _run(
        tmp_path,
        ci_green="failure",
        smoke="skipped",
        open_issues=[
            {"number": 100, "title": "Three releases silently failed to publish"},
            {"number": 44, "title": "Reserve unregistered PyPI package names defensively"},
        ],
    )
    assert "issue create" in _verbs(argv), "an unrelated open issue swallowed the report"


# ── structure: the properties that make it a reporter rather than a gate ────────────────────────


def test_it_runs_even_when_its_dependencies_failed() -> None:
    cond = str(_job()["if"])
    assert "always()" in cond, (
        "release-outcome lost `always()`. Without it the job inherits 'run only if needs "
        "succeeded' and goes silent in exactly the case it exists to report."
    )


def test_it_watches_every_job_that_can_stop_a_release() -> None:
    needs = set(_job()["needs"])
    assert set(REPORTED) <= needs, (
        f"release-outcome does not depend on {set(REPORTED) - needs}, so it can be evaluated "
        "before those jobs finish and report a release that had not failed yet."
    )


def test_it_can_actually_file_an_issue() -> None:
    """A reporter without `issues: write` fails at the last step — visibly, but only in the run.

    publish.yml's top-level permissions are read-only, and job-level permissions REPLACE rather
    than extend them, so this has to be declared on the job itself.
    """
    perms = _job()["permissions"]
    assert perms.get("issues") == "write", f"release-outcome cannot open an issue: {perms}"


def test_it_cannot_turn_a_failed_release_green() -> None:
    """It reports; it must never be mistaken for a gate.

    A notifier that other jobs depend on, or that carries `continue-on-error`, starts having an
    opinion on the release's outcome. This one only ever reads results.
    """
    wf = yaml.safe_load(PUBLISH.read_text())
    dependents = [j for j, spec in wf["jobs"].items() if JOB in (spec.get("needs") or [])]
    assert dependents == [], f"{dependents} depend on the notifier, making a reporter into a gate"
