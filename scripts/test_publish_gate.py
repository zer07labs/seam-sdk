"""`publish.yml`'s CI gate races the CI it is checking, so patience is part of its correctness.

The release step pushes the commit and the tag seconds apart. The commit push starts `ci.yml`; the
tag push starts `publish.yml`. So when the gate asks "is `ci-ok` green for this commit?", the honest
answer is often "no check run exists yet" — not because CI failed, but because it has not registered.

Read once and that reads as absent, which the gate refuses. It is refusing the right way for the
wrong reason. v0.7.47 hit exactly this: publish fired at 03:24:39Z, `ci-ok` appeared at 03:25:26Z,
and the release lost by 47 seconds and needed a hand re-run.

The fix is a bounded wait, and the thing worth testing is that waiting did not soften anything:

  * absent / pending / API failure  → transient, keep waiting
  * settled non-success            → refuse IMMEDIATELY, do not wait out the ceiling
  * ceiling exhausted              → refuse; a timeout is not a pass

These run the real script out of the workflow against a stubbed `gh`, because a gate whose logic is
only read and never executed is how the ordering bug in `release-on-runtime.yml` survived a day.

Run: `python -m pytest scripts/test_publish_gate.py -q`
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
PUBLISH = REPO / ".github" / "workflows" / "publish.yml"
SHA = "860db039ae97d4e52cef956a4959c349b444e468"


def _gate_script() -> str:
    job = yaml.safe_load(PUBLISH.read_text())["jobs"]["ci-green"]
    step = next(s for s in job["steps"] if "resolve ci-ok" in str(s.get("name", "")))
    return step["run"]


def _run(responses: list[str | None], tmp_path: Path) -> subprocess.CompletedProcess:
    """Execute the gate with `gh` returning `responses[i]` on call i (None == API failure).

    The final response repeats forever, so a test can say "absent, then green" or "absent always"
    without enumerating forty entries. `sleep` is stubbed to a no-op so the ceiling is exercised in
    milliseconds rather than twenty minutes.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    calls = tmp_path / "calls"
    calls.write_text("0")

    payloads = tmp_path / "payloads"
    payloads.mkdir()
    for i, r in enumerate(responses):
        (payloads / str(i)).write_text("" if r is None else r)
        (payloads / f"{i}.fail").write_text("1" if r is None else "0")

    (bin_dir / "gh").write_text(
        textwrap.dedent(f"""\
        #!/usr/bin/env bash
        n=$(cat {calls})
        echo $((n + 1)) > {calls}
        last={len(responses) - 1}
        [ "$n" -gt "$last" ] && n=$last
        if [ "$(cat {payloads}/$n.fail)" = "1" ]; then exit 1; fi
        cat {payloads}/$n
        """)
    )
    (bin_dir / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n")
    for f in ("gh", "sleep"):
        (bin_dir / f).chmod(0o755)

    proc = subprocess.run(
        ["bash", "-c", _gate_script()],
        env={
            "GH_TOKEN": "stub",
            "REPO": "zer07labs/seam-sdk",
            "SHA": SHA,
            "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        },
        capture_output=True,
        text=True,
        check=False,  # a non-zero exit IS the thing under test
    )
    proc.gh_calls = int(calls.read_text())  # type: ignore[attr-defined]
    return proc


def test_green_on_the_first_look_publishes(tmp_path: Path) -> None:
    p = _run(["success"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "CI is green" in p.stdout


def test_two_ci_ok_runs_both_green_publishes(tmp_path: Path) -> None:
    """A commit that was also a PR head carries one ci-ok per check suite; all must pass."""
    p = _run(["success\nsuccess"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "2 ci-ok run(s)" in p.stdout


def test_absent_then_green_publishes(tmp_path: Path) -> None:
    """The v0.7.47 regression: CI had not registered yet, and the gate refused for it."""
    p = _run(["", "", "success"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "not registered yet" in p.stdout, "should have reported why it was waiting"


def test_pending_then_green_publishes(tmp_path: Path) -> None:
    p = _run(["pending", "success"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "still running" in p.stdout


def test_api_failure_then_green_publishes(tmp_path: Path) -> None:
    """A transient outage must not read as a verdict in either direction."""
    p = _run([None, "success"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "API call failed" in p.stdout


@pytest.mark.parametrize("verdict", ["failure", "cancelled", "timed_out", "neutral"])
def test_a_settled_non_success_refuses_immediately(verdict: str, tmp_path: Path) -> None:
    """Waiting cannot turn a red run green — refusing late would only delay the same answer."""
    p = _run([verdict], tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "not success" in (p.stdout + p.stderr)
    assert p.gh_calls == 1, (  # type: ignore[attr-defined]
        f"refused after {p.gh_calls} API calls — a settled verdict must not burn the ceiling"  # type: ignore[attr-defined]
    )


def test_one_green_does_not_mask_one_red(tmp_path: Path) -> None:
    p = _run(["success\nfailure"], tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "does not cancel a red one" in (p.stdout + p.stderr)


def test_never_registering_times_out_into_a_refusal(tmp_path: Path) -> None:
    """Fail-closed is the property the wait must not have softened."""
    p = _run([""], tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "Timed out" in (p.stdout + p.stderr)
    assert "not a pass" in (p.stdout + p.stderr)


def test_forever_pending_times_out_into_a_refusal(tmp_path: Path) -> None:
    p = _run(["pending"], tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "Timed out" in (p.stdout + p.stderr)


def test_the_gate_actually_waits_rather_than_asking_once(tmp_path: Path) -> None:
    """Guards the guard: if the loop is ever removed, every test above still passes on its first
    look. Only the call count distinguishes 'patient' from 'lucky'."""
    p = _run([""], tmp_path)
    assert p.gh_calls > 1, (  # type: ignore[attr-defined]
        f"the gate asked {p.gh_calls} time(s) before giving up — it is not waiting at all, which "  # type: ignore[attr-defined]
        "is the v0.7.47 failure"
    )
