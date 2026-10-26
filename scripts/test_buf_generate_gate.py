"""`scripts/buf_generate.sh` retries a transient BSR failure, and nothing else.

The BSR's `Failure: internal: internal error` failed main and the v0.58.0 tag CI on one release
commit, and publish.yml refused a release with nothing wrong in it (#296). The wrapper retries that.
The property worth pinning is the narrowness: a retry loop that also swallows `unauthenticated` or a
bad module ref turns a real refusal into three slow ones, and one that retries forever turns a BSR
outage into a hung job. Each case runs the real script against a stubbed `buf` that replays a
scripted sequence of outcomes and counts its calls.

Run: `python -m pytest scripts/test_buf_generate_gate.py -q`
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "buf_generate.sh"
MAKEFILE = REPO / "Makefile"

INTERNAL = "Failure: internal: internal error, contact support at https://buf.build/docs/contact, reference code: 5cff7c"


def run(tmp_path: Path, outcomes: list[tuple[int, str]], attempts: int = 3):
    """Drive the wrapper with a `buf` that answers call N with outcomes[N] (the last one repeats)."""
    for i, (rc, out) in enumerate(outcomes):
        (tmp_path / f"out{i}").write_text(out + "\n")
        (tmp_path / f"rc{i}").write_text(str(rc))
    stub = tmp_path / "bin" / "buf"
    stub.parent.mkdir()
    stub.write_text(
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            d={tmp_path}
            echo "$*" >> "$d/calls"
            n=$(($(wc -l < "$d/calls") - 1)); [ "$n" -gt {len(outcomes) - 1} ] && n={len(outcomes) - 1}
            cat "$d/out$n" >&2
            exit "$(cat "$d/rc$n")"
            """
        )
    )
    stub.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{stub.parent}{os.pathsep}{os.environ['PATH']}",
        "BUF_GENERATE_ATTEMPTS": str(attempts),
        "BUF_GENERATE_BACKOFF": "0",
    }
    proc = subprocess.run(
        [str(SCRIPT), "buf.build/zer07labs/seam"], env=env, capture_output=True, text=True
    )
    calls = (tmp_path / "calls").read_text().splitlines()
    return proc, calls


def test_a_transient_internal_error_is_retried_until_it_clears(tmp_path):
    proc, calls = run(tmp_path, [(1, INTERNAL), (1, INTERNAL), (0, "")])
    assert proc.returncode == 0, proc.stderr
    assert calls == ["generate buf.build/zer07labs/seam"] * 3


@pytest.mark.parametrize("code", ["unavailable", "deadline_exceeded"])
def test_the_other_server_side_codes_are_retried(tmp_path, code):
    proc, calls = run(tmp_path, [(1, f"Failure: {code}: try again"), (0, "")])
    assert proc.returncode == 0 and len(calls) == 2


@pytest.mark.parametrize(
    "out",
    [
        "Failure: unauthenticated: you must be logged in",
        "Failure: permission_denied: no access to buf.build/zer07labs/seam",
        "Failure: not_found: module not found",
        "seam.proto:12:3: field Foo: unknown type",
    ],
)
def test_a_real_refusal_fails_on_the_first_attempt_with_bufs_own_code(tmp_path, out):
    proc, calls = run(tmp_path, [(100, out), (0, "")])
    assert proc.returncode == 100
    assert len(calls) == 1
    assert "retrying" not in proc.stderr


def test_a_persistent_bsr_failure_gives_up_after_the_attempt_budget(tmp_path):
    proc, calls = run(tmp_path, [(1, INTERNAL)], attempts=3)
    assert proc.returncode == 1
    assert len(calls) == 3
    assert "giving up" in proc.stderr


def test_the_word_internal_inside_a_real_error_is_not_a_transient(tmp_path):
    """Matched on the anchored `Failure: <code>:` prefix, not anywhere in the output."""
    proc, calls = run(tmp_path, [(1, "plugin error: Failure: internal: mentioned mid-line")])
    assert proc.returncode == 1 and len(calls) == 1


def test_both_makefile_generate_targets_go_through_the_wrapper():
    """CI and publish.yml call `make generate`; a raw `buf generate` there bypasses the retry."""
    recipe_lines = [l.strip() for l in MAKEFILE.read_text().splitlines() if l.startswith("\t")]
    assert "./scripts/buf_generate.sh $(BUF_MODULE)" in recipe_lines
    assert "./scripts/buf_generate.sh $(RUNTIME)" in recipe_lines
    assert not [l for l in recipe_lines if l.startswith("buf generate")]
