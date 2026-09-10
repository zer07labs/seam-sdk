"""`probe_framework_coinstall.py` reserves 1 for a verdict, and Python spends 1 on a crash.

The probe's whole discipline is that an infrastructure condition is reported as infrastructure and
never as a finding: exit 2 is "no verdict could be established", exit 1 is "a row disagrees with
COMPATIBILITY.md". It says so at `scripts/probe_framework_coinstall.py:47-51`, and guards the one
instance it thought of — a too-old interpreter — while leaving the general case open. Any other
uncaught exception exited 1 and read as a substantive claim about framework co-installability,
produced by a crash (#110).

Every test here runs the real script as a subprocess against a scratch tree, because the property
is about the **process exit code**, and a test that imported `main()` and asserted on a return
value could not see the difference between the two ways a process reaches 1.

The scratch tree is a copy: the script resolves `REPO` as `Path(__file__).resolve().parents[1]`,
so placing it at `<tmp>/scripts/` makes `<tmp>` its repo root and gives these tests a manifest and
a table they can deliberately break without touching this one.

Run: `python -m pytest scripts/test_framework_coinstall_gate.py -q`
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "probe_framework_coinstall.py"

#: A manifest the probe reads without complaint — `[project].dependencies` must be non-empty or
#: `sdk_floors` raises `InfraError` and we would be exercising the handled path by accident.
PYPROJECT = """\
[project]
name = "seam-sdk"
version = "0.0.0"
dependencies = ["protobuf>=5.29.5", "grpcio>=1.64"]
"""

#: A table the probe parses to exactly one row. The marker and the row shape are the probe's own
#: (`TABLE_MARKER`, `ROW`); zero rows is an `InfraError` there, which is again not what we want.
COMPATIBILITY = """\
# Compatibility

<!-- PROBE-TABLE: framework co-installability -->

| framework | constraint | verdict | note |
|---|---|---|---|
| `crewai` | `>=0.80` | `incompatible` | protobuf floor |
"""


def _tree(tmp_path: Path) -> Path:
    """A scratch repo root holding a copy of the probe, a manifest, and a table."""
    (tmp_path / "scripts").mkdir()
    shutil.copy2(SCRIPT, tmp_path / "scripts" / SCRIPT.name)
    (tmp_path / "python").mkdir()
    (tmp_path / "python" / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (tmp_path / "COMPATIBILITY.md").write_text(COMPATIBILITY, encoding="utf-8")
    return tmp_path


def _run(tree: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(tree / "scripts" / SCRIPT.name), *args],
        capture_output=True,
        text=True,
    )


# ── a crash is not a verdict ───────────────────────────────────────────────────────────────────


def test_an_unhandled_exception_exits_two_not_one(tmp_path: Path) -> None:
    """The defect #110 names: any uncaught exception reported itself as a matrix change.

    Injected by replacing `python/pyproject.toml` with a directory. `sdk_floors` reads it with an
    unguarded `PYPROJECT.read_text()` (`probe_framework_coinstall.py:103`), so `open()` raises
    `IsADirectoryError` — an `OSError`, which is deliberately not an `InfraError` and so is not
    caught by `main`'s `except InfraError` arm. It is the same injection
    `scripts/test_registry_drift_gate.py` uses for the same property, for the same reason: it
    needs no monkeypatching and does not depend on any internal name staying put.
    """
    tree = _tree(tmp_path)
    (tree / "python" / "pyproject.toml").unlink()
    (tree / "python" / "pyproject.toml").mkdir()

    proc = _run(tree)
    assert proc.returncode == 2, (
        f"exit {proc.returncode} — a crash was reported as a verdict about co-installability"
    )
    assert "Traceback" in proc.stderr, "the crash was swallowed; an operator cannot diagnose it"
    assert "crashed" in proc.stderr, proc.stderr


def test_the_crash_does_not_claim_a_row_disagrees(tmp_path: Path) -> None:
    """Exit code aside, the OUTPUT must not read as a matrix finding.

    An operator who sees `COMPATIBILITY.md's framework table no longer matches` goes and edits
    that table. The probe's own infra path says in as many words not to. A crash must not produce
    the sentence that sends someone editing the file.
    """
    tree = _tree(tmp_path)
    (tree / "python" / "pyproject.toml").unlink()
    (tree / "python" / "pyproject.toml").mkdir()

    proc = _run(tree)
    combined = proc.stdout + proc.stderr
    assert "no longer matches" not in combined, combined
    assert "COMPATIBILITY.md §4a" not in combined, combined


# ── the handler must not eat the codes it is wrapping ──────────────────────────────────────────


def test_the_handler_does_not_swallow_a_real_exit_code(tmp_path: Path) -> None:
    """`except SystemExit: raise` is load-bearing, and this is what proves it is there.

    `sys.exit(main())` raises `SystemExit`. A handler catching `BaseException` without re-raising
    it first would convert EVERY run — including a clean one and a genuine verdict — into a 2, and
    the test above would still pass. `--help` is the cheapest fully-hermetic path that must exit
    0: argparse raises `SystemExit(0)` and never reaches the network or `uv`.
    """
    proc = _run(_tree(tmp_path), "--help")
    assert proc.returncode == 0, (
        f"exit {proc.returncode} — the handler is eating SystemExit, so every run is now infra"
    )
    assert "--python-version" in proc.stdout


def test_a_handled_infrastructure_condition_is_not_reported_as_a_crash(tmp_path: Path) -> None:
    """2 has two roads into it, and only one of them is a bug in this script.

    Removing the table marker is an `InfraError` the probe raises on purpose, with a message that
    tells the operator what to fix. It must still exit 2 — and must NOT print `crashed`, or the
    new handler has started catching conditions the script already handles well, hiding a good
    diagnostic behind a traceback.
    """
    tree = _tree(tmp_path)
    (tree / "COMPATIBILITY.md").write_text("# Compatibility\n\nno table here\n", encoding="utf-8")

    proc = _run(tree)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "no longer contains" in proc.stdout, proc.stdout
    assert "crashed" not in proc.stderr, (
        "a condition the script handles is being reported as a crash: " + proc.stderr
    )


def test_the_scratch_tree_is_otherwise_sound(tmp_path: Path) -> None:
    """Anti-vacuity: prove the fixture reaches past the reads the tests above break.

    Without this, a scratch tree malformed in some unrelated way would make every test above pass
    for the wrong reason — each of them asserts on a FAILURE, and a fixture that fails earlier and
    differently still fails. This runs the unmodified tree and requires it to get as far as the
    resolver, which is the first thing beyond both files under test.
    """
    proc = _run(_tree(tmp_path))
    assert "probing 1 framework(s)" in proc.stdout, (
        "the fixture never reached the resolver, so the failure-path tests prove nothing:\n"
        + proc.stdout
        + proc.stderr
    )
