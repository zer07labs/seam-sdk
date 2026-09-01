"""`verify/`'s entire product claim is that it links NOTHING of Seam's — this is what checks that.

The check used to be an ALLOWLIST of forbidden crate names, hand-maintained against a repo this one
does not build against (`seam-runtime`). It had already drifted: measured against
`seam-runtime/crates` it missed `seam-acdp-testkit`, `seam-conformance`, `seam-kms-vault`,
`seam-serving`, `seam-serving-router`, and the `seamd` binary — six real crates the old gate could
not see — while `bandit` in the old list matched nothing that exists. An allowlist's failure mode
is a SILENT FALSE NEGATIVE, which is the worst possible failure for a gate whose whole job is
asserting a negative claim.

`scripts/check-independence.sh` inverts it to a denylist of what is permitted: nothing named
`seam-*` or `seamd` may appear in `cargo tree -e normal` other than the root `seam-verify` crate
itself. That is complete by construction and fails LOUD (a false positive) rather than silently.

This file drives the REAL script — never a reimplementation of its regex — with synthetic
`cargo tree` text via stdin, so it needs no Rust toolchain and never touches the actual `verify/`
tree. It also asserts both workflows call the one script, and that the old inline regex is gone
from both, so the duplication that made this drift possible cannot come back.

Run: `python -m pytest scripts/test_independence_gate.py -q`
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-independence.sh"
CI = REPO / ".github" / "workflows" / "ci.yml"
PUBLISH = REPO / ".github" / "workflows" / "publish.yml"


def _run(tree: str) -> subprocess.CompletedProcess:
    """Run the real script with synthetic `cargo tree` text fed over stdin (`-`).

    Stdin, not a temp file, for the common case — a file-argument path is exercised separately
    below so both input modes the script promises are actually proven.
    """
    return subprocess.run(
        ["bash", str(SCRIPT), "-"],
        input=tree,
        capture_output=True,
        text=True,
        check=False,
    )


# ── the gate itself, executed against synthetic trees ─────────────────────────────────────────


def test_a_seam_dependency_is_refused() -> None:
    """Acceptance criterion 1: `seam-serving` as a dependency must fail."""
    tree = "seam-verify v0.7.70\n├── seam-serving v0.1.0\n"
    p = _run(tree)
    assert p.returncode != 0, f"seam-serving in the tree did not fail: {p.stdout}{p.stderr}"
    assert "seam-verify links a Seam crate" in p.stdout + p.stderr


def test_only_the_root_line_passes() -> None:
    """Acceptance criterion 2: a tree with nothing but the root `seam-verify` line passes.

    This is the case that first broke a naive `set -e` extraction of the old inline script: when
    every non-root line is filtered out, `grep -v` itself exits 1 (no output), which — inside a
    command-substitution assignment under `set -euo pipefail` — aborts the script before it ever
    reaches its own success message. A regression here reads as this test failing, not as a
    generic shell error, because the assertion is on the exit code AND the success message.
    """
    p = _run("seam-verify v0.7.70\n")
    assert p.returncode == 0, f"root-only tree was refused: {p.stdout}{p.stderr}"
    assert "OK" in p.stdout


def test_seamd_is_refused() -> None:
    """Acceptance criterion 3: `seamd` (the binary, no hyphen) must fail.

    `seamd` cannot match a `seam-` prefix — it has no hyphen — which is exactly why the old
    allowlist's `\\bseam-(...)` pattern could never have caught it regardless of which names were
    listed. The denylist needs a second alternative for this reason, asserted here specifically so
    that alternative cannot quietly be dropped.
    """
    p = _run("seam-verify v0.7.70\n└── seamd v0.1.0\n")
    assert p.returncode != 0, f"seamd in the tree did not fail: {p.stdout}{p.stderr}"


def test_a_nested_indented_dependency_is_still_caught() -> None:
    """Acceptance criterion / edge case: box-drawing indentation must not hide a Seam crate.

    `cargo tree` prefixes non-root lines with `├── `, `│   `, `└── ` at arbitrary nesting depth.
    None of that may defeat the `\\b` word-boundary match.
    """
    tree = "seam-verify v0.7.70\n├── some-crate v1.0.0\n│   └── seam-guard v0.2.0\n"
    p = _run(tree)
    assert p.returncode != 0, f"a nested, indented seam-guard was not caught: {p.stdout}{p.stderr}"


def test_a_dependency_literally_named_seam_verify_is_not_exempted() -> None:
    """The root-line exclusion is anchored at column 0 — an indented `seam-verify` dependency
    line (a different resolved version, say, from a diamond dependency) must NOT be treated as the
    root and must still fail."""
    tree = "seam-verify v0.7.70\n├── other-crate v1.0.0\n│   └── seam-verify v0.2.0\n"
    p = _run(tree)
    assert p.returncode != 0, (
        f"an indented seam-verify dependency line was wrongly treated as the root: "
        f"{p.stdout}{p.stderr}"
    )


def test_the_file_argument_form_also_works(tmp_path: Path) -> None:
    """The script promises two synthetic-input modes (stdin via `-`, or a file argument) — this
    proves the second one, not just the one every other test in this file uses."""
    f = tmp_path / "tree.txt"
    f.write_text("seam-verify v0.7.70\n├── seam-api v0.1.0\n", encoding="utf-8")
    p = subprocess.run(
        ["bash", str(SCRIPT), str(f)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p.returncode != 0, f"seam-api via a file argument did not fail: {p.stdout}{p.stderr}"


# ── anti-vacuity: the pattern must not be satisfiable by construction, only by content ────────


@pytest.mark.parametrize(
    "line",
    [
        "├── seam-conformance v0.1.0",  # one of the six the old allowlist actually missed
        "│   ├── seam-kms-vault v0.1.0",
        "│   │   └── seam-acdp-testkit v0.1.0",
        "└── seamd v1.2.3",
        "seam-serving-router v0.0.1",  # no indentation at all — still not the root name
        "   seam-serving v9.9.9",  # plain leading spaces, not box-drawing
    ],
    ids=[
        "seam-conformance",
        "seam-kms-vault",
        "seam-acdp-testkit",
        "seamd",
        "unindented-non-root",
        "plain-space-indent",
    ],
)
def test_every_formatting_shape_of_an_offender_is_caught(line: str) -> None:
    """None of these six names would have tripped the OLD allowlist (that is the defect this
    plan fixes) — every one of them must trip the new denylist regardless of how it is indented,
    proving the check is not trivially satisfiable by a particular whitespace style."""
    tree = f"seam-verify v0.7.70\n{line}\n"
    p = _run(tree)
    assert p.returncode != 0, f"{line!r} was not caught: {p.stdout}{p.stderr}"


def test_a_seam_crate_cannot_pass_by_construction() -> None:
    """Directly restates the anti-vacuity property: for ANY of the crates the old allowlist
    missed, wrapped in any of a handful of tree shapes, the result is never a pass. A denylist
    that only caught crates already named in the plan would be exactly as rot-prone as what it
    replaced."""
    offenders = [
        "seam-acdp-testkit",
        "seam-conformance",
        "seam-kms-vault",
        "seam-serving",
        "seam-serving-router",
        "seamd",
        # not missed by the old allowlist, but must still be caught by the new one
        "seam-store",
        "seam-context-acdp",
    ]
    shapes = [
        "├── {} v0.1.0",
        "│   └── {} v0.1.0",
        "└── {} v0.1.0",
    ]
    for name in offenders:
        for shape in shapes:
            tree = "seam-verify v0.7.70\n" + shape.format(name) + "\n"
            p = _run(tree)
            assert p.returncode != 0, f"{name!r} as {shape!r} passed: {p.stdout}{p.stderr}"


# ── both workflows call the one script, and the old duplication is gone ───────────────────────


def _step(workflow_path: Path, job: str) -> dict:
    wf = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = wf["jobs"][job]["steps"]
    return next(s for s in steps if "verifier must link NOTHING" in str(s.get("name", "")))


def test_ci_yml_invokes_the_script() -> None:
    step = _step(CI, "verify")
    assert "check-independence.sh" in str(step.get("run", "")), (
        f"ci.yml's verify job no longer calls scripts/check-independence.sh: {step}"
    )


def test_publish_yml_invokes_the_script() -> None:
    step = _step(PUBLISH, "publish-verify")
    assert "check-independence.sh" in str(step.get("run", "")), (
        f"publish.yml's publish-verify job no longer calls scripts/check-independence.sh: {step}"
    )


def test_the_old_inline_allowlist_regex_is_gone_from_both_workflows() -> None:
    """The literal defect: the same hand-maintained allowlist, pasted twice, able to disagree.

    Grepped rather than compared against `_step`'s parsed YAML so this also catches the pattern
    surviving anywhere else in either file — a leftover copy in a different job would defeat the
    single-script fix just as effectively as one left behind in `verify`/`publish-verify`.
    """
    for wf in (CI, PUBLISH):
        text = wf.read_text(encoding="utf-8")
        assert "seam-(store|types" not in text, (
            f"{wf.name} still contains the old inline allowlist regex — the extraction to "
            f"scripts/check-independence.sh is incomplete."
        )


def test_both_workflows_still_parse_as_yaml() -> None:
    yaml.safe_load(CI.read_text(encoding="utf-8"))
    yaml.safe_load(PUBLISH.read_text(encoding="utf-8"))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-v"]))
