"""No workflow may call `buf generate` directly — the Makefile is the only sanctioned entry.

This guard exists because the distinction was load-bearing and undocumented in the one file
that got it wrong. `make generate` is::

    buf generate $(BUF_MODULE)
    python3 scripts/root_gen.py

protoc emits top-level imports for a module's siblings (``from seam.event.v1 import ...``);
``root_gen.py`` rewrites them to the rooted ``seam_sdk._gen.*`` form and drops the
``__init__.py`` files. Without that second line the stubs are present, complete, and
**unimportable**::

    File ".../seam_sdk/_gen/seam/api/v1/seam_pb2.py", line 25
      from seam.event.v1 import seam_event_pb2 as ...
    ModuleNotFoundError: No module named 'seam'

`ci.yml` said so in a comment three times over. `publish.yml` ran raw ``buf generate`` in both
its jobs, so **every wheel this repo ever published could not be imported** — and nobody noticed,
because every known consumer resolved seam-sdk from a sibling checkout rather than the index.

The publish job's own guard could not catch it: it listed the wheel's contents, confirmed
``_gen/seam/api/v1/seam_pb2.py`` was present, and printed "refusing to publish a broken wheel".
The file was always present. It was never imported. That guard now installs the wheel into a
fresh venv and imports it; this test is the cheap PR-time twin that names the actual rule, so the
divergence cannot come back in a workflow that no release happens to exercise.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = sorted((Path(__file__).resolve().parents[2] / ".github" / "workflows").glob("*.yml"))

# `buf generate` as a command, not as prose. A comment saying "NOT raw `buf generate`" is the
# right thing to write and must not trip this: the pattern requires the invocation to open a
# line (after YAML/shell indentation), which a backticked mention inside a `#` comment does not.
RAW_BUF_GENERATE = re.compile(r"^\s*buf\s+generate\b", flags=re.M)


def _uncommented(text: str) -> str:
    """Drop whole-line comments so prose about the rule cannot satisfy or violate it."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_there_are_workflows_to_check():
    """Anti-vacuity: a glob that matched nothing would make every assertion below pass."""
    assert WORKFLOWS, "no workflows found — this guard would silently check nothing"
    assert any(w.name == "publish.yml" for w in WORKFLOWS), "publish.yml is the file that got this wrong"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_calls_buf_generate_directly(workflow: Path):
    offenders = RAW_BUF_GENERATE.findall(_uncommented(workflow.read_text()))
    assert not offenders, (
        f"{workflow.name} invokes `buf generate` directly. Use `make generate` (or "
        f"`make generate-local`): raw buf output leaves the generated imports un-rooted and the "
        f"resulting package raises `ModuleNotFoundError: No module named 'seam'` on import. "
        f"See this test's module docstring."
    )


def test_the_makefile_target_still_does_the_rooting_this_guard_assumes():
    """The rule above is only worth enforcing while `make generate` is what makes the difference.

    If someone moves the rooting into buf itself (a managed-mode plugin, say) or renames the
    script, this test fails and the guard above should be re-examined rather than trusted.
    """
    makefile = (Path(__file__).resolve().parents[2] / "Makefile").read_text()
    generate = makefile.split("\ngenerate:", 1)[1].split("\n\n", 1)[0]
    assert "buf generate" in generate
    assert "root_gen.py" in generate, (
        "`make generate` no longer runs scripts/root_gen.py — either the rooting moved, in which "
        "case this whole guard needs rewriting, or the target just lost the step that makes the "
        "published wheel importable."
    )
