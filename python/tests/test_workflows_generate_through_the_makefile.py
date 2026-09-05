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
import yaml

WORKFLOWS = sorted(
    # `.yaml` too: GitHub Actions treats both suffixes identically, so globbing one leaves a
    # blind spot a single character wide — demonstrated with a `.yaml` file carrying a bare
    # `buf generate`, which passed every guard here.
    p
    for suffix in ("*.yml", "*.yaml")
    for p in (Path(__file__).resolve().parents[2] / ".github" / "workflows").glob(
        suffix
    )
)

# `buf generate` as a command, not as prose. A comment saying "NOT raw `buf generate`" is the right
# thing to write and must not trip this.
#
# The pattern used to require the invocation to open a LINE, and that is all it required. Measured,
# every one of these was accepted by the guard whose docstring says every wheel this repo ever
# published could not be imported:
#
#     - run: buf generate buf.build/zer07labs/seam          # the ordinary compact spelling
#       run: make lint && buf generate ...                  # chained
#       run: |
#         echo hi; buf generate ...                         # sequenced
#
# The first is not exotic — it is how most single-command steps in this repo's own workflows are
# written. A guard that only sees a command when it is the first thing on a line is watching
# formatting, not commands.
#
# So the scan is now per SHELL COMMAND, not per line: parse the workflow, walk every `run:` value,
# split it on the separators a shell uses, and look at the head of each segment.
BUF_GENERATE = re.compile(r"^buf\s+generate\b")

#: `\n`, `;`, `&&`, `||`, `|` and `&` — everything that starts a new command in a `run:` block.
SHELL_SEPARATORS = re.compile(r"[\n;&|]+")


def _run_steps(node: object) -> list[str]:
    """Every `run:` value anywhere in a parsed workflow, however deeply nested.

    Recursive because a `run:` lives at `jobs.<id>.steps[n].run`, and neither job ids nor step
    indices are knowable in advance. Walking the parsed tree rather than the raw text also means
    YAML comments are gone before the scan sees them — the parser drops them — which is a stronger
    version of the old whole-line-comment filter and needs no separate exemption.
    """
    if isinstance(node, dict):
        found = []
        for key, value in node.items():
            if key == "run" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_run_steps(value))
        return found
    if isinstance(node, list):
        return [r for item in node for r in _run_steps(item)]
    return []


def _commands(run: str) -> list[str]:
    """The head of each shell command in a `run:` value, comments dropped."""
    out = []
    for segment in SHELL_SEPARATORS.split(run):
        text = segment.strip()
        # A `#` comment INSIDE a run block is still prose about the rule, not an invocation.
        if text and not text.startswith("#"):
            out.append(text)
    return out


def test_there_are_workflows_to_check():
    """Anti-vacuity: a glob that matched nothing would make every assertion below pass."""
    assert WORKFLOWS, "no workflows found — this guard would silently check nothing"
    assert any(w.name == "publish.yml" for w in WORKFLOWS), (
        "publish.yml is the file that got this wrong"
    )


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_calls_buf_generate_directly(workflow: Path):
    parsed = yaml.safe_load(workflow.read_text())
    assert parsed is not None, (
        f"{workflow.name} did not parse; this guard would check nothing"
    )
    offenders = [
        command
        for run in _run_steps(parsed)
        for command in _commands(run)
        if BUF_GENERATE.match(command)
    ]
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


# ── Calibration: the guard against ITS OWN mutation ───────────────────────────────────────────────
# None of this repo's five real workflows contains `buf generate` — they all use `make generate`, and
# that is the point of the guard. So the parametrized test above passes on an empty offender list
# every time, and passed just as happily when the pattern was anchored with `^\s*` and could only see
# a command that opened a line. Blinding `_run_steps` to `return []` left the whole file green.
#
# A guard whose subject never appears in its inputs is only as good as its calibration. These cases
# ARE the inputs: synthetic workflows carrying each spelling, run through the same `_run_steps` /
# `_commands` / `BUF_GENERATE` the real test uses — never a reimplementation of them, which is the
# failure this phase found in the sibling guard next door.

_MUST_BE_CAUGHT = [
    (
        "compact, opens no line",
        "jobs:\n  a:\n    steps:\n      - run: buf generate buf.build/x\n",
    ),
    (
        "chained with &&",
        "jobs:\n  a:\n    steps:\n      - run: make lint && buf generate x\n",
    ),
    (
        "sequenced with ;",
        "jobs:\n  a:\n    steps:\n      - run: |\n          echo hi; buf generate x\n",
    ),
    ("piped", "jobs:\n  a:\n    steps:\n      - run: echo x | buf generate\n"),
    (
        "|| fallback",
        "jobs:\n  a:\n    steps:\n      - run: make generate || buf generate x\n",
    ),
    ("backgrounded with &", "jobs:\n  a:\n    steps:\n      - run: buf generate x &\n"),
    (
        "block scalar, own line",
        "jobs:\n  a:\n    steps:\n      - run: |\n          buf generate x\n",
    ),
    (
        "nested deeper than jobs.steps",
        "jobs:\n  a:\n    steps:\n      - uses: x\n        with:\n          cmd:\n            - run: buf generate x\n",
    ),
]

_MUST_NOT_BE_CAUGHT = [
    (
        "a YAML comment about the rule",
        "jobs:\n  a:\n    steps:\n      # NOT raw `buf generate`\n      - run: make generate\n",
    ),
    (
        "a `#` comment inside a run block",
        "jobs:\n  a:\n    steps:\n      - run: |\n          # not raw buf generate\n          make generate\n",
    ),
    (
        "the phrase as an echo argument",
        'jobs:\n  a:\n    steps:\n      - run: echo "buf generate"\n',
    ),
    (
        "a step named after it",
        "jobs:\n  a:\n    steps:\n      - name: never buf generate directly\n        run: make generate\n",
    ),
]


def _offenders(source: str) -> list[str]:
    """Exactly the pipeline `test_no_workflow_calls_buf_generate_directly` runs."""
    parsed = yaml.safe_load(source)
    return [
        command
        for run in _run_steps(parsed)
        for command in _commands(run)
        if BUF_GENERATE.match(command)
    ]


@pytest.mark.parametrize(
    "label,source", _MUST_BE_CAUGHT, ids=[c[0] for c in _MUST_BE_CAUGHT]
)
def test_the_guard_catches_each_spelling_of_a_direct_invocation(
    label: str, source: str
):
    assert _offenders(source), (
        f"the guard misses `buf generate` spelled as {label}:\n{source}\n"
        "Every one of these is a real invocation that would publish an unimportable wheel."
    )


@pytest.mark.parametrize(
    "label,source", _MUST_NOT_BE_CAUGHT, ids=[c[0] for c in _MUST_NOT_BE_CAUGHT]
)
def test_the_guard_does_not_fire_on_prose_about_the_rule(label: str, source: str):
    assert not _offenders(source), (
        f"the guard refuses {label}, which is prose rather than an invocation:\n{source}\n"
        "This repo's workflows are required to explain WHY they use `make generate`, so a guard "
        "that forbids naming the thing forbids the documentation."
    )


def test_the_walker_actually_reaches_the_commands_in_the_real_workflows():
    """Anti-vacuity for the parametrized test above, which asserts an EMPTY list.

    `assert not offenders` is satisfied just as well by a walker that returns nothing as by a clean
    workflow, so the two are indistinguishable without this. Blinding `_run_steps` to `return []`
    left every other test in this file green.
    """
    total = sum(
        len(_commands(run))
        for w in WORKFLOWS
        for run in _run_steps(yaml.safe_load(w.read_text()))
    )
    assert total > 50, (
        f"the walker found only {total} shell commands across {len(WORKFLOWS)} workflows. It is "
        "scanning far less than the repo actually contains, so the offender lists above are empty "
        "for the wrong reason."
    )
    ci = next(w for w in WORKFLOWS if w.name == "ci.yml")
    assert len(_run_steps(yaml.safe_load(ci.read_text()))) > 20, (
        "ci.yml alone has more than 20 `run:` steps; the recursive walk is not reaching them."
    )


def test_commands_yields_stripped_single_line_segments():
    """The contract that lets `BUF_GENERATE` anchor with a bare `^`.

    Reverting the pattern to the old `^\\s*buf\\s+generate\\b` with `re.MULTILINE` changes nothing —
    measured, every test in this file still passes. That is not a hole; it is a redundancy, and it
    holds only because `_commands` guarantees each segment is stripped and `\\n` is itself a
    separator, so no segment can carry leading space or a second line for an anchor to matter on.

    Nothing checked that guarantee, which made the anchor's correctness depend on a property of a
    different function that a future edit could drop silently. It is checked here instead, so the
    simple anchor stays justified rather than merely lucky.
    """
    messy = "  make lint  &&   buf generate x  \n\n   echo done ;  make generate  \n"
    segments = _commands(messy)
    assert segments, "the splitter returned nothing for a run block with four commands"
    for seg in segments:
        assert seg == seg.strip(), f"segment carries surrounding whitespace: {seg!r}"
        assert "\n" not in seg, f"segment spans more than one line: {seg!r}"
    assert any(s.startswith("buf generate") for s in segments), (
        f"the invocation did not survive splitting: {segments}"
    )
