"""`ts/package.json` must declare a Node floor, and CI must actually exercise a version it allows.

The package shipped with no `engines` field at all, so `npm install` accepted it on any Node — while
CI only ever built and tested it on one. A consumer on Node 16 got no warning at install time and a
runtime failure later, in a crypto library, at the moment it was asked to verify something.

Declaring the floor is half the fix. The other half is this file, because a declared floor nobody
checks is the same shape of defect as the one it replaces: a number in a manifest that no run
compares against reality. `engines.node` and the workflows' `node-version` pins are two statements
of one fact, and this test is what keeps them one fact.

Deliberately a FLOOR and nothing else — there is no upper bound, and adding one would be a fabricated
constraint. The claim that Node >= 24 corrupts canonical JSON was investigated and refuted: it was a
harness artifact, Python's `str.splitlines()` splitting a single JSON-lines record in two because it
treats U+2028/U+2029/U+0085 as line terminators. The TypeScript suite passes on current Node. See
`DECISIONS.md` for the write-up; this comment exists so nobody re-derives the scare and pins a
ceiling against a bug that was never there.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
PACKAGE_JSON = ROOT / "ts" / "package.json"
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))


def _floor() -> int:
    engines = json.loads(PACKAGE_JSON.read_text()).get("engines", {})
    spec = engines.get("node")
    assert spec, (
        "ts/package.json declares no engines.node; npm will install this on any runtime"
    )
    match = re.fullmatch(r">=\s*(\d+)", spec.strip())
    assert match, (
        f"engines.node is {spec!r}; this guard only understands a bare '>=N' floor. If the range "
        "genuinely needs to be richer, widen the parser deliberately — do not loosen it to a "
        "substring check, which would accept an upper bound this repo has decided against."
    )
    return int(match.group(1))


def test_the_package_declares_a_node_floor() -> None:
    assert _floor() >= 18, (
        "a floor below 18 predates the Node versions this SDK's ESM output targets"
    )


def test_no_upper_bound_is_declared() -> None:
    """See the module docstring: the Node >= 24 report was a harness artifact, not a runtime bug."""
    _floor()  # fails first, and with a message about the missing field, if there is no engines.node
    spec = json.loads(PACKAGE_JSON.read_text())["engines"]["node"]
    for forbidden in ("<", "^", "~"):
        assert forbidden not in spec, (
            f"engines.node is {spec!r} — that bounds Node from above. The only reason ever offered "
            "for a ceiling here was refuted (see DECISIONS.md); pinning one strands consumers on "
            "current Node to guard against a bug that does not exist."
        )


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_ci_runs_a_node_version_the_package_claims_to_support(workflow: Path) -> None:
    """Every `node-version:` pin must satisfy the declared floor.

    A floor of `>=22` with CI on 20 would mean the SDK is tested only on a runtime it tells npm to
    refuse; a floor of `>=20` with CI on 18 would mean it is tested only on one npm would warn about.
    Either way the number in the manifest stops describing anything that was run.
    """
    text = workflow.read_text()
    pins = re.findall(r"""node-version:\s*['"]?(\d+)""", text)
    declared = len(re.findall(r"node-version:", text))
    # Counted, not merely "are there any?". A `node-version: ${{ matrix.node }}` matches no digit,
    # and the first version of this test skipped on it — except ci.yml pins Node in TWO jobs, so one
    # unreadable pin was masked by the other readable one and the mutation passed. An unreadable pin
    # is a FAILURE, not a skip, and it has to be counted per pin or a sibling covers for it.
    assert len(pins) == declared, (
        f"{workflow.name} has {declared} node-version pin(s) but only {len(pins)} this test can "
        f"read (a matrix or an expression?). Teach the pattern to resolve it — an unreadable pin "
        f"leaves the engines.node floor unverified in a workflow that selects the runtime."
    )
    if not pins:
        pytest.skip(f"{workflow.name} sets up no Node")
    floor = _floor()
    for pin in pins:
        assert int(pin) >= floor, (
            f"{workflow.name} runs Node {pin}, below the floor engines.node declares (>={floor})"
        )


def test_at_least_one_workflow_actually_pins_node() -> None:
    """Without this, the parametrized test above skips its way to green if the pins are ever renamed.

    `node-version` is `actions/setup-node`'s input name, not a law; a migration to a different
    action, or to a matrix spelling this regex misses, would silently leave the floor unchecked.
    """
    pinned = [
        w.name
        for w in WORKFLOWS
        if re.search(r"""node-version:\s*['"]?\d""", w.read_text())
    ]
    assert pinned, (
        "no workflow pins a node-version this test can read — the floor is now unverified. "
        "Update the pattern to match however Node is selected, do not delete this assertion."
    )
