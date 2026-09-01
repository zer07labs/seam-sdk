"""Structural guard: no live suite may reintroduce the shape that produced #85.

Phase 2 removed three defects — fixed ports, unwaited teardown, discarded child output. Removing them
once is not the same as them staying removed: the next live fixture someone writes will be copied
from a neighbouring one, and the neighbour is now correct only for as long as nothing regresses. This
file is what makes the correction durable.

It reads the live suites as **source text**, not by importing them, so it runs everywhere and never
depends on ``SEAM_GRPC_BIN``. A guard that skips is not a guard.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

HERE = Path(__file__).parent

#: The suites that spawn a real server. Named explicitly rather than globbed: a glob silently
#: shrinks to nothing when files are renamed, and a guard over zero files passes vacuously.
LIVE_SUITES = (
    "test_integration.py",
    "test_admin.py",
    "test_streamed_decode.py",
    "test_verify_attestation.py",
)

#: A literal TCP port in the range the old fixtures squatted on. Matched as a bare word so it catches
#: BOTH spellings the old code used — `"127.0.0.1:8099"` and `data_port, mgmt_port = 8115, 8116`.
#: The colon-anchored pattern this replaced matched only the first, and so was blind to three of the
#: four collision sites it was written to find.
FIXED_PORT = re.compile(r"\b(8[0-9]{3})\b")


def _source(name: str) -> str:
    path = HERE / name
    assert path.exists(), f"{name} is named in LIVE_SUITES but does not exist"
    return path.read_text()


def _attribute_hits(src: str, names: set[str]) -> list[str]:
    """Lines where source *code* touches one of ``names`` as an attribute.

    AST rather than line matching, and for a load-bearing reason: the live suites' module docstrings
    deliberately say "do not reintroduce ... a bare ``proc.terminate()`` here". A text scan flags that
    prose and forces the files to stop documenting what they prevent — a guard that punishes its own
    explanation. The parser sees only real attribute access.
    """
    return [
        f"line {node.lineno} ({node.attr})"
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Attribute) and node.attr in names
    ]


def test_every_named_live_suite_exists_and_spawns() -> None:
    """Anti-vacuity floor.

    Every assertion below is a search over ``LIVE_SUITES``. If a file were renamed or dropped, those
    searches would find nothing and report success. This pins the denominator first: all four files
    exist, and each actually spawns a server through the shared helper.
    """
    assert len(LIVE_SUITES) == 4
    for name in LIVE_SUITES:
        src = _source(name)
        assert "from live_server import spawn_server" in src, (
            f"{name} does not import the shared helper — if it spawns a server another way, this "
            f"guard cannot see it"
        )
        assert "spawn_server(" in src, f"{name} imports the helper but never calls it"


@pytest.mark.parametrize("name", LIVE_SUITES)
def test_no_live_suite_hardcodes_a_port(name: str) -> None:
    """Fixed ports are the collision surface. Ports come from the OS, one per spawn.

    Docstrings and comments are exempt: the module docstrings deliberately *name* the old ports
    (8099, 8115/8116, 8113/8114) to record what was fixed, and forbidding that would force the
    history out of the files that carry it.
    """
    tree = ast.parse(_source(name))
    offenders: list[str] = []

    for node in ast.walk(tree):
        # Numeric literals: `data_port, mgmt_port = 8115, 8116`
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            if 8000 <= node.value <= 8999:
                offenders.append(f"line {node.lineno}: literal {node.value}")
        # String literals: `addr = "127.0.0.1:8099"`. Docstrings are ast.Constant too, so skip any
        # string long enough to be prose — a real address literal is short.
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) < 60 and FIXED_PORT.search(node.value):
                offenders.append(f"line {node.lineno}: string {node.value!r}")

    assert offenders == [], (
        f"{name} hardcodes a TCP port: {offenders}. Use live_server.spawn_server, which allocates "
        f"one per spawn — see #85."
    )


@pytest.mark.parametrize("name", LIVE_SUITES)
def test_no_live_suite_tears_down_without_waiting(name: str) -> None:
    """``proc.terminate()`` returns immediately; the process may still hold its listening socket.

    Teardown belongs to the helper, which escalates to SIGKILL and waits. A suite calling
    ``terminate()`` directly has its own teardown path again, which is how nine of these accumulated.
    """
    hits = _attribute_hits(_source(name), {"terminate", "kill"})
    assert hits == [], (
        f"{name} signals a process directly at {hits}. Teardown belongs to live_server._stop, "
        f"which waits and escalates."
    )


@pytest.mark.parametrize("name", LIVE_SUITES)
def test_no_live_suite_discards_the_servers_output(name: str) -> None:
    """#85: "every re-run destroys the only copy of the explanation".

    The helper writes the child's stdout+stderr to a file and surfaces its tail in failures. A suite
    passing DEVNULL has gone back to spawning its own server.
    """
    hits = _attribute_hits(_source(name), {"DEVNULL"})
    assert hits == [], (
        f"{name} discards the server's output at {hits}. live_server captures it — that log is the "
        f"artefact that makes the next #85 diagnosable."
    )


@pytest.mark.parametrize("name", LIVE_SUITES)
def test_no_live_suite_spawns_a_server_itself(name: str) -> None:
    """One spawn path, not five. ``subprocess.Popen`` in a live suite means a second one exists."""
    hits = _attribute_hits(_source(name), {"Popen"})
    assert hits == [], (
        f"{name} spawns its own process at {hits}; use live_server.spawn_server"
    )


def test_the_guard_would_actually_fire() -> None:
    """The guard's own red-first proof.

    Each check above asserts an *absence*, which is exactly the shape that passes when the detector
    is broken — the previous plan shipped two such tests. So run every detector against synthetic
    source that contains the defect, and assert each one finds it.
    """
    bad_int = "data_port, mgmt_port = 8115, 8116\n"
    bad_str = 'addr = "127.0.0.1:8099"\n'

    def offenders_for(src: str) -> list:
        tree = ast.parse(src)
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, int):
                if 8000 <= node.value <= 8999:
                    out.append(node.value)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if len(node.value) < 60 and FIXED_PORT.search(node.value):
                    out.append(node.value)
        return out

    assert offenders_for(bad_int) == [8115, 8116], (
        "the numeric-literal detector is blind"
    )
    assert offenders_for(bad_str) == ["127.0.0.1:8099"], "the string detector is blind"
    assert offenders_for('x = "no ports here"\n') == [], (
        "the detector fires on innocent source"
    )

    # And the attribute detectors, including the prose exemption that motivated them.
    assert _attribute_hits("proc.terminate()\n", {"terminate", "kill"}), (
        "terminate detector is blind"
    )
    assert _attribute_hits("proc.kill()\n", {"terminate", "kill"}), (
        "kill detector is blind"
    )
    assert _attribute_hits("f(stdout=subprocess.DEVNULL)\n", {"DEVNULL"}), (
        "DEVNULL detector is blind"
    )
    assert _attribute_hits("subprocess.Popen([b])\n", {"Popen"}), (
        "Popen detector is blind"
    )
    assert (
        _attribute_hits('"""do not call proc.terminate() here"""\n', {"terminate"})
        == []
    ), "the detector must not fire on prose that names the defect it prevents"


def test_the_helper_itself_is_exempt_and_owns_the_teardown() -> None:
    """``live_server.py`` is the one place allowed to call terminate/kill/Popen. Asserting that here
    keeps the exemption explicit rather than implicit in the file list above."""
    src = (HERE / "live_server.py").read_text()
    assert "proc.terminate()" in src
    assert "proc.kill()" in src
    assert "subprocess.Popen" in src
    assert "proc.wait(" in src, (
        "teardown must WAIT, not merely signal — that is the whole point"
    )
