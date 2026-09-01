"""Structural guard: no live suite may reintroduce the shape that produced #85.

Phase 2 removed three defects — fixed ports, unwaited teardown, discarded child output. Removing them
once is not the same as them staying removed: the next live fixture someone writes will be copied
from a neighbouring one, and the neighbour is now correct only for as long as nothing regresses. This
file is what makes the correction durable.

It reads the live suites as **source text**, not by importing them, so it runs everywhere and never
depends on ``SEAM_GRPC_BIN``. A guard that skips is not a guard.

**What it can and cannot see, stated honestly.** The detectors are AST-based and name-based, so they
catch the realistic regression — code copied from the old fixtures, in any of its ordinary spellings
(``subprocess.Popen``, ``from subprocess import Popen``, ``proc.terminate()``, ``proc.send_signal()``,
``from os import kill``). They do **not** catch a determined evasion: a port computed by arithmetic, a
spawn helper imported from a third module under a new name, a `ctypes` call. This is a regression
guard, not a sandbox, and it should not be read as proving the shape *cannot* return.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

HERE = Path(__file__).parent

#: The suites that spawn a real server. Named explicitly rather than globbed: a glob silently
#: shrinks to nothing when files are renamed, and a guard over zero files passes vacuously.
#: ``test_no_unregistered_file_spawns_a_server`` below is what keeps this list honest — a fifth live
#: suite added without registering it here would otherwise be invisible to every check in this file.
LIVE_SUITES = (
    "test_integration.py",
    "test_admin.py",
    "test_streamed_decode.py",
    "test_verify_attestation.py",
)

#: Files allowed to touch the live-server surface without being a live suite: the helper itself and
#: its own hermetic tests (which drive it with fake binaries), plus this guard.
_EXEMPT = {"live_server.py", "test_live_server_helper.py", Path(__file__).name}

#: A literal TCP port in the range the old fixtures squatted on. Matched as a bare word so it catches
#: BOTH spellings the old code used — `"127.0.0.1:8099"` and `data_port, mgmt_port = 8115, 8116`.
#: The colon-anchored pattern this replaced matched only the first, and so was blind to three of the
#: four collision sites it was written to find. This is the *historical* window only; the two rules
#: below are the ones that catch a fixed port at any number.
FIXED_PORT = re.compile(r"\b(8[0-9]{3})\b")

#: A whole-string loopback address with a literal port. Ports below 1024 are exempt: the helper
#: allocates ephemeral ports, an unprivileged process cannot bind there, and the two live uses
#: (``"127.0.0.1:0"``, an in-process gRPC server letting the OS choose; ``"127.0.0.1:1"``, a lazy
#: channel that is never dialed) are therefore incapable of colliding with a spawned server.
LOOPBACK_ADDR = re.compile(r"^(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]):(\d+)$")

#: Names that signal a process directly. Teardown belongs to the helper, which waits and escalates.
SIGNAL_NAMES = {"terminate", "kill", "send_signal", "killpg"}
#: Names that start one.
SPAWN_NAMES = {"Popen", "posix_spawn", "spawnv", "spawnl", "spawnvp"}
#: Names that throw the child's output away.
DISCARD_NAMES = {"DEVNULL"}
#: Spawns that are a defect only under a particular root — ``asyncio.run`` is ordinary and appears
#: at test_integration.py:245; ``subprocess.run`` is a spawn. Matched on the full dotted path, so the
#: bare-name rule above cannot be widened to ``run`` and start flagging the innocent one.
SPAWN_DOTTED = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "os.system",
        "os.popen",
    }
)


def _source(name: str) -> str:
    path = HERE / name
    assert path.exists(), f"{name} is named in LIVE_SUITES but does not exist"
    return path.read_text()


def _dotted(node: ast.AST) -> str:
    """``subprocess.run`` for the Attribute chain, ``""`` for anything that isn't a plain chain."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _name_hits(src: str, names: set[str], dotted: frozenset = frozenset()) -> list[str]:
    """Lines where source *code* touches one of ``names`` — as an attribute, as a bare name, or as
    an imported symbol.

    AST rather than line matching, and for a load-bearing reason: the live suites' module docstrings
    deliberately say "do not reintroduce ... a bare ``proc.terminate()`` here". A text scan flags that
    prose and forces the files to stop documenting what they prevent — a guard that punishes its own
    explanation. The parser sees only real code.

    Bare names and import aliases are checked as well as attributes, because
    ``from subprocess import Popen, DEVNULL`` and ``from os import kill`` are ordinary spellings that
    an attribute-only detector reads as clean source.
    """
    hits: list[str] = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Attribute):
            if node.attr in names or _dotted(node) in dotted:
                hits.append(f"line {node.lineno} ({node.attr})")
        elif isinstance(node, ast.Name):
            if node.id in names:
                hits.append(f"line {node.lineno} ({node.id})")
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                path = f"{node.module}.{alias.name}" if node.module else alias.name
                if alias.name in names or path in dotted:
                    hits.append(f"line {node.lineno} (import {alias.name})")
    return hits


def _port_offenders(src: str) -> list[str]:
    """Every fixed-port spelling this guard can see, in one pass.

    Three independent rules, because no single one is sufficient:

    1. **Assignment to a port-named target from an int literal** — ``DATA_PORT = 9113``. Catches a
       fixed port at *any* number, which the historical-window rule below cannot.
    2. **A whole-string loopback address with a literal port** — ``"127.0.0.1:9113"``. Same, for the
       string spelling.
    3. **The historical 8xxx window** — a bare ``8099`` anywhere, which is what a copy-paste of the
       old fixtures actually looks like.

    Deliberately NOT "any int that could be a port": ``test_integration.py`` legitimately holds
    ``BudgetLimits(tokens=5000)``, and a guard that reddens on a token budget is a guard someone
    deletes.
    """
    tree = ast.parse(src)
    offenders: list[str] = []

    for node in ast.walk(tree):
        # (1) `DATA_PORT = 9113`, `data_port, mgmt_port = 8115, 8116`
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = []
            values: list[ast.expr] = []
            for tgt in node.targets:
                if isinstance(tgt, ast.Tuple):
                    targets.extend(tgt.elts)
                else:
                    targets.append(tgt)
            if isinstance(node.value, ast.Tuple):
                values.extend(node.value.elts)
            else:
                values.append(node.value)
            for tgt, val in zip(targets, values):
                name = tgt.id if isinstance(tgt, ast.Name) else getattr(tgt, "attr", "")
                if (
                    "port" in name.lower()
                    and isinstance(val, ast.Constant)
                    and isinstance(val.value, int)
                    and not isinstance(val.value, bool)
                    and val.value >= 1024
                ):
                    offenders.append(f"line {node.lineno}: {name} = {val.value}")

        elif isinstance(node, ast.Constant):
            # (3) numeric literals in the historical window
            if isinstance(node.value, int) and not isinstance(node.value, bool):
                if 8000 <= node.value <= 8999:
                    offenders.append(f"line {node.lineno}: literal {node.value}")
            elif isinstance(node.value, str) and len(node.value) < 60:
                # (2) a whole-string loopback address with a real port
                m = LOOPBACK_ADDR.match(node.value)
                if m and int(m.group(1)) >= 1024:
                    offenders.append(f"line {node.lineno}: address {node.value!r}")
                # (3) again, for the string spelling — `"...:8099"` inside a longer literal
                elif FIXED_PORT.search(node.value):
                    offenders.append(f"line {node.lineno}: string {node.value!r}")

    return sorted(set(offenders))


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


def test_no_unregistered_file_spawns_a_server() -> None:
    """The other half of the floor above: ``LIVE_SUITES`` must be the *whole* set, not a subset.

    Every check in this file iterates that tuple, so a fifth live suite added without registering it
    here would be exempt from all of them while the file still reported green — the same
    "the search found nothing, so it passed" shape the anti-vacuity floor exists to close.
    """
    unregistered = sorted(
        p.name
        for p in HERE.glob("*.py")
        if p.name not in LIVE_SUITES
        and p.name not in _EXEMPT
        and any(
            marker in p.read_text()
            for marker in ("SEAM_GRPC_BIN", "spawn_server", "live_server")
        )
    )
    assert unregistered == [], (
        f"these files touch the live-server surface but are not in LIVE_SUITES: {unregistered}. "
        f"Add them, or this guard is silently blind to them."
    )


@pytest.mark.parametrize("name", LIVE_SUITES)
def test_no_live_suite_hardcodes_a_port(name: str) -> None:
    """Fixed ports are the collision surface. Ports come from the OS, one per spawn.

    Docstrings and comments are exempt: the module docstrings deliberately *name* the old ports
    (8099, 8115/8116, 8113/8114) to record what was fixed, and forbidding that would force the
    history out of the files that carry it.
    """
    offenders = _port_offenders(_source(name))
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
    hits = _name_hits(_source(name), SIGNAL_NAMES)
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
    hits = _name_hits(_source(name), DISCARD_NAMES)
    assert hits == [], (
        f"{name} discards the server's output at {hits}. live_server captures it — that log is the "
        f"artefact that makes the next #85 diagnosable."
    )


@pytest.mark.parametrize("name", LIVE_SUITES)
def test_no_live_suite_spawns_a_server_itself(name: str) -> None:
    """One spawn path, not five. ``subprocess.Popen`` in a live suite means a second one exists."""
    hits = _name_hits(_source(name), SPAWN_NAMES, SPAWN_DOTTED)
    assert hits == [], (
        f"{name} spawns its own process at {hits}; use live_server.spawn_server"
    )


def test_the_guard_would_actually_fire() -> None:
    """The guard's own red-first proof.

    Each check above asserts an *absence*, which is exactly the shape that passes when the detector
    is broken — the previous plan shipped two such tests. So run every detector against synthetic
    source that contains the defect, and assert each one finds it.

    The evasions listed here are the ones an independent reviewer demonstrated against the first
    version of this file, which used attribute access only and a fixed 8000-8999 window: every line
    marked "evaded before" passed that version while reintroducing all three #85 defects.
    """
    # Ports — the historical spellings...
    assert _port_offenders("data_port, mgmt_port = 8115, 8116\n"), (
        "numeric detector is blind"
    )
    assert _port_offenders('addr = "127.0.0.1:8099"\n'), "string detector is blind"
    # ...and the ones that evaded before, outside the 8xxx window.
    assert _port_offenders("DATA_PORT = 9113\n"), (
        "evaded before: port outside the 8xxx window"
    )
    assert _port_offenders('addr = "127.0.0.1:9113"\n'), (
        "evaded before: address outside the window"
    )
    # Innocent source must stay green — a guard that reddens on a token budget gets deleted.
    assert _port_offenders("limits = BudgetLimits(tokens=5000)\n") == []
    assert _port_offenders('port = server.add_insecure_port("127.0.0.1:0")\n') == []
    assert _port_offenders('client = SeamClient.connect("127.0.0.1:1")\n') == []
    assert (
        _port_offenders("data_port, mgmt_port = srv.data_port, srv.mgmt_port\n") == []
    )

    # Signalling — attribute, and the spellings that evaded before.
    assert _name_hits("proc.terminate()\n", SIGNAL_NAMES), "terminate detector is blind"
    assert _name_hits("proc.kill()\n", SIGNAL_NAMES), "kill detector is blind"
    assert _name_hits("proc.send_signal(signal.SIGTERM)\n", SIGNAL_NAMES), (
        "evaded before: send_signal"
    )
    assert _name_hits("from os import kill\nkill(proc.pid, 15)\n", SIGNAL_NAMES), (
        "evaded before: bare kill imported from os"
    )
    assert _name_hits("os.killpg(pgid, 15)\n", SIGNAL_NAMES), "evaded before: killpg"

    # Spawning — attribute, bare name, import, and the dotted-only case.
    assert _name_hits("subprocess.Popen([b])\n", SPAWN_NAMES), "Popen detector is blind"
    assert _name_hits("from subprocess import Popen\nPopen([b])\n", SPAWN_NAMES), (
        "evaded before: bare Popen"
    )
    assert _name_hits("subprocess.run([b])\n", SPAWN_NAMES, SPAWN_DOTTED), (
        "evaded before: subprocess.run"
    )
    assert _name_hits("os.posix_spawn(b, [b], {})\n", SPAWN_NAMES), (
        "evaded before: posix_spawn"
    )
    # ...but the ordinary `.run` that test_integration.py actually uses must NOT fire.
    assert _name_hits("asyncio.run(scenario())\n", SPAWN_NAMES, SPAWN_DOTTED) == [], (
        "the dotted rule must not turn `run` into a blanket ban — asyncio.run is innocent"
    )

    # Discarding output, including the bare-import spelling.
    assert _name_hits("f(stdout=subprocess.DEVNULL)\n", DISCARD_NAMES), (
        "DEVNULL detector is blind"
    )
    assert _name_hits(
        "from subprocess import DEVNULL\nf(stdout=DEVNULL)\n", DISCARD_NAMES
    ), "evaded before: bare DEVNULL"

    # And the prose exemption that motivated the AST approach in the first place.
    assert (
        _name_hits('"""do not call proc.terminate() here"""\n', SIGNAL_NAMES) == []
    ), "the detector must not fire on prose that names the defect it prevents"


def test_the_whole_evasion_fixture_is_caught() -> None:
    """One end-to-end proof, not five unit proofs.

    This is the exact replacement fixture an independent reviewer wrote to defeat the first version
    of this guard: it reintroduces all three #85 defects using nothing but ordinary spellings, and it
    passed every check in that version. It must now be caught by all three detectors.
    """
    evasion = (
        "from subprocess import DEVNULL, Popen\n"
        "from os import kill\n"
        "import signal\n"
        "\n"
        "DATA_PORT = 9113\n"
        "MGMT_PORT = 9114\n"
        "\n"
        "@pytest.fixture\n"
        "def dual_plane():\n"
        "    proc = Popen([binary], stdout=DEVNULL, stderr=DEVNULL)\n"
        "    _wait(DATA_PORT)\n"
        "    try:\n"
        '        yield f"127.0.0.1:{DATA_PORT}"\n'
        "    finally:\n"
        "        kill(proc.pid, signal.SIGTERM)\n"
    )
    assert _port_offenders(evasion), "fixed ports evade the guard"
    assert _name_hits(evasion, SPAWN_NAMES, SPAWN_DOTTED), "the spawn evades the guard"
    assert _name_hits(evasion, DISCARD_NAMES), "the discarded output evades the guard"
    assert _name_hits(evasion, SIGNAL_NAMES), "the unwaited teardown evades the guard"


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
