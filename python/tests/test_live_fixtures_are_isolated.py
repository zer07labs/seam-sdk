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

#: A literal TCP port in the range the old fixtures squatted on, matched inside a *string* constant.
#: Bare integers go through the separate numeric range check in ``_port_offenders`` — two mechanisms,
#: because a regex over source text is what this replaced and it was blind to three of the four
#: collision sites. This is the *historical* window only; rules (1) and (2) below are the ones that
#: catch a fixed port at any number. Its cost is a known false-positive surface: `timeout_ms = 8000`
#: or `max_bytes = 8192` in a live suite would redden. That has not happened, and the alternative —
#: dropping the window — loses the spelling a copy-paste of the old fixtures actually produces.
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


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """``{"sp": "subprocess"}`` for every ``import x as y``. **Aliased imports only.**

    Without this, ``import subprocess as sp`` followed by ``sp.run([binary])`` resolves to ``sp.run``,
    which is in no banned set — an ordinary spelling, not a contrived evasion.

    The ``asname`` guard is load-bearing, and its absence made this function *lose* hits. The first
    version also recorded unaliased imports, so ``import os.path`` mapped ``os -> os.path`` and
    ``os.system(...)`` resolved to ``os.path.system`` — matching nothing. A helper added to widen the
    detector narrowed it instead, which is the same "calibrated against the motivating example, never
    re-run against what already matched" mistake the calibration test below exists to stop. It went
    unnoticed because the red-first proof exercised one of the five ``SPAWN_DOTTED`` entries; it now
    exercises all of them.
    """
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    out[alias.asname] = alias.name
    return out


def _dotted(node: ast.AST, aliases: dict[str, str] | None = None) -> str:
    """``subprocess.run`` for the Attribute chain, ``""`` for anything that isn't a plain chain.

    The root is resolved through ``aliases`` so an aliased import lands on its real module name.
    """
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append((aliases or {}).get(node.id, node.id))
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
    tree = ast.parse(src)
    aliases = _import_aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr in names or _dotted(node, aliases) in dotted:
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


def _docstring_ids(tree: ast.AST) -> set[int]:
    """Identities of the string constants that are docstrings.

    The exemption the module-level comment promises has to be *real*. The first version leaned on a
    ``len(value) < 60`` cutoff, which is not an exemption but a coincidence: it happened to spare the
    live suites' docstrings while ``test_streamed_decode.py``'s — which names 8113/8114 — sat 27
    characters from firing, and it simultaneously blinded the string rule to a fixed port buried in a
    long argv-style literal. Skipping docstring nodes by identity does exactly what it says instead.
    """
    out: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            not isinstance(
                node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            )
            or not body
        ):
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            out.add(id(first.value))
    return out


def _assigned_pairs(node: ast.AST):
    """``(target_name, value_node)`` for every assignment form, tuples and lists flattened.

    ``ast.Assign`` alone was not enough: ``DATA_PORT: int = 9113`` is an ``ast.AnnAssign`` and a
    dataclass field is too — and ``live_server.LiveServer`` is itself a dataclass, so that is the
    idiom a copied fixture reaches for. ``PORTS = [9113, 9114]`` (a list, where the first version
    only unpacked tuples) was the same kind of arbitrary hole.
    """

    def _flat(x):
        if isinstance(x, (ast.Tuple, ast.List)):
            return list(x.elts)
        return [x]

    if isinstance(node, ast.Assign):
        targets = [t for tgt in node.targets for t in _flat(tgt)]
        values = _flat(node.value)
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        targets, values = _flat(node.target), _flat(node.value)
    else:
        return []
    # A bare `PORTS = [9113, 9114]` has one target and many values; pair them all against it.
    if len(targets) == 1 and len(values) > 1:
        return [(targets[0], v) for v in values]
    return list(zip(targets, values))


def _names_a_port(name: str) -> bool:
    """True for ``port``/``data_port``/``mgmtPort``, false for ``support``/``report``/``transport``.

    A substring test reddens on the SDK's own vocabulary — ``report_*``, ``transport``, ``export`` are
    everywhere — and rule (1b) below applies this to every keyword argument, function default and
    dict key in the guarded files, so a substring would have made the guard noisy enough to delete.
    """
    # Split camelCase only where a lowercase letter meets an uppercase one, so ALL_CAPS survives:
    # a blanket "before any uppercase" rule shatters DATA_PORT into single letters and the whole
    # historical spelling stops matching. (It did, on the first attempt.)
    words = re.split(
        r"[^a-z0-9]+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()
    )
    return any(w in {"port", "ports"} for w in words)


def _is_port_literal(node: ast.AST) -> bool:
    """An int constant big enough to be a real, bindable TCP port."""
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
        and node.value >= 1024
    )


def _defaults(args: ast.arguments):
    """``(arg, default)`` pairs for positional and keyword-only parameters alike."""
    positional = list(args.posonlyargs) + list(args.args)
    for arg, default in zip(
        positional[len(positional) - len(args.defaults) :], args.defaults
    ):
        yield arg, default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default is not None:
            yield arg, default


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
    deletes. Rule 1 is what buys coverage outside the 8xxx window without that cost, because a
    *port-named target* is the thing being asserted about, not the number.

    Docstrings are exempt by identity (see ``_docstring_ids``); comments are invisible to the parser
    and so are exempt for free.
    """
    tree = ast.parse(src)
    docstrings = _docstring_ids(tree)
    offenders: list[str] = []

    for node in ast.walk(tree):
        # (1) `DATA_PORT = 9113`, `data_port, mgmt_port = 8115, 8116`, `port: int = 9113`
        for tgt, val in _assigned_pairs(node):
            name = tgt.id if isinstance(tgt, ast.Name) else getattr(tgt, "attr", "")
            if (
                _names_a_port(name)
                and isinstance(val, ast.Constant)
                and isinstance(val.value, int)
                and not isinstance(val.value, bool)
                and val.value >= 1024
            ):
                offenders.append(f"line {node.lineno}: {name} = {val.value}")

        # (1b) the other ways a port-named thing is bound to a literal: a keyword argument
        # (`LiveServer(data_port=9113)`), a function default (`def spawn(data_port=9113)`), and a
        # dict entry (`CFG = {"data_port": 9113}`). The assignment form alone justified itself by
        # "a dataclass is the idiom a copied fixture reaches for" — but *constructing* that dataclass
        # and `field(default=...)` are both keyword arguments, so the justification argued for these.
        if isinstance(node, ast.keyword) and node.arg and _names_a_port(node.arg):
            if _is_port_literal(node.value):
                offenders.append(
                    f"line {node.value.lineno}: {node.arg}={node.value.value}"
                )
        elif isinstance(node, ast.arguments):
            for arg, default in _defaults(node):
                if _names_a_port(arg.arg) and _is_port_literal(default):
                    offenders.append(
                        f"line {default.lineno}: {arg.arg}={default.value}"
                    )
        elif isinstance(node, ast.Dict):
            for key, val in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and _names_a_port(key.value)
                    and _is_port_literal(val)
                ):
                    offenders.append(f"line {val.lineno}: {key.value!r}: {val.value}")

        if isinstance(node, ast.Constant) and id(node) not in docstrings:
            # (3) numeric literals in the historical window
            if isinstance(node.value, int) and not isinstance(node.value, bool):
                if 8000 <= node.value <= 8999:
                    offenders.append(f"line {node.lineno}: literal {node.value}")
            elif isinstance(node.value, str):
                # (2) a whole-string loopback address with a real port
                m = LOOPBACK_ADDR.match(node.value)
                if m and int(m.group(1)) >= 1024:
                    offenders.append(f"line {node.lineno}: address {node.value!r}")
                # (3) again, for the string spelling — `"...:8099"` inside a longer literal
                elif FIXED_PORT.search(node.value):
                    offenders.append(f"line {node.lineno}: string {node.value!r}")

    return sorted(set(offenders))


#: Calling one of these is how a test reaches a server it just spawned. This is the discriminator,
#: and it was chosen by measurement over BOTH sets rather than by intuition: it is present in all four
#: registered live suites and absent from all four files here that spawn subprocesses for ordinary
#: reasons (running the conformance CLI, building a wheel, importing in a clean interpreter).
#:
#: ``connect_ex`` is here because it was a verified false negative (issue #92 §2): it is the
#: canonical NON-RAISING readiness probe, so a suite that polls with ``sock.connect_ex(...)`` and
#: then reaches the server through a locally-named wrapper went undetected. That is not a contrived
#: shape — it is what you write when you do not want an exception per failed poll.
CONNECT_NAMES = {
    "connect",
    "connect_ex",
    "create_connection",
    "insecure_channel",
    "secure_channel",
}


def _looks_like_a_live_suite(src: str) -> str:
    """Why ``src`` looks like a suite that spawns a live server, or ``""`` if it does not.

    Two independent signals, both from the AST so prose cannot trip either one:

    * it imports ``live_server`` — an unambiguous declaration;
    * it **spawns a process and then connects a client to it**. That conjunction is the definition of
      a live suite, and it is why ``test_conformance.py``, ``test_packaging.py``,
      ``test_field_manifest_gate.py`` and ``test_errors_is_import_light.py`` — which all legitimately
      spawn subprocesses and read their output — are not flagged. Eleven other files here *connect*
      without spawning; the conjunction excludes those too.

    **The previous version of this used ``socket``/``grpc`` imports as the second signal, and it was
    wrong.** Three of the four suites in ``LIVE_SUITES`` import neither. It was calibrated against the
    four innocent files it must not redden and never re-run against the true positives already in this
    directory, so a de-adopted copy of ``test_integration.py`` — fixed ports, raw ``Popen``, ``DEVNULL``,
    bare ``terminate()`` — passed the whole guard. That is the third round in a row a detector was
    tuned only against its negative set; ``test_the_detector_is_calibrated_against_real_live_suites``
    below is what stops the fourth.

    A raw fixture that does neither — spawning through a helper imported from a third module under a
    new name — is out of reach. The module docstring says so rather than implying a sandbox.
    """
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return ""
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    if "live_server" in imported:
        return "imports live_server"
    # NON-BLOCKING spawns only. ``subprocess.run``/``call``/``check_call``/``os.system`` all wait
    # for the child to exit, so they cannot start a server you then connect to — the call would
    # never return. Including them (issue #92 §3) left the guard resting on the accident that no
    # file both used one and called a CONNECT_NAME: eleven files here connect without spawning, and
    # any one of them adding `subprocess.run([sys.executable, "-c", ...])` — the idiom
    # ``test_errors_is_import_light.py`` already uses — would have been reported as an unregistered
    # live suite. They stay in ``SPAWN_DOTTED`` for ``test_no_live_suite_spawns_a_server_itself``,
    # which asks a different question: not "is this a live suite" but "does a live suite spawn
    # anything for itself".
    spawns = _name_hits(src, SPAWN_NAMES)
    connects = _name_hits(src, CONNECT_NAMES)
    if spawns and connects:
        return f"spawns a process at {spawns} and connects to it at {connects}"
    return ""


def _deadopt(src: str) -> str:
    """``src`` with the shared helper torn back out and the #85 shape put back.

    Not a synthetic fixture — the real file, regressed the way a real regression happens: someone
    copies a suite, drops the import they do not understand, and reinstates a local spawn. Used by the
    calibration test below, which is the only thing that checks the detector against a *positive*.
    """
    out = src.replace(
        "from live_server import spawn_server",
        "import subprocess\n\nDATA_PORT = 9113\n\n\n"
        "def _spawn_raw(binary):\n"
        "    return subprocess.Popen(\n"
        "        [binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL\n"
        "    )",
    )
    assert out != src, "the suite no longer imports the helper the way _deadopt expects"
    return out


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

    The scan itself gets a floor for the same reason. An independent reviewer broke the first version
    of this test by pointing its glob at ``*.NOPE``: the scan found no files, the absence assertion
    held, and all 21 tests passed. Asserting the denominator is the only thing that catches that.
    """
    scanned = sorted(HERE.glob("*.py"))
    assert len(scanned) >= 30, (
        f"the scan found only {len(scanned)} files in {HERE} — the glob is broken, and every "
        f"assertion below would pass over nothing"
    )
    checked = [
        p for p in scanned if p.name not in LIVE_SUITES and p.name not in _EXEMPT
    ]
    assert len(checked) >= 25, (
        f"only {len(checked)} files left after exemptions — _EXEMPT has grown into a blanket"
    )

    unregistered = {}
    for path in checked:
        reason = _looks_like_a_live_suite(path.read_text())
        if reason:
            unregistered[path.name] = reason
    assert unregistered == {}, (
        f"these files look like live suites but are not in LIVE_SUITES: {unregistered}.\n"
        f"Two different situations, and only one of them is fixed by editing LIVE_SUITES:\n"
        f"  * it really does spawn a server and talk to it — then it must spawn through "
        f"`live_server.spawn_server` FIRST, and only then be registered here. Registering a file "
        f"that still spawns for itself just moves the failure to "
        f"`test_no_live_suite_spawns_a_server_itself`.\n"
        f"  * it spawns a subprocess for some unrelated reason and happens to call a name in "
        f"CONNECT_NAMES ({sorted(CONNECT_NAMES)}) — then this is a false positive, and the fix is "
        f"to narrow the discriminator here, NOT to register the file or add it to _EXEMPT."
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
    # ...and the two assignment forms the first version could not see.
    assert _port_offenders("DATA_PORT: int = 9113\n"), (
        "evaded before: an annotated assignment"
    )
    assert _port_offenders("PORTS = [9113, 9114]\n"), "evaded before: a list of ports"
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
    # EVERY dotted entry, not just the one that motivated the set. Exercising a single entry is how
    # `_import_aliases` was able to silently stop resolving four of the five: the proof was as narrow
    # as the bug.
    for dotted in sorted(SPAWN_DOTTED):
        module, leaf = dotted.rsplit(".", 1)
        assert _name_hits(
            f"import {module}\n{dotted}(['x'])\n", SPAWN_NAMES, SPAWN_DOTTED
        ), f"{dotted} is in SPAWN_DOTTED but the detector does not see it"
        # ...and through an alias, which is what _import_aliases exists for.
        assert _name_hits(
            f"import {module} as _m\n_m.{leaf}(['x'])\n", SPAWN_NAMES, SPAWN_DOTTED
        ), f"{dotted} evades when the module is imported under an alias"
    # A dotted *submodule* import must not knock out the parent's own banned attributes. Recording a
    # mapping for an unaliased import made `import os.path` resolve `os.system` to `os.path.system`.
    assert _name_hits("import os.path\nos.system('x')\n", SPAWN_NAMES, SPAWN_DOTTED), (
        "an unaliased dotted import must not blind the detector to the parent module"
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

    # And the prose exemption that motivated the AST approach in the first place — for the name
    # detectors, and for the port detectors, whose exemption used to be a length coincidence.
    assert (
        _name_hits('"""do not call proc.terminate() here"""\n', SIGNAL_NAMES) == []
    ), "the detector must not fire on prose that names the defect it prevents"
    assert _port_offenders('def f():\n    """was 8099 before #85"""\n') == [], (
        "a docstring naming the old port must be exempt — by identity, not by being short enough"
    )
    assert _port_offenders(
        'x = "--listen=127.0.0.1:8099 --and-a-long-tail-of-other-flags-here"\n'
    ), (
        "a fixed port inside a long literal must NOT be exempt; the old len<60 cutoff missed it"
    )


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


def test_an_unregistered_raw_live_suite_is_caught() -> None:
    """H2's proof: the registry check must catch a suite that never names the helper.

    An independent reviewer dropped exactly this file into the directory and all 21 tests passed —
    the first version searched for the substrings ``SEAM_GRPC_BIN``/``spawn_server``/``live_server``,
    so a fixture spawning its own server under a different env var was invisible to the very check
    written to close that hole.
    """
    raw = (
        "import os, socket, subprocess\n"
        "DATA_PORT = 9113\n"
        "def fixture():\n"
        "    p = subprocess.Popen([os.environ['SEAMD_BIN']], stdout=subprocess.DEVNULL)\n"
        "    socket.create_connection(('127.0.0.1', DATA_PORT))\n"
        "    p.terminate()\n"
    )
    assert _looks_like_a_live_suite(raw), (
        "a raw live suite that never names the helper evades"
    )
    assert _looks_like_a_live_suite("from live_server import spawn_server\n"), (
        "a suite that imports the helper evades"
    )


def test_the_detector_is_calibrated_against_real_live_suites() -> None:
    """The check no round performed, and the reason three rounds of this guard were evadable.

    Every previous version of ``_looks_like_a_live_suite`` was tuned until a reviewer's synthetic
    example was caught and the four known-innocent files stayed green. Nobody ran it against the
    **true positives already in this directory**. Had they, the ``socket``/``grpc`` signal would have
    died in one line: three of the four registered suites import neither.

    So this asserts the positive direction directly. Each registered suite is de-adopted — the helper
    import torn out, a raw ``Popen`` with ``DEVNULL`` and a fixed port put back, which is exactly what
    the regression looks like — and the detector must catch all four. A future narrowing of the signal
    cannot pass this without being checked against the files it exists to protect.
    """
    missed = []
    for name in LIVE_SUITES:
        regressed = _deadopt(_source(name))
        if not _looks_like_a_live_suite(regressed):
            missed.append(name)
    assert missed == [], (
        f"a de-adopted copy of {missed} would sit in python/tests/ unregistered and unguarded — "
        f"the detector is calibrated against innocent files only"
    )

    # ...and the de-adopted copy must also trip the three defect detectors, not merely the registry.
    regressed = _deadopt(_source("test_integration.py"))
    assert _port_offenders(regressed), (
        "the fixed port in a de-adopted suite is invisible"
    )
    assert _name_hits(regressed, SPAWN_NAMES, SPAWN_DOTTED), (
        "the raw spawn is invisible"
    )
    assert _name_hits(regressed, DISCARD_NAMES), "the discarded output is invisible"


def test_the_helper_itself_hardcodes_no_port() -> None:
    """``live_server.py`` is exempt from the spawn and teardown rules — it owns both — but nothing
    exempts it from the port rule, and a fixed port *there* is the worst available regression: it
    would put every suite back on one socket at once."""
    assert _port_offenders((HERE / "live_server.py").read_text()) == [], (
        "the helper that exists to allocate ports must not contain one"
    )


def test_the_registry_check_does_not_fire_on_innocent_files() -> None:
    """The conjunction is load-bearing.

    Four real files here spawn subprocesses for entirely ordinary reasons — running the conformance
    CLI, building a wheel, importing in a clean interpreter — and none opens a socket. A rule on
    "spawns anything" would redden all four, and this guard would be deleted rather than fixed.
    """
    assert (
        _looks_like_a_live_suite('import subprocess\nsubprocess.run(["x"])\n') == ""
    ), "spawning without talking TCP is not a live suite"
    assert (
        _looks_like_a_live_suite('"""See live_server for the shared spawn helper."""\n')
        == ""
    ), "prose naming the helper must not register a file as a live suite"
    for name in (
        "test_conformance.py",
        "test_packaging.py",
        "test_field_manifest_gate.py",
        "test_errors_is_import_light.py",
    ):
        assert _looks_like_a_live_suite((HERE / name).read_text()) == "", (
            f"{name} spawns subprocesses legitimately and must not be flagged"
        )


#: The real pre-#85 fixtures, as they stood at ``960cf81``, vendored as inert ``.txt`` data.
#: See the header inside each file. This is the positive corpus for the calibration below.
PRE85 = HERE / "fixtures" / "pre-85"


def test_the_vendored_corpus_is_present_and_untouched() -> None:
    """Anti-vacuity floor for the calibration below, which is otherwise a loop over a glob.

    An empty or renamed directory makes every assertion in it pass over nothing — the exact shape
    ``test_no_unregistered_file_spawns_a_server`` already had to be fixed for once.
    """
    found = sorted(p.name for p in PRE85.glob("*.py.txt"))
    assert found == [
        "test_admin.py.txt",
        "test_integration.py.txt",
        "test_streamed_decode.py.txt",
        "test_verify_attestation.py.txt",
    ], f"the pre-85 corpus is {found}; it must be the four suites LIVE_SUITES names"

    for path in PRE85.glob("*.py.txt"):
        src = path.read_text(encoding="utf-8")
        assert "VENDORED TEST DATA" in src, f"{path.name} lost its header"
        assert "from live_server import" not in src, (
            f"{path.name} imports the shared helper, so it is not a PRE-fix fixture at all — "
            f"someone regenerated it from the wrong commit and the corpus now proves nothing"
        )


@pytest.mark.parametrize(
    "name", sorted(p.name for p in (HERE / "fixtures" / "pre-85").glob("*.py.txt"))
)
def test_the_detector_fires_on_the_real_pre_85_fixtures(name: str) -> None:
    """Calibration against a positive corpus the guard did not author (issue #92 §1).

    ``test_the_detector_is_calibrated_against_real_live_suites`` uses ``_deadopt``, which INJECTS
    ``subprocess.Popen``, ``subprocess.DEVNULL`` and ``DATA_PORT = 9113`` into the source it
    produces — the very tokens the detector keys on. It therefore confirms the detector can see its
    own graft, and nothing more: swapping ``CONNECT_NAMES`` for ``DISCARD_NAMES``, a strictly worse
    discriminator, left that test green while the detector went blind to a raw live suite.

    These four files were extracted from git at ``960cf81`` by AST and not edited. Every token below
    is one the pre-fix fixtures really contained.
    """
    src = (PRE85 / name).read_text(encoding="utf-8")

    reason = _looks_like_a_live_suite(src)
    assert reason, (
        f"{name} is a real live suite from before #85 and the detector does not recognise it. "
        f"Whatever narrowing was just made to CONNECT_NAMES/SPAWN_NAMES is too aggressive: this "
        f"corpus is the floor, and it is the one thing here that cannot be satisfied by adjusting "
        f"the graft to match the detector."
    )

    assert _name_hits(src, DISCARD_NAMES), (
        f"{name} should show the DEVNULL it really had"
    )
    assert _name_hits(src, SIGNAL_NAMES), (
        f"{name} should show the unwaited terminate() it really had"
    )


def test_the_pre_85_corpus_still_carries_the_fixed_ports() -> None:
    """The port detector needs a positive too, and only two of the four fixtures had a literal
    port — the other two took theirs from the environment. Pinning WHICH two keeps this honest: a
    blanket "some file has a port" would survive the detector going blind on the other one."""
    with_ports = {
        p.name for p in PRE85.glob("*.py.txt") if _port_offenders(p.read_text())
    }
    assert with_ports == {"test_integration.py.txt", "test_streamed_decode.py.txt"}, (
        f"the pre-85 files carrying hardcoded ports are now {with_ports}. Those two are the ones "
        f"that really used 8099/8115 and 8113/8114; if this set changed, either the corpus was "
        f"regenerated from a different commit or _port_offenders stopped seeing a literal port."
    )


def test_the_connect_signal_cannot_be_swapped_for_the_discard_signal() -> None:
    """``CONNECT_NAMES`` must be doing the discriminating, not riding along with ``DISCARD_NAMES``.

    Issue #92 demonstrated the hole: replacing ``CONNECT_NAMES`` with ``DISCARD_NAMES`` in
    ``_looks_like_a_live_suite`` — a strictly worse discriminator — left the whole file green,
    because every positive available to the guard happened to contain a ``DEVNULL`` too. The
    vendored pre-85 corpus does not fix that on its own: those fixtures really did discard output,
    so they satisfy both signals equally.

    What separates the two is a live suite that CAPTURES its server's output — which is not
    hypothetical, it is what `live_server.py` does today, and what #85 asked for. Derived from the
    real corpus by the single substitution that makes it, so the shape stays a real one.
    """
    real = (PRE85 / "test_integration.py.txt").read_text(encoding="utf-8")
    captures = real.replace("subprocess.DEVNULL", "subprocess.PIPE")
    assert "subprocess.DEVNULL" not in captures, (
        "the corpus file no longer spells DEVNULL as `subprocess.DEVNULL`, so this substitution "
        "silently did nothing and the probe below proves nothing"
    )
    assert not _name_hits(captures, DISCARD_NAMES), (
        "the output-capturing variant still trips the discard detector, so it cannot separate the "
        "two signals"
    )

    assert _looks_like_a_live_suite(captures), (
        "a suite that spawns a server, connects to it, and CAPTURES its output is not recognised. "
        "The connect signal is the one that must carry this — if this fails, the detector is keying "
        "on DEVNULL, which is a property of the bug rather than a property of a live suite."
    )


def test_a_blocking_spawn_next_to_a_connect_is_not_a_live_suite() -> None:
    """The false positive issue #92 §3 measured, and the twin that must still fire.

    Eleven files in this directory call a ``CONNECT_NAME`` without spawning anything; four spawn
    without connecting. The sets being disjoint was the entire safety margin, and it was one edit
    from ending: any of those eleven adding ``subprocess.run([sys.executable, "-c", ...])`` — the
    idiom ``test_errors_is_import_light.py`` already uses — would have been reported as an
    unregistered live suite, with a failure message telling the author to register it, which would
    then have failed a different test.

    A blocking call cannot start a server you go on to talk to, so it is not evidence of one.
    """
    blocking = (
        "import subprocess, sys, grpc\n"
        "def test_imports_are_light():\n"
        "    subprocess.run([sys.executable, '-c', 'import seam_sdk'], check=True)\n"
        "    with grpc.insecure_channel('127.0.0.1:50051') as ch:\n"
        "        pass\n"
    )
    assert not _looks_like_a_live_suite(blocking), (
        "a file that runs a blocking subprocess and separately opens a channel is reported as a "
        "live suite. That is the false positive this narrowing removes."
    )

    non_blocking = blocking.replace(
        "subprocess.run([sys.executable, '-c', 'import seam_sdk'], check=True)",
        "proc = subprocess.Popen([sys.executable, '-c', 'import seam_sdk'])",
    )
    assert _looks_like_a_live_suite(non_blocking), (
        "narrowing to non-blocking spawns went too far: Popen + connect is exactly the live-suite "
        "shape and must still be caught"
    )
