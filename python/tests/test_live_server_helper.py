"""Proofs for ``live_server.spawn_server``, hermetic by construction.

Every test here builds the state it asserts on — a decoy listener it binds itself, a fake "binary"
it writes into ``tmp_path``, a port it allocated. **No test reads ``SEAM_GRPC_BIN``**, so none of them
skips, and none depends on the ambient machine. That is deliberate: the tests that prove the #85 fix
must not themselves be gated on the lane that was flaky, and a test whose result is decided by the
environment rather than by the property it names is the specific defect this repo has shipped before
(see ``plans/gate-blindness-hardening.md``'s post-merge record).

Each test names the old behaviour it would have caught, so a future reader can tell what is being
prevented rather than merely what is being asserted.
"""

from __future__ import annotations

import pathlib
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from live_server import (
    STOP_TIMEOUT,
    ServerDidNotStart,
    _accepts,
    free_port,
    free_ports,
    spawn_server,
)

# A fake seam-grpc: binds whatever it is told to bind, then idles. Optionally ignores SIGTERM, which
# is how the escalation path is made deterministic rather than timing-dependent.
_FAKE_SERVER = """
import os, signal, socket, sys, time

if os.environ.get("FAKE_IGNORE_SIGTERM"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

held = []
for var in ("SEAM_GRPC_LISTEN", "SEAM_GRPC_MGMT_LISTEN"):
    addr = os.environ.get(var)
    if not addr:
        continue
    host, port = addr.rsplit(":", 1)
    s = socket.socket()
    s.bind((host, int(port)))
    s.listen(8)
    held.append(s)

sys.stderr.write("fake seam-grpc serving on %d socket(s)\\n" % len(held))
sys.stderr.flush()
while True:
    time.sleep(0.05)
"""

# A fake seam-grpc that binds, serves briefly, then dies — the "accepted the connection and then
# dropped it" shape #85 actually observed, which happens *inside* the test body rather than at startup.
_FAKE_DIES_MIDWAY = """
import os, socket, sys, time

addr = os.environ["SEAM_GRPC_LISTEN"]
host, port = addr.rsplit(":", 1)
s = socket.socket()
s.bind((host, int(port)))
s.listen(8)
sys.stderr.write("fake seam-grpc serving, about to fall over\\n")
sys.stderr.flush()
time.sleep(0.4)
raise SystemExit(9)
"""

# A fake seam-grpc that binds nothing and dies at once — the "it never came up" path.
_FAKE_DEAD = """
import sys
sys.stderr.write("boom: could not initialise the data plane\\n")
raise SystemExit(3)
"""


def _write_binary(tmp_path: Path, source: str, name: str) -> str:
    """A real executable wrapping ``source``, so ``subprocess.Popen([binary])`` works as it does for
    the genuine binary — no special-casing inside the helper for the sake of its own tests."""
    script = tmp_path / f"{name}.py"
    script.write_text(source)
    launcher = tmp_path / name
    launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    launcher.chmod(0o755)
    return str(launcher)


def _old_wait(port: int, timeout: float = 5.0) -> None:
    """The readiness check exactly as ``test_integration.py`` carried it before this phase.

    Copied byte-for-byte from ``960cf81:python/tests/test_integration.py:26-34`` so the contrast in
    the tests below is a measurement against the real prior behaviour rather than against a
    paraphrase of it. The other three suites carried the same loop with a different timeout and
    message — identical in behaviour, which is what is under test here, but this is one file's copy
    rather than a single shared original.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server never came up")


def test_the_old_readiness_check_returns_against_a_process_that_never_bound(
    tmp_path: Path,
) -> None:
    """The #85 defect itself, reproduced with no ``seam-grpc`` and no network beyond loopback.

    This test asserts the OLD behaviour is broken. It is the red-first evidence for everything below:
    a decoy listener stands in for a previous test's draining server, and the "binary" exits before
    binding anything. ``_old_wait`` calls that success in milliseconds.
    """
    decoy = socket.socket()
    decoy.bind(("127.0.0.1", 0))
    decoy.listen(8)
    port = decoy.getsockname()[1]
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", "raise SystemExit(0)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc.wait()

        started = time.monotonic()
        _old_wait(port)  # returns; does not raise
        elapsed = time.monotonic() - started

        assert proc.returncode == 0, "the 'server' was already dead"
        assert elapsed < 1.0, (
            "it returned immediately, against a port its process never bound"
        )
    finally:
        decoy.close()


def test_readiness_refuses_a_port_the_spawned_process_never_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fix for the test above: a port that already answers is refused before the spawn.

    ``free_port`` is monkeypatched to hand back a port that is already held, which is exactly the
    situation a leaked or draining server creates. The helper must refuse rather than hand back an
    address that answers now and resets on the first RPC.
    """
    decoy = socket.socket()
    decoy.bind(("127.0.0.1", 0))
    decoy.listen(8)
    port = decoy.getsockname()[1]
    binary = _write_binary(tmp_path, _FAKE_SERVER, "fake-grpc")
    try:
        monkeypatch.setattr("live_server.free_ports", lambda count: [port] * count)
        with pytest.raises(ServerDidNotStart) as ei:
            with spawn_server(binary=binary, log_dir=tmp_path):
                pass
        assert "already accepting" in str(ei.value)
        assert str(port) in str(ei.value)
    finally:
        decoy.close()


def test_readiness_aborts_naming_the_exit_code_when_the_child_dies(
    tmp_path: Path,
) -> None:
    """A child that dies must fail fast with its own output, not time out on a generic message.

    The old ``_wait`` polled for the full timeout and then raised ``server never came up``, which
    named nothing — #85 calls that out directly ("a message that describes the symptom and names
    nothing").
    """
    binary = _write_binary(tmp_path, _FAKE_DEAD, "dead-grpc")
    started = time.monotonic()
    with pytest.raises(ServerDidNotStart) as ei:
        with spawn_server(binary=binary, log_dir=tmp_path, ready_timeout=10.0):
            pass
    elapsed = time.monotonic() - started

    assert "exited with code 3" in str(ei.value)
    assert "could not initialise the data plane" in str(ei.value), (
        "the child's own output is carried"
    )
    assert elapsed < 5.0, (
        "it aborted on the child's death rather than waiting out the timeout"
    )


def test_teardown_waits_and_escalates_so_the_port_is_actually_free(
    tmp_path: Path,
) -> None:
    """Teardown must return only once the process is gone and the socket released.

    The fake ignores SIGTERM, so a bare ``proc.terminate()`` — what every live fixture did before this
    phase — would return with the process alive and the port still held. Ignoring the signal makes
    that deterministic instead of a race.
    """
    binary = _write_binary(tmp_path, _FAKE_SERVER, "stubborn-grpc")
    with spawn_server(
        binary=binary,
        log_dir=tmp_path,
        env_extra={"FAKE_IGNORE_SIGTERM": "1"},
        stop_timeout=2.0,
    ) as srv:
        port = srv.data_port
        assert _accepts(port), "the fake is serving"
        proc = srv.proc

    assert proc.poll() is not None, "the process was reaped, not merely signalled"
    # The port must be re-bindable immediately — the property a following test depends on.
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", port))
    finally:
        probe.close()


def test_two_consecutive_spawns_never_share_a_port(tmp_path: Path) -> None:
    """Trivially false for any fixed-port fixture, which is the point."""
    binary = _write_binary(tmp_path, _FAKE_SERVER, "fake-grpc")
    with spawn_server(binary=binary, log_dir=tmp_path) as first:
        a = first.data_port
    with spawn_server(binary=binary, log_dir=tmp_path) as second:
        b = second.data_port
    assert a != b, f"two spawns reused port {a}"


def test_mgmt_allocates_both_ports_from_one_call(tmp_path: Path) -> None:
    """Both planes come from one call, so a caller cannot half-adopt the helper and leave one on a
    fixed port — which is how ``dual_plane`` kept 8115/8116 while ``test_admin.py`` had already moved
    to ephemeral allocation."""
    binary = _write_binary(tmp_path, _FAKE_SERVER, "fake-grpc")
    with spawn_server(binary=binary, log_dir=tmp_path, mgmt=True) as srv:
        assert srv.mgmt_port is not None
        assert srv.data_port != srv.mgmt_port
        assert _accepts(srv.data_port) and _accepts(srv.mgmt_port)
        assert srv.data_addr == f"127.0.0.1:{srv.data_port}"
        assert srv.mgmt_addr == f"127.0.0.1:{srv.mgmt_port}"


def test_mgmt_addr_refuses_rather_than_inventing_one(tmp_path: Path) -> None:
    """Asking for a management address on a data-only server is a programming error, not a default."""
    binary = _write_binary(tmp_path, _FAKE_SERVER, "fake-grpc")
    with spawn_server(binary=binary, log_dir=tmp_path) as srv:
        with pytest.raises(AssertionError):
            _ = srv.mgmt_addr


def test_the_child_output_is_captured_not_discarded(tmp_path: Path) -> None:
    """#85's explicit ask: the old fixtures used ``DEVNULL``, so every re-run destroyed the only copy
    of the explanation."""
    binary = _write_binary(tmp_path, _FAKE_SERVER, "fake-grpc")
    with spawn_server(binary=binary, log_dir=tmp_path) as srv:
        deadline = time.monotonic() + 5.0
        while (
            "fake seam-grpc serving" not in srv.tail() and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        assert "fake seam-grpc serving" in srv.tail()
        assert srv.log_path.exists()


def test_free_port_returns_a_bindable_port() -> None:
    """The helper's own foundation. A floor, not a formality: if this ever returns something already
    held, every isolation guarantee above collapses quietly."""
    port = free_port()
    assert not _accepts(port)
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
    finally:
        s.close()


def test_stop_timeout_is_bounded() -> None:
    """A leaked process must not become a hung suite. Guards against someone 'simplifying' the
    escalation into an unbounded ``proc.wait()``."""
    assert 0 < STOP_TIMEOUT <= 60, f"STOP_TIMEOUT={STOP_TIMEOUT} is not a usable bound"


def test_the_helper_is_the_only_copy_of_free_port() -> None:
    """``_free_port`` used to exist twice, verbatim, in two suites. Collapsing duplicates is only
    durable if a third copy cannot quietly reappear."""
    here = Path(__file__).parent
    me = Path(__file__).name
    offenders = [
        p.name
        for p in sorted(here.glob("test_*.py"))
        if p.name != me and "def _free_port(" in p.read_text()
    ]
    assert offenders == [], (
        f"these files redefine _free_port instead of importing it: {offenders}"
    )


def test_every_spawn_here_passes_an_explicit_binary() -> None:
    """Anti-vacuity floor.

    If any test in this module fell back to ``$SEAM_GRPC_BIN``, it would *skip* on a machine without
    the binary — and the proofs for the #85 fix would silently stop running while the suite still
    reported green. That is the "skip reads as green" shape this repo has already had to fix once, so
    it is asserted structurally rather than trusted.
    """
    import ast

    source = pathlib.Path(__file__).read_text()
    tree = ast.parse(source)
    bare = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == "spawn_server":
            if not any(kw.arg == "binary" for kw in node.keywords):
                bare.append(node.lineno)
    assert bare == [], (
        f"spawn_server() called without an explicit binary= at line(s) {bare}"
    )

    calls = sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "spawn_server"
    )
    assert calls >= 5, (
        f"expected this module to exercise spawn_server repeatedly, found {calls}"
    )


def test_the_two_ports_are_held_open_together(monkeypatch: pytest.MonkeyPatch) -> None:
    """``free_ports(2)`` must bind both sockets before releasing either.

    Allocating one at a time — bind, read the number, close, repeat — lets the kernel legitimately
    return the same port twice, which would put both planes on one socket. Asserted by watching the
    call order rather than by sampling, because sampling a rare event proves nothing when it passes.
    """
    events: list[str] = []
    real_socket = socket.socket

    class _Watched(socket.socket):  # type: ignore[misc]
        def bind(self, *a, **k):
            events.append("bind")
            return real_socket.bind(self, *a, **k)

        def close(self, *a, **k):
            events.append("close")
            return real_socket.close(self, *a, **k)

    monkeypatch.setattr(socket, "socket", _Watched)
    ports = free_ports(2)
    assert len(set(ports)) == 2, f"free_ports(2) returned a duplicate: {ports}"
    assert events[:2] == ["bind", "bind"], (
        f"the second port was allocated only after the first socket closed: {events}"
    )


def test_a_child_that_dies_during_the_test_surfaces_its_log(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """The #85 shape exactly: it served, the test used it, then it fell over.

    ``_stop`` returns immediately for an already-dead process, so this is the one path where teardown
    could stay silent — and it is the path where the server's own output matters most. Teardown must
    print it rather than swallow it, and must not raise (which would replace whatever the test was
    actually failing on).
    """
    binary = _write_binary(tmp_path, _FAKE_DIES_MIDWAY, "dying-grpc")
    with spawn_server(binary=binary, log_dir=tmp_path) as srv:
        assert _accepts(srv.data_port)
        deadline = time.monotonic() + 5.0
        while srv.proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert srv.proc.poll() == 9, "the fake fell over as intended"

    err = capsys.readouterr().err
    assert "exited with code 9 DURING the test" in err
    assert "about to fall over" in err, (
        "the child's own output is carried, not just the code"
    )
