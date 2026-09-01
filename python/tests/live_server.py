"""One place that spawns a live ``seam-grpc``, waits for it, tears it down, and keeps its output.

Why this exists (zer07labs/seam-sdk#85)
=======================================
The required ``integration`` lane produced both outcomes twice on byte-identical code, failing three
tests with ``UNAVAILABLE: ... recvmsg:Connection reset by peer (104)`` — **reset, not refused**, and
immediately after the workflow's own smoke step printed ``seam-grpc is serving``. Reset means
something accepted the connection and then dropped it, which is a different failure from "nothing is
listening".

Three defects in the old per-file fixtures made that possible, and each is wrong on its own terms:

1. **Fixed ports, shared across tests.** ``test_integration.py`` used ``8099`` for four tests and
   ``8115`` for three more; ``test_streamed_decode.py`` used ``8113``/``8114``. Function-scoped
   fixtures meant every test spawned a *new* server on the *same* port as the one just torn down.
2. **Teardown did not wait.** Every site called ``proc.terminate()`` and returned. SIGTERM starts a
   graceful drain, so the previous server can still hold its listening socket when the next one
   tries to bind.
3. **Readiness could not identify its own server.** The old ``_wait(port)`` returned as soon as
   *anything* accepted a TCP connection there. It never checked that the acceptor was the process
   just spawned, or that that process was even alive.

Defect 3 is the one that turns 1 and 2 into a wrong answer rather than a bind error, and it is
demonstrable in milliseconds with no ``seam-grpc`` at all — see
``test_live_server_helper.py::test_readiness_refuses_a_port_the_spawned_process_never_bound``.

**On the causal story, stated honestly.** The correlation in CI was exact: all three failures were
users of the shared-8099 fixture, and the first such test passed. But the collection order is
8099, 8099, 8099, 8115, 8115, 8115, 8099 — and the three consecutive 8115 tests *all passed*, where a
pure "previous test's draining server" mechanism predicts two of them fail. So the shared-port race
is a **hypothesis** for the observed CI symptom, not a confirmed cause. It is fixed here anyway,
because all three defects above are real independent of which one produced that particular log, and
because the fourth property below is what will settle it if #85 recurs.

What this module guarantees
===========================
* **A fresh OS-allocated port per spawn.** No fixed port numbers anywhere in the live suites.
* **Readiness that proves the port is ours.** The port is asserted *unreachable* before the spawn, and
  the wait loop aborts the moment the child dies rather than timing out on a generic message.
* **Teardown that waits, with escalation.** ``terminate()`` -> ``wait(timeout)`` -> ``kill()`` ->
  ``wait()``, so the socket is released before the next spawn.
* **Server output kept, never discarded.** The old fixtures sent stdout and stderr to ``DEVNULL``,
  which is why #85 says "every re-run destroys the only copy of the explanation".
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Mapping, Optional

import pytest

#: How long to wait for the child to start accepting. Generous: a cold CI runner pulling a fresh
#: binary is slower than a warm dev machine, and the failure this bound produces is a *timeout*,
#: which is strictly worse to debug than waiting a few extra seconds.
READY_TIMEOUT = 15.0

#: How long to wait for a SIGTERMed child before escalating to SIGKILL. Both planes are served with
#: a graceful-drain shutdown and one suite deliberately holds a `StreamEvents follow=true` tail open,
#: so an *unbounded* wait would convert a leaked process into a hung suite. This is a bound chosen
#: for this repo's needs — deliberately NOT a mirror of any runtime-side grace-window constant, which
#: would silently rot the moment that constant moved.
STOP_TIMEOUT = 10.0

_POLL = 0.05


def free_port() -> int:
    """An OS-allocated ephemeral port.

    The single copy of what ``test_admin.py`` and ``test_verify_attestation.py`` each defined
    separately. Note the residual TOCTOU window this accepts by design: the socket is bound, closed,
    and the number handed to a subprocess, so in principle another process can take it in between.
    That window is *far* smaller than a fixed port shared by four tests in the same file, and it is
    the same trade the pre-existing ``_free_port()`` already made. If it ever actually bites, the fix
    is to pass a pre-bound file descriptor to the child — not to widen a retry until it goes quiet.
    """
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _accepts(port: int, timeout: float = 0.1) -> bool:
    """True iff *something* accepts a TCP connection on ``port``. Deliberately says nothing about
    *who* — that ambiguity is the whole defect, and it is contained here rather than trusted."""
    try:
        socket.create_connection(("127.0.0.1", port), timeout).close()
        return True
    except OSError:
        return False


@dataclass
class LiveServer:
    """A running ``seam-grpc``, its ports, and its captured output."""

    proc: subprocess.Popen
    data_port: int
    log_path: Path
    mgmt_port: Optional[int] = None
    _ports: tuple = field(default_factory=tuple, repr=False)

    @property
    def data_addr(self) -> str:
        return f"127.0.0.1:{self.data_port}"

    @property
    def mgmt_addr(self) -> str:
        if self.mgmt_port is None:
            raise AssertionError(
                "this server was spawned without a management plane (mgmt=False)"
            )
        return f"127.0.0.1:{self.mgmt_port}"

    def tail(self, limit: int = 4000) -> str:
        """The child's own output, for a failure message that names something."""
        try:
            return self.log_path.read_text(errors="replace")[-limit:]
        except OSError:
            return "(no log captured)"


class ServerDidNotStart(RuntimeError):
    """Raised instead of a bare timeout, so the message carries the child's own explanation."""


def _wait_ready(
    proc: subprocess.Popen, port: int, log_path: Path, timeout: float
) -> None:
    """Wait until ``port`` accepts, aborting early if the child dies.

    The liveness check on every iteration is the difference between "the server refused to start,
    here is its stderr" and the old ``server never came up``, which named nothing.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _accepts(port):
            return
        rc = proc.poll()
        if rc is not None:
            raise ServerDidNotStart(
                f"seam-grpc exited with code {rc} before serving on {port}. Its own output:\n"
                f"{log_path.read_text(errors='replace')[-4000:]}"
            )
        time.sleep(_POLL)
    raise ServerDidNotStart(
        f"seam-grpc did not accept on {port} within {timeout}s (pid {proc.pid} still alive). "
        f"Its own output:\n{log_path.read_text(errors='replace')[-4000:]}"
    )


def _stop(proc: subprocess.Popen, timeout: float = STOP_TIMEOUT) -> None:
    """SIGTERM, wait, then SIGKILL and wait again — so the port is actually free on return."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=timeout)


@contextlib.contextmanager
def spawn_server(
    *,
    mgmt: bool = False,
    env_extra: Optional[Mapping[str, str]] = None,
    log_dir: Optional[Path] = None,
    binary: Optional[str] = None,
    ready_timeout: float = READY_TIMEOUT,
    stop_timeout: float = STOP_TIMEOUT,
) -> Iterator[LiveServer]:
    """Spawn ``seam-grpc`` on fresh ports, wait for it, and tear it down completely.

    ``mgmt=True`` also binds the management plane and allocates its port from the same call, so a
    caller cannot half-adopt this helper and leave one plane on a fixed port.

    ``binary`` overrides ``$SEAM_GRPC_BIN``; without either, the test skips. The override exists so
    this module's own tests can drive it with a *fake* binary and stay hermetic — the tests that
    prove the #85 fix must not themselves be gated on the lane that was flaky.
    """
    if binary is None:
        binary = os.environ.get("SEAM_GRPC_BIN")
        if not binary:
            pytest.skip("set SEAM_GRPC_BIN to run the live server suites")

    data_port = free_port()
    mgmt_port = free_port() if mgmt else None

    # Assert the ports are OURS before spawning. If anything already accepts here — a leaked server
    # from a previous test, another worker, an unrelated process — fail loudly now, rather than
    # letting the readiness check below succeed against a stranger and handing the caller an address
    # that answers and then resets. This is the #85 defect, closed at the only point it can be.
    for label, port in (("data", data_port), ("mgmt", mgmt_port)):
        if port is not None and _accepts(port):
            raise ServerDidNotStart(
                f"the {label} port {port} was already accepting connections before spawn — refusing "
                f"to start, because readiness could not then distinguish this server from that one"
            )

    log_dir = (
        Path(log_dir) if log_dir is not None else Path(os.environ.get("TMPDIR", "/tmp"))
    )
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"seam-grpc-{data_port}.log"

    env = {
        **os.environ,
        "SEAM_GRPC_LISTEN": f"127.0.0.1:{data_port}",
        "SEAM_DEV_INSECURE": "1",
    }
    if mgmt_port is not None:
        env["SEAM_GRPC_MGMT_LISTEN"] = f"127.0.0.1:{mgmt_port}"
    if env_extra:
        env.update(env_extra)

    with log_path.open("wb") as sink:
        proc = subprocess.Popen(
            [binary], env=env, stdout=sink, stderr=subprocess.STDOUT
        )
        try:
            _wait_ready(proc, data_port, log_path, ready_timeout)
            if mgmt_port is not None:
                _wait_ready(proc, mgmt_port, log_path, ready_timeout)
            yield LiveServer(
                proc=proc, data_port=data_port, mgmt_port=mgmt_port, log_path=log_path
            )
        finally:
            _stop(proc, stop_timeout)
