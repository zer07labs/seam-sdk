"""Channel lifecycle on the sync clients, and a deadline on every management-plane call.

Two gaps that were invisible because nothing fails loudly when you hit them.

**Channel lifecycle.** ``seam_sdk.aio.SeamClient`` has had ``close()`` and ``async with`` since it
shipped; the two SYNC clients had neither. A process that constructs a client per request, or
rebuilds one on reconnect, leaked a channel — and with it a connection and its keepalive timers —
every time. Nothing raises; the process just grows.

**Admin timeouts.** Every ``SeamAdminClient`` method took no ``timeout`` and passed none, while every
data-plane method has always had one. That included ``erase_subject``, which crypto-shreds a
subject's records. An unbounded destructive RPC against a wedged management plane hangs the
operator's process with no way to learn whether the erasure landed — and the human instinct at that
point is Ctrl-C and re-run, against a server that may still be working.
"""

from __future__ import annotations

import inspect
import time
from concurrent import futures

import grpc
import pytest

from seam_sdk import Agent, SeamClient
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.admin import DEFAULT_ADMIN_TIMEOUT_S, SeamAdminClient
from seam_sdk.errors import DeadlineExceededError

from test_authorize import SEED, FakeSeam, HangingSeam

# ── Channel lifecycle ────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_addr():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    servicer = FakeSeam()
    rpc.add_SeamAdmissionServicer_to_server(servicer, server)
    rpc.add_SeamAuthorizationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


def _channel_is_shut(client) -> bool:
    """A closed grpc channel refuses new calls: ``unary_unary`` raises ``ValueError: Cannot invoke
    RPC: Channel closed!``.

    Asserted by BEHAVIOUR rather than by reading a private state field, which is grpc's to change
    and part of no contract. Not via ``channel_ready_future`` either — that spawns a connectivity
    poller thread which then raises inside grpc's own thread, turning a passing test into five
    unhandled-thread warnings.
    """
    try:
        client._ch.unary_unary("/probe/Probe")(b"", timeout=0.2)
    except ValueError:
        # "Cannot invoke RPC on closed channel!" — only a CLOSED channel raises this.
        return True
    except grpc.RpcError:
        # An open channel to a port that answers nothing: UNAVAILABLE, not closed. Creating the
        # multicallable is not enough to tell these apart — grpc lets you build one on a closed
        # channel and only refuses at invocation — so the probe has to actually call.
        return False
    return False


def test_the_sync_client_closes_its_channel(fake_addr):
    _, addr = fake_addr
    client = SeamClient.connect(addr)
    assert client.authorize(Agent(SEED), "t", {}).allowed
    client.close()
    assert _channel_is_shut(client)


def test_the_sync_client_is_a_context_manager(fake_addr):
    _, addr = fake_addr
    with SeamClient.connect(addr) as client:
        assert client.authorize(Agent(SEED), "t", {}).allowed
    assert _channel_is_shut(client)


def test_the_admin_client_closes_its_channel(fake_addr):
    _, addr = fake_addr
    admin = SeamAdminClient.connect(addr)
    admin.close()
    assert _channel_is_shut(admin)


def test_the_admin_client_is_a_context_manager(fake_addr):
    _, addr = fake_addr
    with SeamAdminClient.connect(addr) as admin:
        channel = admin._ch
    assert _channel_is_shut(admin) and channel is admin._ch


@pytest.mark.parametrize("factory", [SeamClient.connect, SeamAdminClient.connect])
def test_closing_twice_is_safe(fake_addr, factory):
    """``with`` plus a defensive explicit ``close()`` is a shape real code has, and the second call
    must not raise — otherwise the cleanup path becomes its own error path."""
    _, addr = fake_addr
    client = factory(addr)
    client.close()
    client.close()


def test_the_admin_client_closes_a_token_intercepted_channel(fake_addr):
    """With a token, ``connect`` wraps the channel in an interceptor and stores the WRAPPER. If
    ``close()`` were written against the raw channel it would close the wrong object — and an
    intercepted channel is exactly the configuration a real operator uses."""
    _, addr = fake_addr
    admin = SeamAdminClient.connect(addr, token="operator-token")
    admin.close()
    assert _channel_is_shut(admin)


# ── Admin timeouts ───────────────────────────────────────────────────────────────────────────────

#: Every public method that talks to the management plane, with a minimal call. `stream_events` is
#: excluded deliberately — see the test below for why it is the one method that must NOT default to
#: a deadline.
ADMIN_CALLS = {
    "preview_erasure": lambda a: a.preview_erasure("acme", "cust-42", timeout=0.1),
    "erase_subject": lambda a: a.erase_subject("acme", "cust-42", 0, timeout=0.1),
    "erase_subject_confirmed": lambda a: a.erase_subject_confirmed(
        "acme", "cust-42", timeout=0.1
    ),
    "enroll_tenant": lambda a: a.enroll_tenant("aid:x", "acme", "ns", timeout=0.1),
    "list_tenants": lambda a: a.list_tenants(timeout=0.1),
    "register_party": lambda a: a.register_party("p", b"\x00" * 32, timeout=0.1),
    "resume_session": lambda a: a.resume_session("s", "approver", timeout=0.1),
    "place_legal_hold": lambda a: a.place_legal_hold("d", timeout=0.1),
    "release_legal_hold": lambda a: a.release_legal_hold("d", timeout=0.1),
    "enforce_retention": lambda a: a.enforce_retention(1, 2, 3, timeout=0.1),
    "audit_trail": lambda a: a.audit_trail(timeout=0.1),
}


@pytest.fixture
def hanging_admin():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    rpc.add_SeamAdminServicer_to_server(HangingSeam(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield f"127.0.0.1:{port}"
    server.stop(None)


@pytest.mark.parametrize("name", sorted(ADMIN_CALLS), ids=sorted(ADMIN_CALLS))
def test_every_admin_method_enforces_its_timeout(hanging_admin, name):
    """Against a server where every RPC hangs, each call must come back as a typed
    ``DeadlineExceededError`` inside its budget rather than blocking forever."""
    with SeamAdminClient.connect(hanging_admin) as admin:
        started = time.monotonic()
        with pytest.raises(DeadlineExceededError):
            ADMIN_CALLS[name](admin)
        elapsed = time.monotonic() - started
    assert elapsed < 3.0, f"{name} took {elapsed:.1f}s against a 0.1s deadline"


def test_every_admin_method_accepts_a_timeout_argument():
    """A signature check, so a method ADDED later cannot quietly ship without one.

    The behavioural test above only covers methods listed in ADMIN_CALLS; this covers the class, so
    the gap that produced this whole test module cannot reopen one method at a time.
    """
    missing = []
    for name, member in inspect.getmembers(SeamAdminClient, inspect.isfunction):
        if name.startswith("_") or name in {"connect", "close"}:
            continue
        if "timeout" not in inspect.signature(member).parameters:
            missing.append(name)
    assert not missing, (
        f"SeamAdminClient methods with no timeout parameter: {missing}. Every management-plane "
        "call needs a deadline — erase_subject shipped without one."
    )


def test_the_admin_default_timeout_is_generous_but_finite():
    """The value is a judgement call and is allowed to change; being FINITE is not."""
    assert 0 < DEFAULT_ADMIN_TIMEOUT_S < float("inf")
    assert DEFAULT_ADMIN_TIMEOUT_S >= 10, (
        "management-plane work (erasure, retention) is operator-cadence, not hot-path — too tight "
        "a default turns a slow-but-healthy erase into a spurious failure an operator will retry"
    )


def test_stream_events_defaults_to_no_deadline():
    """The one deliberate exception, pinned so nobody 'fixes' it into consistency.

    A gRPC deadline bounds the whole STREAM, not the gap between events, so any finite default would
    kill a healthy ``follow=True`` live tail the moment it outlived the number.
    """
    default = (
        inspect.signature(SeamAdminClient.stream_events).parameters["timeout"].default
    )
    assert default is None
