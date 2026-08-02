"""Streaming failures surface at ITERATION time, not call time — and must still be typed.

A unary call fails where you called it. A server stream does not: the call returns, you start
iterating, and the failure arrives partway through — possibly after you have already processed and
acted on several events. Both clients have a wrapper for this and neither wrapper was tested.

The sync one (``SeamAdminClient.stream_events``) is live: it is how an operator drains the
``seam-event.v1`` governance outbox, and ``ack=True`` marks the yielded rows published. An untyped
error escaping mid-drain is the case where "how many events did I actually get before it broke" is a
question with consequences.

The aio one (``seam_sdk.aio._MappedStream``) is currently **unreachable through the public API** —
the only server-streaming RPC in the contract is ``SeamEvents.StreamEvents``, and the aio client does
not stub ``SeamEvents``. It is tested here anyway, and the reason is worth stating plainly: it is
dispatched by TYPE in ``_AioMappedStub.__getattr__``, so the day any existing RPC becomes
server-streaming, this code goes live with no diff to review. Untested code that activates on
somebody else's schema change is the kind that fails in production first.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent import futures

import grpc
import pytest

from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev
from seam_sdk.admin import SeamAdminClient
from seam_sdk.aio import _MappedStream
from seam_sdk.errors import (
    InternalError,
    ResourceExhaustedError,
    SeamRpcError,
    UnavailableError,
)


class PartialEventStream(rpc.SeamEventsServicer):
    """Yields ``before_abort`` events, then aborts — the mid-stream failure, for real."""

    def __init__(self):
        self.before_abort = 3
        self.abort_with = grpc.StatusCode.UNAVAILABLE
        self.abort = True
        self.lock = threading.Lock()

    def StreamEvents(self, request, context):  # noqa: N802
        for seq in range(1, self.before_abort + 1):
            yield ev.SeamEvent(seq=seq, event_id=f"evt-{seq}", kind="AUDIT_ENTRY")
        if self.abort:
            context.abort(self.abort_with, "stream died mid-drain")


@pytest.fixture
def event_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    servicer = PartialEventStream()
    rpc.add_SeamEventsServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


# ── The live path: SeamAdminClient.stream_events ─────────────────────────────────────────────────


def test_a_mid_stream_abort_surfaces_typed_and_keeps_what_was_already_yielded(
    event_server,
):
    """The events consumed before the failure are real and must not be lost with the exception.

    An ``ack=True`` drain has already marked them published server-side, so a consumer that
    discarded them on error would silently drop governance events — the outbox is at-least-once,
    but only if the consumer keeps what it received.
    """
    servicer, addr = event_server
    servicer.abort_with = grpc.StatusCode.UNAVAILABLE

    received = []
    with SeamAdminClient.connect(addr) as admin:
        with pytest.raises(UnavailableError) as excinfo:
            for event in admin.stream_events():
                received.append(event.event_id)

    assert received == ["evt-1", "evt-2", "evt-3"]
    assert excinfo.value.code() is grpc.StatusCode.UNAVAILABLE
    assert isinstance(excinfo.value, grpc.RpcError), "still catchable the old way"


@pytest.mark.parametrize(
    "code",
    [
        grpc.StatusCode.UNAVAILABLE,
        grpc.StatusCode.RESOURCE_EXHAUSTED,
        grpc.StatusCode.INTERNAL,
        grpc.StatusCode.DATA_LOSS,  # no dedicated subclass — must still map
    ],
    ids=lambda c: c.name,
)
def test_every_mid_stream_status_is_mapped_not_leaked(event_server, code):
    servicer, addr = event_server
    servicer.abort_with = code
    with SeamAdminClient.connect(addr) as admin:
        with pytest.raises(SeamRpcError) as excinfo:
            list(admin.stream_events())
    assert excinfo.value.code() is code


def test_an_abort_on_the_very_first_event_is_still_an_iteration_time_failure(
    event_server,
):
    """Zero events then abort. The failure still arrives from the loop rather than from the call —
    a caller cannot wrap `stream_events(...)` in a try and expect to catch anything."""
    servicer, addr = event_server
    servicer.before_abort = 0
    servicer.abort_with = grpc.StatusCode.RESOURCE_EXHAUSTED

    with SeamAdminClient.connect(addr) as admin:
        stream = admin.stream_events()  # no error here — it is a generator
        with pytest.raises(ResourceExhaustedError):
            next(stream)


def test_a_clean_stream_ends_without_raising(event_server):
    """The control: the wrapper must not turn a normal end-of-stream into an error."""
    servicer, addr = event_server
    servicer.abort = False
    with SeamAdminClient.connect(addr) as admin:
        assert [e.event_id for e in admin.stream_events()] == [
            "evt-1",
            "evt-2",
            "evt-3",
        ]


# ── The staged path: aio._MappedStream ───────────────────────────────────────────────────────────


class _FakeAioCall:
    """A stand-in for a ``grpc.aio`` streaming call: async-iterable, cancellable."""

    def __init__(self, items, raises=None):
        self._items, self._raises = items, raises
        self.cancelled = False

    async def __aiter__(self):
        for item in self._items:
            yield item
        if self._raises is not None:
            raise self._raises

    def cancel(self) -> bool:
        self.cancelled = True
        return True


class _RawRpcError(grpc.RpcError):
    def __init__(self, code, details="mid-stream"):
        self._code, self._details = code, details

    def code(self):
        return self._code

    def details(self):
        return self._details


def test_mapped_stream_maps_a_mid_iteration_error():
    async def scenario():
        call = _FakeAioCall(
            ["a", "b"], raises=_RawRpcError(grpc.StatusCode.UNAVAILABLE)
        )
        seen = []
        with pytest.raises(UnavailableError):
            async for item in _MappedStream(call):
                seen.append(item)
        assert seen == ["a", "b"], "items before the failure still reach the consumer"

    asyncio.run(scenario())


def test_mapped_stream_maps_an_unmapped_status_to_internal():
    async def scenario():
        call = _FakeAioCall([], raises=_RawRpcError(grpc.StatusCode.DATA_LOSS))
        with pytest.raises(InternalError) as excinfo:
            async for _ in _MappedStream(call):
                pass
        assert excinfo.value.code() is grpc.StatusCode.DATA_LOSS

    asyncio.run(scenario())


def test_mapped_stream_passes_a_clean_stream_through_untouched():
    async def scenario():
        assert [x async for x in _MappedStream(_FakeAioCall([1, 2, 3]))] == [1, 2, 3]

    asyncio.run(scenario())


def test_mapped_stream_forwards_cancel_to_the_underlying_call():
    """Without this the wrapper would swallow cancellation and leave the RPC running on the
    server — a live tail nobody is reading, held open by a client that thinks it stopped."""
    call = _FakeAioCall([1])
    assert _MappedStream(call).cancel() is True
    assert call.cancelled is True


def test_mapped_stream_does_not_swallow_a_non_rpc_error():
    """A bug in the consumer's own code, or a decode failure, must not be relabelled as a
    transport error — that would send a reader looking at the network for a logic bug."""

    async def scenario():
        call = _FakeAioCall([1], raises=ValueError("not a transport problem"))
        with pytest.raises(ValueError):
            async for _ in _MappedStream(call):
                pass

    asyncio.run(scenario())
