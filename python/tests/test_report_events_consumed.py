"""``SeamAdminClient.report_events_consumed`` — the unary RPC a relay calls to bound the runtime outbox.

Unlike ``stream_events`` (a server stream that fails at iteration time), this is a unary call: it fails
where you call it, and returns nothing on success. This pins that the wrapper (1) sends the exact
``consumed_cursor`` the caller passed and (2) maps a server error to a typed ``SeamRpcError`` — the same
error-mapping contract every other management call upholds.
"""

from __future__ import annotations

from concurrent import futures

import grpc
import pytest

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.admin import SeamAdminClient
from seam_sdk.errors import SeamRpcError, UnavailableError


class RecordingEvents(rpc.SeamEventsServicer):
    """Records the reported cursor; optionally aborts to exercise error mapping."""

    def __init__(self):
        self.received: int | None = None
        self.abort_with: grpc.StatusCode | None = None

    def ReportEventsConsumed(self, request, context):  # noqa: N802
        self.received = request.consumed_cursor
        if self.abort_with is not None:
            context.abort(self.abort_with, "report failed server-side")
        return pb.Empty()


@pytest.fixture
def events_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    servicer = RecordingEvents()
    rpc.add_SeamEventsServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


def test_report_events_consumed_sends_the_cursor_and_returns_none(events_server):
    servicer, addr = events_server
    with SeamAdminClient.connect(addr) as admin:
        result = admin.report_events_consumed(42)
    assert result is None, "the RPC returns Empty; the wrapper returns None"
    assert servicer.received == 42, (
        "the reported cursor must reach the server unchanged"
    )


def test_report_events_consumed_maps_a_server_error_to_a_typed_exception(events_server):
    servicer, addr = events_server
    servicer.abort_with = grpc.StatusCode.UNAVAILABLE
    with SeamAdminClient.connect(addr) as admin:
        with pytest.raises(UnavailableError) as excinfo:
            admin.report_events_consumed(7)
    assert excinfo.value.code() is grpc.StatusCode.UNAVAILABLE
    assert isinstance(excinfo.value, SeamRpcError), (
        "still catchable as the SDK's base RPC error"
    )
    assert isinstance(excinfo.value, grpc.RpcError), "and still catchable the old way"
