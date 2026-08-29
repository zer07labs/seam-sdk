"""``EvaluationRequest.confidence`` is EXPLICIT PRESENCE on the wire (proto ``optional double``).

Absent means "declined to claim" — the runtime never fabricates ``0.0`` into the caller's intent.
Passing ``confidence=0.0`` into the wrapper's constructor kwarg would be indistinguishable from
absent on the wire if the wrapper defaulted it into the request unconditionally; that collapse is
precisely what ``SeamClient.submit_evaluation`` / ``aio.SeamClient.submit_evaluation`` must not
produce. This pins the presence contract through the wrapper itself (not a copy of its logic),
against a real in-process gRPC server, for both the sync and async clients.
"""

from __future__ import annotations

import asyncio
from concurrent import futures

import grpc
import pytest

from seam_sdk import SeamClient
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.aio import SeamClient as AioSeamClient


class RecordingCoordination(rpc.SeamCoordinationServicer):
    """Records the last ``EvaluationRequest`` / ``ObjectionRequest`` it received."""

    def __init__(self) -> None:
        self.last_evaluation: pb.EvaluationRequest | None = None
        self.last_objection: pb.ObjectionRequest | None = None

    def SubmitEvaluation(self, request, context):
        self.last_evaluation = request
        return pb.SessionStep()

    def SubmitObjection(self, request, context):
        self.last_objection = request
        return pb.SessionStep()


@pytest.fixture
def coord_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    servicer = RecordingCoordination()
    rpc.add_SeamCoordinationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


# ── sync client ──────────────────────────────────────────────────────────────────────────────────


def test_sync_confidence_absent_is_not_present_on_the_wire(coord_server):
    servicer, addr = coord_server
    client = SeamClient.connect(addr)
    client.submit_evaluation("s-1", "evaluator-a", "p-1", "APPROVE")
    req = servicer.last_evaluation
    assert req is not None
    assert not req.HasField("confidence")


def test_sync_confidence_zero_is_present_and_zero_on_the_wire(coord_server):
    servicer, addr = coord_server
    client = SeamClient.connect(addr)
    client.submit_evaluation("s-1", "evaluator-a", "p-1", "APPROVE", confidence=0.0)
    req = servicer.last_evaluation
    assert req is not None
    assert req.HasField("confidence")
    assert req.confidence == 0.0


def test_sync_submit_objection_severity_defaults_to_empty(coord_server):
    servicer, addr = coord_server
    client = SeamClient.connect(addr)
    client.submit_objection("s-1", "objector-a", "p-1", "too risky")
    req = servicer.last_objection
    assert req is not None
    assert req.severity == ""
    assert req.reason == "too risky"


# ── async client ─────────────────────────────────────────────────────────────────────────────────


def test_aio_confidence_absent_is_not_present_on_the_wire(coord_server):
    servicer, addr = coord_server

    async def scenario():
        async with AioSeamClient.connect(addr) as client:
            await client.submit_evaluation("s-1", "evaluator-a", "p-1", "APPROVE")

    asyncio.run(scenario())
    req = servicer.last_evaluation
    assert req is not None
    assert not req.HasField("confidence")


def test_aio_confidence_zero_is_present_and_zero_on_the_wire(coord_server):
    servicer, addr = coord_server

    async def scenario():
        async with AioSeamClient.connect(addr) as client:
            await client.submit_evaluation(
                "s-1", "evaluator-a", "p-1", "APPROVE", confidence=0.0
            )

    asyncio.run(scenario())
    req = servicer.last_evaluation
    assert req is not None
    assert req.HasField("confidence")
    assert req.confidence == 0.0


def test_aio_submit_objection_reaches_the_server(coord_server):
    servicer, addr = coord_server

    async def scenario():
        async with AioSeamClient.connect(addr) as client:
            await client.submit_objection(
                "s-1", "objector-a", "p-1", "too risky", severity="high"
            )

    asyncio.run(scenario())
    req = servicer.last_objection
    assert req is not None
    assert req.severity == "high"
