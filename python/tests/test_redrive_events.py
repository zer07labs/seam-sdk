"""seam-runtime #1176: SeamEvents.RedriveEvents (DLQ retry by reference) and the EVENT_REDRIVEN wrapper."""

from __future__ import annotations

from concurrent import futures

import grpc
import pytest

from seam_sdk import Agent, SeamAdminClient, SeamClient
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev

# ── Unit: request shaping, server-free ───────────────────────────────────────────────────────────


class RecordingEvents(rpc.SeamEventsServicer):
    def __init__(self):
        self.requests: list[pb.RedriveEventsRequest] = []

    def RedriveEvents(self, request, context):  # noqa: N802
        self.requests.append(request)
        return pb.RedriveEventsResponse(
            outcomes=[
                pb.RedriveOutcome(
                    seq=request.from_seq, status="redriven", redrive_seq=99
                )
            ]
        )


@pytest.fixture
def recording_events():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    servicer = RecordingEvents()
    rpc.add_SeamEventsServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


def test_single_seq_leaves_the_optional_fields_absent(recording_events):
    servicer, addr = recording_events
    with SeamAdminClient.connect(addr) as admin:
        out = admin.redrive_events("acme", 7)
    req = servicer.requests[0]
    assert (req.tenant, req.from_seq) == ("acme", 7)
    assert not req.HasField("to_seq") and not req.HasField("event_id")
    assert [(o.seq, o.status, o.redrive_seq) for o in out] == [(7, "redriven", 99)]


def test_range_and_event_id_are_sent_when_given(recording_events):
    servicer, addr = recording_events
    with SeamAdminClient.connect(addr) as admin:
        admin.redrive_events("acme", 7, to_seq=9)
        admin.redrive_events("acme", 7, event_id="ev-1")
    rng, one = servicer.requests
    assert rng.HasField("to_seq") and rng.to_seq == 9 and not rng.HasField("event_id")
    assert (
        one.HasField("event_id")
        and one.event_id == "ev-1"
        and not one.HasField("to_seq")
    )


@pytest.mark.parametrize(
    "args, kwargs, exc",
    [
        (("", 1), {}, ValueError),  # the tenant is required
        (("acme", -1), {}, ValueError),
        (("acme", 1), {"to_seq": -1}, ValueError),
    ],
)
def test_bad_arguments_are_refused_before_the_wire(recording_events, args, kwargs, exc):
    servicer, addr = recording_events
    with SeamAdminClient.connect(addr) as admin, pytest.raises(exc):
        admin.redrive_events(*args, **kwargs)
    assert servicer.requests == []


# ── Live: seal → re-drive the DECISION_SEALED by reference → the wrapper carries it verbatim ─────


def test_redrive_round_trip_live(tmp_path):
    from governing_root import STREAM_ID
    from live_server import spawn_server
    from operator_token import mint_operator_token

    with spawn_server(mgmt=True, log_dir=tmp_path) as srv:
        data = SeamClient.connect(srv.data_addr)
        agent = Agent(bytes([42] * 32))
        dec = data.run_decision(
            agent,
            "redrive-1-sid-0123456789abcdef",
            ["fraud-v3", "risk-v2"],
            [("fraud-v3", "BLOCK"), ("risk-v2", "BLOCK")],
        )
        audit = SeamAdminClient.connect(
            srv.mgmt_addr, token=mint_operator_token(["audit:read"])
        )
        sealed = [
            e
            for e in audit.stream_events(stream_id=STREAM_ID, follow=False)
            if e.kind == "DECISION_SEALED" and e.decision_id == dec.decision_id
        ]
        assert len(sealed) == 1
        original = sealed[0]

        admin = SeamAdminClient.connect(
            srv.mgmt_addr, token=mint_operator_token(["events:redrive"])
        )
        (outcome,) = admin.redrive_events(
            original.tenant, original.seq, event_id=original.event_id
        )
        assert outcome.status == "redriven", outcome
        assert outcome.seq == original.seq and outcome.event_id == original.event_id
        assert outcome.HasField("redrive_seq")

        # A seq past the head is answered, never silently dropped.
        (missing,) = admin.redrive_events(original.tenant, original.seq + 10_000)
        assert missing.status == "not_found"

        wrappers = [
            e
            for e in audit.stream_events(stream_id=STREAM_ID, follow=False)
            if e.kind == "EVENT_REDRIVEN" and e.seq == outcome.redrive_seq
        ]
        assert len(wrappers) == 1
        w = wrappers[0]
        inner = ev.SeamEvent.FromString(w.event_redriven.event)
        assert inner.event_id == original.event_id == w.event_redriven.original_event_id
        assert inner.seq == original.seq == w.event_redriven.original_seq
        assert w.event_redriven.original_kind == "DECISION_SEALED"
        # An advisory wrapper: no chain fields of its own, and not itself re-drivable.
        assert not w.digest and not w.checksum and not w.prev_checksum
        (again,) = admin.redrive_events(w.tenant, w.seq)
        assert again.status == "not_redrivable"
