"""``x-seam-tenant`` on every data-plane call, and ``WRONG_CELL`` (seam-runtime k8s P15, D123).

The router routes on the header before authentication, so it must ride ``IssueChallenge`` and
``Admit`` — the two calls that carry no tenant of their own — which is exactly what ``admit()``
sends. Asserted on a real server's received metadata, sync and aio, rather than on the interceptor
in isolation: what matters is what reaches the wire.
"""

from __future__ import annotations

import asyncio
import threading
import time
from concurrent import futures

import grpc
import pytest

from seam_sdk import (
    TENANT_HEADER,
    WRONG_CELL_REASON,
    Agent,
    AioTenantInterceptor,
    SeamClient,
    TenantInterceptor,
    is_retryable,
    is_wrong_cell,
)
from seam_sdk import aio
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.errors import FailedPreconditionError, map_rpc_error

from test_error_details import KEY, _Raw, error_info, status


class _Admission(rpc.SeamAdmissionServicer):
    def __init__(self):
        self.seen: list[tuple[str, list[str]]] = []
        self._lock = threading.Lock()

    def _record(self, verb, context):
        with self._lock:
            self.seen.append(
                (
                    verb,
                    [v for k, v in context.invocation_metadata() if k == TENANT_HEADER],
                )
            )

    def IssueChallenge(self, request, context):  # noqa: N802
        self._record("IssueChallenge", context)
        return pb.Challenge(nonce="bm9uY2U", receiver_aid="aid:pubkey:receiver")

    def Admit(self, request, context):  # noqa: N802
        self._record("Admit", context)
        return pb.AdmissionTicket(
            ticket=b"tkt:ok", expires_at_ms=int(time.time() * 1000) + 300_000
        )


@pytest.fixture
def server():
    srv = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    servicer = _Admission()
    rpc.add_SeamAdmissionServicer_to_server(servicer, srv)
    port = srv.add_insecure_port("127.0.0.1:0")
    srv.start()
    yield servicer, f"127.0.0.1:{port}"
    srv.stop(None)


def test_sync_connect_sends_the_tenant_on_the_pre_auth_calls(server):
    servicer, addr = server
    with SeamClient.connect(addr, tenant="acme") as client:
        client.admit(Agent.generate())
    assert servicer.seen == [("IssueChallenge", ["acme"]), ("Admit", ["acme"])]


def test_aio_connect_sends_the_tenant_on_the_pre_auth_calls(server):
    servicer, addr = server

    async def scenario():
        async with aio.SeamClient.connect(addr, tenant="acme") as client:
            await client.admit(Agent.generate())

    asyncio.run(scenario())
    assert servicer.seen == [("IssueChallenge", ["acme"]), ("Admit", ["acme"])]


def test_no_tenant_sends_no_header(server):
    """The direct-to-cell path (Railway prd/partner) is byte-unchanged: no option, no header."""
    servicer, addr = server
    with SeamClient.connect(addr) as client:
        client.admit(Agent.generate())
    assert servicer.seen == [("IssueChallenge", []), ("Admit", [])]


def test_a_caller_built_channel_installs_the_interceptor_itself(server):
    servicer, addr = server
    channel = grpc.intercept_channel(
        grpc.insecure_channel(addr), TenantInterceptor("globex")
    )
    with SeamClient(channel) as client:
        client.admit(Agent.generate())
    assert [t for _, t in servicer.seen] == [["globex"], ["globex"]]


def test_a_header_the_call_already_names_is_kept_not_doubled(server):
    servicer, addr = server
    channel = grpc.intercept_channel(
        grpc.insecure_channel(addr), TenantInterceptor("acme")
    )
    stub = rpc.SeamAdmissionStub(channel)
    stub.IssueChallenge(
        pb.IssueChallengeRequest(), metadata=((TENANT_HEADER, "explicit"),)
    )
    channel.close()
    assert servicer.seen == [("IssueChallenge", ["explicit"])]


@pytest.mark.parametrize("bad", ["", None, 7])
def test_an_empty_or_non_string_tenant_is_refused_before_any_call(bad):
    for make in (TenantInterceptor, AioTenantInterceptor):
        with pytest.raises(ValueError, match="tenant"):
            make(bad)
    if bad is not None:  # None is "omitted" on connect — no header, not an error
        with pytest.raises(ValueError, match="tenant"):
            SeamClient.connect("127.0.0.1:1", tenant=bad)


# ── WRONG_CELL ────────────────────────────────────────────────────────────────────────────────────


def _wrong_cell():
    trailing = (
        (
            KEY,
            status(
                9,
                error_info(
                    WRONG_CELL_REASON,
                    cell="aws-stg-b",
                    root_snapshot_id="snap-41",
                    root_generated_at="2026-10-25T12:00:00Z",
                ),
            ),
        ),
    )
    return map_rpc_error(_Raw(grpc.StatusCode.FAILED_PRECONDITION, trailing))


def test_wrong_cell_is_typed_and_exposes_its_metadata():
    err = _wrong_cell()
    assert isinstance(err, FailedPreconditionError)
    assert err.reason == "WRONG_CELL"
    assert err.error_metadata == {
        "cell": "aws-stg-b",
        "root_snapshot_id": "snap-41",
        "root_generated_at": "2026-10-25T12:00:00Z",
    }
    assert is_wrong_cell(err)


def test_wrong_cell_is_never_retryable():
    assert not is_retryable(_wrong_cell())


def test_error_metadata_is_a_copy_and_absent_without_a_detail():
    err = _wrong_cell()
    err.error_metadata["cell"] = "mutated"
    assert err.error_metadata["cell"] == "aws-stg-b"
    bare = map_rpc_error(_Raw(grpc.StatusCode.FAILED_PRECONDITION, ()))
    assert bare.error_metadata is None and not is_wrong_cell(bare)


def test_another_failed_precondition_reason_is_not_wrong_cell():
    trailing = ((KEY, status(9, error_info("stream_id_mismatch"))),)
    err = map_rpc_error(_Raw(grpc.StatusCode.FAILED_PRECONDITION, trailing))
    assert err.error_metadata == {} and not is_wrong_cell(err)
