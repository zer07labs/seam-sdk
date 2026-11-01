"""``who_am_i`` — the caller's resolved identity over ``SeamTrust/WhoAmI`` (runtime 0.71.0, OI-R7).

Both clients. Unlike ``server_info`` the verb is subject-bearing: with a credential (explicit or the
bound agent) it carries a ``seam-request-call-v1`` credential that binds the verb ONLY — an empty
resource id and an empty body digest, the framing the runtime's ``Binding::ReadNoResource`` and the
HTTP twin ``GET /v1/whoami`` share. Without one it sends no credential metadata. The four fields come
back as the server sent them, and a runtime without the method surfaces ``UnimplementedError``.
"""

from __future__ import annotations

import asyncio
import time
from concurrent import futures

import grpc
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_sdk import (
    ENROLMENT_KIND_OUTCOME_REPORTER,
    Agent,
    SeamClient,
    UnauthenticatedError,
    UnimplementedError,
)
from seam_sdk._authorize import TicketCache
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.aio import SeamClient as AioSeamClient
from seam_sdk.crypto import request_sig_payload

SEED = bytes(range(32))
TICKET = b"\x01\x02\x03fake-ticket"
RPC = "/seam.api.v1.SeamTrust/WhoAmI"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _seed_ticket(client, aid: str) -> None:
    cache = TicketCache()
    cache.store(TICKET, _now_ms() + 60_000, _now_ms())
    client._tickets[aid] = cache


class _Trust(rpc.SeamTrustServicer):
    def __init__(self) -> None:
        self.answer = pb.WhoAmIResponse(
            tenant="acme",
            namespace="fraud",
            kind=ENROLMENT_KIND_OUTCOME_REPORTER,
            subject_enforcement=True,
        )
        self.refuse = False
        self.requests: list[pb.Empty] = []
        self.metadata: list[dict[str, object]] = []

    def WhoAmI(self, request, context):  # noqa: N802 — gRPC method name
        self.requests.append(request)
        self.metadata.append(dict(context.invocation_metadata()))
        if self.refuse:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "unenrolled subject")
        return self.answer


def _serve(register) -> tuple[grpc.Server, str]:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    register(server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    return server, f"127.0.0.1:{port}"


@pytest.fixture
def trust_server():
    servicer = _Trust()
    server, addr = _serve(lambda s: rpc.add_SeamTrustServicer_to_server(servicer, s))
    yield servicer, addr
    server.stop(None)


@pytest.fixture
def bare_server():
    """No ``SeamTrust`` registered: a stand-in for a pre-0.71.0 runtime (UNIMPLEMENTED either way)."""
    server, addr = _serve(
        lambda s: rpc.add_SeamAdmissionServicer_to_server(
            rpc.SeamAdmissionServicer(), s
        )
    )
    yield addr
    server.stop(None)


def _assert_verb_only_credential(md: dict[str, object], signer: Agent) -> None:
    assert md["x-seam-ticket-bin"] == TICKET
    payload = request_sig_payload(TICKET, RPC, "", "")  # no resource id, no body digest
    pub = Ed25519PrivateKey.from_private_bytes(signer.seed).public_key()
    pub.verify(md["x-seam-call-sig-bin"], payload)  # raises InvalidSignature if wrong


def _assert_the_four_fields(r: pb.WhoAmIResponse) -> None:
    assert (r.tenant, r.namespace, r.kind, r.subject_enforcement) == (
        "acme",
        "fraud",
        "outcome_reporter",
        True,
    )


def test_sync_unbound_sends_no_credential(trust_server) -> None:
    servicer, addr = trust_server
    _assert_the_four_fields(SeamClient.connect(addr).who_am_i())
    assert servicer.requests == [pb.Empty()]
    md = servicer.metadata[0]
    assert "x-seam-ticket-bin" not in md and "x-seam-call-sig-bin" not in md


@pytest.mark.parametrize("bound", [True, False], ids=["bound-agent", "credential="])
def test_sync_carries_a_verb_only_credential(trust_server, bound: bool) -> None:
    servicer, addr = trust_server
    agent = Agent(SEED)
    client = SeamClient.connect(addr, agent=agent if bound else None)
    _seed_ticket(client, agent.aid)
    r = client.who_am_i() if bound else client.who_am_i(credential=agent)
    _assert_the_four_fields(r)
    _assert_verb_only_credential(servicer.metadata[0], agent)


@pytest.mark.parametrize("bound", [True, False], ids=["bound-agent", "credential="])
def test_aio_carries_a_verb_only_credential(trust_server, bound: bool) -> None:
    servicer, addr = trust_server
    agent = Agent(SEED)

    async def scenario() -> pb.WhoAmIResponse:
        client = AioSeamClient.connect(addr, agent=agent if bound else None)
        _seed_ticket(client, agent.aid)
        try:
            if bound:
                return await client.who_am_i()
            return await client.who_am_i(credential=agent)
        finally:
            await client.close()

    _assert_the_four_fields(asyncio.run(scenario()))
    _assert_verb_only_credential(servicer.metadata[0], agent)


def test_the_empty_triple_is_returned_not_refused(trust_server) -> None:
    """Enforcement off and no proven subject: the runtime answers the empty triple; the SDK passes it
    through rather than inventing a refusal."""
    servicer, addr = trust_server
    servicer.answer = pb.WhoAmIResponse(subject_enforcement=False)
    r = SeamClient.connect(addr).who_am_i()
    assert (r.tenant, r.namespace, r.kind, r.subject_enforcement) == ("", "", "", False)


def test_unauthenticated_is_typed(trust_server) -> None:
    servicer, addr = trust_server
    servicer.refuse = True
    with pytest.raises(UnauthenticatedError):
        SeamClient.connect(addr).who_am_i()


def test_sync_older_runtime_raises_unimplemented(bare_server) -> None:
    with pytest.raises(UnimplementedError) as exc:
        SeamClient.connect(bare_server).who_am_i()
    assert exc.value.code() == grpc.StatusCode.UNIMPLEMENTED


def test_aio_older_runtime_raises_unimplemented(bare_server) -> None:
    async def scenario() -> None:
        client = AioSeamClient.connect(bare_server)
        try:
            await client.who_am_i()
        finally:
            await client.close()

    with pytest.raises(UnimplementedError) as exc:
        asyncio.run(scenario())
    assert exc.value.code() == grpc.StatusCode.UNIMPLEMENTED
