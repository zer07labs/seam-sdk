"""``server_info`` — the runtime's version over ``SeamTrust/ServerInfo`` (runtime 0.63.0, seam-sdk#307).

Both clients, against an in-process server: the value comes back verbatim, the call carries no
credential or ticket metadata even on an agent-bound client, and a runtime without the method
surfaces the typed ``UnimplementedError``.
"""

from __future__ import annotations

import asyncio
from concurrent import futures

import grpc
import pytest

from seam_sdk import Agent, SeamClient, UnimplementedError
from seam_sdk.errors import SeamRpcError
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.aio import SeamClient as AioSeamClient

SEED = bytes(range(32))


class _Trust(rpc.SeamTrustServicer):
    def __init__(self, version: str) -> None:
        self.version = version
        self.requests: list[pb.Empty] = []
        self.metadata: list[dict[str, object]] = []

    def ServerInfo(self, request, context):  # noqa: N802 — gRPC method name
        self.requests.append(request)
        self.metadata.append(dict(context.invocation_metadata()))
        return pb.ServerInfoResponse(runtime_version=self.version)


def _serve(register) -> tuple[grpc.Server, str]:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    register(server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    return server, f"127.0.0.1:{port}"


@pytest.fixture
def trust_server():
    servicer = _Trust("0.63.0")
    server, addr = _serve(lambda s: rpc.add_SeamTrustServicer_to_server(servicer, s))
    yield servicer, addr
    server.stop(None)


@pytest.fixture
def bare_server():
    """No ``SeamTrust`` registered. A stand-in for a pre-0.63.0 runtime, which registers the service
    but lacks the method; both answer UNIMPLEMENTED."""
    server, addr = _serve(
        lambda s: rpc.add_SeamAdmissionServicer_to_server(
            rpc.SeamAdmissionServicer(), s
        )
    )
    yield addr
    server.stop(None)


# The headers a credentialed call attaches (`_authorize.py`): the ticket, the call signature, the
# subject and clearance. Any `x-seam-` key at all would be wrong here (no tenant was configured).
_CREDENTIAL_HEADERS = (
    "x-seam-ticket-bin",
    "x-seam-call-sig-bin",
    "x-seam-subject",
    "x-seam-clearance",
    "authorization",
)


def _no_credential_headers(md: dict[str, object]) -> None:
    for key in md:
        assert not key.startswith("x-seam-"), key
        assert key not in _CREDENTIAL_HEADERS, key


@pytest.mark.parametrize("agent", [None, Agent(SEED)], ids=["unbound", "agent-bound"])
def test_sync_returns_the_version_verbatim_with_no_credential(
    trust_server, agent
) -> None:
    servicer, addr = trust_server
    client = SeamClient.connect(addr, agent=agent)
    assert client.server_info() == "0.63.0"
    assert servicer.requests == [pb.Empty()]
    _no_credential_headers(servicer.metadata[0])


@pytest.mark.parametrize("agent", [None, Agent(SEED)], ids=["unbound", "agent-bound"])
def test_aio_returns_the_version_verbatim_with_no_credential(
    trust_server, agent
) -> None:
    servicer, addr = trust_server

    async def scenario() -> str:
        client = AioSeamClient.connect(addr, agent=agent)
        try:
            return await client.server_info()
        finally:
            await client.close()

    assert asyncio.run(scenario()) == "0.63.0"
    assert servicer.requests == [pb.Empty()]
    _no_credential_headers(servicer.metadata[0])


def test_the_value_is_not_normalised(trust_server) -> None:
    """Returned as the server sent it — no parsing, trimming or semver validation in the SDK."""
    servicer, addr = trust_server
    servicer.version = " 0.63.0-rc.1+build "
    assert SeamClient.connect(addr).server_info() == " 0.63.0-rc.1+build "


def test_an_empty_version_is_returned_not_refused(trust_server) -> None:
    """A non-conforming server's empty value comes back as ``""``; the SDK invents no refusal."""
    servicer, addr = trust_server
    servicer.version = ""
    assert SeamClient.connect(addr).server_info() == ""


def test_sync_older_runtime_raises_unimplemented(bare_server) -> None:
    with pytest.raises(UnimplementedError) as exc:
        SeamClient.connect(bare_server).server_info()
    assert isinstance(exc.value, grpc.RpcError)
    assert exc.value.code() == grpc.StatusCode.UNIMPLEMENTED
    assert isinstance(exc.value.__cause__, grpc.RpcError)
    assert not isinstance(exc.value.__cause__, SeamRpcError)  # the raw, unmapped error


def test_aio_older_runtime_raises_unimplemented(bare_server) -> None:
    async def scenario() -> None:
        client = AioSeamClient.connect(bare_server)
        try:
            await client.server_info()
        finally:
            await client.close()

    with pytest.raises(UnimplementedError) as exc:
        asyncio.run(scenario())
    assert isinstance(exc.value, grpc.RpcError)
    assert exc.value.code() == grpc.StatusCode.UNIMPLEMENTED
    assert isinstance(exc.value.__cause__, grpc.RpcError)
    assert not isinstance(exc.value.__cause__, SeamRpcError)  # the raw, unmapped error
