"""Live: a DPoP-bound operator token against a real `seam-grpc` (seam-sdk#290). Skips without SEAM_GRPC_BIN.

The spawned management listener is loopback, so its DPoP posture is *optional* — but a token that carries
`cnf.jkt` "must come with a valid proof on every call, on every listener" (docs/specs/mgmt-dpop.md), so
everything the SDK sends is checked here exactly as a required listener would check it. That a required
listener also refuses UNBOUND Bearer tokens is runtime behaviour, exercised on a real deployment by the
aws-stg smoke (plans/operator-dpop-signer.md, Phase 9).

Every refusal is asserted to carry the runtime's one fixed message, so a 401 for an unrelated reason (a
bad operator signature, a missing scope) cannot pass for a DPoP refusal.
"""

from __future__ import annotations

import time

import grpc
import pytest

from governing_root import DEMO_NAMESPACE, DEMO_TENANT, STREAM_ID
from live_server import spawn_server
from operator_token import mint_operator_token

from seam_sdk import Agent, OperatorDpopKey, SeamAdminClient, UnauthenticatedError
from seam_sdk import mgmt_dpop_grpc_htu, mgmt_dpop_proof
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.errors import _MappedStub

TENANT = DEMO_TENANT
REFUSED = "management call refused: DPoP proof of possession failed"
LIST_TENANTS = "/seam.api.v1.SeamAdmin/ListTenants"

KEY = OperatorDpopKey.from_seed(b"\x42" * 32)
OTHER = OperatorDpopKey.from_seed(b"\x07" * 32)


@pytest.fixture(scope="module")
def mgmt_addr(tmp_path_factory):
    with spawn_server(mgmt=True, log_dir=tmp_path_factory.mktemp("dpop-live")) as srv:
        yield srv.mgmt_addr


def _bound(*scopes: str, jkt: str = KEY.jkt) -> str:
    return mint_operator_token(list(scopes), cnf_jkt=jkt)


@pytest.fixture
def raw(mgmt_addr):
    """A typed-error stub with NO auth interceptor, for the requests the SDK refuses to build."""
    with grpc.insecure_channel(mgmt_addr) as channel:
        yield _MappedStub(rpc.SeamAdminStub(channel))


def _proof(token: str, body: bytes, *, iat: int | None = None) -> str:
    return mgmt_dpop_proof(
        KEY, token, htm="POST", htu=mgmt_dpop_grpc_htu(LIST_TENANTS), body=body, iat=iat
    )


def _assert_dpop_refusal(ei: pytest.ExceptionInfo) -> None:
    assert ei.value.code() == grpc.StatusCode.UNAUTHENTICATED
    assert REFUSED in str(ei.value), str(ei.value)


# ── accepted ───────────────────────────────────────────────────────────────────────────────────


def test_bound_token_lists_tenants(mgmt_addr) -> None:
    with SeamAdminClient.connect(
        mgmt_addr, token=_bound("tenant:list"), dpop_key=KEY
    ) as admin:
        assert isinstance(admin.list_tenants(), list)


def test_bound_token_enrolls_a_tenant(mgmt_addr) -> None:
    agent = Agent(bytes(range(1, 33)))
    with SeamAdminClient.connect(
        mgmt_addr, token=_bound("tenant:enroll"), dpop_key=KEY
    ) as admin:
        view = admin.enroll_tenant(agent.aid, TENANT, DEMO_NAMESPACE)
    assert view.tenant == TENANT


def test_bound_token_drains_events(mgmt_addr) -> None:
    with SeamAdminClient.connect(
        mgmt_addr, token=_bound("audit:read"), dpop_key=KEY
    ) as admin:
        assert isinstance(list(admin.stream_events(stream_id=STREAM_ID)), list)


def test_many_calls_on_one_client_each_re_sign(mgmt_addr) -> None:
    """Each proof is burned on acceptance; a client that reused one would fail on its second call."""
    with SeamAdminClient.connect(
        mgmt_addr, token=_bound("tenant:list"), dpop_key=KEY
    ) as admin:
        for _ in range(5):
            admin.list_tenants()


# ── refused, each with the fixed DPoP message ──────────────────────────────────────────────────


def test_bound_token_sent_as_bearer_is_refused(raw) -> None:
    token = _bound("tenant:list")
    with pytest.raises(UnauthenticatedError) as ei:
        raw.ListTenants(
            pb.Empty(), metadata=(("authorization", f"Bearer {token}"),), timeout=10
        )
    _assert_dpop_refusal(ei)


def test_token_bound_to_another_key_is_refused(raw) -> None:
    token = _bound("tenant:list", jkt=OTHER.jkt)
    with pytest.raises(UnauthenticatedError) as ei:
        raw.ListTenants(
            pb.Empty(),
            metadata=(("authorization", f"DPoP {token}"), ("dpop", _proof(token, b""))),
            timeout=10,
        )
    _assert_dpop_refusal(ei)


def test_a_replayed_proof_is_refused(raw) -> None:
    token = _bound("tenant:list")
    md = (("authorization", f"DPoP {token}"), ("dpop", _proof(token, b"")))
    raw.ListTenants(pb.Empty(), metadata=md, timeout=10)  # first use: accepted
    with pytest.raises(UnauthenticatedError) as ei:
        raw.ListTenants(pb.Empty(), metadata=md, timeout=10)
    _assert_dpop_refusal(ei)


def test_a_stale_iat_is_refused(mgmt_addr) -> None:
    with SeamAdminClient.connect(
        mgmt_addr,
        token=_bound("tenant:list"),
        dpop_key=KEY,
        clock=lambda: int(time.time()) - 120,
    ) as admin:
        with pytest.raises(UnauthenticatedError) as ei:
            admin.list_tenants()
    _assert_dpop_refusal(ei)


def test_a_proof_over_other_bytes_is_refused(raw) -> None:
    token = _bound("tenant:list")
    with pytest.raises(UnauthenticatedError) as ei:
        raw.ListTenants(
            pb.Empty(),
            metadata=(
                ("authorization", f"DPoP {token}"),
                ("dpop", _proof(token, b"\x00")),
            ),
            timeout=10,
        )
    _assert_dpop_refusal(ei)
