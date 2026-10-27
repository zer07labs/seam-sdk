"""`SeamAdminClient.connect(..., dpop_key=)` — the management-plane DPoP interceptor (seam-sdk#290).

An in-process server registers both management services with raw-bytes handlers, so each assertion is
made against the bytes the server actually RECEIVED, not against what the client believes it sent.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from concurrent import futures

import grpc
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from seam_sdk import DpopError, DpopKeyError, OperatorDpopKey, SeamAdminClient
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev

KEY = OperatorDpopKey.from_seed(b"\x42" * 32)
OTHER = OperatorDpopKey.from_seed(b"\x07" * 32)


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _token(**claims: object) -> str:
    def seg(o: object) -> str:
        return _b64e(json.dumps(o).encode())

    return f"{seg({'alg': 'EdDSA', 'typ': 'JWT'})}.{seg({'sub': 'op', **claims})}.c2ln"


BOUND = _token(aud="seam-runtime", cnf={"jkt": KEY.jkt})


class _Recorder:
    """Raw-bytes handlers for the RPCs these tests drive; records (method, metadata, request bytes)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, list[str]], bytes]] = []
        self.fail_with: grpc.StatusCode | None = None

    def _record(
        self, method: str, request: bytes, context: grpc.ServicerContext
    ) -> None:
        md: dict[str, list[str]] = {}
        for k, v in context.invocation_metadata():
            md.setdefault(k, []).append(v)
        self.calls.append((method, md, request))
        if self.fail_with is not None:
            context.abort(self.fail_with, "injected")

    def handlers(self) -> list[grpc.GenericRpcHandler]:
        def unary(method: str, reply: bytes):
            def h(request: bytes, context: grpc.ServicerContext) -> bytes:
                self._record(method, request, context)
                return reply

            return grpc.unary_unary_rpc_method_handler(h)

        def stream(method: str, replies: list[bytes]):
            def h(request: bytes, context: grpc.ServicerContext):
                self._record(method, request, context)
                yield from replies

            return grpc.unary_stream_rpc_method_handler(h)

        admin = grpc.method_handlers_generic_handler(
            "seam.api.v1.SeamAdmin",
            {
                "EnrollTenant": unary(
                    "/seam.api.v1.SeamAdmin/EnrollTenant",
                    pb.TenantView(tenant="acme").SerializeToString(),
                ),
                "ListTenants": unary(
                    "/seam.api.v1.SeamAdmin/ListTenants",
                    pb.ListTenantsResponse().SerializeToString(),
                ),
                "PlaceLegalHold": unary(
                    "/seam.api.v1.SeamAdmin/PlaceLegalHold",
                    pb.Empty().SerializeToString(),
                ),
            },
        )
        events = grpc.method_handlers_generic_handler(
            "seam.api.v1.SeamEvents",
            {
                "StreamEvents": stream(
                    "/seam.api.v1.SeamEvents/StreamEvents",
                    [ev.SeamEvent(seq=1).SerializeToString()],
                )
            },
        )
        return [admin, events]


@pytest.fixture
def server():
    rec = _Recorder()
    srv = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    srv.add_generic_rpc_handlers(rec.handlers())
    port = srv.add_insecure_port("127.0.0.1:0")
    srv.start()
    yield rec, f"127.0.0.1:{port}"
    srv.stop(None)


def _check_proof(
    md: dict[str, list[str]], method: str, request: bytes, *, aud: str, token: str
):
    assert md["authorization"] == [f"DPoP {token}"]
    (proof,) = md["dpop"]
    signing_input, _, sig = proof.rpartition(".")
    Ed25519PublicKey.from_public_bytes(_b64d(KEY.x)).verify(
        _b64d(sig), signing_input.encode()
    )
    header = json.loads(_b64d(proof.split(".")[0]))
    claims = json.loads(_b64d(proof.split(".")[1]))
    assert header == {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": KEY.public_jwk()}
    assert claims["htm"] == "POST"
    assert claims["htu"] == f"grpc://{aud}{method}"
    assert claims["seam_bd"] == _b64e(hashlib.sha256(request).digest())
    assert claims["ath"] == _b64e(hashlib.sha256(token.encode()).digest())
    return claims


# ── AC1: the proof binds the bytes the server received ─────────────────────────────────────────


def test_enroll_tenant_proof_binds_the_received_bytes(server) -> None:
    rec, addr = server
    with SeamAdminClient.connect(addr, token=BOUND, dpop_key=KEY) as admin:
        admin.enroll_tenant("aid:x", "acme", "ns")
    ((method, md, request),) = rec.calls
    assert request, "EnrollTenant must carry a non-empty message"
    _check_proof(md, method, request, aud="seam-runtime", token=BOUND)


def test_list_tenants_empty_message(server) -> None:
    rec, addr = server
    with SeamAdminClient.connect(addr, token=BOUND, dpop_key=KEY) as admin:
        admin.list_tenants()
    ((method, md, request),) = rec.calls
    assert request == b""
    claims = _check_proof(md, method, request, aud="seam-runtime", token=BOUND)
    assert claims["htu"] == "grpc://seam-runtime/seam.api.v1.SeamAdmin/ListTenants"


def test_stream_events_is_signed_once_at_call_start(server) -> None:
    rec, addr = server
    with SeamAdminClient.connect(addr, token=BOUND, dpop_key=KEY) as admin:
        events = list(admin.stream_events(stream_id="s1", from_seq=7))
    assert [e.seq for e in events] == [1]
    ((method, md, request),) = rec.calls
    assert method == "/seam.api.v1.SeamEvents/StreamEvents"
    _check_proof(md, method, request, aud="seam-runtime", token=BOUND)


def test_aud_comes_from_the_token(server) -> None:
    rec, addr = server
    token = _token(aud="ops.internal", cnf={"jkt": KEY.jkt})
    with SeamAdminClient.connect(addr, token=token, dpop_key=KEY) as admin:
        admin.list_tenants()
    ((method, md, request),) = rec.calls
    _check_proof(md, method, request, aud="ops.internal", token=token)


def test_explicit_aud_wins_over_the_token(server) -> None:
    rec, addr = server
    with SeamAdminClient.connect(
        addr, token=BOUND, dpop_key=KEY, aud="cell-7"
    ) as admin:
        admin.list_tenants()
    ((method, md, request),) = rec.calls
    _check_proof(md, method, request, aud="cell-7", token=BOUND)


def test_aud_defaults_when_the_token_has_none(server) -> None:
    rec, addr = server
    token = _token(cnf={"jkt": KEY.jkt})
    with SeamAdminClient.connect(addr, token=token, dpop_key=KEY) as admin:
        admin.list_tenants()
    ((method, md, request),) = rec.calls
    _check_proof(md, method, request, aud="seam-runtime", token=token)


def test_clock_hook_sets_iat(server) -> None:
    rec, addr = server
    with SeamAdminClient.connect(
        addr, token=BOUND, dpop_key=KEY, clock=lambda: 1_234
    ) as admin:
        admin.list_tenants()
    ((method, md, request),) = rec.calls
    assert (
        _check_proof(md, method, request, aud="seam-runtime", token=BOUND)["iat"]
        == 1_234
    )


# ── AC2: every call is freshly signed ──────────────────────────────────────────────────────────


def test_consecutive_calls_carry_distinct_proofs(server) -> None:
    rec, addr = server
    with SeamAdminClient.connect(
        addr, token=BOUND, dpop_key=KEY, clock=lambda: 1
    ) as admin:
        admin.list_tenants()
        admin.list_tenants()
    (_, a, _), (_, b, _) = rec.calls
    assert a["dpop"] != b["dpop"]
    jti = [json.loads(_b64d(md["dpop"][0].split(".")[1]))["jti"] for md in (a, b)]
    assert jti[0] != jti[1]


def test_a_failed_call_is_not_resent_by_the_transport(server) -> None:
    """A transport-level retry would resend a proof the runtime has already burned. The admin channel
    configures no retry policy; pin it, so adding one later is a deliberate, visible change."""
    rec, addr = server
    rec.fail_with = grpc.StatusCode.UNAVAILABLE
    with SeamAdminClient.connect(addr, token=BOUND, dpop_key=KEY) as admin:
        with pytest.raises(Exception):
            admin.list_tenants()
    assert len(rec.calls) == 1


# ── AC5: the tenant header survives ────────────────────────────────────────────────────────────


def test_tenant_header_rides_alongside_dpop(server) -> None:
    rec, addr = server
    with SeamAdminClient.connect(addr, token=BOUND, dpop_key=KEY) as admin:
        admin.place_legal_hold("dec:1", tenant="acme")
    ((method, md, request),) = rec.calls
    assert md["x-seam-tenant"] == ["acme"]
    _check_proof(md, method, request, aud="seam-runtime", token=BOUND)


# ── AC3: guaranteed-to-fail pairings are refused before any connection ─────────────────────────


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"dpop_key": KEY}, "needs token"),
        ({"dpop_key": KEY, "token": ""}, "needs token"),
        ({"dpop_key": KEY, "token": _token(aud="seam-runtime")}, "not DPoP-bound"),
        ({"dpop_key": OTHER, "token": BOUND}, "bound to key"),
        ({"token": BOUND}, "DPoP-bound"),
        (
            {"dpop_key": KEY, "token": _token(aud=["a", "b"], cnf={"jkt": KEY.jkt})},
            "not a single string",
        ),
        ({"dpop_key": KEY, "token": "not-a-jws"}, "compact JWS"),
        ({"dpop_key": KEY, "token": _token(cnf={"jkt": 7})}, "malformed"),
    ],
)
def test_misuse_is_refused_before_connecting(
    kwargs: dict, match: str, monkeypatch
) -> None:
    def no_channel(*_a, **_k):
        raise AssertionError("a channel was created for a pairing that cannot work")

    monkeypatch.setattr(grpc, "insecure_channel", no_channel)
    monkeypatch.setattr(grpc, "secure_channel", no_channel)
    with pytest.raises(DpopKeyError, match=match):
        SeamAdminClient.connect("127.0.0.1:1", **kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"token": "tok", "aud": "x"},
        {"token": "tok", "clock": lambda: 1},
        {"dpop_key": b"\x42" * 32, "token": BOUND},
        {"dpop_key": KEY, "token": BOUND, "aud": "a/b"},
        {"dpop_key": KEY, "token": BOUND, "clock": 5},
        {"dpop_key": KEY, "token": BOUND, "clock": lambda: 1.5},
        {"dpop_key": KEY, "token": BOUND, "clock": lambda: True},
        {"dpop_key": KEY, "token": _token(aud="has space", cnf={"jkt": KEY.jkt})},
    ],
)
def test_bad_arguments_are_refused(kwargs: dict) -> None:
    with pytest.raises(DpopError):
        SeamAdminClient.connect("127.0.0.1:1", **kwargs)


# ── AC4: the Bearer path is unchanged ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("token", ["tok", _token(aud="seam-runtime")])
def test_unbound_tokens_still_go_as_bearer(server, token: str) -> None:
    rec, addr = server
    with SeamAdminClient.connect(addr, token=token) as admin:
        admin.list_tenants()
    ((_, md, _),) = rec.calls
    assert md["authorization"] == [f"Bearer {token}"]
    assert "dpop" not in md


def test_no_token_sends_no_authorization(server) -> None:
    rec, addr = server
    with SeamAdminClient.connect(addr) as admin:
        admin.list_tenants()
    ((_, md, _),) = rec.calls
    assert "authorization" not in md and "dpop" not in md


def test_concurrent_calls_each_get_their_own_proof(server) -> None:
    rec, addr = server
    with SeamAdminClient.connect(addr, token=BOUND, dpop_key=KEY) as admin:
        threads = [threading.Thread(target=admin.list_tenants) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert len(rec.calls) == 16
    for method, md, request in rec.calls:
        _check_proof(md, method, request, aud="seam-runtime", token=BOUND)
    jtis = {
        json.loads(_b64d(md["dpop"][0].split(".")[1]))["jti"] for _, md, _ in rec.calls
    }
    assert len(jtis) == 16


def test_a_bytes_method_name_is_signed_as_text() -> None:
    from seam_sdk.admin import _ClientCallDetails, _DpopAuthInterceptor

    seen = []
    icpt = _DpopAuthInterceptor(BOUND, KEY, "seam-runtime", None)
    details = _ClientCallDetails(
        b"/seam.api.v1.SeamAdmin/ListTenants", None, None, None, None, None
    )
    icpt.intercept_unary_unary(lambda d, r: seen.append(d), details, pb.Empty())
    ((d,),) = [seen]
    assert d.method == b"/seam.api.v1.SeamAdmin/ListTenants"  # passed through untouched
    proof = dict(d.metadata)["dpop"]
    claims = json.loads(_b64d(proof.split(".")[1]))
    assert claims["htu"] == "grpc://seam-runtime/seam.api.v1.SeamAdmin/ListTenants"


def test_a_pathological_token_on_the_bearer_path_still_goes_as_bearer(server) -> None:
    rec, addr = server
    token = (
        "a." + _b64e(b"[" * 5_000) + ".c"
    )  # past the parser's recursion limit, under the metadata cap
    with SeamAdminClient.connect(addr, token=token) as admin:
        admin.list_tenants()
    ((_, md, _),) = rec.calls
    assert md["authorization"] == [f"Bearer {token}"]
