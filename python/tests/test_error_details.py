"""P11 — Seam's error class, read off ``grpc-status-details-bin``: ``reason``, ``macp_code``, ``retry_after``.

The runtime attaches a ``google.rpc.ErrorInfo`` (domain ``seam.zer07labs.com``) to every refusal, and a
``google.rpc.RetryInfo`` to a load-shed. ``errors.py`` may import the standard library and ``grpc`` and
nothing else (seam-sdk#54), so it decodes the three messages by hand; these tests encode them by hand
too, from the ``google.rpc`` field numbers, so neither side borrows the other's decoder.

Field numbers: ``Status{code=1, message=2, details=3 (Any)}``, ``Any{type_url=1, value=2}``,
``ErrorInfo{reason=1, domain=2, metadata=3 (map<string,string>)}``, ``RetryInfo{retry_delay=1
(Duration{seconds=1, nanos=2})}``.
"""

from __future__ import annotations

import threading
import time
from concurrent import futures

import grpc
import pytest

from seam_sdk import Agent, SeamClient
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.errors import (
    PermissionDeniedError,
    ResourceExhaustedError,
    SeamRpcError,
    UnauthenticatedError,
    UnavailableError,
    map_rpc_error,
)

DOMAIN = "seam.zer07labs.com"
KEY = "grpc-status-details-bin"


def _varint(n: int) -> bytes:
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _ld(num: int, payload: bytes) -> bytes:
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def _vi(num: int, value: int) -> bytes:
    return _varint(num << 3) + _varint(value)


def _any(type_name: str, value: bytes) -> bytes:
    return _ld(1, f"type.googleapis.com/{type_name}".encode()) + _ld(2, value)


def error_info(reason: str, domain: str = DOMAIN, **metadata: str) -> bytes:
    body = _ld(1, reason.encode()) + _ld(2, domain.encode())
    for k, v in metadata.items():
        body += _ld(3, _ld(1, k.encode()) + _ld(2, v.encode()))
    return _any("google.rpc.ErrorInfo", body)


def retry_info(seconds: int, nanos: int = 0) -> bytes:
    duration = (_vi(1, seconds) if seconds else b"") + (_vi(2, nanos) if nanos else b"")
    return _any("google.rpc.RetryInfo", _ld(1, duration))


def status(code: int, *details: bytes) -> bytes:
    return _vi(1, code) + _ld(2, b"refused") + b"".join(_ld(3, d) for d in details)


class _Raw(grpc.RpcError):
    def __init__(self, code, trailing):
        self._code, self._trailing = code, trailing

    def code(self):
        return self._code

    def details(self):
        return "refused"

    def trailing_metadata(self):
        return self._trailing


def _mapped(code, blob) -> SeamRpcError:
    return map_rpc_error(_Raw(code, ((KEY, blob),)))


def test_a_protocol_refusal_carries_its_macp_code():
    err = _mapped(
        grpc.StatusCode.PERMISSION_DENIED,
        status(7, error_info("PROTOCOL", macp_code="FORBIDDEN")),
    )
    assert isinstance(err, PermissionDeniedError)
    assert err.reason == "PROTOCOL"
    assert err.macp_code == "FORBIDDEN"


def test_an_unknown_macp_code_is_surfaced_raw_not_dropped():
    """MACP grows codes on its own schedule; a code this SDK cannot name must still be routable."""
    err = _mapped(
        grpc.StatusCode.INVALID_ARGUMENT,
        status(3, error_info("PROTOCOL", macp_code="SOME_FUTURE_CODE")),
    )
    assert err.macp_code == "SOME_FUTURE_CODE"


@pytest.mark.parametrize(
    "reason", ["POLICY_DENIED", "SCOPE_DENIED", "FACT_ATTESTOR_REJECTED"]
)
def test_the_permission_denied_classes_are_told_apart_by_reason(reason):
    """POLICY_DENIED moved from FAILED_PRECONDITION to PERMISSION_DENIED, which it now shares with two
    other classes. The status cannot tell them apart; the reason can."""
    err = _mapped(grpc.StatusCode.PERMISSION_DENIED, status(7, error_info(reason)))
    assert isinstance(err, PermissionDeniedError)
    assert err.reason == reason


def test_macp_code_is_only_read_on_a_protocol_reason():
    """Every other class has no macp_code by contract; a stray key is ignored, not surfaced."""
    err = _mapped(
        grpc.StatusCode.PERMISSION_DENIED,
        status(7, error_info("POLICY_DENIED", macp_code="FORBIDDEN")),
    )
    assert err.reason == "POLICY_DENIED"
    assert err.macp_code is None


def test_a_foreign_domain_is_not_seams_error_class():
    err = _mapped(
        grpc.StatusCode.PERMISSION_DENIED,
        status(7, error_info("PROTOCOL", domain="example.com", macp_code="FORBIDDEN")),
    )
    assert err.reason is None and err.macp_code is None


def test_load_shed_surfaces_retry_after_and_is_not_retried():
    err = _mapped(
        grpc.StatusCode.RESOURCE_EXHAUSTED,
        status(8, error_info("QUOTA_EXCEEDED"), retry_info(2, 500_000_000)),
    )
    assert isinstance(err, ResourceExhaustedError)
    assert err.reason == "QUOTA_EXCEEDED"
    assert err.retry_after == pytest.approx(2.5)
    assert err.macp_code is None


def test_a_challenge_capacity_refusal_is_unavailable_and_carries_retry_after():
    """AITP 0.15.0 (plan item 16): a nonce store at capacity refuses `IssueChallenge` with UNAVAILABLE,
    reason CHALLENGE_REFUSED, and a RetryInfo. RetryInfo is read on ANY status, not only
    RESOURCE_EXHAUSTED, so the caller can honour it; it is never typed as an identity failure."""
    err = _mapped(
        grpc.StatusCode.UNAVAILABLE,
        status(14, error_info("CHALLENGE_REFUSED"), retry_info(1, 250_000_000)),
    )
    assert isinstance(err, UnavailableError)
    assert not isinstance(err, (UnauthenticatedError, PermissionDeniedError))
    assert err.reason == "CHALLENGE_REFUSED"
    assert err.retry_after == pytest.approx(1.25)
    assert err.macp_code is None


def test_no_details_means_none_everywhere():
    err = map_rpc_error(_Raw(grpc.StatusCode.INTERNAL, ()))
    assert (err.reason, err.macp_code, err.retry_after) == (None, None, None)
    bare = SeamRpcError(grpc.StatusCode.INTERNAL, "constructed directly")
    assert (bare.reason, bare.macp_code, bare.retry_after) == (None, None, None)


@pytest.mark.parametrize(
    "blob",
    [b"\xff", b"\x1a\x05ab", status(7, b"\x0a\xff"), b"\x08" + b"\xff" * 11],
    ids=["bad-key", "truncated-length", "truncated-any", "overlong-varint"],
)
def test_a_malformed_payload_fails_soft(blob):
    """The typed error must never be displaced by a failure to read metadata about it."""
    err = _mapped(grpc.StatusCode.PERMISSION_DENIED, blob)
    assert isinstance(err, PermissionDeniedError)
    assert (err.reason, err.macp_code, err.retry_after) == (None, None, None)


# ── End to end: through a real server's trailers, and the challenge request type ──────────────────


class _Seam(rpc.SeamAdmissionServicer, rpc.SeamAuthorizationServicer):
    def __init__(self):
        self.trailing = None
        self.challenge_requests = []
        self._lock = threading.Lock()

    def IssueChallenge(self, request, context):  # noqa: N802
        with self._lock:
            self.challenge_requests.append(request)
        return pb.Challenge(nonce="bm9uY2U", receiver_aid="aid:pubkey:receiver")

    def Admit(self, request, context):  # noqa: N802
        return pb.AdmissionTicket(
            ticket=b"tkt:ok", expires_at_ms=int(time.time() * 1000) + 300_000
        )

    def Authorize(self, request, context):  # noqa: N802
        context.set_trailing_metadata(self.trailing)
        context.abort(grpc.StatusCode.PERMISSION_DENIED, "refused")


@pytest.fixture
def server():
    srv = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    servicer = _Seam()
    rpc.add_SeamAdmissionServicer_to_server(servicer, srv)
    rpc.add_SeamAuthorizationServicer_to_server(servicer, srv)
    port = srv.add_insecure_port("127.0.0.1:0")
    srv.start()
    yield servicer, f"127.0.0.1:{port}"
    srv.stop(None)


def test_reason_and_macp_code_survive_a_real_call(server):
    servicer, addr = server
    servicer.trailing = (
        (KEY, status(7, error_info("PROTOCOL", macp_code="FORBIDDEN"))),
    )
    with SeamClient.connect(addr) as client:
        with pytest.raises(PermissionDeniedError) as excinfo:
            client.authorize(Agent(bytes([9] * 32)), "t", {})
    assert excinfo.value.reason == "PROTOCOL"
    assert excinfo.value.macp_code == "FORBIDDEN"


def test_issue_challenge_sends_an_issue_challenge_request(server):
    """IssueChallenge takes ``IssueChallengeRequest`` now (P11), not ``google.protobuf.Empty``."""
    servicer, addr = server
    servicer.trailing = ()
    with SeamClient.connect(addr) as client:
        with pytest.raises(PermissionDeniedError):
            client.authorize(Agent(bytes([9] * 32)), "t", {})
    assert servicer.challenge_requests
    assert all(type(r) is pb.IssueChallengeRequest for r in servicer.challenge_requests)
