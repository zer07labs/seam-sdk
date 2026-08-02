"""gRPC status → typed error. The mapping the adapters' fail-closed behaviour is built on.

Only two codes were exercised anywhere: ``UNAUTHENTICATED`` (via the ticket-refresh path) and
``DEADLINE_EXCEEDED`` (via the hanging-server fixture). Every other row of the table was untested,
including the three that carry the most weight downstream:

* ``UNAVAILABLE`` — the adapters' Gate resolves it through FailPolicy; under FAIL_CLOSED it denies.
  If it mapped to something else, a FAIL_CLOSED deployment would fail OPEN when the runtime is down,
  which is the single worst failure this stack can have.
* ``UNIMPLEMENTED`` — an old runtime with no Authorize service; adapters degrade to Observe on it.
  Miscategorised, an unsupported runtime looks like a transport blip and gets retried forever.
* the **unknown-code fallback** — the growth path. A status this SDK has never seen must still
  become a typed error, never leak a bare ``grpc.RpcError`` past the mapping layer.

Two levels, deliberately. The table test pins the mapping itself; the fake-server tests prove the
mapping is actually REACHED through ``authorize()`` — a correct table wired to nothing would pass
the first and fail the second.
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
    AlreadyExistsError,
    DeadlineExceededError,
    FailedPreconditionError,
    InternalError,
    InvalidArgumentError,
    NotFoundError,
    PermissionDeniedError,
    ResourceExhaustedError,
    SeamError,
    SeamRpcError,
    UnauthenticatedError,
    UnavailableError,
    UnimplementedError,
    map_rpc_error,
)

from test_authorize import SEED

#: (status code, expected type). Every entry in ``errors._BY_CODE``, plus what each means to a caller.
MAPPING = [
    (grpc.StatusCode.INVALID_ARGUMENT, InvalidArgumentError),
    (grpc.StatusCode.FAILED_PRECONDITION, FailedPreconditionError),
    (grpc.StatusCode.PERMISSION_DENIED, PermissionDeniedError),
    (grpc.StatusCode.UNAUTHENTICATED, UnauthenticatedError),
    (grpc.StatusCode.NOT_FOUND, NotFoundError),
    (grpc.StatusCode.ALREADY_EXISTS, AlreadyExistsError),
    (grpc.StatusCode.RESOURCE_EXHAUSTED, ResourceExhaustedError),
    (grpc.StatusCode.UNAVAILABLE, UnavailableError),
    (grpc.StatusCode.DEADLINE_EXCEEDED, DeadlineExceededError),
    (grpc.StatusCode.UNIMPLEMENTED, UnimplementedError),
    (grpc.StatusCode.INTERNAL, InternalError),
]

#: Statuses with no dedicated subclass. They must still map — to InternalError — because the
#: alternative is a bare grpc.RpcError escaping the typed layer.
UNMAPPED = [
    grpc.StatusCode.UNKNOWN,
    grpc.StatusCode.CANCELLED,
    grpc.StatusCode.ABORTED,
    grpc.StatusCode.OUT_OF_RANGE,
    grpc.StatusCode.DATA_LOSS,
]


class _RawRpcError(grpc.RpcError):
    """A raw gRPC error as the runtime raises it — code() and details(), nothing typed."""

    def __init__(self, code: grpc.StatusCode, details: str = "boom"):
        self._code, self._details = code, details

    def code(self):
        return self._code

    def details(self):
        return self._details


@pytest.mark.parametrize(
    ("code", "expected"), MAPPING, ids=[c.name for c, _ in MAPPING]
)
def test_every_status_in_the_table_maps_to_its_typed_error(code, expected):
    mapped = map_rpc_error(_RawRpcError(code, "detail text"))
    assert type(mapped) is expected
    assert mapped.code() is code
    assert mapped.details() == "detail text"


@pytest.mark.parametrize(
    ("code", "expected"), MAPPING, ids=[c.name for c, _ in MAPPING]
)
def test_every_typed_error_is_catchable_as_both_seam_and_grpc(code, expected):
    """The compatibility promise: adding types was purely ADDITIVE. Existing
    ``except grpc.RpcError`` handlers and ``.code()`` checks must keep working unchanged."""
    mapped = map_rpc_error(_RawRpcError(code))
    assert isinstance(mapped, SeamError)
    assert isinstance(mapped, grpc.RpcError)
    assert isinstance(mapped, SeamRpcError)


@pytest.mark.parametrize("code", UNMAPPED, ids=[c.name for c in UNMAPPED])
def test_an_unmapped_status_falls_back_to_internal_rather_than_escaping(code):
    """The growth path. A future or rarely-seen status must not leak past the mapping layer as an
    untyped error — a caller written against the typed taxonomy would miss it entirely."""
    mapped = map_rpc_error(_RawRpcError(code))
    assert type(mapped) is InternalError
    assert mapped.code() is code, "the ORIGINAL code must survive the fallback"


def test_mapping_is_idempotent():
    """``_MappedStub`` maps at the boundary and callers may map again; double-mapping must not
    re-wrap an already-typed error and lose its class."""
    once = map_rpc_error(_RawRpcError(grpc.StatusCode.UNAVAILABLE, "down"))
    twice = map_rpc_error(once)
    assert twice is once


def test_an_error_with_no_code_accessor_still_maps():
    """Defensive, and not hypothetical: `grpc.RpcError` is a plain Exception subclass, so a stub or
    an interceptor can raise one with no `code()` at all. It must still leave the mapping layer
    typed rather than as a bare RpcError nobody catches."""

    class Bare(grpc.RpcError):
        pass

    mapped = map_rpc_error(Bare())
    assert type(mapped) is InternalError
    assert mapped.code() is grpc.StatusCode.UNKNOWN


# ── The same mapping, reached through a real call ────────────────────────────────────────────────


class AbortingSeam(rpc.SeamAdmissionServicer, rpc.SeamAuthorizationServicer):
    """Admits normally, then aborts ``Authorize`` with a configurable status.

    Admission has to work for the authorize path to be reached at all — otherwise every test here
    would prove only that admission failed.
    """

    def __init__(self):
        self.abort_with = None
        self.admits = 0
        self._lock = threading.Lock()

    def IssueChallenge(self, request, context):  # noqa: N802
        return pb.Challenge(nonce="bm9uY2U", receiver_aid="aid:pubkey:receiver")

    def Admit(self, request, context):  # noqa: N802
        with self._lock:
            self.admits += 1
        return pb.AdmissionTicket(
            ticket=b"tkt:ok", expires_at_ms=int(time.time() * 1000) + 300_000
        )

    def Authorize(self, request, context):  # noqa: N802
        if self.abort_with is not None:
            context.abort(self.abort_with, f"aborted with {self.abort_with.name}")
        return pb.AuthorizeResponse(verdict=pb.ALLOW, authorize_id="01AUTHZ")


@pytest.fixture
def aborting_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    servicer = AbortingSeam()
    rpc.add_SeamAdmissionServicer_to_server(servicer, server)
    rpc.add_SeamAuthorizationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


#: UNAUTHENTICATED is excluded here: authorize() treats it as the refresh signal and retries, so it
#: is not a pass-through case. That path has its own tests in test_authorize.py.
THROUGH_AUTHORIZE = [
    (c, e) for c, e in MAPPING if c is not grpc.StatusCode.UNAUTHENTICATED
]


@pytest.mark.parametrize(
    ("code", "expected"), THROUGH_AUTHORIZE, ids=[c.name for c, _ in THROUGH_AUTHORIZE]
)
def test_a_server_abort_surfaces_typed_through_authorize(
    aborting_server, code, expected
):
    """End-to-end: a real server abort, through ``_MappedStub``, out of ``authorize()``.

    This is the assertion that would have caught a mapping wired up but never reached — the table
    test above passes whether or not the stub wrapper is applied to the authorization stub at all.
    """
    servicer, addr = aborting_server
    servicer.abort_with = code
    with SeamClient.connect(addr) as client:
        with pytest.raises(expected) as excinfo:
            client.authorize(Agent(SEED), "t", {})
    assert excinfo.value.code() is code


def test_unavailable_is_reachable_and_typed_the_way_the_gate_depends_on(
    aborting_server,
):
    """Called out on its own because of what rides on it: the adapters' Gate maps
    ``UnavailableError`` onto ``TransportFailure``, which under FAIL_CLOSED denies. If UNAVAILABLE
    arrived as anything else, a FAIL_CLOSED deployment would fail OPEN with the runtime down."""
    servicer, addr = aborting_server
    servicer.abort_with = grpc.StatusCode.UNAVAILABLE
    with SeamClient.connect(addr) as client:
        with pytest.raises(UnavailableError):
            client.authorize(Agent(SEED), "t", {})


def test_unimplemented_is_reachable_and_typed_so_adapters_can_degrade(aborting_server):
    """An old runtime with no Authorize service. Adapters degrade to their Observe tier on this
    specific type; miscategorised as a transport blip it would instead be retried forever."""
    servicer, addr = aborting_server
    servicer.abort_with = grpc.StatusCode.UNIMPLEMENTED
    with SeamClient.connect(addr) as client:
        with pytest.raises(UnimplementedError):
            client.authorize(Agent(SEED), "t", {})
