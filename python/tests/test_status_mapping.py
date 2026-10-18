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

import pathlib
import pickle
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


def test_an_error_whose_code_returns_none_still_maps():
    """The sibling of the no-code-method case: `code()` EXISTS but returns None (a half-built stub or
    an interceptor's hand-rolled error). Before the guard this raised AttributeError on `code.name`
    INSIDE the mapping layer — the error about the error, shadowing the real failure."""

    class NoneCode(grpc.RpcError):
        def code(self):
            return None

        def details(self):
            return "no status attached"

    mapped = map_rpc_error(NoneCode())
    assert type(mapped) is InternalError
    assert mapped.code() is grpc.StatusCode.UNKNOWN
    assert "no status attached" in str(mapped)


@pytest.mark.parametrize(
    ("code", "expected"), MAPPING, ids=[c.name for c, _ in MAPPING]
)
def test_every_typed_error_survives_a_pickle_round_trip(code, expected):
    """Typed errors cross process boundaries (multiprocessing / concurrent.futures workers). The
    Exception default replays __init__ with the FORMATTED message, not (code, details) — so without
    __reduce__ the unpickle raised TypeError and the worker's real error was lost in transit."""
    err = map_rpc_error(_RawRpcError(code, "detail text"))
    clone = pickle.loads(pickle.dumps(err))
    assert type(clone) is expected
    assert clone.code() is code
    assert clone.details() == "detail text"
    assert str(clone) == str(err)


def test_client_side_semantic_errors_survive_a_pickle_round_trip():
    """IssuerMismatchError and UnknownVerdictError take multi-arg __init__s too, so they need the
    same __reduce__ discipline as the SeamRpcError family (a worker's security signal must not be
    replaced by a TypeError in transit)."""
    from seam_sdk.errors import IssuerMismatchError, UnknownVerdictError

    mism = pickle.loads(
        pickle.dumps(IssuerMismatchError("aid:pubkey:AA", "aid:pubkey:BB"))
    )
    assert type(mism) is IssuerMismatchError
    assert (mism.proof_issuer, mism.expected_issuer) == (
        "aid:pubkey:AA",
        "aid:pubkey:BB",
    )

    verd = pickle.loads(pickle.dumps(UnknownVerdictError(7, "az-1")))
    assert type(verd) is UnknownVerdictError
    assert (verd.raw_value, verd.authorize_id) == (7, "az-1")


# ── The same mapping, reached through a real call ────────────────────────────────────────────────


class AbortingSeam(rpc.SeamAdmissionServicer, rpc.SeamAuthorizationServicer):
    """Admits normally, then aborts ``Authorize`` with a configurable status.

    Admission has to work for the authorize path to be reached at all — otherwise every test here
    would prove only that admission failed.
    """

    def __init__(self):
        self.abort_with = None
        self.trailing = None
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
            if self.trailing is not None:
                context.set_trailing_metadata(self.trailing)
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


# ── Trailing metadata: status details reach the typed error (seam-sdk#119) ────────────────────────
#
# Asked by `seam-adapters`. `map_rpc_error` rebuilt the typed error from (code, details) alone, so
# `grpc-status-details-bin` — where `google.rpc.Status` details travel — never reached the object.
# It was not lost, because every call site raises `from e`, but reading it meant walking `__cause__`
# to find an AioRpcError: a rule nothing documented and nothing tested, which a refactor could break
# with no signature change and no version signal.


class _RawWithTrailing(_RawRpcError):
    """A raw gRPC error that also carries trailing metadata, as a real one does."""

    def __init__(self, code, details="boom", trailing=()):
        super().__init__(code, details)
        self._trailing = trailing

    def trailing_metadata(self):
        return self._trailing


def test_trailing_metadata_survives_the_mapping():
    raw = _RawWithTrailing(
        grpc.StatusCode.FAILED_PRECONDITION,
        "policy denied: unvoted governed round",
        trailing=(("x-seam-reason", "policy-denied"),),
    )
    mapped = map_rpc_error(raw)
    assert mapped.trailing_metadata() == (("x-seam-reason", "policy-denied"),)


def test_a_binary_metadatum_survives_byte_for_byte():
    """The whole point of the ask. `grpc-status-details-bin` is a serialized `google.rpc.Status`;
    coercing its value to `str` — or decoding it here — would corrupt exactly the payload a consumer
    needs. It is carried through untouched."""
    blob = b"\x08\x09\x12\x05hello\x00\xff"
    mapped = map_rpc_error(
        _RawWithTrailing(
            grpc.StatusCode.INVALID_ARGUMENT,
            "bad",
            trailing=(("grpc-status-details-bin", blob),),
        )
    )
    assert mapped.trailing_metadata() == (("grpc-status-details-bin", blob),)
    assert mapped.trailing_metadata()[0][1] is blob, "no copy, no re-encode"


def test_an_aio_metadata_object_is_normalized_to_plain_tuples():
    """`grpc.aio.Metadata` pickles on grpcio 1.83, but this package's floor is `grpcio>=1.64` and
    nothing promises it there. Normalizing at construction makes picklability true by construction
    instead of true by observation — the distinction this repo keeps rediscovering the hard way."""
    from grpc.aio import Metadata

    md = Metadata(("grpc-status-details-bin", b"\x08\x09"), ("date", "Mon"))
    mapped = map_rpc_error(_RawWithTrailing(grpc.StatusCode.INTERNAL, "x", trailing=md))
    out = mapped.trailing_metadata()
    assert out == (("grpc-status-details-bin", b"\x08\x09"), ("date", "Mon"))
    assert type(out) is tuple
    assert all(type(pair) is tuple for pair in out), (
        "a grpc internal (Metadata, _Metadatum) in the payload would make unpickling depend on "
        "that class living at the same import path in the RECEIVING interpreter"
    )


def test_absent_and_empty_trailing_metadata_are_different_answers():
    """`None` = never observed. `()` = the wire was read and carried nothing. A consumer that
    conflates them cannot tell "the server told us nothing" from "we never asked" — which is the
    false green seam-sdk#119 raised."""
    never = map_rpc_error(_RawRpcError(grpc.StatusCode.INTERNAL, "no accessor at all"))
    empty = map_rpc_error(
        _RawWithTrailing(grpc.StatusCode.INTERNAL, "read, and empty", trailing=())
    )
    assert never.trailing_metadata() is None
    assert empty.trailing_metadata() == ()
    assert never.trailing_metadata() != empty.trailing_metadata()


def test_an_error_with_no_trailing_metadata_accessor_still_maps():
    """Same defensiveness as the no-`code()` case above: `grpc.RpcError` is a plain Exception
    subclass, so a stub or interceptor can raise one with no such method."""

    class Bare(grpc.RpcError):
        pass

    mapped = map_rpc_error(Bare())
    assert type(mapped) is InternalError
    assert mapped.trailing_metadata() is None


def test_a_raising_accessor_does_not_displace_the_real_error():
    """A failure to READ metadata about the error must never replace the error itself. The status
    the server sent is the thing the caller has to act on."""

    class Hostile(grpc.RpcError):
        def code(self):
            return grpc.StatusCode.PERMISSION_DENIED

        def details(self):
            return "scope floor"

        def trailing_metadata(self):
            raise RuntimeError("channel already closed")

    mapped = map_rpc_error(Hostile())
    assert type(mapped) is PermissionDeniedError
    assert mapped.code() is grpc.StatusCode.PERMISSION_DENIED
    assert mapped.details() == "scope floor"
    assert mapped.trailing_metadata() is None


def test_unpairable_metadata_degrades_to_none_rather_than_raising():
    mapped = map_rpc_error(
        _RawWithTrailing(grpc.StatusCode.INTERNAL, "x", trailing=object())
    )
    assert mapped.trailing_metadata() is None


def test_trailing_metadata_survives_a_pickle_round_trip():
    """`__reduce__` grew a third element. It must still cross a process boundary — the property the
    two-element version existed to protect."""
    err = map_rpc_error(
        _RawWithTrailing(
            grpc.StatusCode.RESOURCE_EXHAUSTED,
            "cap",
            trailing=(("grpc-status-details-bin", b"\x08\x09"), ("k", "v")),
        )
    )
    clone = pickle.loads(pickle.dumps(err))
    assert type(clone) is type(err)
    assert clone.code() is err.code()
    assert clone.details() == err.details()
    assert clone.trailing_metadata() == err.trailing_metadata()


def test_the_two_argument_constructor_still_works():
    """Purely additive: the third parameter has a default, so existing construction — and an OLD
    two-element pickle payload — still loads."""
    err = SeamRpcError(grpc.StatusCode.INTERNAL, "boom")
    assert err.trailing_metadata() is None
    revived = pickle.loads(pickle.dumps(err))
    assert revived.details() == "boom"


def test_idempotent_mapping_keeps_the_metadata():
    """`_MappedStub` maps at the boundary and callers may map again; the pass-through arm must not
    drop what the first mapping captured."""
    once = map_rpc_error(
        _RawWithTrailing(grpc.StatusCode.UNAVAILABLE, "down", trailing=(("a", "b"),))
    )
    twice = map_rpc_error(once)
    assert twice is once
    assert twice.trailing_metadata() == (("a", "b"),)


def test_trailing_metadata_survives_a_real_server_abort(aborting_server):
    """The second level, as this file's header requires: the table test above passes whether or not
    anything actually reads trailing metadata off a live channel. This one fails if it does not."""
    servicer, addr = aborting_server
    servicer.abort_with = grpc.StatusCode.FAILED_PRECONDITION
    servicer.trailing = (
        ("x-seam-reason", "policy-denied"),
        ("grpc-status-details-bin", b"\x08\x09real-wire"),
    )
    with SeamClient.connect(addr) as client:
        with pytest.raises(FailedPreconditionError) as excinfo:
            client.authorize(Agent(SEED), "t", {})

    md = dict(excinfo.value.trailing_metadata())
    assert md["x-seam-reason"] == "policy-denied"
    assert md["grpc-status-details-bin"] == b"\x08\x09real-wire"


# ── The `__cause__` guarantee is a contract now, not an observation (seam-sdk#119) ────────────────


def _raise_sites_of_map_rpc_error():
    """Every `raise map_rpc_error(...)` in the package, with whether it has a `from` clause.

    Static rather than behavioural on purpose. A behavioural test can only cover the paths it
    happens to drive; this one sees a site the moment it is written, including one added to a module
    no test exercises yet — which is the case that would otherwise ship broken.
    """
    import ast

    pkg = pathlib.Path(__file__).resolve().parents[1] / "seam_sdk"
    sites = []
    for path in sorted(pkg.rglob("*.py")):
        if "_gen" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise) or node.exc is None:
                continue
            exc = node.exc
            if (
                isinstance(exc, ast.Call)
                and isinstance(exc.func, ast.Name)
                and exc.func.id == "map_rpc_error"
            ):
                sites.append(
                    (
                        path.relative_to(pkg.parent).as_posix(),
                        node.lineno,
                        node.cause is not None,
                    )
                )
    return sites


def test_every_map_rpc_error_raise_preserves_the_raw_error_as_cause():
    """`seam-adapters` reads status details by walking `__cause__` until it finds an `AioRpcError`.
    That works, and it worked before anyone wrote it down — which is the problem: a refactor that
    raised without `from e` would break every consumer doing it, silently."""
    sites = _raise_sites_of_map_rpc_error()

    assert sites, (
        "the AST scan found NO `raise map_rpc_error(...)` sites at all. That is a broken scan, not "
        "a clean bill of health — this package raises it from the mapped stub, the aio client and "
        "the admin client. A guard that passes by finding nothing is this repo's named failure class."
    )

    missing = [f"{f}:{ln}" for f, ln, has_cause in sites if not has_cause]
    assert not missing, (
        "these raise the mapped error without `from e`, which severs `__cause__` and with it the "
        "only route to anything not lifted onto the typed error:\n  "
        + "\n  ".join(missing)
    )


def test_the_cause_chain_actually_reaches_the_raw_error():
    """The behavioural half. The AST guard proves the syntax is present; this proves the object it
    produces is the one a consumer expects to find at the end of the walk."""
    from seam_sdk.errors import _MappedStub

    raw = _RawWithTrailing(
        grpc.StatusCode.FAILED_PRECONDITION, "policy denied: x", trailing=(("a", "b"),)
    )

    class _Stub:
        def Call(self, *a, **k):
            raise raw

    with pytest.raises(FailedPreconditionError) as excinfo:
        _MappedStub(_Stub()).Call()

    assert excinfo.value.__cause__ is raw, "the raw error must survive as __cause__"
    # And the reason a caller no longer HAS to walk it:
    assert excinfo.value.trailing_metadata() == (("a", "b"),)
