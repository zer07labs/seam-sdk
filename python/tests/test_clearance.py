"""``clearance=`` on the decision reads (#384): ``x-seam-clearance`` on GetDecision, ReplayDecision,
GetCommitmentProof (and verify_decision, through it), in BOTH clients.

What is pinned:

* the default ``None`` leaves the wire exactly as before — ``metadata=None`` without a credential,
  exactly the two #508 keys with one;
* each of the six runtime labels is sent verbatim, once, with or without a credential, and on BOTH
  attempts of the #275 refresh retry;
* anything else raises ``ValueError`` before ANY RPC (admission included) — the runtime would
  silently read an unknown label as Public, so the SDK must refuse it instead;
* the header is not part of the #508 call signature: the signature still verifies over the
  unchanged payload.

No network: the stubs are swapped for a recorder, exactly as in ``test_credential_refresh.py``.
"""

from __future__ import annotations

import asyncio
import threading
import time

import grpc
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import seam_sdk
from seam_sdk import Agent, SeamClient
from seam_sdk._authorize import TicketCache
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.aio import SeamClient as AioSeamClient
from seam_sdk.crypto import request_sig_payload
from seam_sdk.errors import IssuerMismatchError, UnauthenticatedError

CRED_SEED = bytes(range(32, 64))
TICKET = b"\x01\x02\x03fake-ticket"
DECISION = "d-384"
HEADER = "x-seam-clearance"
LABELS = ("Public", "Internal", "Confidential", "Financial", "Pii", "Phi")


def _now_ms() -> int:
    return int(time.time() * 1000)


class _Wire:
    def __init__(self) -> None:
        self.calls: list = []  # (name, request, metadata-or-None)
        self.reject: dict = {}
        self._lock = threading.Lock()

    def handle(self, name: str, req, kw: dict):
        with self._lock:
            self.calls.append((name, req, kw.get("metadata")))
            if name == "IssueChallenge":
                return pb.Challenge(nonce="bm9uY2U", receiver_aid="aid:pubkey:receiver")
            if name == "Admit":
                return pb.AdmissionTicket(
                    ticket=b"new-ticket", expires_at_ms=_now_ms() + 60_000
                )
            if self.reject.get(name, 0) > 0:
                self.reject[name] -= 1
                raise UnauthenticatedError(
                    grpc.StatusCode.UNAUTHENTICATED, "unauthenticated"
                )
            if name == "GetCommitmentProof":
                return pb.CommitmentProof(issuer_aid="aid:served")
            if name == "ReplayDecision":
                return pb.ReplayView()
            return pb.DecisionRecordView()

    def of(self, name: str) -> list:
        return [c for c in self.calls if c[0] == name]


class _SyncStub:
    def __init__(self, wire: _Wire) -> None:
        self._wire = wire

    def __getattr__(self, name):
        def call(req, **kw):
            return self._wire.handle(name, req, kw)

        return call


class _AioStub:
    def __init__(self, wire: _Wire) -> None:
        self._wire = wire

    def __getattr__(self, name):
        async def call(req, **kw):
            return self._wire.handle(name, req, kw)

        return call


class _Harness:
    def __init__(self, aio: bool) -> None:
        self.aio = aio
        self.loop = asyncio.new_event_loop() if aio else None
        self._clients: list = []

    def client(self, wire: _Wire):
        if self.aio:

            async def make():
                return AioSeamClient.connect("127.0.0.1:1")

            c = self.loop.run_until_complete(make())
            stub = _AioStub(wire)
        else:
            c = SeamClient.connect("127.0.0.1:1")
            stub = _SyncStub(wire)
        c._coord = c._authz = c._admission = c._context = stub
        self._clients.append(c)
        return c

    def run(self, value):
        return self.loop.run_until_complete(value) if self.aio else value

    def close(self) -> None:
        for c in self._clients:
            self.run(c.close())
        if self.loop is not None:
            self.loop.close()


@pytest.fixture(params=["sync", "aio"])
def h(request):
    harness = _Harness(request.param == "aio")
    yield harness
    harness.close()


def _seed(client, agent: Agent) -> None:
    cache = TicketCache()
    cache.store(TICKET, _now_ms() + 60_000, _now_ms())
    client._tickets[agent.aid] = cache


# verb -> (the RPC it lands on, how to call it). verify_decision lands on GetCommitmentProof and
# then fails the issuer check against the canned proof, which is after the wire and irrelevant here.
VERBS = {
    "get_decision": (
        "GetDecision",
        lambda c, **kw: c.get_decision(DECISION, **kw),
    ),
    "replay_decision": (
        "ReplayDecision",
        lambda c, **kw: c.replay_decision(DECISION, **kw),
    ),
    "get_commitment_proof": (
        "GetCommitmentProof",
        lambda c, **kw: c.get_commitment_proof(DECISION, **kw),
    ),
    "verify_decision": (
        "GetCommitmentProof",
        lambda c, **kw: c.verify_decision(DECISION, "aid:expected", **kw),
    ),
}


def _call(h: _Harness, client, verb: str, **kw):
    try:
        return h.run(VERBS[verb][1](client, **kw))
    except IssuerMismatchError:
        assert verb == "verify_decision"
        return None


def _clearances(md) -> list:
    return [v for k, v in (md or ()) if k == HEADER]


# ── The default is byte-identical ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("verb", VERBS)
def test_the_default_sends_no_clearance_and_leaves_metadata_untouched(h, verb):
    wire = _Wire()
    client = h.client(wire)
    _call(h, client, verb)
    (_, _, md) = wire.of(VERBS[verb][0])[-1]
    assert md is None, f"{verb}: clearance=None must leave metadata=None"

    cred = Agent(CRED_SEED)
    _seed(client, cred)
    _call(h, client, verb, credential=cred)
    (_, _, md) = wire.of(VERBS[verb][0])[-1]
    assert {k for k, _ in md} == {"x-seam-ticket-bin", "x-seam-call-sig-bin"}


# ── Each label is sent verbatim, once ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("label", LABELS)
@pytest.mark.parametrize("verb", VERBS)
def test_each_label_is_sent_verbatim_without_a_credential(h, verb, label):
    wire = _Wire()
    client = h.client(wire)
    _call(h, client, verb, clearance=label)
    (_, req, md) = wire.of(VERBS[verb][0])[-1]
    assert list(md) == [(HEADER, label)]
    assert req.decision_id == DECISION


@pytest.mark.parametrize("verb", VERBS)
def test_with_a_credential_the_clearance_rides_beside_the_call_signature(h, verb):
    wire = _Wire()
    client = h.client(wire)
    cred = Agent(CRED_SEED)
    _seed(client, cred)
    _call(h, client, verb, credential=cred, clearance="Financial")
    (_, _, md) = wire.of(VERBS[verb][0])[-1]
    keys = [k for k, _ in md]
    assert sorted(keys) == sorted(["x-seam-ticket-bin", "x-seam-call-sig-bin", HEADER])
    assert _clearances(md) == ["Financial"]

    # The header is not in the #508 signature: it verifies over the unchanged bodyless payload.
    d = dict(md)
    payload = request_sig_payload(
        TICKET, f"/seam.api.v1.SeamCoordination/{VERBS[verb][0]}", DECISION, ""
    )
    Ed25519PrivateKey.from_private_bytes(cred.seed).public_key().verify(
        d["x-seam-call-sig-bin"], payload
    )


@pytest.mark.parametrize("verb", VERBS)
def test_both_attempts_of_the_refresh_retry_carry_the_clearance(h, verb):
    wire = _Wire()
    client = h.client(wire)
    cred = Agent(CRED_SEED)
    _seed(client, cred)
    rpc = VERBS[verb][0]
    wire.reject[rpc] = 1
    _call(h, client, verb, credential=cred, clearance="Phi")
    attempts = wire.of(rpc)
    assert len(attempts) == 2, "one rejection, one refreshed retry"
    for _, _, md in attempts:
        assert _clearances(md) == ["Phi"]
    assert dict(attempts[0][2])["x-seam-ticket-bin"] == TICKET
    assert dict(attempts[1][2])["x-seam-ticket-bin"] == b"new-ticket"


# ── Anything else is refused before any RPC ──────────────────────────────────────────────────────

BAD = [
    "PUBLIC",
    "public",
    "",
    " Public",
    "Public ",
    "Restricted",
    "PII",
    b"Public",
    1,
    ["Public"],
]


@pytest.mark.parametrize("bad", BAD, ids=repr)
@pytest.mark.parametrize("verb", VERBS)
def test_an_unknown_clearance_raises_before_any_rpc(h, verb, bad):
    wire = _Wire()
    client = h.client(wire)
    cred = Agent(CRED_SEED)  # no seeded ticket: admission would be the first RPC
    with pytest.raises(ValueError, match="clearance"):
        _call(h, client, verb, credential=cred, clearance=bad)
    assert wire.calls == [], f"{verb}: {bad!r} reached the wire: {wire.calls}"


# ── The public surface ───────────────────────────────────────────────────────────────────────────


def test_the_label_set_is_exported_and_closed():
    assert seam_sdk.CLEARANCES == frozenset(LABELS)
    assert isinstance(seam_sdk.CLEARANCES, frozenset)
    assert seam_sdk.CLEARANCE_HEADER == HEADER
    consts = {
        "CLEARANCE_PUBLIC": "Public",
        "CLEARANCE_INTERNAL": "Internal",
        "CLEARANCE_CONFIDENTIAL": "Confidential",
        "CLEARANCE_FINANCIAL": "Financial",
        "CLEARANCE_PII": "Pii",
        "CLEARANCE_PHI": "Phi",
    }
    for name, value in consts.items():
        assert getattr(seam_sdk, name) == value
        assert name in seam_sdk.__all__
    assert "CLEARANCES" in seam_sdk.__all__ and "CLEARANCE_HEADER" in seam_sdk.__all__


@pytest.mark.parametrize("cls", [SeamClient, AioSeamClient])
def test_clearance_is_keyword_only_and_defaults_to_none(cls):
    import inspect

    for name in VERBS:
        p = inspect.signature(getattr(cls, name)).parameters["clearance"]
        assert p.kind is inspect.Parameter.KEYWORD_ONLY
        assert p.default is None
