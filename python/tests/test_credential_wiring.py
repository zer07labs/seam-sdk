"""`client.py` / `aio.py` wiring for the per-request credential (`seam-request-call-v1`, #508).

`request_sig_payload`/`request_sig` themselves are pinned against the runtime's conformance vector
in ``test_request_sig_payload.py``; this file is the layer above — that each of the 15 target verbs,
in BOTH clients, attaches (or omits) the right gRPC metadata for the right RPC/resource/body.

No network: ``_coord``/``_authz`` are swapped for a recorder that captures the exact request object
and keyword arguments a wrapper method passed on, and a ticket is pre-seeded into the per-AID cache
so ``credential=`` never needs a real ``Admit``. The signature check recomputes the expected payload
from the RECORDED (i.e. actually-sent) request via the independent, already-tested
``request_sig_payload`` primitive and verifies it with the credential's own Ed25519 public key — a
client that signed a stale, wrong, or missing body would fail this, not merely a client that never
sent metadata at all.
"""

from __future__ import annotations

import asyncio
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
import pytest

from seam_sdk import Agent, SeamClient
from seam_sdk._authorize import TicketCache
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.aio import SeamClient as AioSeamClient
from seam_sdk.crypto import request_sig_payload, tool_input_digest

SEED = bytes(range(32))
CRED_SEED = bytes(range(32, 64))
OTHER_CRED_SEED = bytes(range(64, 96))
TICKET = b"\x01\x02\x03fake-ticket"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _seed_ticket(tickets: dict, aid: str) -> None:
    cache = TicketCache()
    cache.store(TICKET, _now_ms() + 60_000, _now_ms())
    tickets[aid] = cache


class _Recorder:
    """Stands in for ``_coord``/``_authz``. Every RPC-shaped attribute records ``(req, kwargs)``
    and returns a generic ``SessionStep`` — none of the 15 wrapper methods below inspect it."""

    def __init__(self, seen: dict):
        self._seen = seen

    def __getattr__(self, name):
        def record(req, **kw):
            self._seen[name] = (req, kw)
            return pb.SessionStep(state="Open")

        return record


class _AioRecorder:
    def __init__(self, seen: dict):
        self._seen = seen

    def __getattr__(self, name):
        async def record(req, **kw):
            self._seen[name] = (req, kw)
            return pb.SessionStep(state="Open")

        return record


# Every target verb: the RPC's full name (exactly as the client signs it), whether it is a bodyless
# read (resource_id carries the id, no body) or a bodied verb (resource_id="", the whole request is
# the body), and how to invoke it — a lambda over (client, credential) shared verbatim between the
# sync and async clients, since the two wrappers are argument-for-argument identical.
CALLS = {
    "OpenSession": {
        "rpc": "/seam.api.v1.SeamCoordination/OpenSession",
        "bodyless": False,
        "invoke": lambda c, cred: c.open_session(
            Agent(SEED), "s1", ["a", "b"], credential=cred
        ),
    },
    "SubmitProposal": {
        "rpc": "/seam.api.v1.SeamCoordination/SubmitProposal",
        "bodyless": False,
        "invoke": lambda c, cred: c.submit_proposal(
            "s1", "a", "p1", "opt", credential=cred
        ),
    },
    "SubmitVote": {
        "rpc": "/seam.api.v1.SeamCoordination/SubmitVote",
        "bodyless": False,
        "invoke": lambda c, cred: c.submit_vote(
            "s1", "a", "p1", "yes", credential=cred
        ),
    },
    "SubmitEvaluation": {
        "rpc": "/seam.api.v1.SeamCoordination/SubmitEvaluation",
        "bodyless": False,
        "invoke": lambda c, cred: c.submit_evaluation(
            "s1", "a", "p1", "APPROVE", credential=cred
        ),
    },
    "SubmitObjection": {
        "rpc": "/seam.api.v1.SeamCoordination/SubmitObjection",
        "bodyless": False,
        "invoke": lambda c, cred: c.submit_objection(
            "s1", "a", "p1", "reason", credential=cred
        ),
    },
    "SubmitCommit": {
        "rpc": "/seam.api.v1.SeamCoordination/SubmitCommit",
        "bodyless": False,
        "invoke": lambda c, cred: c.submit_commit(
            "s1", "c1", "approve", credential=cred
        ),
    },
    "SubmitApprovalRequest": {
        "rpc": "/seam.api.v1.SeamCoordination/SubmitApprovalRequest",
        "bodyless": False,
        "invoke": lambda c, cred: c.submit_approval_request(
            "s1", "a", "r1", "approve", 2, credential=cred
        ),
    },
    "SubmitBallot": {
        "rpc": "/seam.api.v1.SeamCoordination/SubmitBallot",
        "bodyless": False,
        "invoke": lambda c, cred: c.submit_ballot(
            "s1", "a", "r1", pb.BALLOT_CHOICE_APPROVE, credential=cred
        ),
    },
    "CancelSession": {
        "rpc": "/seam.api.v1.SeamCoordination/CancelSession",
        "bodyless": False,
        "invoke": lambda c, cred: c.cancel_session("s1", credential=cred),
    },
    "ExpireSession": {
        "rpc": "/seam.api.v1.SeamCoordination/ExpireSession",
        "bodyless": False,
        "invoke": lambda c, cred: c.expire_session("s1", credential=cred),
    },
    "SessionStatus": {
        "rpc": "/seam.api.v1.SeamCoordination/SessionStatus",
        "bodyless": True,
        "resource_id": "s1",
        "invoke": lambda c, cred: c.session_status("s1", credential=cred),
    },
    "GetDecision": {
        "rpc": "/seam.api.v1.SeamCoordination/GetDecision",
        "bodyless": True,
        "resource_id": "d1",
        "invoke": lambda c, cred: c.get_decision("d1", credential=cred),
    },
    "ReplayDecision": {
        "rpc": "/seam.api.v1.SeamCoordination/ReplayDecision",
        "bodyless": True,
        "resource_id": "d1",
        "invoke": lambda c, cred: c.replay_decision("d1", credential=cred),
    },
    "GetEscalation": {
        "rpc": "/seam.api.v1.SeamAuthorization/GetEscalation",
        "bodyless": True,
        "resource_id": "az-1",
        "invoke": lambda c, cred: c.get_escalation("az-1", credential=cred),
    },
    "GetCommitmentProof": {
        "rpc": "/seam.api.v1.SeamCoordination/GetCommitmentProof",
        "bodyless": True,
        "resource_id": "d1",
        "invoke": lambda c, cred: c.get_commitment_proof("d1", credential=cred),
    },
}


def _assert_no_credential_sent(seen: dict, verb: str) -> None:
    req, kw = seen[verb]
    assert kw.get("metadata") is None, (
        f"{verb}: metadata was sent despite credential=None (the default must be unaffected)"
    )


def _assert_credential_sent_and_verifies(
    seen: dict, verb: str, spec: dict, credential: Agent
) -> None:
    req, kw = seen[verb]
    md = kw.get("metadata")
    assert md is not None, f"{verb}: no metadata despite credential="
    md = dict(md)
    assert set(md) == {"x-seam-ticket-bin", "x-seam-call-sig-bin"}, (
        f"{verb}: unexpected metadata keys {set(md)}"
    )
    assert md["x-seam-ticket-bin"] == TICKET, f"{verb}: wrong ticket on the wire"

    resource_id = spec.get("resource_id", "")
    body_digest = "" if spec["bodyless"] else tool_input_digest(req.SerializeToString())
    expected_payload = request_sig_payload(
        TICKET, spec["rpc"], resource_id, body_digest
    )
    pubkey = Ed25519PrivateKey.from_private_bytes(credential.seed).public_key()
    pubkey.verify(
        md["x-seam-call-sig-bin"], expected_payload
    )  # raises InvalidSignature if wrong


def test_sync_credential_wiring_every_verb() -> None:
    credential = Agent(CRED_SEED)
    for verb, spec in CALLS.items():
        seen: dict = {}
        client = SeamClient.connect("127.0.0.1:1")  # lazy channel, never dialed
        client._coord = _Recorder(seen)
        client._authz = _Recorder(seen)
        client._presentation = lambda agent, timeout=None: pb.PinnedPresentation()  # type: ignore
        _seed_ticket(client._tickets, credential.aid)

        spec["invoke"](client, None)
        _assert_no_credential_sent(seen, verb)

        spec["invoke"](client, credential)
        _assert_credential_sent_and_verifies(seen, verb, spec, credential)


def test_async_credential_wiring_every_verb() -> None:
    credential = Agent(CRED_SEED)

    async def scenario() -> None:
        for verb, spec in CALLS.items():
            seen: dict = {}
            client = AioSeamClient.connect("127.0.0.1:1")  # lazy channel, never dialed
            client._coord = _AioRecorder(seen)
            client._authz = _AioRecorder(seen)

            async def _fake_presentation(agent, timeout=None):
                return pb.PinnedPresentation()

            client._presentation = _fake_presentation  # type: ignore[method-assign]
            _seed_ticket(client._tickets, credential.aid)

            await spec["invoke"](client, None)
            _assert_no_credential_sent(seen, verb)

            await spec["invoke"](client, credential)
            _assert_credential_sent_and_verifies(seen, verb, spec, credential)
            await client.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("verb", ["SubmitVote", "GetDecision"])
def test_a_different_credential_produces_a_signature_that_does_not_verify(
    verb: str,
) -> None:
    """Confirms the signature is actually keyed on ``credential.seed`` — not a value that happens to
    be constant across agents, which the same-body check above cannot distinguish on its own."""
    spec = CALLS[verb]
    cred_a = Agent(CRED_SEED)
    cred_b = Agent(OTHER_CRED_SEED)
    seen: dict = {}
    client = SeamClient.connect("127.0.0.1:1")
    client._coord = _Recorder(seen)
    client._authz = _Recorder(seen)
    _seed_ticket(client._tickets, cred_a.aid)
    _seed_ticket(client._tickets, cred_b.aid)

    spec["invoke"](client, cred_a)
    _, kw_a = seen[verb]
    sig_a = dict(kw_a["metadata"])["x-seam-call-sig-bin"]

    resource_id = spec.get("resource_id", "")
    body_digest = (
        "" if spec["bodyless"] else tool_input_digest(seen[verb][0].SerializeToString())
    )
    payload = request_sig_payload(TICKET, spec["rpc"], resource_id, body_digest)

    wrong_pubkey = Ed25519PrivateKey.from_private_bytes(cred_b.seed).public_key()
    with pytest.raises(InvalidSignature):
        wrong_pubkey.verify(sig_a, payload)
