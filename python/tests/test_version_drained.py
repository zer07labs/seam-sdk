"""``VERSION_DRAINED`` (seam-runtime DC2 S5, runtime 0.126.0): classification, never a same-call retry,
and the one automatic reopen of the two verbs that admit a pin (D-VERSION-DRAINED).

The control plane drained the agent version an open or a one-shot decision was admitted under, and
the drain floor passed the snapshot generation it was admitted at. The runtime refuses with
``FAILED_PRECONDITION`` + ``ErrorInfo`` ``admitted_generation`` / ``floor_generation`` and no
``RetryInfo``; nothing is registered or sealed. No request names a version (the runtime resolves the
Active pin at admission), so the reopen is the same call re-admitted with a FRESH challenge: it
lands on the current version. ``run_decision`` and ``open_session`` do that once by themselves; a
second refusal, and the refusal on any other verb, propagates typed.
"""

from __future__ import annotations

import grpc
import pytest

from seam_sdk import (
    TENANT_MOVING_REASON,
    VERSION_DRAINED_REASON,
    WRONG_CELL_REASON,
    Agent,
    is_retryable,
    is_tenant_moving,
    is_version_drained,
    is_wrong_cell,
    load_shed_retry_classifier,
    with_session_retry,
)
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.errors import FailedPreconditionError

from test_credential_refresh import (
    OLD,
    SUBMITS,
    _cached,
    _invoke,
    _seed,
    _Harness,
    _Wire,
)
from test_credential_wiring import CRED_SEED, SEED
from test_error_details import KEY, error_info, retry_info, status

GENS = {"admitted_generation": "41", "floor_generation": "42"}


def _refusal(reason: str, seconds: int = 0, **md: str) -> FailedPreconditionError:
    details = [error_info(reason, **md)]
    if seconds:
        details.append(retry_info(seconds, 0))
    trailing = ((KEY, status(9, *details)),)
    return FailedPreconditionError(
        grpc.StatusCode.FAILED_PRECONDITION, "refused", trailing
    )


def version_drained() -> FailedPreconditionError:
    return _refusal(VERSION_DRAINED_REASON, **GENS)


# ── Classification ────────────────────────────────────────────────────────────────────────────────


def test_version_drained_is_typed_and_never_retryable():
    err = version_drained()
    assert err.reason == "VERSION_DRAINED" == VERSION_DRAINED_REASON
    assert err.error_metadata == GENS
    assert err.retry_after is None
    assert is_version_drained(err)
    assert not is_retryable(err)
    assert not is_tenant_moving(err) and not is_wrong_cell(err)


@pytest.mark.parametrize(
    "err",
    [
        _refusal(TENANT_MOVING_REASON, 5, move_id="mv-1", target_cell="b"),
        _refusal(WRONG_CELL_REASON, cell="a"),
        _refusal("stream_id_mismatch"),
    ],
)
def test_other_failed_preconditions_are_not_version_drained(err):
    assert not is_version_drained(err)


def test_the_opt_in_retry_helper_never_re_sends_it():
    calls = 0

    def call():
        nonlocal calls
        calls += 1
        raise version_drained()

    with pytest.raises(FailedPreconditionError) as exc:
        with_session_retry(call, sleep=lambda _d: pytest.fail("slept"))
    assert is_version_drained(exc.value) and calls == 1
    assert load_shed_retry_classifier(version_drained()) is None


# ── The client: one reopen on the two admitting verbs, nothing anywhere else ──────────────────────


@pytest.fixture(params=["sync", "aio"])
def h(request):
    harness = _Harness(request.param == "aio")
    yield harness
    harness.close()


class _DrainWire(_Wire):
    """``refuse[name]`` is a list of errors raised by that verb's next calls, in order. Every
    challenge carries a new nonce, as the runtime's do, so a re-built presentation is new bytes."""

    def __init__(self) -> None:
        super().__init__()
        self.refuse: dict = {}
        self.challenges = 0

    def handle(self, name, req, kw):
        if name == "IssueChallenge":
            with self._lock:
                self.calls.append((name, req, kw.get("metadata")))
                self.challenges += 1
                return pb.Challenge(
                    nonce="bm9uY2U%d" % self.challenges,
                    receiver_aid="aid:pubkey:receiver",
                )
        if self.refuse.get(name):
            with self._lock:
                self.calls.append((name, req, kw.get("metadata")))
            raise self.refuse[name].pop(0)
        return super().handle(name, req, kw)


def _run_decision(h, client):
    return h.run(
        client.run_decision(
            Agent(SEED), "s-drained-0001", ["a", "b"], [("a", "APPROVE")]
        )
    )


def _open_session(h, client, cred):
    return h.run(
        client.open_session(Agent(SEED), "s-drained-0001", ["a", "b"], credential=cred)
    )


def test_run_decision_reopens_once_with_a_fresh_presentation(h):
    wire = _DrainWire()
    wire.serve["RunDecision"] = pb.DecisionResponse(decision_id="dec:t:s-drained-0001")
    wire.refuse["RunDecision"] = [version_drained()]
    client = h.client(wire)

    resp = _run_decision(h, client)

    assert resp.decision_id == "dec:t:s-drained-0001"
    sent = [c[1] for c in wire.of("RunDecision")]
    assert len(sent) == 2 and wire.challenges == 2
    first, second = sent
    assert first.presentation != second.presentation, "never the refused bytes again"
    first.ClearField("presentation")
    second.ClearField("presentation")
    assert first == second, (
        "same session_id (the idempotency key), votes and participants"
    )


def test_run_decision_a_second_drain_propagates_typed(h):
    wire = _DrainWire()
    wire.refuse["RunDecision"] = [version_drained(), version_drained()]
    client = h.client(wire)

    with pytest.raises(FailedPreconditionError) as exc:
        _run_decision(h, client)

    assert is_version_drained(exc.value)
    assert len(wire.of("RunDecision")) == 2, "one reopen, never a loop"


@pytest.mark.parametrize(
    "err",
    [
        _refusal(TENANT_MOVING_REASON, 5, move_id="mv-1", target_cell="b"),
        _refusal(WRONG_CELL_REASON, cell="a"),
    ],
)
def test_run_decision_reopens_on_nothing_else(h, err):
    wire = _DrainWire()
    wire.refuse["RunDecision"] = [err]
    client = h.client(wire)

    with pytest.raises(FailedPreconditionError) as exc:
        _run_decision(h, client)

    assert exc.value is err
    assert len(wire.of("RunDecision")) == 1


def test_open_session_reopens_once_and_keeps_the_ticket(h):
    wire = _DrainWire()
    wire.refuse["OpenSession"] = [version_drained()]
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)

    step = _open_session(h, client, cred)

    assert step.state == "served:OpenSession"
    sent = wire.of("OpenSession")
    assert len(sent) == 2 and wire.challenges == 2
    assert sent[0][1].session_id == sent[1][1].session_id
    assert sent[0][1].presentation != sent[1][1].presentation
    assert sent[0][2] != sent[1][2], (
        "re-signed over the new body, never the refused bytes"
    )
    assert wire.admits == 0 and _cached(client, cred) == OLD


def test_open_session_a_second_drain_propagates_typed(h):
    wire = _DrainWire()
    wire.refuse["OpenSession"] = [version_drained(), version_drained()]
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)

    with pytest.raises(FailedPreconditionError) as exc:
        _open_session(h, client, cred)

    assert is_version_drained(exc.value)
    assert len(wire.of("OpenSession")) == 2


@pytest.mark.parametrize("verb", SUBMITS)
def test_a_step_is_never_retried_or_reopened(h, verb):
    """A step cannot be reopened in place: its session's earlier steps would have to be replayed.
    The typed refusal reaches the caller, who opens a new session."""
    wire = _DrainWire()
    wire.refuse[verb] = [version_drained()]
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)

    with pytest.raises(FailedPreconditionError) as exc:
        _invoke(h, client, verb, cred)

    assert is_version_drained(exc.value)
    assert len(wire.of(verb)) == 1
    assert wire.challenges == 0 and _cached(client, cred) == OLD
