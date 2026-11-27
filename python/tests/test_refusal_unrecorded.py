"""``REFUSAL_UNRECORDED`` (seam-runtime Authorize D3, ``docs/specs/error-model.md`` §REFUSAL_UNRECORDED):
classification, the opt-in retry helper, and the client dropping a burned ticket.

The runtime reached a commit-time refusal (a policy or scope denial) but could not write its chained
audit entry, so it answers ``FAILED_PRECONDITION`` + ``RetryInfo`` (1s) + ``ErrorInfo`` reason
``REFUSAL_UNRECORDED`` instead of delivering the refusal. Nothing was applied, so the same call is
retryable — but it is never an allow, and it is not a session-lease refusal. The request proof of a
replay-guarded write was burned at admission (seamd ``authorize.rs`` ``replay_guarded``), before the
op reached its refusal, so its ticket must be dropped exactly as for ``TENANT_MOVING``: otherwise the
retry re-signs the same bytes and is refused ``request_replayed``, which is not retryable.
"""

from __future__ import annotations

import grpc
import pytest

from seam_sdk import (
    REFUSAL_UNRECORDED_REASON,
    TENANT_MOVING_REASON,
    Agent,
    is_refusal_unrecorded,
    is_retryable,
    is_session_unavailable,
    is_tenant_moving,
    load_shed_retry_classifier,
    with_session_retry,
    with_session_retry_async,
)
from seam_sdk.errors import (
    FailedPreconditionError,
    InvalidArgumentError,
    UnavailableError,
)

from test_credential_refresh import (
    EXCLUDED,
    OLD,
    READS_AND_OUTCOME,
    SUBMITS,
    _cached,
    _invoke,
    _seed,
    _Harness,
    _Wire,
)
from test_credential_wiring import CRED_SEED
from test_error_details import KEY, error_info, retry_info, status

GUARDED = SUBMITS + EXCLUDED + ("RegisterContext",)


def _refusal(
    reason, seconds: int = 0, *, cls=FailedPreconditionError, code: int = 9
) -> grpc.RpcError:
    details = [error_info(reason)] if reason is not None else []
    if seconds:
        details.append(retry_info(seconds, 0))
    trailing = ((KEY, status(code, *details)),)
    return cls(grpc.StatusCode.FAILED_PRECONDITION, "refused", trailing)


def refusal_unrecorded(seconds: int = 1) -> FailedPreconditionError:
    return _refusal(REFUSAL_UNRECORDED_REASON, seconds)


# ── Classification ────────────────────────────────────────────────────────────────────────────────


def test_refusal_unrecorded_is_typed_retryable_and_not_a_lease_refusal():
    err = refusal_unrecorded()
    assert isinstance(err, FailedPreconditionError)
    assert err.reason == "REFUSAL_UNRECORDED" == REFUSAL_UNRECORDED_REASON
    assert err.retry_after == pytest.approx(1.0)
    assert is_refusal_unrecorded(err) and is_retryable(err)
    assert not is_session_unavailable(err) and not is_tenant_moving(err)
    assert load_shed_retry_classifier(err).delay_s == pytest.approx(1.0)


def test_it_is_selected_on_the_reason_never_the_status_or_message():
    assert not is_refusal_unrecorded(_refusal(TENANT_MOVING_REASON, 5))
    assert not is_refusal_unrecorded(_refusal(None, 1))
    # The reason on another status is not this refusal.
    assert not is_refusal_unrecorded(
        _refusal(REFUSAL_UNRECORDED_REASON, 1, cls=UnavailableError, code=14)
    )


def test_the_opt_in_helper_waits_the_hinted_delay_and_retries():
    errors = [refusal_unrecorded(1)]
    calls = 0

    def call():
        nonlocal calls
        calls += 1
        if errors:
            raise errors.pop(0)
        return "ok"

    slept: list = []
    assert with_session_retry(call, sleep=slept.append, rng=lambda: 0.0) == "ok"
    assert calls == 2 and slept == pytest.approx([1.0])


# ── The client: a burned proof's ticket is dropped, nothing else changes ─────────────────────────


@pytest.fixture(params=["sync", "aio"])
def h(request):
    harness = _Harness(request.param == "aio")
    yield harness
    harness.close()


class _RefusingWire(_Wire):
    """``refuse[name]`` refuses that verb once with the given error."""

    def __init__(self) -> None:
        super().__init__()
        self.refuse: dict = {}

    def handle(self, name, req, kw):
        if name in self.refuse:
            with self._lock:
                self.calls.append((name, req, kw.get("metadata")))
            raise self.refuse.pop(name)
        return super().handle(name, req, kw)


class _BurningWire(_Wire):
    """The runtime's seen-proof cache in front of ``verb``: a call signature it has already seen is
    refused ``request_replayed`` (INVALID_ARGUMENT), whatever the verb then answers. ``unrecorded``
    first attempts burn their proof and then answer ``REFUSAL_UNRECORDED``."""

    def __init__(self, verb: str, unrecorded: int = 1) -> None:
        super().__init__()
        self.verb = verb
        self.unrecorded = unrecorded
        self.burned: set = set()

    def handle(self, name, req, kw):
        if name == self.verb:
            sig = dict(kw.get("metadata") or ())["x-seam-call-sig-bin"]
            with self._lock:
                if sig in self.burned:
                    self.calls.append((name, req, kw.get("metadata")))
                    raise InvalidArgumentError(
                        grpc.StatusCode.INVALID_ARGUMENT, "request_replayed"
                    )
                self.burned.add(sig)
                if self.unrecorded > 0:
                    self.unrecorded -= 1
                    self.calls.append((name, req, kw.get("metadata")))
                    raise refusal_unrecorded(1)
        return super().handle(name, req, kw)


@pytest.mark.parametrize("verb", GUARDED)
def test_refusal_unrecorded_on_a_guarded_write_drops_the_burned_ticket(h, verb):
    wire = _RefusingWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.refuse[verb] = refusal_unrecorded()

    with pytest.raises(FailedPreconditionError) as exc:
        _invoke(h, client, verb, cred)

    assert is_refusal_unrecorded(exc.value)
    assert len(wire.of(verb)) == 1, "the SDK itself never retries it"
    assert wire.admits == 0, "dropping the ticket costs nothing until the next call"
    assert _cached(client, cred) is None


@pytest.mark.parametrize("verb", READS_AND_OUTCOME + ("ResolveContext",))
def test_refusal_unrecorded_on_an_unguarded_call_keeps_the_ticket(h, verb):
    """Reads and ``ReportOutcome`` are outside the runtime's seen-proof cache: nothing was burned."""
    wire = _RefusingWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.refuse[verb] = refusal_unrecorded()

    with pytest.raises(FailedPreconditionError):
        _invoke(h, client, verb, cred)

    assert _cached(client, cred) == OLD


@pytest.mark.parametrize("verb", GUARDED)
def test_the_retry_of_a_guarded_write_carries_a_new_ticket_and_never_meets_request_replayed(
    h, verb
):
    """The leader's acceptance for the ticket-drop decision (DECISIONS.md 2026-11-27): wrapped in the
    opt-in helper, a replay-guarded write refused ``REFUSAL_UNRECORDED`` re-admits, re-signs under the
    NEW ticket, and succeeds — the runtime's seen-proof cache never sees the burned signature twice."""
    wire = _BurningWire(verb)
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    slept: list = []

    if h.aio:

        async def sleep(d):
            slept.append(d)

        h.run(
            with_session_retry_async(
                lambda: _invoke_aio(client, verb, cred), sleep=sleep, rng=lambda: 0.0
            )
        )
    else:
        with_session_retry(
            lambda: _invoke(h, client, verb, cred),
            sleep=slept.append,
            rng=lambda: 0.0,
        )

    sent = wire.of(verb)
    assert len(sent) == 2, "exactly one retry"
    assert slept == pytest.approx([1.0]), "it waited the RetryInfo delay"
    assert wire.admits == 1, "the retry re-admitted"
    tickets = [dict(md)["x-seam-ticket-bin"] for _, _, md in sent]
    assert tickets == [OLD, b"new-ticket-1"]
    assert _cached(client, cred) == b"new-ticket-1"


def _invoke_aio(client, verb, cred):
    from test_credential_refresh import CALLS

    return CALLS[verb]["invoke"](client, cred)
