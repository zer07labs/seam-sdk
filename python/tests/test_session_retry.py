"""``SESSION_UNAVAILABLE`` (seam-runtime k8s P6): classification, the opt-in retry helper, and the
client dropping a burned ticket so a retry signs fresh bytes.

The runtime returns it as ``UNAVAILABLE`` + ``RetryInfo`` when another replica holds the live
session's lease (the delay is the holder's remaining lease, at most the 30s ``LEASE_TTL``) or the
shared store is unreachable (1s). It burns a credentialed write's proof at admission, BEFORE the
lease, so resending the same body under the same ticket would be refused ``request_replayed``.
"""

from __future__ import annotations

import asyncio

import grpc
import pytest

from seam_sdk import (
    DEFAULT_RETRY_BUDGET_S,
    SESSION_UNAVAILABLE_REASON,
    Agent,
    is_retryable,
    is_session_unavailable,
    with_session_retry,
    with_session_retry_async,
)
from seam_sdk.errors import (
    InternalError,
    PermissionDeniedError,
    UnavailableError,
)

from test_credential_refresh import (
    ADMISSION,
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


def _unavailable(
    reason: str | None, seconds: int = 0, nanos: int = 0
) -> UnavailableError:
    details = []
    if reason is not None:
        details.append(error_info(reason))
    if seconds or nanos:
        details.append(retry_info(seconds, nanos))
    trailing = ((KEY, status(14, *details)),) if details else ()
    return UnavailableError(grpc.StatusCode.UNAVAILABLE, "busy", trailing)


def session_unavailable(seconds: int = 0, nanos: int = 0) -> UnavailableError:
    return _unavailable(SESSION_UNAVAILABLE_REASON, seconds, nanos)


# ── Classification ────────────────────────────────────────────────────────────────────────────────


def test_session_unavailable_is_classified_retryable():
    err = session_unavailable(12, 200_000_000)
    assert err.reason == "SESSION_UNAVAILABLE" == SESSION_UNAVAILABLE_REASON
    assert err.retry_after == pytest.approx(12.2)
    assert is_session_unavailable(err) and is_retryable(err)


@pytest.mark.parametrize(
    "err",
    [
        _unavailable(None),
        _unavailable("CHALLENGE_REFUSED", 1),
        _unavailable("CONTEXT_REVOCATION_UNAVAILABLE"),
        InternalError(
            grpc.StatusCode.INTERNAL,
            "x",
            ((KEY, status(13, error_info("SESSION_UNAVAILABLE"))),),
        ),
        PermissionDeniedError(grpc.StatusCode.PERMISSION_DENIED, "x"),
        ValueError("not an rpc error"),
    ],
    ids=[
        "bare-unavailable",
        "challenge-refused",
        "revocation-unavailable",
        "reason-on-wrong-code",
        "denied",
        "non-rpc",
    ],
)
def test_every_other_error_is_not_retryable(err):
    assert not is_session_unavailable(err)
    assert not is_retryable(err)


# ── The helper, on a scripted callable ────────────────────────────────────────────────────────────


class _Script:
    """Raise each scripted error in turn, then return ``"ok"``."""

    def __init__(self, *errors: BaseException) -> None:
        self.errors = list(errors)
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return "ok"


def _retry(script, *, rng=lambda: 1.0, **kw):
    slept: list = []
    result = with_session_retry(script, sleep=slept.append, rng=rng, **kw)
    return result, slept


def test_retries_until_success_honouring_retry_info_plus_exponential_jitter():
    script = _Script(
        session_unavailable(2), session_unavailable(1), session_unavailable()
    )
    result, slept = _retry(script)
    assert result == "ok" and script.calls == 4
    # retry_after + U(0, min(8, 0.25 * 2**n)), with the jitter draw pinned to its upper bound.
    assert slept == pytest.approx([2.25, 1.5, 1.0])


def test_jitter_is_full_jitter_over_the_capped_exponential():
    script = _Script(*[session_unavailable() for _ in range(7)])
    _, slept = _retry(script, rng=lambda: 0.5)
    assert slept == pytest.approx([0.125, 0.25, 0.5, 1.0, 2.0, 4.0, 4.0])


def test_the_default_budget_outlasts_a_full_lease():
    """A lease just taken has 30s to run (``LEASE_TTL``); the default waits it out."""
    assert DEFAULT_RETRY_BUDGET_S > 30
    script = _Script(session_unavailable(30))
    result, slept = _retry(script)
    assert result == "ok" and slept == pytest.approx([30.25])


def test_a_delay_that_would_overrun_the_budget_raises_the_last_error_as_is():
    second = session_unavailable(30)
    script = _Script(session_unavailable(30), second)
    with pytest.raises(UnavailableError) as exc:
        _retry(script)
    assert exc.value is second
    assert script.calls == 2


def test_max_attempts_counts_the_first_call():
    script = _Script(*[session_unavailable() for _ in range(5)])
    with pytest.raises(UnavailableError):
        _retry(script, max_attempts=3)
    assert script.calls == 3


@pytest.mark.parametrize(
    "err",
    [
        _unavailable(None),
        _unavailable("CHALLENGE_REFUSED", 1),
        PermissionDeniedError(grpc.StatusCode.PERMISSION_DENIED, "x"),
        RuntimeError("boom"),
    ],
    ids=["bare-unavailable", "challenge-refused", "denied", "non-rpc"],
)
def test_every_other_error_propagates_on_the_first_attempt(err):
    script = _Script(err)
    with pytest.raises(type(err)) as exc:
        _retry(script)
    assert exc.value is err
    assert script.calls == 1


def test_the_async_helper_has_the_same_policy():
    script = _Script(session_unavailable(1), session_unavailable())
    slept: list = []

    async def call():
        return script()

    async def sleep(d):
        slept.append(d)

    result = asyncio.run(with_session_retry_async(call, sleep=sleep, rng=lambda: 1.0))
    assert result == "ok" and script.calls == 3
    assert slept == pytest.approx([1.25, 0.5])


# ── The client: a burned proof's ticket is dropped, nothing else changes ─────────────────────────


@pytest.fixture(params=["sync", "aio"])
def h(request):
    harness = _Harness(request.param == "aio")
    yield harness
    harness.close()


class _BusyWire(_Wire):
    """``busy[name]`` refuses that verb ``SESSION_UNAVAILABLE`` that many times; ``other[name]``
    refuses it once with the given (non-session) error."""

    def __init__(self) -> None:
        super().__init__()
        self.busy: dict = {}
        self.other: dict = {}

    def handle(self, name, req, kw):
        if self.busy.get(name, 0) > 0:
            with self._lock:
                self.calls.append((name, req, kw.get("metadata")))
                self.busy[name] -= 1
            raise session_unavailable(1)
        if name in self.other:
            with self._lock:
                self.calls.append((name, req, kw.get("metadata")))
            raise self.other.pop(name)
        return super().handle(name, req, kw)


@pytest.mark.parametrize("verb", SUBMITS + EXCLUDED)
def test_session_unavailable_on_a_guarded_write_drops_the_burned_ticket(h, verb):
    wire = _BusyWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.busy[verb] = 1

    with pytest.raises(UnavailableError) as exc:
        _invoke(h, client, verb, cred)

    assert is_session_unavailable(exc.value)
    assert len(wire.of(verb)) == 1, "the SDK itself never retries it"
    assert wire.admits == 0, "dropping the ticket costs nothing until the next call"
    assert _cached(client, cred) is None


@pytest.mark.parametrize("verb", READS_AND_OUTCOME)
def test_session_unavailable_on_an_unguarded_call_keeps_the_ticket(h, verb):
    """Reads and ``ReportOutcome`` are outside the runtime's seen-proof cache: nothing was burned."""
    wire = _BusyWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.busy[verb] = 1

    with pytest.raises(UnavailableError):
        _invoke(h, client, verb, cred)

    assert _cached(client, cred) == OLD


@pytest.mark.parametrize("verb", SUBMITS + EXCLUDED)
@pytest.mark.parametrize(
    "err",
    [_unavailable(None), _unavailable("CHALLENGE_REFUSED", 1)],
    ids=["bare-unavailable", "challenge-refused"],
)
def test_any_other_unavailable_leaves_the_ticket_as_before(h, verb, err):
    wire = _BusyWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.other[verb] = err

    with pytest.raises(UnavailableError) as exc:
        _invoke(h, client, verb, cred)

    assert exc.value is err
    assert _cached(client, cred) == OLD


def test_session_unavailable_on_the_refresh_resend_drops_the_new_ticket(h):
    """UNAUTHENTICATED → refresh → the resend lands on a busy session: the NEW ticket is burned."""
    wire = _BusyWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject["SubmitVote"] = 1

    real = wire.handle

    def handle(name, req, kw):
        if name == "SubmitVote" and wire.reject.get(name, 0) == 0 and not wire.busy:
            wire.busy[name] = 1  # arm once the rejection has been spent
        return real(name, req, kw)

    wire.handle = handle
    with pytest.raises(UnavailableError):
        _invoke(h, client, "SubmitVote", cred)

    assert len(wire.of("SubmitVote")) == 2
    assert _cached(client, cred) is None, "the refreshed ticket's proof was burned too"


def test_with_session_retry_re_signs_every_attempt_under_a_fresh_ticket(h):
    """End to end: two busy refusals, then success — three sends, three tickets, three signatures."""
    wire = _BusyWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.busy["SubmitVote"] = 2

    def vote():
        return client.submit_vote("s1", "a", "p1", "APPROVE", credential=cred)

    if h.aio:

        async def sleep(_):
            pass

        step = h.run(with_session_retry_async(vote, sleep=sleep))
    else:
        step = with_session_retry(vote, sleep=lambda _: None)

    assert step == wire.responses["SubmitVote"]
    sends = wire.of("SubmitVote")
    assert len(sends) == 3
    assert len({s[1].SerializeToString() for s in sends}) == 1, (
        "the same request every time"
    )
    tickets = [dict(md)["x-seam-ticket-bin"] for _, _, md in sends]
    sigs = [dict(md)["x-seam-call-sig-bin"] for _, _, md in sends]
    assert tickets == [OLD, b"new-ticket-1", b"new-ticket-2"]
    assert len(set(sigs)) == 3
    assert wire.admission_rpcs() == 2 * len(ADMISSION)
