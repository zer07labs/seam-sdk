"""``TENANT_MOVING`` (seam-runtime k8s P16, ``docs/design/cells.md`` §7): classification, the
opt-in retry helper, and the client dropping a burned ticket.

The runtime refuses new opens, authorizes and one-shot decisions for a tenant moving between cells
with ``FAILED_PRECONDITION`` + ``RetryInfo`` (5s) + ``ErrorInfo`` ``move_id``/``target_cell``. Unlike
``WRONG_CELL`` it is retryable: once the control plane flips the tenant, the routed call reaches the
target cell. The refusal comes after admission has burned a replay-guarded write's proof (seamd
``session.rs`` ``refuse_moving``), so a guarded write's ticket must be dropped exactly as for
``SESSION_UNAVAILABLE``, or the retry re-signs the same bytes and is refused ``request_replayed``.
"""

from __future__ import annotations

import grpc
import pytest

from seam_sdk import (
    TENANT_MOVING_REASON,
    WRONG_CELL_REASON,
    Agent,
    is_retryable,
    is_tenant_moving,
    is_wrong_cell,
    with_session_retry,
)
from seam_sdk.errors import FailedPreconditionError

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

MOVE = {"move_id": "mv-1", "target_cell": "aws-stg-b"}


def _refusal(reason: str, seconds: int = 0, **md: str) -> FailedPreconditionError:
    details = [error_info(reason, **md)]
    if seconds:
        details.append(retry_info(seconds, 0))
    trailing = ((KEY, status(9, *details)),)
    return FailedPreconditionError(
        grpc.StatusCode.FAILED_PRECONDITION, "refused", trailing
    )


def tenant_moving(seconds: int = 5) -> FailedPreconditionError:
    return _refusal(TENANT_MOVING_REASON, seconds, **MOVE)


# ── Classification ────────────────────────────────────────────────────────────────────────────────


def test_tenant_moving_is_typed_retryable_and_carries_the_move():
    err = tenant_moving()
    assert err.reason == "TENANT_MOVING" == TENANT_MOVING_REASON
    assert err.error_metadata == MOVE
    assert err.retry_after == pytest.approx(5.0)
    assert is_tenant_moving(err) and is_retryable(err)
    assert not is_wrong_cell(err)


def test_wrong_cell_stays_never_retryable_and_is_not_tenant_moving():
    err = _refusal(WRONG_CELL_REASON, cell="aws-stg-a")
    assert is_wrong_cell(err) and not is_tenant_moving(err) and not is_retryable(err)


def test_another_failed_precondition_is_neither():
    err = _refusal("stream_id_mismatch")
    assert not is_tenant_moving(err) and not is_retryable(err)


def test_the_opt_in_helper_waits_the_hinted_delay_and_retries():
    errors = [tenant_moving(5), tenant_moving(5)]
    calls = 0

    def call():
        nonlocal calls
        calls += 1
        if errors:
            raise errors.pop(0)
        return "ok"

    slept: list = []
    result = with_session_retry(call, sleep=slept.append, rng=lambda: 0.0)
    assert result == "ok" and calls == 3
    assert slept == pytest.approx([5.0, 5.0])


def test_the_opt_in_helper_gives_up_inside_its_budget():
    """A move can outlast the default budget (its drain waits on live sessions); the last refusal
    is raised as-is rather than looping past it."""

    def call():
        raise tenant_moving(5)

    with pytest.raises(FailedPreconditionError) as exc:
        with_session_retry(call, sleep=lambda _d: None, rng=lambda: 0.0, budget_s=12)
    assert is_tenant_moving(exc.value)


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


@pytest.mark.parametrize("verb", SUBMITS + EXCLUDED)
def test_tenant_moving_on_a_guarded_write_drops_the_burned_ticket(h, verb):
    wire = _RefusingWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.refuse[verb] = tenant_moving()

    with pytest.raises(FailedPreconditionError) as exc:
        _invoke(h, client, verb, cred)

    assert is_tenant_moving(exc.value)
    assert len(wire.of(verb)) == 1, "the SDK itself never retries it"
    assert wire.admits == 0, "dropping the ticket costs nothing until the next call"
    assert _cached(client, cred) is None


@pytest.mark.parametrize("verb", READS_AND_OUTCOME)
def test_tenant_moving_on_an_unguarded_call_keeps_the_ticket(h, verb):
    """Reads and ``ReportOutcome`` are outside the runtime's seen-proof cache: nothing was burned."""
    wire = _RefusingWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.refuse[verb] = tenant_moving()

    with pytest.raises(FailedPreconditionError):
        _invoke(h, client, verb, cred)

    assert _cached(client, cred) == OLD


@pytest.mark.parametrize("verb", SUBMITS + EXCLUDED)
def test_any_other_failed_precondition_leaves_the_ticket_as_before(h, verb):
    wire = _RefusingWire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    err = _refusal(WRONG_CELL_REASON, cell="aws-stg-a")
    wire.refuse[verb] = err

    with pytest.raises(FailedPreconditionError) as exc:
        _invoke(h, client, verb, cred)

    assert exc.value is err
    assert _cached(client, cred) == OLD
