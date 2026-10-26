"""Opt-in retry for the runtime's ``SESSION_UNAVAILABLE`` refusal (seam-runtime k8s P6).

The SDK never retries on its own (``client.py``, D-WRITES-EXCLUDED); this is a helper a caller wraps
around a call it chooses to retry. It re-invokes the callable, so every attempt is a fresh SDK call:
it re-signs its credential and, when the ticket is cold, re-admits. Only :func:`is_retryable`
errors are retried — every other error, including every other ``UNAVAILABLE``, propagates on the
first attempt exactly as it would unwrapped.

The delay before attempt ``n+1`` is the server's ``RetryInfo`` (the lease holder's remaining lease,
or 1s while the store is down) plus full jitter over a capped exponential: ``retry_after +
U(0, min(max_delay_s, base_delay_s * 2**n))``. The default 40s budget outlasts the runtime's 30s
lease TTL (``seamd/src/live_fence.rs`` ``LEASE_TTL``), so one lapsed lease is always waited out.
It does NOT outlast a tenant move (``TENANT_MOVING``, also :func:`is_retryable`; 5s ``RetryInfo``):
the source cell drains until its live sessions finish, so pass a ``budget_s`` sized for that drain.
The budget bounds the time spent waiting, not the calls themselves: each attempt keeps its own
per-RPC ``timeout``. When the next delay would overrun the budget, the last error is raised as-is.

Wrap unary calls. A streaming response surfaces its error while it is consumed, not when the call
returns, so it would escape this helper.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Awaitable, Callable, Optional, TypeVar

from .errors import SeamRpcError, is_retryable

T = TypeVar("T")

#: Total seconds a retry loop may spend waiting between attempts. Longer than the 30s lease TTL.
DEFAULT_RETRY_BUDGET_S = 40.0
DEFAULT_RETRY_BASE_DELAY_S = 0.25
DEFAULT_RETRY_MAX_DELAY_S = 8.0
DEFAULT_RETRY_MAX_ATTEMPTS = 10


def _next_delay(
    exc: BaseException,
    attempt: int,
    waited: float,
    *,
    budget_s: float,
    base_delay_s: float,
    max_delay_s: float,
    max_attempts: int,
    rng: Callable[[], float],
) -> Optional[float]:
    """The delay before the next attempt, or ``None`` when ``exc`` must be raised."""
    if not is_retryable(exc) or attempt >= max_attempts:
        return None
    retry_after = exc.retry_after if isinstance(exc, SeamRpcError) else None
    delay = (retry_after or 0.0) + rng() * min(
        max_delay_s, base_delay_s * 2 ** (attempt - 1)
    )
    if waited + delay > budget_s:
        return None
    return delay


def with_session_retry(
    call: Callable[[], T],
    *,
    budget_s: float = DEFAULT_RETRY_BUDGET_S,
    base_delay_s: float = DEFAULT_RETRY_BASE_DELAY_S,
    max_delay_s: float = DEFAULT_RETRY_MAX_DELAY_S,
    max_attempts: int = DEFAULT_RETRY_MAX_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
    rng: Callable[[], float] = random.random,
) -> T:
    """Run ``call()``, re-invoking it on ``SESSION_UNAVAILABLE`` with bounded, jittered backoff.

    ``call`` is a zero-argument callable that makes ONE SDK call, e.g.
    ``with_session_retry(lambda: client.submit_proposal(...))``. ``max_attempts`` counts the first.
    """
    attempt, waited = 1, 0.0
    while True:
        try:
            return call()
        except Exception as exc:
            delay = _next_delay(
                exc,
                attempt,
                waited,
                budget_s=budget_s,
                base_delay_s=base_delay_s,
                max_delay_s=max_delay_s,
                max_attempts=max_attempts,
                rng=rng,
            )
            if delay is None:
                raise
        sleep(delay)
        waited += delay
        attempt += 1


async def with_session_retry_async(
    call: Callable[[], Awaitable[T]],
    *,
    budget_s: float = DEFAULT_RETRY_BUDGET_S,
    base_delay_s: float = DEFAULT_RETRY_BASE_DELAY_S,
    max_delay_s: float = DEFAULT_RETRY_MAX_DELAY_S,
    max_attempts: int = DEFAULT_RETRY_MAX_ATTEMPTS,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    rng: Callable[[], float] = random.random,
) -> T:
    """:func:`with_session_retry` for :mod:`seam_sdk.aio`: ``call`` returns a fresh awaitable per
    attempt, e.g. ``await with_session_retry_async(lambda: client.submit_proposal(...))``."""
    attempt, waited = 1, 0.0
    while True:
        try:
            return await call()
        except Exception as exc:
            delay = _next_delay(
                exc,
                attempt,
                waited,
                budget_s=budget_s,
                base_delay_s=base_delay_s,
                max_delay_s=max_delay_s,
                max_attempts=max_attempts,
                rng=rng,
            )
            if delay is None:
                raise
        await sleep(delay)
        waited += delay
        attempt += 1
