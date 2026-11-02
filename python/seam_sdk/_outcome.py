"""Branchpoint BP-2 / plan 47 OI-R1 outcome fields on ``ReportOutcome`` (``reward``, ``metrics``,
``observed_at_millis``) and the OI-R6 wire-feature names that gate them.

The checks here mirror the runtime's request-shape validation (``seamd::facade::validate_outcome_shape``)
so a malformed value is refused **before any RPC** — an outcome report is permanent, and an invalid one
must never reach the wire. The one runtime check that needs the sealed record, ``observed_at`` lying in
``[sealed_at, now + 300 s]``, stays server-side. Shared by the sync and async clients.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Dict, Mapping, Optional, Tuple, Union

# OI-R6 wire features (seam-runtime ``docs/specs/wire-features.md``). A name is never reused or renamed.
WIRE_FEATURE_ENROLL_KIND = "enroll.kind"
"""Enrolment accepts a ``kind`` (runtime 0.71.0+)."""
WIRE_FEATURE_OUTCOME_REWARD_METRICS = "outcome.reward_metrics"
"""``ReportOutcome`` accepts ``reward`` and ``metrics`` (runtime BP-2c)."""
WIRE_FEATURE_OUTCOME_OBSERVED_AT = "outcome.observed_at"
"""``ReportOutcome`` accepts ``observed_at`` (runtime BP-2c)."""

# The runtime's limits (``seamd::facade::OUTCOME_METRICS_MAX`` / ``OUTCOME_METRIC_KEY_MAX``).
OUTCOME_METRICS_MAX = 16
_METRIC_KEY = re.compile(r"[a-z][a-z0-9_]{0,62}")
_U64_MAX = (1 << 64) - 1
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

ObservedAt = Union[datetime, int]


def _finite(name: str, v: object) -> float:
    # ``bool`` is an ``int`` subclass: ``reward=True`` is a caller bug, never a 1.0.
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise TypeError(f"{name} must be a float, got {type(v).__name__}")
    try:
        f = float(v)
    except (
        OverflowError
    ):  # an int beyond the f64 range (e.g. 10**400) is not finite either
        f = math.inf
    if not math.isfinite(f):
        raise ValueError(
            f"{name} must be a finite number (NaN and ±infinity are refused); "
            "the runtime refuses it with INVALID_ARGUMENT"
        )
    return f


def _observed_at_millis(observed_at: ObservedAt) -> int:
    if isinstance(observed_at, datetime):
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            # A naive datetime has no instant: guessing local time or UTC would silently shift the
            # source-event time by the machine's offset.
            raise ValueError(
                "observed_at must be a timezone-aware datetime (or integer ms since the Unix epoch)"
            )
        # Integer arithmetic on the timedelta, not ``timestamp() * 1000`` — float rounding would move
        # some instants by a millisecond.
        td = observed_at - _EPOCH
        ms = (td.days * 86_400 + td.seconds) * 1000 + td.microseconds // 1000
    elif isinstance(observed_at, int) and not isinstance(observed_at, bool):
        ms = observed_at
    else:
        raise TypeError(
            "observed_at must be a timezone-aware datetime or integer ms since the Unix epoch, "
            f"got {type(observed_at).__name__}"
        )
    if not 0 <= ms <= _U64_MAX:
        raise ValueError(
            "observed_at must not be before the Unix epoch (ms must fit a u64)"
        )
    return ms


def check_outcome_fields(
    reward: Optional[float],
    metrics: Optional[Mapping[str, float]],
    observed_at: Optional[ObservedAt],
) -> Tuple[Optional[float], Dict[str, float], Optional[int]]:
    """Validate the BP-2 fields the way the runtime does and return ``(reward, metrics, observed_at_millis)``
    ready for the request. ``metrics=None`` and ``metrics={}`` are the same: absent (the v1 digest)."""
    r = None if reward is None else _finite("reward", reward)
    m: Dict[str, float] = {}
    if metrics is not None:
        if not isinstance(metrics, Mapping):
            raise TypeError(
                f"metrics must be a mapping of str to float, got {type(metrics).__name__}"
            )
        if len(metrics) > OUTCOME_METRICS_MAX:
            raise ValueError(
                f"metrics carries {len(metrics)} entries; at most {OUTCOME_METRICS_MAX} are accepted"
            )
        for k, v in metrics.items():
            if not isinstance(k, str) or _METRIC_KEY.fullmatch(k) is None:
                # Not echoed: the runtime does not echo it either (caller text bound for a SIEM).
                raise ValueError("a metrics key does not match ^[a-z][a-z0-9_]{0,62}$")
            m[k] = _finite("metrics values", v)
    t = None if observed_at is None else _observed_at_millis(observed_at)
    return r, m, t
