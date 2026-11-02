"""`report_outcome(reward=, metrics=, observed_at=)` (Branchpoint BP-2 / plan 47 OI-R1) and
`server_wire_features()` (OI-R6).

The three fields are gated by the runtime (`outcome.reward_metrics` / `outcome.observed_at`); the SDK
mirrors the runtime's request-shape checks so an invalid value never reaches the wire, and a caller that
passes none of them sends byte-identical requests to the previous release.
"""

from __future__ import annotations

import asyncio
import math
from datetime import datetime, timedelta, timezone

import pytest

import seam_sdk
from seam_sdk import SeamClient
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.aio import SeamClient as AioSeamClient

# Hand-derived (not produced by protobuf): 0a 08 "dec:t:s1" | 10 01 | 1a 02 "qa" | 22 09 "review-77".
# A call omitting every BP-2 argument must keep producing exactly these bytes (AC4).
GOLDEN_PRE_BP2 = "0a086465633a743a733110011a02716122097265766965772d3737"
# The same request plus reward=0.5 (29 | f64le), metrics={"latency_ms": 12.0} (32 15 | entry) and
# observed_at_millis=1700000000123 (38 | varint). Shared with ts/tests/report_outcome_reward.test.ts.
GOLDEN_FULL = (
    GOLDEN_PRE_BP2
    + "29000000000000e03f"
    + "32150a0a6c6174656e63795f6d73110000000000002840"
    + "38fbd095ffbc31"
)


class _Coord:
    def __init__(self, seen: list):
        self._seen = seen

    def ReportOutcome(self, req, **kw):
        self._seen.append(req)
        return pb.ReportOutcomeResponse(recorded=True)


class _AioCoord(_Coord):
    async def ReportOutcome(self, req, **kw):  # type: ignore[override]
        return _Coord.ReportOutcome(self, req, **kw)


def _clients(seen: list):
    sync = object.__new__(SeamClient)
    sync._coord = _Coord(seen)
    aio = object.__new__(AioSeamClient)
    aio._coord = _AioCoord(seen)
    return sync, aio


def _run(out):
    return asyncio.run(out) if asyncio.iscoroutine(out) else out


def _report(client, **kw):
    return _run(
        client.report_outcome("dec:t:s1", True, "qa", idempotency_key="review-77", **kw)
    )


BOTH = pytest.mark.parametrize("which", [0, 1], ids=["sync", "aio"])


@BOTH
def test_omitting_every_new_argument_is_byte_identical_to_the_previous_release(
    which: int,
) -> None:
    seen: list = []
    assert _report(_clients(seen)[which]) is True
    assert seen[0].SerializeToString().hex() == GOLDEN_PRE_BP2


@BOTH
def test_the_fields_ride_on_the_wire(which: int) -> None:
    seen: list = []
    _report(
        _clients(seen)[which],
        reward=0.5,
        metrics={"latency_ms": 12.0},
        observed_at=1_700_000_000_123,
    )
    (req,) = seen
    assert req.SerializeToString(deterministic=True).hex() == GOLDEN_FULL
    assert req.HasField("reward") and req.reward == 0.5
    assert dict(req.metrics) == {"latency_ms": 12.0}
    assert req.HasField("observed_at_millis")


@BOTH
def test_each_field_is_independent(which: int) -> None:
    seen: list = []
    c = _clients(seen)[which]
    _report(c, reward=0.0)
    _report(c, metrics={"a": 1})
    _report(c, observed_at=0)
    r0, r1, r2 = seen
    assert r0.HasField("reward") and r0.reward == 0.0 and not r0.metrics
    assert not r0.HasField("observed_at_millis")
    assert not r1.HasField("reward") and dict(r1.metrics) == {"a": 1.0}
    assert r2.HasField("observed_at_millis") and r2.observed_at_millis == 0
    assert not r2.HasField("reward")


@BOTH
def test_empty_metrics_is_absent(which: int) -> None:
    """`metrics={}` is the v1 digest on the runtime: it must be the pre-BP-2 bytes, not an empty map."""
    seen: list = []
    _report(_clients(seen)[which], metrics={})
    assert seen[0].SerializeToString().hex() == GOLDEN_PRE_BP2


@BOTH
def test_an_aware_datetime_converts_exactly_to_millis(which: int) -> None:
    seen: list = []
    c = _clients(seen)[which]
    utc = datetime(2023, 11, 14, 22, 13, 20, 123_999, tzinfo=timezone.utc)
    ist = utc.astimezone(timezone(timedelta(hours=5, minutes=30)))
    _report(c, observed_at=utc)
    _report(c, observed_at=ist)
    # Truncated, never rounded: 123.999 ms is 123.
    assert [r.observed_at_millis for r in seen] == [1_700_000_000_123] * 2


@BOTH
def test_int_values_are_accepted_as_floats(which: int) -> None:
    seen: list = []
    _report(_clients(seen)[which], reward=1, metrics={"n": 3})
    assert seen[0].reward == 1.0 and seen[0].metrics["n"] == 3.0


@BOTH
def test_metric_key_bounds_are_the_runtimes(which: int) -> None:
    seen: list = []
    keys = {"a": 1.0, "z" + "9" * 62: 2.0, "a_b_0": 3.0}
    full = {f"k{i}": float(i) for i in range(16)}
    c = _clients(seen)[which]
    _report(c, metrics=keys)
    _report(c, metrics=full)
    assert dict(seen[0].metrics) == keys and len(seen[1].metrics) == 16


_BAD = [
    ({"reward": math.nan}, ValueError, "reward must be a finite"),
    ({"reward": math.inf}, ValueError, "reward must be a finite"),
    ({"reward": -math.inf}, ValueError, "reward must be a finite"),
    ({"reward": True}, TypeError, "reward must be a float"),
    ({"reward": "0.5"}, TypeError, "reward must be a float"),
    ({"metrics": {"a": math.nan}}, ValueError, "metrics values must be a finite"),
    ({"metrics": {"a": False}}, TypeError, "metrics values must be a float"),
    ({"metrics": {f"k{i}": 0.0 for i in range(17)}}, ValueError, "at most 16"),
    ({"metrics": {"": 1.0}}, ValueError, "metrics key"),
    ({"metrics": {"Latency": 1.0}}, ValueError, "metrics key"),
    ({"metrics": {"9lives": 1.0}}, ValueError, "metrics key"),
    ({"metrics": {"_a": 1.0}}, ValueError, "metrics key"),
    ({"metrics": {"a-b": 1.0}}, ValueError, "metrics key"),
    ({"metrics": {"a\n": 1.0}}, ValueError, "metrics key"),
    ({"metrics": {"é": 1.0}}, ValueError, "metrics key"),
    ({"metrics": {"a" * 64: 1.0}}, ValueError, "metrics key"),
    ({"metrics": {1: 1.0}}, ValueError, "metrics key"),
    ({"metrics": [("a", 1.0)]}, TypeError, "metrics must be a mapping"),
    ({"observed_at": -1}, ValueError, "before the Unix epoch"),
    ({"observed_at": 1 << 64}, ValueError, "u64"),
    ({"observed_at": True}, TypeError, "observed_at must be"),
    ({"observed_at": 1.7e12}, TypeError, "observed_at must be"),
    ({"observed_at": datetime(2023, 1, 1)}, ValueError, "timezone-aware"),
    (
        {"observed_at": datetime(1969, 12, 31, 23, 59, 59, tzinfo=timezone.utc)},
        ValueError,
        "before the Unix epoch",
    ),
]


@BOTH
@pytest.mark.parametrize("kw,exc,match", _BAD, ids=[repr(b[0])[:60] for b in _BAD])
def test_an_invalid_value_is_refused_before_any_rpc(
    which: int, kw: dict, exc: type, match: str
) -> None:
    seen: list = []
    with pytest.raises(exc, match=match):
        _report(_clients(seen)[which], **kw)
    assert seen == [], "an invalid outcome field must never reach the wire"


@BOTH
def test_the_key_is_checked_first(which: int) -> None:
    """The runtime's order is key → gate → values; an invalid key wins over an invalid reward."""
    seen: list = []
    with pytest.raises(ValueError, match="idempotency_key"):
        _run(
            _clients(seen)[which].report_outcome(
                "d", True, idempotency_key="", reward=math.nan
            )
        )
    assert seen == []


@BOTH
def test_the_new_arguments_are_keyword_only(which: int) -> None:
    with pytest.raises(TypeError):
        _run(_clients([])[which].report_outcome("d", True, "qa", "k", 0.5))  # type: ignore[misc]


# ── server_wire_features ─────────────────────────────────────────────────────────────────────────


class _Trust:
    def __init__(self, seen: list, features: list[str]):
        self._seen, self._features = seen, features

    def ServerInfo(self, req, **kw):
        self._seen.append((req, kw))
        return pb.ServerInfoResponse(
            runtime_version="0.73.0", wire_features=self._features
        )


class _AioTrust(_Trust):
    async def ServerInfo(self, req, **kw):  # type: ignore[override]
        return _Trust.ServerInfo(self, req, **kw)


def _trust_clients(seen: list, features: list[str]):
    sync = object.__new__(SeamClient)
    sync._trust = _Trust(seen, features)
    aio = object.__new__(AioSeamClient)
    aio._trust = _AioTrust(seen, features)
    return sync, aio


@BOTH
def test_server_wire_features_returns_the_list(which: int) -> None:
    seen: list = []
    feats = [
        seam_sdk.WIRE_FEATURE_ENROLL_KIND,
        seam_sdk.WIRE_FEATURE_OUTCOME_OBSERVED_AT,
        seam_sdk.WIRE_FEATURE_OUTCOME_REWARD_METRICS,
    ]
    got = _run(_trust_clients(seen, feats)[which].server_wire_features(timeout=3.0))
    assert got == ("enroll.kind", "outcome.observed_at", "outcome.reward_metrics")
    assert isinstance(got, tuple)
    ((req, kw),) = seen
    assert isinstance(req, pb.Empty) and kw == {"timeout": 3.0}


@BOTH
def test_server_wire_features_is_empty_on_a_runtime_that_lists_none(which: int) -> None:
    assert _run(_trust_clients([], [])[which].server_wire_features()) == ()


def test_the_feature_names_are_the_runtimes_vocabulary() -> None:
    # seam-runtime docs/specs/wire-features.md — a name is never reused or renamed.
    assert seam_sdk.WIRE_FEATURE_ENROLL_KIND == "enroll.kind"
    assert seam_sdk.WIRE_FEATURE_OUTCOME_OBSERVED_AT == "outcome.observed_at"
    assert seam_sdk.WIRE_FEATURE_OUTCOME_REWARD_METRICS == "outcome.reward_metrics"
    assert seam_sdk.OUTCOME_METRICS_MAX == 16
