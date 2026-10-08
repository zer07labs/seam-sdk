"""`ReportOutcome` carries a required, client-validated idempotency key (#209, seam-runtime #1154)."""

from __future__ import annotations

import asyncio

import pytest

from seam_sdk import SeamClient
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.aio import SeamClient as AioSeamClient


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


def _call(client, *args, **kw):
    out = client.report_outcome(*args, **kw)
    return asyncio.run(out) if asyncio.iscoroutine(out) else out


@pytest.mark.parametrize("which", [0, 1], ids=["sync", "aio"])
def test_the_key_rides_on_the_wire(which: int) -> None:
    seen: list = []
    client = _clients(seen)[which]
    assert _call(client, "d1", True, "qa", idempotency_key="review-77") is True
    (req,) = seen
    assert (req.decision_id, req.correct, req.verified_by, req.idempotency_key) == (
        "d1",
        True,
        "qa",
        "review-77",
    )


@pytest.mark.parametrize("which", [0, 1], ids=["sync", "aio"])
def test_the_key_is_required(which: int) -> None:
    """No default: a missing key must fail at the call site, not as a server INVALID_ARGUMENT, and a
    defaulted random key would make every retry a second report."""
    client = _clients([])[which]
    with pytest.raises(TypeError):
        _call(client, "d1", True)


@pytest.mark.parametrize("which", [0, 1], ids=["sync", "aio"])
@pytest.mark.parametrize(
    "key", ["", "x" * 129, "tab\there", "naïve", "line\n", "\x7f"], ids=repr
)
def test_an_invalid_key_is_refused_before_any_rpc(which: int, key: str) -> None:
    seen: list = []
    client = _clients(seen)[which]
    with pytest.raises(ValueError, match="idempotency_key"):
        _call(client, "d1", True, idempotency_key=key)
    assert seen == [], "an invalid key must never reach the wire"


@pytest.mark.parametrize("key", ["k", "x" * 128, " ~!review/77:retry-safe ~"], ids=repr)
def test_the_whole_printable_ascii_range_is_accepted(key: str) -> None:
    seen: list = []
    assert _call(_clients(seen)[0], "d1", False, idempotency_key=key) is True
    assert seen[0].idempotency_key == key
