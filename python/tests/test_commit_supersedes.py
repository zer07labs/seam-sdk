"""`CommitRequest.supersedes` (#141): `submit_commit`'s write-side override hint.

`supersedes` is EXPLICIT PRESENCE on the wire (proto `optional string`). Omitting it is absence —
`submit_commit` must never collapse "no override" into `""`, mirroring how `submit_evaluation`
already treats `confidence`/`rationale_ref`. No network: `_coord` is swapped for a recorder that
captures the exact request object a wrapper method passed on, same harness as
`test_credential_wiring.py`.
"""

from __future__ import annotations

import asyncio

from seam_sdk import SeamClient
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.aio import SeamClient as AioSeamClient


class _Recorder:
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


def test_submit_commit_omits_supersedes_when_absent_and_sends_it_when_given() -> None:
    seen: dict = {}
    client = SeamClient.connect("127.0.0.1:1")  # lazy channel, never dialed
    client._coord = _Recorder(seen)

    client.submit_commit("s", "c-1", "approve")
    req, _ = seen["SubmitCommit"]
    assert not req.HasField("supersedes"), (
        "supersedes must be absent, not an empty string"
    )

    client.submit_commit("s", "c-2", "approve", supersedes="c-1")
    req, _ = seen["SubmitCommit"]
    assert req.HasField("supersedes")
    assert req.supersedes == "c-1"


def test_async_submit_commit_omits_supersedes_when_absent_and_sends_it_when_given() -> (
    None
):
    async def scenario() -> None:
        seen: dict = {}
        client = AioSeamClient.connect("127.0.0.1:1")  # lazy channel, never dialed
        client._coord = _AioRecorder(seen)

        await client.submit_commit("s", "c-1", "approve")
        req, _ = seen["SubmitCommit"]
        assert not req.HasField("supersedes")

        await client.submit_commit("s", "c-2", "approve", supersedes="c-1")
        req, _ = seen["SubmitCommit"]
        assert req.HasField("supersedes")
        assert req.supersedes == "c-1"
        await client.close()

    asyncio.run(scenario())
