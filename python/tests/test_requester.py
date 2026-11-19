"""RT4 (runtime 0.95.0, seam-runtime#1776): ``open_session(requester=...)``.

The accept/refuse cases are the runtime spec's own table (``docs/specs/session-open.md`` §Requester),
so a drift between this mirror and the runtime's Ring-0 rule shows up as a named case here.
"""

from __future__ import annotations

import asyncio

import pytest

from seam_sdk import (
    REQUESTER_ID_MAX_BYTES,
    REQUESTER_ID_MIN_BYTES,
    Agent,
    SeamClient,
    valid_requester_id,
)
from seam_sdk.aio import SeamClient as AioSeamClient
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

SEED = bytes(range(32))

ACCEPTED = [
    "p_a",  # the 3-byte minimum
    "p_" + "a" * (REQUESTER_ID_MAX_BYTES - 2),  # exactly 128 bytes
    "p_0123456789abcdefABCDEF",
    "p_x.y_z:w-v",  # every punctuation byte in the charset
]

REFUSED = [
    "",  # under 3 bytes
    "p_",  # `p_` alone
    "p_" + "a" * (REQUESTER_ID_MAX_BYTES - 1),  # 129 bytes
    "alice@example.com",  # raw email, no `p_`
    "p_alice@example.com",  # `@` outside the charset
    "google-oauth2|1048",  # raw IdP subject
    "auth0|5f7c",
    "0123abcd",  # no `p_`
    "P_abc",  # the prefix is case-sensitive
    "q_abc",
    "p_a b",  # whitespace
    "p_a\n",  # control character
    "p_é",  # non-ASCII
    "p_a/b",
    "p_a=b",
]


def test_the_bounds_are_the_runtime_spec():
    assert (REQUESTER_ID_MIN_BYTES, REQUESTER_ID_MAX_BYTES) == (3, 128)


@pytest.mark.parametrize("rid", ACCEPTED)
def test_accepted(rid):
    assert valid_requester_id(rid)


@pytest.mark.parametrize("rid", REFUSED)
def test_refused(rid):
    assert not valid_requester_id(rid)


@pytest.mark.parametrize("rid", [None, 7, b"p_abc"])
def test_a_non_string_is_refused_without_raising(rid):
    assert not valid_requester_id(rid)


def _sync_client(seen, presented):
    client = SeamClient.connect("127.0.0.1:1")  # lazy channel, never dialed

    class _Recorder:
        def __getattr__(self, name):
            def record(req, **_kw):
                seen[name] = req
                return pb.SessionStep(state="Open")

            return record

    def _presentation(agent, timeout=None):
        presented.append(1)
        return pb.PinnedPresentation()

    client._coord = _Recorder()
    client._presentation = _presentation  # type: ignore[method-assign]
    return client


def test_sync_open_session_sends_a_human_requester():
    seen, presented = {}, []
    client = _sync_client(seen, presented)
    client.open_session(Agent(SEED), "s", ["a"], requester="p_abc")
    req = seen["OpenSession"]
    assert req.HasField("requester")
    assert req.requester.kind == pb.REQUESTER_KIND_HUMAN
    assert req.requester.id == "p_abc"


def test_sync_open_session_without_a_requester_leaves_the_field_absent():
    seen, presented = {}, []
    client = _sync_client(seen, presented)
    client.open_session(Agent(SEED), "s", ["a"])
    assert not seen["OpenSession"].HasField("requester")


@pytest.mark.parametrize("rid", ["alice@example.com", "p_", "auth0|5f7c"])
def test_a_refused_id_raises_before_any_rpc_and_never_echoes_it(rid):
    seen, presented = {}, []
    client = _sync_client(seen, presented)
    with pytest.raises(ValueError) as exc:
        client.open_session(Agent(SEED), "s", ["a"], requester=rid)
    assert "OpenSession" not in seen
    assert presented == [], (
        "no presentation (no admit handshake) for a refused requester"
    )
    if rid != "p_":  # "p_" is a substring of the rule text itself
        assert rid not in str(exc.value)


def test_aio_open_session_sends_and_refuses_the_same():
    async def scenario():
        client = AioSeamClient.connect("127.0.0.1:1")
        seen, presented = {}, []

        class _Recorder:
            def __getattr__(self, name):
                async def record(req, **_kw):
                    seen[name] = req
                    return pb.SessionStep(state="Open")

                return record

        async def _presentation(agent, timeout=None):
            presented.append(1)
            return pb.PinnedPresentation()

        client._coord = _Recorder()
        client._presentation = _presentation  # type: ignore[method-assign]
        agent = Agent(SEED)

        await client.open_session(agent, "s", ["a"], requester="p_abc")
        assert seen["OpenSession"].requester.kind == pb.REQUESTER_KIND_HUMAN
        assert seen["OpenSession"].requester.id == "p_abc"

        await client.open_session(agent, "s2", ["a"])
        assert not seen["OpenSession"].HasField("requester")

        seen.clear()
        presented.clear()
        with pytest.raises(ValueError) as exc:
            await client.open_session(agent, "s3", ["a"], requester="alice@example.com")
        assert "OpenSession" not in seen and presented == []
        assert "alice@example.com" not in str(exc.value)
        await client.close()

    asyncio.run(scenario())
