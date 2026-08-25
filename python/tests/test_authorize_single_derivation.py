"""One `authorize` call canonicalizes its input exactly once — including across the retry.

THE DEFECT THIS PINS
--------------------
`seam-sdk#60 <https://github.com/zer07labs/seam-sdk/issues/60>`_ is about a caller and the SDK each
canonicalizing the same object. Reading the code to fix that turned up a second derivation *inside*
the SDK, which no caller discipline could have prevented:

``authorize`` builds its request through a closure, and calls that closure **twice** when a stale
ticket comes back ``UNAUTHENTICATED`` — once before the refresh, once after. Each call re-derived the
canonical bytes from the caller's object. A ``tool_input`` mutated during the admit round trip
therefore got a *different* digest on the retry than on the first attempt. The retried request is
internally consistent — digest, bytes and ``call_sig`` all re-derived together — so the runtime
accepts it without complaint. The SDK simply authorized different input than it first asked about,
and than whatever the caller recorded before the call.

``ts/src/client.ts`` has always hoisted its canonicalization out of the equivalent closure. This was
a Python-vs-TypeScript divergence in a signed-digest path, not a design difference.

The mutation here is driven by the *server*, on the rejection that triggers the retry, rather than by
a background thread. That places it exactly in the window that matters and makes the test
deterministic; a real race would prove the same thing intermittently.

Run: `python -m pytest python/tests/test_authorize_single_derivation.py -q`
"""

from __future__ import annotations

import asyncio

import pytest
from test_authorize import SEED, FakeSeam, fake_server  # noqa: F401 — fixture is used by name

import seam_sdk._authorize as _authorize
from seam_sdk import Agent, CanonicalizationError, SeamClient
from seam_sdk._authorize import build_authorize_request, canonicalize_tool_input
from seam_sdk.aio import SeamClient as AioSeamClient
from seam_sdk.crypto import jcs_canonicalize

_ARGS = dict(ticket=b"tkt", agent_seed=bytes(range(32)), tool_name="read_file")


class RecordingSeam(FakeSeam):
    """`FakeSeam`, but it keeps every request rather than only the last, and can run a hook.

    Keeping every request is the whole point: the bug is a *difference between two attempts*, and a
    servicer that remembers only `last_request` cannot express it.
    """

    def __init__(self) -> None:
        super().__init__()
        self.requests: list = []
        self.on_authorize = None

    def Authorize(self, request, context):  # noqa: N802
        self.requests.append(request)
        if self.on_authorize is not None:
            self.on_authorize(len(self.requests))
        return super().Authorize(request, context)


@pytest.fixture
def recording_server():
    from concurrent import futures

    import grpc

    from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    servicer = RecordingSeam()
    rpc.add_SeamAdmissionServicer_to_server(servicer, server)
    rpc.add_SeamAuthorizationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


def _mutating(servicer: RecordingSeam) -> dict:
    """A tool_input the server rewrites the moment it rejects the first attempt."""
    victim = {"path": "/tmp/harmless"}
    servicer.fail_next_unauthenticated = 1

    def hook(n: int) -> None:
        if n == 1:
            victim["path"] = "/etc/shadow"

    servicer.on_authorize = hook
    return victim


def _assert_retry_signed_one_input(servicer: RecordingSeam) -> None:
    assert len(servicer.requests) == 2, (
        f"expected one rejection and one retry, saw {len(servicer.requests)} Authorize calls — "
        "the scenario did not exercise the retry path, so it proved nothing"
    )
    first, second = servicer.requests
    assert first.tool_input_digest == second.tool_input_digest, (
        "the retry carried a DIFFERENT digest than the first attempt — the SDK re-derived the "
        "canonical bytes from a tool_input that changed during the admit RTT, and signed and sent "
        "the new one (seam-sdk#60)"
    )
    assert first.tool_input == second.tool_input
    assert first.call_sig != second.call_sig, (
        "call_sig MUST be re-signed on the retry — it binds the ticket bytes, which changed. If "
        "these are equal the hoist went too far and took the signature with it."
    )


# ── the retry path derives once ──────────────────────────────────────────────────────────────────


def test_sync_retry_signs_one_input_not_two(recording_server) -> None:
    servicer, addr = recording_server
    victim = _mutating(servicer)
    SeamClient.connect(addr).authorize(Agent(SEED), "read_file", victim)
    assert victim["path"] == "/etc/shadow", "the scenario's own mutation did not happen"
    _assert_retry_signed_one_input(servicer)


def test_aio_retry_signs_one_input_not_two(recording_server) -> None:
    servicer, addr = recording_server
    victim = _mutating(servicer)

    async def scenario() -> None:
        async with AioSeamClient.connect(addr) as client:
            await client.authorize(Agent(SEED), "read_file", victim)

    asyncio.run(scenario())
    _assert_retry_signed_one_input(servicer)


@pytest.mark.parametrize("flavour", ["sync", "aio"])
def test_canonicalization_happens_exactly_once_across_a_retry(
    recording_server, monkeypatch, flavour
) -> None:
    """The digest test above proves the *observable* symptom is gone. This proves the mechanism:
    a fix that canonicalized twice but happened to agree would pass that test and fail this one."""
    servicer, addr = recording_server
    calls = []
    real = jcs_canonicalize

    def counting(obj):
        calls.append(obj)
        return real(obj)

    monkeypatch.setattr(_authorize, "jcs_canonicalize", counting)
    servicer.fail_next_unauthenticated = 1

    if flavour == "sync":
        SeamClient.connect(addr).authorize(Agent(SEED), "read_file", {"path": "/tmp/x"})
    else:

        async def scenario() -> None:
            async with AioSeamClient.connect(addr) as client:
                await client.authorize(Agent(SEED), "read_file", {"path": "/tmp/x"})

        asyncio.run(scenario())

    assert len(servicer.requests) == 2, "the retry path was not exercised"
    assert len(calls) == 1, (
        f"canonicalized {len(calls)} times for one authorize call; the closure is re-deriving on "
        f"the retry"
    )


def test_uncanonicalizable_input_costs_no_round_trip(recording_server) -> None:
    """Canonicalizing before the admit is a deliberate ordering, so it is asserted rather than left
    as an accident of where the line was placed."""
    servicer, addr = recording_server
    with pytest.raises(CanonicalizationError):
        SeamClient.connect(addr).authorize(Agent(SEED), "read_file", object())
    assert servicer.admits == 0 and servicer.authorizes == 0


# ── the `canonical=` parameter the hoist rides on ────────────────────────────────────────────────


def test_canonical_bytes_produce_an_identical_request() -> None:
    """If these ever diverge, `canonical=` is a second implementation of canonicalization rather
    than a way to avoid one — the exact thing it exists to prevent."""
    tool_input = {"zeta": 1, "alpha": [True, None, "x"], "n": 2.5}
    from_object = build_authorize_request(tool_input=tool_input, **_ARGS)
    from_bytes = build_authorize_request(
        canonical=canonicalize_tool_input(tool_input), **_ARGS
    )
    assert from_object.SerializeToString(
        deterministic=True
    ) == from_bytes.SerializeToString(deterministic=True)


def test_digest_only_still_withholds_the_bytes_when_canonical_is_given() -> None:
    req = build_authorize_request(
        canonical=jcs_canonicalize({"k": "v"}), digest_only=True, **_ARGS
    )
    assert req.tool_input == b""
    assert req.tool_input_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("kwargs", "why"),
    [
        pytest.param(
            dict(tool_input={"a": 1}, canonical=b'{"a":1}'),
            "both",
            id="both-is-an-error-not-a-precedence-rule",
        ),
        pytest.param(dict(canonical='{"a":1}'), "str", id="str-not-silently-encoded"),
        pytest.param(dict(canonical=b""), "empty", id="empty-bytes"),
        pytest.param(
            dict(canonical=bytearray(b'{"a":1}')),
            "mutable",
            id="bytearray-could-change-after-digest",
        ),
    ],
)
def test_canonical_is_validated_without_re_deriving(kwargs, why) -> None:
    with pytest.raises(CanonicalizationError):
        build_authorize_request(**kwargs, **_ARGS)


def test_explicit_none_tool_input_is_not_treated_as_supplied() -> None:
    """`tool_input=None` is the default, not a supplied input, so pairing it with `canonical=` must
    not trip the mutual-exclusion check."""
    req = build_authorize_request(
        tool_input=None, canonical=jcs_canonicalize({"a": 1}), **_ARGS
    )
    assert req.tool_input == b'{"a":1}'


# ── the public surface: a caller can own the derivation outright ─────────────────────────────────


@pytest.mark.parametrize("flavour", ["sync", "aio"])
def test_client_canonical_derives_nothing_at_all(
    recording_server, monkeypatch, flavour
) -> None:
    """The end state #60 actually asked for: with the caller supplying the bytes, the SDK does not
    canonicalize even once — so there is no second derivation left to disagree with the first."""
    servicer, addr = recording_server
    calls = []
    real = jcs_canonicalize
    monkeypatch.setattr(
        _authorize, "jcs_canonicalize", lambda o: (calls.append(o), real(o))[1]
    )

    tool_input = {"path": "/tmp/x", "n": 2.5}
    canonical = real(tool_input)  # derived by the CALLER, outside the counter
    calls.clear()
    servicer.fail_next_unauthenticated = 1  # and it survives the retry too

    if flavour == "sync":
        SeamClient.connect(addr).authorize(
            Agent(SEED), "read_file", canonical=canonical
        )
    else:

        async def scenario() -> None:
            async with AioSeamClient.connect(addr) as client:
                await client.authorize(Agent(SEED), "read_file", canonical=canonical)

        asyncio.run(scenario())

    assert len(servicer.requests) == 2, "the retry path was not exercised"
    assert calls == [], (
        f"the SDK canonicalized {len(calls)} time(s) despite being handed the bytes"
    )
    assert servicer.requests[0].tool_input == canonical


@pytest.mark.parametrize("flavour", ["sync", "aio"])
def test_client_canonical_matches_passing_the_object(recording_server, flavour) -> None:
    servicer, addr = recording_server
    tool_input = {"zeta": 1, "alpha": [True, None, "x"], "n": 2.5}

    if flavour == "sync":
        client = SeamClient.connect(addr)
        client.authorize(Agent(SEED), "wire_transfer", tool_input)
        client.authorize(
            Agent(SEED), "wire_transfer", canonical=jcs_canonicalize(tool_input)
        )
    else:

        async def scenario() -> None:
            async with AioSeamClient.connect(addr) as client:
                await client.authorize(Agent(SEED), "wire_transfer", tool_input)
                await client.authorize(
                    Agent(SEED), "wire_transfer", canonical=jcs_canonicalize(tool_input)
                )

        asyncio.run(scenario())

    by_object, by_bytes = servicer.requests
    assert by_object.tool_input_digest == by_bytes.tool_input_digest
    assert by_object.tool_input == by_bytes.tool_input
    assert (
        by_object.call_sig == by_bytes.call_sig
    )  # same ticket, same digest, same signature


@pytest.mark.parametrize("flavour", ["sync", "aio"])
def test_client_rejects_both_at_once(recording_server, flavour) -> None:
    """Mutual exclusion has to hold at the layer a consumer actually calls, not only in the builder
    underneath it — otherwise the guard exists but nothing reaches it."""
    _servicer, addr = recording_server
    if flavour == "sync":
        with pytest.raises(CanonicalizationError):
            SeamClient.connect(addr).authorize(
                Agent(SEED), "t", {"a": 1}, canonical=b'{"a":1}'
            )
    else:

        async def scenario() -> None:
            async with AioSeamClient.connect(addr) as client:
                with pytest.raises(CanonicalizationError):
                    await client.authorize(
                        Agent(SEED), "t", {"a": 1}, canonical=b'{"a":1}'
                    )

        asyncio.run(scenario())
