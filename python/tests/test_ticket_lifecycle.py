"""The admission-ticket cache: direct unit tests, and the refresh-stampede regression.

Two things live here that did not before.

**The stampede.** N concurrent callers hitting ``UNAUTHENTICATED`` produced N re-admits. Cold start
always coalesced correctly — they all find an empty cache and the first one fills it — which is why
the existing suite, which tests cold start, stayed green over a real bug. The refresh path had the
opposite shape: each caller invalidated the ticket the previous one had just minted, so every caller
admitted for itself. The condition that triggers it is a **mass revocation**, i.e. exactly when the
admission endpoint is already the most loaded thing in the system.

**The cache itself.** ``TicketCache`` takes injected time specifically so tests need not sleep, and
nothing exercised it directly — its behaviour was inferred through a client, through a fake server,
through a real 180 ms ``time.sleep``. A wall-clock sleep is not a test of TTL arithmetic; it is a
test of whether the machine was busy. These drive the arithmetic at its exact boundaries.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent import futures

import grpc
import pytest

from seam_sdk import Agent, SeamClient
from seam_sdk._authorize import TicketCache
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.aio import SeamClient as AioSeamClient

from test_authorize import SEED, FakeSeam

CONCURRENCY = 8


@pytest.fixture
def busy_server():
    """The fake server with enough worker threads to actually run CONCURRENCY calls at once.

    The default fixture's pool would serialize them, and a serialized stampede is not a stampede —
    the test would pass against the unfixed client.
    """
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=CONCURRENCY * 4))
    servicer = FakeSeam()
    rpc.add_SeamAdmissionServicer_to_server(servicer, server)
    rpc.add_SeamAuthorizationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


# ── The stampede ─────────────────────────────────────────────────────────────────────────────────


def test_cold_start_coalesces_to_one_admit(busy_server):
    """The half that already worked. Kept explicit so a future change cannot fix the refresh path
    by breaking this one — and so the contrast with the test below is visible in the file."""
    servicer, addr = busy_server
    with SeamClient.connect(addr) as client:
        agent = Agent(SEED)
        gate = threading.Barrier(CONCURRENCY)

        def call(_):
            gate.wait()  # every caller starts with an EMPTY cache, simultaneously
            return client.authorize(agent, "t", {"k": 1})

        with futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            results = list(pool.map(call, range(CONCURRENCY)))

    assert all(r.allowed for r in results)
    assert servicer.admits == 1, (
        f"{CONCURRENCY} concurrent cold-start callers caused {servicer.admits} admits"
    )


def test_mass_revocation_produces_exactly_one_readmit_sync(busy_server):
    """The regression. Before the fix this was ``CONCURRENCY`` re-admits, not one.

    Every in-flight call is rejected at once, which is what a revocation does. Each caller then has
    to decide whether to re-admit; the fix is that it re-checks the cache under the lock and only
    pays for the round trip if the ticket it failed on is still the cached one.
    """
    servicer, addr = busy_server
    with SeamClient.connect(addr) as client:
        agent = Agent(SEED)
        client.authorize(agent, "t", {})  # warm the cache: one shared, valid ticket
        assert servicer.admits == 1

        servicer.fail_next_unauthenticated = CONCURRENCY
        gate = threading.Barrier(CONCURRENCY)

        def call(_):
            gate.wait()
            return client.authorize(agent, "t", {"k": 2})

        with futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            results = list(pool.map(call, range(CONCURRENCY)))

    assert all(r.allowed for r in results), "every caller must still get its verdict"
    readmits = servicer.admits - 1
    assert readmits == 1, (
        f"{CONCURRENCY} callers rejected at once caused {readmits} re-admits; the refresh must "
        "coalesce to one, because a mass revocation is exactly when the admission endpoint is "
        "least able to absorb a fan-out"
    )


def test_mass_revocation_produces_exactly_one_readmit_aio(busy_server):
    """The async twin, and the one that matters more: an aio client is the one most likely to have
    hundreds of authorizes genuinely in flight together."""
    servicer, addr = busy_server

    async def scenario():
        async with AioSeamClient.connect(addr) as client:
            agent = Agent(SEED)
            await client.authorize(agent, "t", {})
            assert servicer.admits == 1

            servicer.fail_next_unauthenticated = CONCURRENCY
            results = await asyncio.gather(
                *(client.authorize(agent, "t", {"k": i}) for i in range(CONCURRENCY))
            )
            assert all(r.allowed for r in results)

    asyncio.run(scenario())
    readmits = servicer.admits - 1
    assert readmits == 1, (
        f"{CONCURRENCY} concurrent aio callers caused {readmits} re-admits"
    )


def test_a_caller_holding_a_stale_ticket_uses_the_refreshed_one(busy_server):
    """The mechanism, isolated from the concurrency that motivates it.

    A caller that failed on ticket A, arriving at the lock after someone else cached ticket B, must
    USE B rather than mint a third. Asserting this directly means the coalescing tests above are not
    the only thing standing between a regression and a green build — a scheduler that happened to
    serialize them would let a broken client pass both.
    """
    servicer, addr = busy_server
    with SeamClient.connect(addr) as client:
        agent = Agent(SEED)
        client.authorize(agent, "t", {})
        cache = client._tickets[agent.aid]
        already_refreshed = cache._ticket

        # Simulate the loser of the race: it failed on some OTHER, older ticket.
        refreshed = client._refresh_ticket(agent, b"tkt:an-older-one", timeout=2.0)

    assert refreshed == already_refreshed, "it must adopt the cached ticket"
    assert servicer.admits == 1, "and must not have admitted again"


def test_a_caller_holding_the_current_ticket_does_readmit(busy_server):
    """The other side of the same branch — without this, `_refresh_ticket` could simply never
    re-admit and the test above would still pass. A refresh that never refreshes is worse than a
    stampede: the caller retries with the ticket the server just rejected."""
    servicer, addr = busy_server
    with SeamClient.connect(addr) as client:
        agent = Agent(SEED)
        client.authorize(agent, "t", {})
        current = client._tickets[agent.aid]._ticket

        refreshed = client._refresh_ticket(agent, current, timeout=2.0)

    assert refreshed != current, "the failed ticket must be replaced, not returned"
    assert servicer.admits == 2


def test_one_identity_does_not_block_another_identitys_cached_ticket(busy_server):
    """Per-AID locking. One global lock meant a hung `Admit` for agent A held it for the whole
    timeout, so agent B could not even READ its own already-cached ticket."""
    servicer, addr = busy_server
    with SeamClient.connect(addr) as client:
        a, b = Agent(SEED), Agent(bytes(range(1, 33)))
        client.authorize(a, "t", {})
        client.authorize(b, "t", {})

        assert client._ticket_locks[a.aid] is not client._ticket_locks[b.aid]
        assert client._tickets[a.aid] is not client._tickets[b.aid]

        # B's lock is free while A's is held — the property the single lock did not have.
        client._ticket_locks[a.aid].acquire()
        try:
            assert client._ticket_locks[b.aid].acquire(timeout=0.5), (
                "agent B's ticket lock is blocked while agent A's is held — one slow identity "
                "would stall every other identity's hot path"
            )
            client._ticket_locks[b.aid].release()
        finally:
            client._ticket_locks[a.aid].release()


# ── TicketCache, directly, with injected time ────────────────────────────────────────────────────

TTL = 1000  # ms — the arithmetic is exact, so the numbers can be round


def _stored(now: int = 0, ttl: int = TTL, ticket: bytes = b"tkt:1") -> TicketCache:
    cache = TicketCache()
    cache.store(ticket, expires_at_ms=now + ttl, now_ms=now)
    return cache


def test_a_fresh_ticket_is_returned():
    assert _stored().get(0) == b"tkt:1"


def test_an_empty_cache_returns_none():
    assert TicketCache().get(0) is None


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (799, b"tkt:1"),  # just before the refresh point
        (800, None),  # AT it — stale, because `get` compares with <, not <=
        (801, None),  # past it
        (999, None),  # still before true expiry, but the client should have refreshed
        (10_000, None),  # long expired
    ],
)
def test_the_refresh_point_is_80_percent_of_ttl_exactly(now, expected):
    """The boundary, at the boundary. The value of refreshing at 80% is that the refresh lands
    BEFORE expiry rather than after a failed call, so the off-by-one here is the whole feature: at
    ``now == 800`` the ticket is still valid on the wire and must nonetheless be treated as stale."""
    assert _stored().get(now) == expected


def test_the_refresh_point_is_relative_to_the_time_of_storage():
    """A ticket admitted at t=5000 with a 1000 ms TTL goes stale at 5800, not at 800. Trivially
    true, and trivially broken by an implementation that stores an absolute 80%-of-expiry."""
    cache = _stored(now=5000)
    assert cache.get(5799) == b"tkt:1"
    assert cache.get(5800) is None


def test_an_already_expired_ticket_is_never_cached():
    """A server clock ahead of ours, or a ticket that spent its whole TTL in flight. Caching it
    would hand the next caller a ticket guaranteed to be rejected."""
    cache = TicketCache()
    cache.store(b"tkt:1", expires_at_ms=100, now_ms=100)  # zero TTL
    assert cache.get(100) is None
    cache.store(b"tkt:1", expires_at_ms=50, now_ms=100)  # negative TTL
    assert cache.get(100) is None


def test_an_empty_ticket_is_never_cached():
    """An empty ticket with a healthy TTL is a malformed server answer, not a usable credential."""
    cache = TicketCache()
    cache.store(b"", expires_at_ms=10_000, now_ms=0)
    assert cache.get(0) is None


def test_storing_over_a_live_ticket_replaces_it_and_resets_the_clock():
    cache = _stored(now=0)
    cache.store(b"tkt:2", expires_at_ms=5000 + TTL, now_ms=5000)
    assert cache.get(5000) == b"tkt:2"
    assert cache.get(5799) == b"tkt:2"
    assert cache.get(5800) is None


def test_invalidate_clears_both_the_ticket_and_the_refresh_point():
    cache = _stored()
    cache.invalidate()
    assert cache.get(0) is None
    # The refresh point must go too: a stale one left behind would make the NEXT stored ticket's
    # freshness depend on the previous ticket's clock.
    cache.store(b"tkt:2", expires_at_ms=TTL, now_ms=0)
    assert cache.get(799) == b"tkt:2"


def test_a_sub_millisecond_ttl_floors_to_immediately_stale():
    """Integer arithmetic: a 1 ms TTL gives a refresh point of ``now + (1*8)//10 == now``, so the
    ticket is stale the instant it is stored. That is the safe direction — the alternative is
    caching a credential that has already expired — but it is worth pinning, because it means a
    pathologically short TTL degrades to admit-per-call rather than to using a dead ticket."""
    cache = TicketCache()
    cache.store(b"tkt:1", expires_at_ms=1, now_ms=0)
    assert cache.get(0) is None
