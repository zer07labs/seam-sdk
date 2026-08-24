"""The sync client and its async mirror must expose the same verbs.

`client.SeamClient` and `aio.SeamClient` are two hand-written transports over one contract. Every
verb has to be added to both, by hand, every time — and a verb that lands on one and not the other
is this package's standing drift hazard: the async caller gets an `AttributeError` at runtime, on a
call path the sync tests all cover.

This asserts the two inventories are equal **as sets**, which a spot-check per new verb is not: a
spot-check proves the verb you remembered is present, and the failure mode is the one you forgot.
"""

from __future__ import annotations

import inspect

from seam_sdk import aio, client


def _public_methods(cls: type) -> set[str]:
    return {
        name
        for name, member in inspect.getmembers(cls)
        if not name.startswith("_")
        and (inspect.isfunction(member) or inspect.iscoroutinefunction(member))
    }


def test_sync_and_async_clients_expose_the_same_verbs() -> None:
    sync_only = _public_methods(client.SeamClient) - _public_methods(aio.SeamClient)
    async_only = _public_methods(aio.SeamClient) - _public_methods(client.SeamClient)

    assert not sync_only, (
        f"verbs on the sync client with no async mirror: {sorted(sync_only)} — "
        "add them to python/seam_sdk/aio.py"
    )
    assert not async_only, (
        f"verbs on the async client with no sync twin: {sorted(async_only)} — "
        "add them to python/seam_sdk/client.py"
    )


def test_the_quorum_verbs_are_present_on_both() -> None:
    # Named explicitly as well as covered by the set equality above: these two landed together with
    # the batched regeneration, and the set test alone would pass if BOTH were forgotten.
    for verb in ("submit_approval_request", "submit_ballot"):
        assert hasattr(client.SeamClient, verb), f"sync client is missing {verb}"
        assert hasattr(aio.SeamClient, verb), f"async client is missing {verb}"

    assert inspect.iscoroutinefunction(aio.SeamClient.submit_approval_request)
    assert inspect.iscoroutinefunction(aio.SeamClient.submit_ballot)


def test_the_two_clients_agree_on_each_verbs_signature() -> None:
    """Same names is not enough — same *arguments*, modulo `async`.

    A parameter added to one side only is the same drift with a longer fuse: it type-checks on the
    sync path and raises `TypeError` on the async one, for callers who pass it.
    """
    mismatches = []
    for name in sorted(_public_methods(client.SeamClient) & _public_methods(aio.SeamClient)):
        sync_sig = inspect.signature(getattr(client.SeamClient, name))
        async_sig = inspect.signature(getattr(aio.SeamClient, name))
        if list(sync_sig.parameters) != list(async_sig.parameters):
            mismatches.append(f"{name}: sync{sync_sig} != async{async_sig}")

    assert not mismatches, "sync/async signature drift:\n  " + "\n  ".join(mismatches)
