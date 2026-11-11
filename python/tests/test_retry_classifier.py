"""Opt-in classifiers: wire details, bounded recovery, and fresh SDK admission."""

import asyncio

import grpc
import pytest

from seam_sdk import (
    NOT_GOVERNED_REASON,
    Agent,
    RetryDecision,
    is_not_governed,
    load_shed_retry_classifier,
    with_session_retry,
    with_session_retry_async,
)
from seam_sdk.errors import (
    InvalidArgumentError,
    ResourceExhaustedError,
    UnavailableError,
)
from test_error_details import KEY, error_info, retry_info, status
from test_credential_refresh import _Harness, _Wire
from test_credential_wiring import CRED_SEED


def refusal(cls, code, reason, *, delay=2, **metadata):
    return cls(
        code,
        "namespace is not governed (similar message)",
        (
            (
                KEY,
                status(
                    code.value[0], error_info(reason, **metadata), retry_info(delay)
                ),
            ),
        ),
    )


def quota():
    return refusal(
        ResourceExhaustedError, grpc.StatusCode.RESOURCE_EXHAUSTED, "QUOTA_EXCEEDED"
    )


def challenge():
    return refusal(UnavailableError, grpc.StatusCode.UNAVAILABLE, "CHALLENGE_REFUSED")


@pytest.mark.parametrize(
    "reason,cause,expected",
    [
        (NOT_GOVERNED_REASON, "other", True),
        ("COORDINATION", NOT_GOVERNED_REASON, True),
        ("COORDINATION", "other", False),
        ("OTHER", NOT_GOVERNED_REASON, False),
        ("namespace_not_governed_similar", "", False),
    ],
)
def test_not_governed_reason_then_cause(reason, cause, expected):
    err = refusal(
        InvalidArgumentError, grpc.StatusCode.INVALID_ARGUMENT, reason, cause=cause
    )
    before = err.details()
    assert is_not_governed(err) is expected
    assert err.code() == grpc.StatusCode.INVALID_ARGUMENT and err.details() == before
    assert not is_not_governed(ValueError(before))
    assert not is_not_governed(
        refusal(UnavailableError, grpc.StatusCode.UNAVAILABLE, reason, cause=cause)
    )


@pytest.mark.parametrize("aio", [False, True])
@pytest.mark.parametrize("kind", ["quota", "challenge", "other", "custom"])
def test_classifier_sync_async(aio, kind):
    err = (
        quota()
        if kind == "quota"
        else challenge()
        if kind == "challenge"
        else ValueError("stop")
    )
    events = []
    attempts = 0

    def call():
        nonlocal attempts
        attempts += 1
        events.append("call")
        if attempts == 1:
            raise err
        return "ok"

    def refresh():
        events.append("fresh challenge")

    def sleep(delay):
        events.append(delay)

    classifier = (
        (lambda e: RetryDecision(3)) if kind == "custom" else load_shed_retry_classifier
    )
    opts = dict(
        classifier=classifier, rng=lambda: 0, refresh_challenge=refresh, sleep=sleep
    )
    if aio:

        async def acall():
            return call()

        async def arefresh():
            refresh()

        async def asleep(delay):
            sleep(delay)

        opts.update(refresh_challenge=arefresh, sleep=asleep)

        def run():
            return asyncio.run(with_session_retry_async(acall, **opts))
    else:

        def run():
            return with_session_retry(call, **opts)

    if kind == "other":
        with pytest.raises(ValueError) as caught:
            run()
        assert caught.value is err and events == ["call"]
    else:
        assert run() == "ok"
        assert events == ["call", 3 if kind == "custom" else 2] + (
            ["fresh challenge"] if kind == "challenge" else []
        ) + ["call"]


@pytest.mark.parametrize("aio", [False, True])
@pytest.mark.parametrize(
    "mode",
    ["success", "twice", "refresh-fails", "no-hook", "budget", "attempts", "default"],
)
def test_challenge_recovery_uses_real_client_admission(aio, mode):
    h = _Harness(aio)
    wire = _Wire()
    agent = Agent(CRED_SEED)
    client = h.client(wire)
    err = challenge()
    attempts = 0
    events = []

    def call():
        nonlocal attempts
        attempts += 1
        events.append("call")
        if attempts == 1 or mode == "twice":
            raise err
        assert wire.admits == 1
        return "ok"

    def refresh():
        events.append("refresh")
        return client.admit(agent)

    if mode == "refresh-fails":
        wire.errors["IssueChallenge"] = err
    opts = dict(classifier=load_shed_retry_classifier, rng=lambda: 0)
    if mode == "budget":
        opts["budget_s"] = 1
    if mode == "attempts":
        opts["max_attempts"] = 1
    if mode == "default":
        opts.pop("classifier")
    try:
        if aio:

            async def acall():
                return call()

            async def asleep(delay):
                events.append(delay)

            opts["sleep"] = asleep
            if mode != "no-hook":
                opts["refresh_challenge"] = refresh

            def run():
                return h.run(with_session_retry_async(acall, **opts))
        else:
            opts["sleep"] = events.append
            if mode != "no-hook":
                opts["refresh_challenge"] = refresh

            def run():
                return with_session_retry(call, **opts)

        if mode == "success":
            assert run() == "ok"
        else:
            with pytest.raises(UnavailableError) as caught:
                run()
            assert caught.value is err
        if mode in ("success", "twice"):
            assert events == ["call", 2, "refresh", "call"]
            assert [c[0] for c in wire.calls] == ["IssueChallenge", "Admit"]
        elif mode == "refresh-fails":
            assert events == ["call", 2, "refresh"]
            assert [c[0] for c in wire.calls] == ["IssueChallenge"]
        else:
            assert events == ["call"] and not wire.calls
    finally:
        h.close()


def test_default_does_not_retry_quota_and_bad_delay_is_rejected():
    err = quota()

    def call():
        raise err

    with pytest.raises(ResourceExhaustedError) as caught:
        with_session_retry(call)
    assert caught.value is err
    for delay in [-1, float("inf"), float("nan")]:
        with pytest.raises(ValueError, match="finite and non-negative"):
            with_session_retry(call, classifier=lambda e: RetryDecision(delay))


def test_classifier_requires_correct_status_and_reason():
    for err in [
        refusal(UnavailableError, grpc.StatusCode.UNAVAILABLE, "QUOTA_EXCEEDED"),
        refusal(
            ResourceExhaustedError,
            grpc.StatusCode.RESOURCE_EXHAUSTED,
            "CHALLENGE_REFUSED",
        ),
        refusal(ResourceExhaustedError, grpc.StatusCode.RESOURCE_EXHAUSTED, "other"),
    ]:
        assert load_shed_retry_classifier(err) is None


@pytest.mark.parametrize("aio", [False, True])
def test_cold_sdk_call_recovers_refused_challenge_before_reporting(aio):
    h = _Harness(aio)
    wire = _Wire()
    agent = Agent(CRED_SEED)
    client = h.client(wire)
    original = wire.handle
    challenges = 0

    def handle(name, req, kw):
        nonlocal challenges
        if name == "IssueChallenge":
            challenges += 1
            if challenges == 1:
                raise challenge()
        return original(name, req, kw)

    wire.handle = handle
    opts = dict(
        classifier=load_shed_retry_classifier,
        refresh_challenge=lambda: client.admit(agent),
        rng=lambda: 0,
    )

    def report():
        return client.report_outcome(
            "decision-fixture", True, idempotency_key="report-fixture", credential=agent
        )

    try:
        if aio:

            async def sleep(_delay):
                pass

            result = h.run(with_session_retry_async(report, sleep=sleep, **opts))
        else:
            result = with_session_retry(report, sleep=lambda _: None, **opts)
        assert result is True
        assert challenges == 2
        assert [c[0] for c in wire.calls] == [
            "IssueChallenge",
            "Admit",
            "ReportOutcome",
        ]
    finally:
        h.close()


def test_not_governed_does_not_infer_a_reason_from_the_message():
    err = InvalidArgumentError(
        grpc.StatusCode.INVALID_ARGUMENT, "namespace is not governed for this tenant"
    )
    assert not is_not_governed(err)


@pytest.mark.parametrize(
    "cls,code,reason,fresh",
    [
        (UnavailableError, grpc.StatusCode.UNAVAILABLE, "SESSION_UNAVAILABLE", False),
        (
            ResourceExhaustedError,
            grpc.StatusCode.RESOURCE_EXHAUSTED,
            "QUOTA_EXCEEDED",
            False,
        ),
        (UnavailableError, grpc.StatusCode.UNAVAILABLE, "CHALLENGE_REFUSED", True),
    ],
)
def test_builtin_classifier_clamps_negative_server_delays(cls, code, reason, fresh):
    err = refusal(cls, code, reason, delay=-1)
    assert err.retry_after == -1
    assert load_shed_retry_classifier(err) == RetryDecision(0, fresh_challenge=fresh)
