"""Unit tests for the session budget DTOs — the DTO↔pb mapping + absent-field semantics.

No server required; the live open→propose→vote→commit + the 6.2 suspend/resume loop are in
``test_integration.py`` (env-gated).
"""

import inspect

from seam_sdk import BudgetLimits, SeamClient, StepUsage
from seam_sdk import aio
from seam_sdk.admin import SeamAdminClient


def test_budget_limits_maps_only_set_dimensions():
    pb = BudgetLimits(tokens=1000, wall_ms=60_000).to_pb()
    assert pb.tokens == 1000
    assert pb.wall_ms == 60_000
    # Unset dimensions are ABSENT (proto3 optional), so the server reads them as "unlimited".
    assert not pb.HasField("messages")
    assert not pb.HasField("cost_micros")
    assert not pb.HasField("soft_pct")


def test_budget_limits_all_dimensions():
    pb = BudgetLimits(
        messages=10, tokens=2000, cost_micros=500, wall_ms=90_000, soft_pct=75
    ).to_pb()
    assert (pb.messages, pb.tokens, pb.cost_micros, pb.wall_ms, pb.soft_pct) == (
        10,
        2000,
        500,
        90_000,
        75,
    )


def test_budget_limits_empty_is_all_unlimited():
    pb = BudgetLimits().to_pb()
    for field in ("messages", "tokens", "cost_micros", "wall_ms", "soft_pct"):
        assert not pb.HasField(field)


def test_step_usage_defaults_to_zero():
    assert StepUsage().to_pb().tokens == 0
    pb = StepUsage(tokens=1000, cost_micros=40).to_pb()
    assert pb.tokens == 1000 and pb.cost_micros == 40


def test_every_budget_default_is_zero_meaning_server_default():
    """The proto's semantics: 0 ⇒ the server default (currently 32). A client that bakes in 32
    silently pins today's server default forever; sending 0 keeps the server the owner of the
    number. Pinned across every entry point that carries a ``budget``."""
    entry_points = [
        SeamClient.open_session,
        SeamClient.resume_session,
        aio.SeamClient.open_session,
        aio.SeamClient.resume_session,
        SeamAdminClient.resume_session,
    ]
    for method in entry_points:
        default = inspect.signature(method).parameters["budget"].default
        assert default == 0, f"{method.__qualname__} budget default is {default}, not 0"


def test_client_exposes_the_full_session_lifecycle():
    for method in (
        "open_session",
        "submit_proposal",
        "submit_vote",
        "submit_commit",
        "resume_session",
        "cancel_session",
        "expire_session",
        "session_status",
    ):
        assert callable(getattr(SeamClient, method)), method
