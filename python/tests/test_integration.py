"""Live round-trip against a running Seam gRPC server — admit → decide → seal → read → verify.

Env-gated so the unit/conformance suite stays server-free:
  * ``SEAM_GRPC_ADDR``  — connect to an already-running server (e.g. ``127.0.0.1:8090``), or
  * ``SEAM_GRPC_BIN``   — path to a ``seam-grpc`` binary the test spawns on a free port.
If neither is set, the test is skipped.
"""

import os
import socket
import subprocess
import time

import pytest

from seam_sdk import Agent, BudgetLimits, SeamClient, StepUsage


def _wait(port: int, timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server never came up")


@pytest.fixture
def server():
    addr = os.environ.get("SEAM_GRPC_ADDR")
    if addr:
        yield addr
        return
    binary = os.environ.get("SEAM_GRPC_BIN")
    if not binary:
        pytest.skip(
            "set SEAM_GRPC_ADDR or SEAM_GRPC_BIN to run the live integration test"
        )
    addr = "127.0.0.1:8099"
    proc = subprocess.Popen(
        [binary],
        # SEAM_DEV_INSECURE lets the dev binary boot with the public dev seed AND enrol the
        # well-known demo tenant (the [42;32] agent this test admits as) — both required since
        # the server refuses a public identity by default (runtime security hardening).
        env={
            **os.environ,
            "SEAM_GRPC_LISTEN": addr,
            "SEAM_DEV_INSECURE": "1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait(8099)
        yield addr
    finally:
        proc.terminate()


def test_full_round_trip(server):
    client = SeamClient.connect(server)
    agent = Agent(bytes([42] * 32))  # the enrolled reference agent

    dec = client.run_decision(
        agent,
        "py-int",
        ["fraud-v3", "risk-v2"],
        [("fraud-v3", "BLOCK"), ("risk-v2", "BLOCK")],
    )
    assert dec.decided_value == "BLOCK"
    assert dec.outcome == "Resolved"

    assert client.get_decision(dec.decision_id).outcome == "Resolved"
    assert client.replay_decision(dec.decision_id).chain_verified

    # Independent verification — pin the issuer (TOFU here) then verify the rooted TCT locally.
    issuer = client.issuer_aid()
    assert client.verify_decision(dec.decision_id, issuer) is True
    # A wrong pinned issuer must be rejected even though the server's proof is internally consistent.
    assert (
        client.verify_decision(dec.decision_id, "aid:pubkey:ed25519:" + "A" * 43)
        is False
    )


def test_session_lifecycle_seals(server):
    """open → propose → vote → commit seals a decision over the incremental session API."""
    client = SeamClient.connect(server)
    agent = Agent(bytes([42] * 32))

    client.open_session(agent, "py-sess", ["lead", "peer"])
    client.submit_proposal("py-sess", "lead", "p1", "BLOCK")
    client.submit_vote("py-sess", "peer", "p1", "APPROVE")
    step = client.submit_commit("py-sess", "c1", "BLOCK")

    assert step.state == "Resolved"
    assert step.decision_id
    assert client.get_decision(step.decision_id).outcome == "Resolved"


def test_budget_suspend_resume_loop(server):
    """The enterprise-6.2 loop: a hard budget breach suspends (an Ok step, not an error); the
    dimension-raising resume un-suspends it and the session seals."""
    client = SeamClient.connect(server)
    agent = Agent(bytes([42] * 32))

    # Open with a 1000-token allowance.
    client.open_session(
        agent, "py-budget", ["lead", "peer"], limits=BudgetLimits(tokens=1000)
    )
    # The proposal reports the full allowance — applied, ledger now exhausted.
    client.submit_proposal(
        "py-budget", "lead", "p1", "BLOCK", usage=StepUsage(tokens=1000, cost_micros=40)
    )
    # The next step breaches the hard token limit: refused + Suspended (not an error).
    step = client.submit_vote("py-budget", "peer", "p1", "APPROVE")
    assert step.state == "Suspended", step.state

    # The R9 approver raises the token dimension and resumes.
    client.resume_session("py-budget", raise_=BudgetLimits(tokens=5000))
    # Re-submit (the breached vote was never applied): now within budget → continues.
    step = client.submit_vote("py-budget", "peer", "p1", "APPROVE")
    assert step.state != "Suspended", step.state
    # And the session seals.
    step = client.submit_commit("py-budget", "c1", "BLOCK")
    assert step.state == "Resolved"
    assert step.decision_id
