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

from seam_sdk import Agent, SeamClient


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
        pytest.skip("set SEAM_GRPC_ADDR or SEAM_GRPC_BIN to run the live integration test")
    addr = "127.0.0.1:8099"
    proc = subprocess.Popen(
        [binary],
        env={**os.environ, "SEAM_GRPC_LISTEN": addr},
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
        agent, "py-int", ["fraud-v3", "risk-v2"], [("fraud-v3", "BLOCK"), ("risk-v2", "BLOCK")]
    )
    assert dec.decided_value == "BLOCK"
    assert dec.outcome == "Resolved"

    assert client.get_decision(dec.decision_id).outcome == "Resolved"
    assert client.replay_decision(dec.decision_id).chain_verified

    # Independent verification — fetch the proof and verify the rooted TCT locally, zero server trust.
    assert client.verify_decision(dec.decision_id) is True
