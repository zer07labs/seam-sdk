"""The cross-language conformance test for the `call_sig` signed payload (v2).

This file exists because of a specific failure. seam-runtime #286 moved the payload from v1
(`ticket || digest`) to v2 (domain-separated, length-prefixed, additionally covering `tool_name`
and `agent_id`). Every published SDK kept signing v1, and **nothing in this repo noticed**: the
SDK's own tests sign and verify with the SDK's own function, so they stay green no matter what the
framing is. The break surfaced only as a live runtime rejecting every ENFORCE call.

A self-consistent signature is not a conformant one. So these tests assert against bytes generated
by executing the runtime's Rust `call_sig_payload`, not against our own output.

There is deliberately no bless mode: a mismatch here is a CONTRACT BREAK, not a prompt to
regenerate the vector.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_sdk.crypto import CALL_SIG_CONTEXT, call_sig, call_sig_payload

VECTOR = (
    Path(__file__).resolve().parents[2] / "conformance" / "call_sig_payload_vector.json"
)


def _vector() -> dict:
    return json.loads(VECTOR.read_text())


def _cases() -> list[dict]:
    return _vector()["cases"]


def test_vector_file_is_present_and_populated() -> None:
    """A missing or emptied vector must fail loudly.

    Parametrising over an empty list silently collects zero tests and reports green — which is the
    same class of non-event that let the v1/v2 skew ship.
    """
    assert VECTOR.exists(), f"conformance vector missing: {VECTOR}"
    assert len(_cases()) >= 6, "the vector lost cases; it pins a wire contract"


def test_context_tag_matches_the_vector() -> None:
    """The tag IS the version. If the runtime bumps it and we do not, every call is rejected."""
    assert CALL_SIG_CONTEXT.decode() == _vector()["context"]


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_payload_matches_the_runtime_bytes(case: dict) -> None:
    got = call_sig_payload(
        bytes.fromhex(case["ticket_hex"]),
        case["tool_input_digest"],
        case["tool_name"],
        case["agent_id"],
    )
    assert got.hex() == case["payload_hex"], (
        f"call_sig payload diverged from the runtime for case {case['name']!r}.\n"
        f"  expected {case['payload_hex']}\n  actual   {got.hex()}\n"
        "This is a wire CONTRACT BREAK — every ENFORCE call will be rejected with "
        "'admission ticket is not valid'. Do not regenerate the vector to make this pass."
    )


def test_length_prefixes_disambiguate_adjacent_fields() -> None:
    """('read','x') and ('read_x','') must not frame identically.

    Without length prefixes they do, which would let a captured signature be re-pointed at a
    different tool — the exact gap v2 closes. The vector carries the pair; this asserts the
    property directly so it survives someone 'simplifying' the framing.
    """
    a = call_sig_payload(b"t", "d", "read", "x")
    b = call_sig_payload(b"t", "d", "read_x", "")
    assert a != b


def test_lengths_are_byte_counts_not_character_counts() -> None:
    """A multi-byte tool name must lengthen the payload by its UTF-8 size, not its char count."""
    ascii_p = call_sig_payload(b"", "", "abcde", "")
    utf8_p = call_sig_payload(b"", "", "träns", "")  # 5 chars, 6 UTF-8 bytes
    assert len(utf8_p) == len(ascii_p) + 1


def test_every_field_is_bound() -> None:
    """Changing any one input must change the payload.

    A field that is accepted but not actually mixed in is the worst version of this bug: the
    signature verifies locally, the runtime rejects it, and the parameter looks wired up.
    """
    base = dict(ticket=b"t", tool_input_digest="d", tool_name="n", agent_id="a")
    baseline = call_sig_payload(**base)
    for field, altered in [
        ("ticket", b"T"),
        ("tool_input_digest", "D"),
        ("tool_name", "N"),
        ("agent_id", "A"),
    ]:
        assert call_sig_payload(**{**base, field: altered}) != baseline, (
            f"{field} is not bound into the payload"
        )


def test_signature_verifies_over_the_payload() -> None:
    seed = bytes(range(32))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    sig = call_sig(seed, b"ticket", "sha256:aa", tool_name="tool", agent_id="a7")
    sk.public_key().verify(sig, call_sig_payload(b"ticket", "sha256:aa", "tool", "a7"))


def test_v1_framing_no_longer_verifies() -> None:
    """The regression, pinned.

    v1 signed `ticket || digest`. If that ever verifies against the v2 payload again, the domain
    separation has been lost and a stale client would be silently accepted.
    """
    seed = bytes(range(32))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    v1 = sk.sign(b"ticket" + b"sha256:aa")
    v2_payload = call_sig_payload(b"ticket", "sha256:aa", "tool", "a7")
    with pytest.raises(Exception):
        sk.public_key().verify(v1, v2_payload)


def test_tool_name_and_agent_id_are_required() -> None:
    """No defaults, on purpose.

    A default would let existing callers keep working while emitting a signature the runtime
    rejects — reported as 'admission ticket is not valid', which names the wrong artifact. A local
    TypeError is the far cheaper failure.
    """
    with pytest.raises(TypeError):
        call_sig(bytes(32), b"t", "d")  # type: ignore[call-arg]
