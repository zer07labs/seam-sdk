"""JCS + tool_input_digest must reproduce the runtime's cross-language vector byte-for-byte.

The vector (`conformance/authorize_jcs_digest_vector.json`) is COPIED from the runtime
(`crates/seam-api/tests/fixtures/`), never re-derived here. A mismatch is a contract break,
not a prompt to regenerate — the digest is what `call_sig` signs and what the advisory
audit row records.
"""

import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_sdk.crypto import call_sig, jcs_canonicalize, tool_input_digest

VECTOR = json.loads(
    (
        pathlib.Path(__file__).parents[2]
        / "conformance"
        / "authorize_jcs_digest_vector.json"
    ).read_text()
)


@pytest.mark.parametrize(
    "case", VECTOR["cases"], ids=[c["name"] for c in VECTOR["cases"]]
)
def test_vector_case_is_byte_exact(case):
    canonical = jcs_canonicalize(case["input"])
    assert canonical == case["canonical"].encode("utf-8")
    assert tool_input_digest(canonical) == case["digest"]


def test_number_es6_rendering_edges():
    # Not in the vector, but pinned by ECMA-262 Number::toString — the exponent-boundary cases.
    cases = {
        1e-7: "1e-7",
        0.000001: "0.000001",
        1.5e22: "1.5e+22",
        100.0: "100",
        -0.0: "0",
        333333333.3333333: "333333333.3333333",
    }
    for v, want in cases.items():
        assert jcs_canonicalize(v).decode() == want, v


def test_unrepresentable_inputs_are_rejected():
    with pytest.raises(ValueError):
        jcs_canonicalize(float("nan"))
    with pytest.raises(ValueError):
        jcs_canonicalize(float("inf"))
    with pytest.raises(ValueError):
        jcs_canonicalize(2**53 + 1)  # cannot round-trip as an IEEE double
    with pytest.raises(TypeError):
        jcs_canonicalize({1: "non-string key"})
    with pytest.raises(TypeError):
        jcs_canonicalize(object())


def test_lone_surrogate_is_rejected():
    # Not valid Unicode -> not UTF-8-encodable; both SDK languages must refuse, not silently escape.
    with pytest.raises(ValueError):
        jcs_canonicalize({"s": "\ud800"})


def test_call_sig_is_ed25519_over_ticket_then_digest():
    seed = bytes(range(32))
    ticket = b"opaque-ticket-bytes"
    digest = tool_input_digest(jcs_canonicalize({"a": 1}))
    sig = call_sig(seed, ticket, digest)
    assert len(sig) == 64
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    pub.verify(sig, ticket + digest.encode())  # raises on mismatch
    with pytest.raises(Exception):
        pub.verify(sig, ticket + b"tampered")
