"""Management-plane DPoP proofs (seam-sdk#290, seam-runtime docs/specs/mgmt-dpop.md).

Asserts against `conformance/mgmt_dpop_vector.json`. Its `golden` group is the runtime's own vector, so
the golden proof is compared byte for byte: a self-consistent proof is not a conformant one. There is no
bless mode — a mismatch is a contract break.
"""

from __future__ import annotations

import base64
import copy
import json
import pickle
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from seam_sdk import (
    DEFAULT_OPERATOR_AUD,
    MGMT_DPOP_MAX_BODY_BYTES,
    MGMT_DPOP_MAX_JTI_BYTES,
    DpopError,
    DpopKeyError,
    OperatorDpopKey,
    mgmt_dpop_grpc_htu,
    mgmt_dpop_http_headers,
    mgmt_dpop_http_htu,
    mgmt_dpop_proof,
    new_mgmt_dpop_jti,
)
from seam_sdk.dpop import _peek_token_claims, _token_cnf_jkt

VECTOR = Path(__file__).resolve().parents[2] / "conformance" / "mgmt_dpop_vector.json"


def _v() -> dict:
    return json.loads(VECTOR.read_text())


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _golden_key() -> OperatorDpopKey:
    return OperatorDpopKey.from_jwk(_v()["golden"]["jwk"])


def test_vector_file_is_present_and_populated() -> None:
    """Parametrising over an empty list collects zero tests and reports green, so fail loudly here."""
    v = _v()
    assert len(v["derived"]) >= 5
    assert len(v["jwk_rejects"]) >= 10
    assert len(v["http_htu"]) >= 5 and len(v["http_htu_rejects"]) >= 3


# ── the golden vector ──────────────────────────────────────────────────────────────────────────


def test_golden_key_outputs() -> None:
    g = _v()["golden"]
    key = OperatorDpopKey.from_seed(bytes.fromhex(g["seed_hex"]))
    assert key.x == g["x"]
    assert key.jkt == g["jkt"]
    assert _golden_key().jkt == g["jkt"], "from_jwk and from_seed disagree"


def test_golden_proof_is_byte_exact() -> None:
    g = _v()["golden"]
    htu = mgmt_dpop_grpc_htu(g["method"], g["aud"])
    assert htu == g["htu"]
    proof = mgmt_dpop_proof(
        _golden_key(),
        g["token"],
        htm=g["htm"],
        htu=htu,
        body=bytes.fromhex(g["message_hex"]),
        iat=g["iat"],
        jti=g["jti"],
    )
    assert proof == g["proof"]
    header, claims, _sig = proof.split(".")
    assert _b64d(header).decode() == g["header_json"]
    assert _b64d(claims).decode() == g["claims_json"]
    decoded = json.loads(_b64d(claims))
    assert decoded["ath"] == g["ath"]
    assert decoded["seam_bd"] == g["seam_bd"]


def test_golden_proof_member_order_and_set() -> None:
    g = _v()["golden"]
    header, claims, _ = g["proof"].split(".")
    assert list(json.loads(_b64d(header))) == ["typ", "alg", "jwk"]
    assert list(json.loads(_b64d(header))["jwk"]) == ["kty", "crv", "x"]
    assert list(json.loads(_b64d(claims))) == [
        "jti",
        "htm",
        "htu",
        "iat",
        "ath",
        "seam_bd",
    ]


def test_proof_verifies_under_the_public_key() -> None:
    key = _golden_key()
    proof = mgmt_dpop_proof(key, "a.b.c", htm="POST", htu="grpc://x/y.Z/W", body=b"")
    signing_input, _, sig = proof.rpartition(".")
    Ed25519PublicKey.from_public_bytes(_b64d(key.x)).verify(
        _b64d(sig), signing_input.encode()
    )


def test_a_one_byte_seed_change_changes_the_proof() -> None:
    g = _v()["golden"]
    seed = bytearray(bytes.fromhex(g["seed_hex"]))
    seed[0] ^= 1
    args = dict(
        htm="POST",
        htu=g["htu"],
        body=bytes.fromhex(g["message_hex"]),
        iat=g["iat"],
        jti=g["jti"],
    )
    assert (
        mgmt_dpop_proof(OperatorDpopKey.from_seed(bytes(seed)), g["token"], **args)
        != g["proof"]
    )


# ── derived (five-way agreement) ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", _v()["derived"], ids=lambda c: c["name"])
def test_derived_proofs(case: dict) -> None:
    g = _v()["golden"]
    key = _golden_key()
    body = bytes.fromhex(case["message_hex"])
    if "url" in case:
        assert mgmt_dpop_http_htu(case["url"]) == case["htu"]
        headers = mgmt_dpop_http_headers(
            key,
            g["token"],
            case["htm"],
            case["url"],
            body,
            iat=case["iat"],
            jti=case["jti"],
        )
        assert headers == {"Authorization": f"DPoP {g['token']}", "DPoP": case["proof"]}
    proof = mgmt_dpop_proof(
        key,
        g["token"],
        htm=case["htm"],
        htu=case["htu"],
        body=body,
        iat=case["iat"],
        jti=case["jti"],
    )
    assert proof == case["proof"]
    assert json.loads(_b64d(proof.split(".")[1]))["seam_bd"] == case["seam_bd"]


@pytest.mark.parametrize("case", _v()["grpc_htu"], ids=lambda c: c["htu"])
def test_grpc_htu(case: dict) -> None:
    assert mgmt_dpop_grpc_htu(case["method"], case["aud"]) == case["htu"]


def test_grpc_htu_defaults_to_the_runtime_audience() -> None:
    assert DEFAULT_OPERATOR_AUD == "seam-runtime"
    assert mgmt_dpop_grpc_htu("/a.B/C") == "grpc://seam-runtime/a.B/C"


@pytest.mark.parametrize("method", ["", "a.B/C", "/a.B/C\n", "/a.B/é"])
def test_grpc_htu_refuses_a_bad_method(method: str) -> None:
    with pytest.raises(DpopError):
        mgmt_dpop_grpc_htu(method)


@pytest.mark.parametrize("aud", ["", "has space", "a/b", "café"])
def test_grpc_htu_refuses_a_bad_aud(aud: str) -> None:
    with pytest.raises(DpopError):
        mgmt_dpop_grpc_htu("/a.B/C", aud)


@pytest.mark.parametrize("case", _v()["http_htu"], ids=lambda c: c["url"])
def test_http_htu(case: dict) -> None:
    assert mgmt_dpop_http_htu(case["url"]) == case["htu"]


@pytest.mark.parametrize("case", _v()["http_htu_rejects"], ids=lambda c: c["reason"])
def test_http_htu_rejects(case: dict) -> None:
    with pytest.raises(DpopError):
        mgmt_dpop_http_htu(case["url"])


def test_http_htu_refuses_a_bad_port() -> None:
    with pytest.raises(DpopError):
        mgmt_dpop_http_htu("https://host.example:99999/v1/a")


# ── key loading ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", _v()["jwk_rejects"], ids=lambda c: c["reason"])
def test_jwk_rejects(case: dict) -> None:
    with pytest.raises(DpopKeyError):
        OperatorDpopKey.from_jwk(case["jwk"])
    with pytest.raises(DpopKeyError):  # the JSON-text form takes the same path
        OperatorDpopKey.from_jwk(json.dumps(case["jwk"]))


@pytest.mark.parametrize("case", _v()["jwk_accepts"], ids=lambda c: c["reason"])
def test_jwk_accepts(case: dict) -> None:
    assert OperatorDpopKey.from_jwk(case["jwk"]).jkt == _v()["golden"]["jkt"]


def test_jwk_text_that_is_not_json() -> None:
    with pytest.raises(DpopKeyError, match="not valid JSON"):
        OperatorDpopKey.from_jwk("{kty: OKP")


@pytest.mark.parametrize("seed", [b"", b"\x00" * 31, b"\x00" * 33, "x" * 32])
def test_from_seed_refuses_a_bad_seed(seed: object) -> None:
    with pytest.raises(DpopKeyError):
        OperatorDpopKey.from_seed(seed)  # type: ignore[arg-type]


def test_key_never_shows_its_private_half() -> None:
    g = _v()["golden"]
    key = _golden_key()
    for text in (repr(key), str(key), f"{key}"):
        assert g["jwk"]["d"] not in text
        assert g["seed_hex"] not in text
        assert g["jkt"] in text
    assert key.public_jwk() == {"kty": "OKP", "crv": "Ed25519", "x": g["x"]}
    assert "d" not in key.public_jwk()


def test_key_refuses_to_be_pickled() -> None:
    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(_golden_key())


@pytest.mark.parametrize("dup", [copy.copy, copy.deepcopy])
def test_key_refuses_to_be_copied(dup: object) -> None:
    with pytest.raises(TypeError, match="cannot be pickled"):
        dup(_golden_key())  # type: ignore[operator]


def test_deeply_nested_jwk_text_is_a_key_error() -> None:
    with pytest.raises(DpopKeyError, match="nested too deeply"):
        OperatorDpopKey.from_jwk("[" * 100_000)


def test_the_proof_header_never_carries_d() -> None:
    proof = mgmt_dpop_proof(
        _golden_key(), "a.b.c", htm="POST", htu="grpc://x/y.Z/W", body=b""
    )
    assert "d" not in json.loads(_b64d(proof.split(".")[0]))["jwk"]


# ── defaults and local refusals ────────────────────────────────────────────────────────────────


def test_default_jti_is_fresh_22_char_b64url() -> None:
    a, b = new_mgmt_dpop_jti(), new_mgmt_dpop_jti()
    assert a != b and len(a) == 22 and len(_b64d(a)) == 16


def test_default_iat_is_now(monkeypatch: pytest.MonkeyPatch) -> None:
    import seam_sdk.dpop as dpop

    monkeypatch.setattr(dpop.time, "time", lambda: 1_900_000_000.7)
    proof = mgmt_dpop_proof(
        _golden_key(), "a.b.c", htm="POST", htu="grpc://x/y.Z/W", body=b""
    )
    claims = json.loads(_b64d(proof.split(".")[1]))
    assert claims["iat"] == 1_900_000_000
    assert len(claims["jti"]) == 22


def test_two_default_proofs_differ() -> None:
    key = _golden_key()
    kw = dict(htm="POST", htu="grpc://x/y.Z/W", body=b"", iat=1)
    assert mgmt_dpop_proof(key, "a.b.c", **kw) != mgmt_dpop_proof(key, "a.b.c", **kw)


_OK = dict(htm="POST", htu="grpc://x/y.Z/W", body=b"", iat=1, jti="j")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("htm", ""),
        ("htm", "PO ST"),
        ("htu", ""),
        ("htu", "grpc://x/é"),
        ("htu", "grpc://x/\n"),
        ("body", "not bytes"),
        ("body", b"\x00" * (MGMT_DPOP_MAX_BODY_BYTES + 1)),
        ("iat", -1),
        ("iat", True),
        ("iat", 1.5),
        ("iat", 2**53),
        ("jti", ""),
        ("jti", "é"),
        ("jti", "j" * (MGMT_DPOP_MAX_JTI_BYTES + 1)),
    ],
)
def test_local_refusals(field: str, value: object) -> None:
    with pytest.raises(DpopError):
        mgmt_dpop_proof(_golden_key(), "a.b.c", **{**_OK, field: value})


def test_the_body_cap_is_inclusive() -> None:
    mgmt_dpop_proof(
        _golden_key(), "a.b.c", **{**_OK, "body": b"\x00" * MGMT_DPOP_MAX_BODY_BYTES}
    )


def test_max_iat_is_the_shared_bound() -> None:
    from seam_sdk import MGMT_DPOP_MAX_IAT

    assert MGMT_DPOP_MAX_IAT == _v()["iat_max"]
    mgmt_dpop_proof(_golden_key(), "a.b.c", **{**_OK, "iat": MGMT_DPOP_MAX_IAT})


def test_max_length_jti_is_accepted() -> None:
    mgmt_dpop_proof(
        _golden_key(), "a.b.c", **{**_OK, "jti": "j" * MGMT_DPOP_MAX_JTI_BYTES}
    )


@pytest.mark.parametrize("token", ["", "has space", "café", None])
def test_bad_tokens(token: object) -> None:
    with pytest.raises(DpopError):
        mgmt_dpop_proof(_golden_key(), token, **_OK)  # type: ignore[arg-type]


def test_an_oversized_proof_is_refused_locally() -> None:
    with pytest.raises(DpopError, match="refuses one over"):
        mgmt_dpop_proof(
            _golden_key(), "a.b.c", **{**_OK, "htu": "grpc://x/" + "a" * 8192}
        )


def test_key_must_be_an_operator_dpop_key() -> None:
    with pytest.raises(DpopError):
        mgmt_dpop_proof(b"\x42" * 32, "a.b.c", **_OK)  # type: ignore[arg-type]


def test_errors_are_value_errors() -> None:
    assert issubclass(DpopKeyError, DpopError) and issubclass(DpopError, ValueError)


# ── token peeking (diagnostics only) ───────────────────────────────────────────────────────────


def _token(claims: dict) -> str:
    def seg(o: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()

    return f"{seg({'alg': 'EdDSA'})}.{seg(claims)}.c2ln"


def test_peek_reads_cnf_and_aud() -> None:
    claims = _peek_token_claims(_token({"aud": "seam-runtime", "cnf": {"jkt": "abc"}}))
    assert claims["aud"] == "seam-runtime" and _token_cnf_jkt(claims) == "abc"
    assert _token_cnf_jkt(_peek_token_claims(_token({"sub": "x"}))) is None


@pytest.mark.parametrize(
    "token", ["only.two", "a.!!!.c", "a.bm90LWpzb24.c", "a.WzFd.c"]
)
def test_peek_refuses_a_non_jws(token: str) -> None:
    with pytest.raises(DpopKeyError):
        _peek_token_claims(token)


@pytest.mark.parametrize("cnf", [{"jkt": 1}, "abc", {"x5t": "y"}])
def test_peek_refuses_a_malformed_cnf(cnf: object) -> None:
    with pytest.raises(DpopKeyError):
        _token_cnf_jkt({"cnf": cnf})
