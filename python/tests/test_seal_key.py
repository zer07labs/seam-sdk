"""seam-runtime #2031 (deep-cleanup S-4): the commitment TCT is signed by a seal key the pinned issuer
certifies, and :func:`seam_sdk.crypto.verify_tct` accepts exactly that shape.

Pinned by ``conformance/seal_key_cert_vector.json`` (byte-identical copy of the runtime's
``crates/seam-trust-aitp/tests/fixtures/seal_key_cert_vector.json``); the refusals below each change ONE
thing over a token :mod:`seal_key_tokens` mints and that verifies (the control).
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest
import seal_key_tokens as sk
from seam_sdk.crypto import (
    _seam_commitment_digest,
    parse_seal_key_cert,
    verify_seal_key_cert,
    verify_tct,
)

ROOT = pathlib.Path(__file__).resolve().parents[2] / "conformance"
VEC = json.loads((ROOT / "seal_key_cert_vector.json").read_text())
TCT = json.loads((ROOT / "vectors.json").read_text())["tct"]

ISSUER_SEED = bytes([7] * 32)
ISSUER = sk.untagged_aid(ISSUER_SEED)
NB = 1_700_000_000_000
NA = 1_700_000_900_000

COMMITMENT = {
    "id": "c-seal-key",
    "action": "transfer",
    "authority": "treasury",
    "supersedes": None,
    "auth_method": "pinned-key",
    "trust_basis": "attested",
    "committer": "",
    "explanation": [],
}
STATEMENT = {
    "type": "seam:commitment",
    "commitment_digest": _seam_commitment_digest(COMMITMENT),
}


def _ok(jws: str, issuer: str = ISSUER) -> bool:
    return verify_tct(issuer, jws, COMMITMENT, now_s=1_700_000_000)


# -- the frozen certificate vector ----------------------------------------------------------------


def test_the_vector_rebuilds_from_its_fields():
    cert = bytes.fromhex(VEC["cert_hex"])
    seal_pk = bytes.fromhex(VEC["seal_pk_hex"])
    assert VEC["domain"] == "seam.seal-key-cert.v1"
    assert (
        sk.cert_bytes(
            seal_pk, VEC["not_before_ms"], VEC["not_after_ms"], VEC["issuer_aid"]
        )
        == cert
    )
    assert hashlib.sha256(cert).hexdigest() == VEC["cert_digest_hex"]
    assert sk.pk(bytes.fromhex(VEC["seal_seed_hex"])) == seal_pk
    assert sk.untagged_aid(bytes.fromhex(VEC["issuer_seed_hex"])) == VEC["issuer_aid"]
    assert "aid:pubkey:" + sk.b64(seal_pk) == VEC["seal_aid"]
    assert VEC["ext_member"] == {
        "cert": sk.b64(cert),
        "sig": sk.b64(bytes.fromhex(VEC["sig_hex"])),
    }


def test_the_vector_parses_and_verifies_under_its_issuer():
    cert = bytes.fromhex(VEC["cert_hex"])
    sig = bytes.fromhex(VEC["sig_hex"])
    f = verify_seal_key_cert(VEC["issuer_aid"], cert, sig)
    assert f is not None and f == parse_seal_key_cert(cert)
    assert f.seal_pk == bytes.fromhex(VEC["seal_pk_hex"])
    assert (f.not_before_ms, f.not_after_ms) == (
        VEC["not_before_ms"],
        VEC["not_after_ms"],
    )
    assert f.issuer_aid == VEC["issuer_aid"]
    # The certifier reproduces the bytes (PureEdDSA is deterministic).
    issuer_seed = bytes.fromhex(VEC["issuer_seed_hex"])
    assert (
        sk.cert_member(
            issuer_seed,
            bytes.fromhex(VEC["seal_seed_hex"]),
            VEC["not_before_ms"],
            VEC["not_after_ms"],
        )
        == VEC["ext_member"]
    )


def test_another_pinned_issuer_refuses_the_vector():
    other = sk.untagged_aid(bytes([8] * 32))
    cert = bytes.fromhex(VEC["cert_hex"])
    assert verify_seal_key_cert(other, cert, bytes.fromhex(VEC["sig_hex"])) is None


def test_any_flipped_cert_byte_is_refused():
    cert = bytes.fromhex(VEC["cert_hex"])
    sig = bytes.fromhex(VEC["sig_hex"])
    for i in range(len(cert)):
        bad = bytearray(cert)
        bad[i] ^= 1
        assert verify_seal_key_cert(VEC["issuer_aid"], bytes(bad), sig) is None, i
    for i in range(len(sig)):
        bad = bytearray(sig)
        bad[i] ^= 1
        assert verify_seal_key_cert(VEC["issuer_aid"], cert, bytes(bad)) is None, i


# -- verify_tct over the seal-key shape -----------------------------------------------------------


def test_the_control_verifies():
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, nb=NB, na=NA)) is True


def test_the_runtime_tct_vector_verifies():
    assert TCT["issuer_aid"] == ISSUER
    p = json.loads(sk.unb64(TCT["signed_artifact_jws"].split(".")[1]))
    assert p["iss"] != TCT["issuer_aid"], "S-4: the token's own issuer is the seal key"


def test_an_issuer_signed_tct_is_refused():
    """No backward compatibility: the pre-S-4 shape (the issuer signs the TCT itself) is refused."""
    payload = {
        "ver": "aitp/0.3",
        "iss": ISSUER,
        "sub": ISSUER,
        "aud": ISSUER,
        "cnf": {"jkt": sk.jkt(sk.pk(ISSUER_SEED))},
        "iat": 1_700_000_000,
        "exp": 4_000_000_000,
        "grants": ["aitp.attestation"],
        "ext": {"com.zer07labs.seam": STATEMENT},
    }
    jws = sk.sign(ISSUER_SEED, {"alg": "EdDSA", "typ": "aitp-tct+jwt"}, payload)
    assert _ok(jws) is False


def test_the_window_cap_is_inclusive():
    cap = sk.MAX_WINDOW_MS
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, nb=NB, na=NB + cap)) is True
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, nb=NB, na=NB + cap + 1)) is False


@pytest.mark.parametrize(
    "nb,na",
    [
        (NB + 1, NB),  # inverted
        (2**63 - 1_000, 2**63),  # not_after beyond i64::MAX ms
    ],
)
def test_an_ill_formed_window_is_refused(nb, na):
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, nb=nb, na=na, iat=nb // 1000)) is False


@pytest.mark.parametrize(
    "iat,ok",
    [
        (NB // 1000 - 1, False),
        (NB // 1000, True),
        (NA // 1000, True),
        (NA // 1000 + 1, False),
    ],
)
def test_iat_must_lie_inside_the_window_with_no_grace(iat, ok):
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, nb=NB, na=NA, iat=iat)) is ok


@pytest.mark.parametrize("iat", [True, 1_700_000_000.0, "1700000000", None, 2**62])
def test_iat_must_be_an_in_range_integer(iat):
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, nb=NB, na=NA, iat=iat)) is False


def test_a_missing_iat_is_refused():
    jws = sk.mint(ISSUER_SEED, STATEMENT, edit=lambda p: p.pop("iat"))
    assert _ok(jws) is False


def test_a_cert_naming_another_issuer_is_refused():
    # Signed by the pinned key, naming another AID.
    other = sk.untagged_aid(bytes([8] * 32))
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, issuer_aid=other)) is False
    # A forger certifies their own key under their own AID: refused against the pin.
    forged = sk.mint(
        bytes([8] * 32), STATEMENT, seal_seed=sk.seeded_seal_seed(ISSUER_SEED)
    )
    assert _ok(forged) is False
    assert (
        _ok(forged, issuer=other) is True
    )  # the control: it IS a valid token for its own pin


def test_a_tagged_spelling_of_the_pinned_issuer_is_not_the_pin():
    tagged = "aid:pubkey:ed25519:" + sk.b64(sk.pk(ISSUER_SEED))
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, issuer_aid=tagged)) is False
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, issuer_aid=tagged), issuer=tagged)


def test_trailing_cert_bytes_are_refused():
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, trailing=b"\x00")) is False


def _member(**kw):
    return sk.cert_member(ISSUER_SEED, sk.seeded_seal_seed(ISSUER_SEED), NB, NA, **kw)


@pytest.mark.parametrize(
    "name,member",
    [
        ("third key", {**_member(), "x": ""}),
        ("cert only", {"cert": _member()["cert"]}),
        ("padded cert", {**_member(), "cert": _member()["cert"] + "="}),
        ("std-alphabet sig", {**_member(), "sig": _member()["sig"] + "+"}),
        ("non-string cert", {**_member(), "cert": 1}),
        ("not an object", [_member()["cert"], _member()["sig"]]),
    ],
)
def test_the_cert_member_shape_is_exact(name, member):
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, member=member)) is False, name


def test_a_non_canonical_base64_tail_is_refused():
    m = _member()
    # The sig is 64 bytes → 86 chars, whose last char carries 4 spare (zero) bits; set one of them.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    bad = m["sig"][:-1] + alphabet[alphabet.index(m["sig"][-1]) | 1]
    assert bad != m["sig"] and sk.unb64(bad) == sk.unb64(m["sig"]), (
        "a lax decoder agrees"
    )
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, member={**m, "sig": bad})) is False


def test_a_cert_for_another_seal_key_is_refused():
    other_seal = bytes([0x5E] * 32)
    m = sk.cert_member(ISSUER_SEED, other_seal, NB, NA)
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, member=m)) is False


def test_an_extra_ext_namespace_is_refused():
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, extra_ext={"org.example": {}})) is False


def test_a_missing_cert_member_is_refused():
    jws = sk.mint(
        ISSUER_SEED,
        STATEMENT,
        edit=lambda p: p["ext"].pop("com.zer07labs.seam.seal-key-cert"),
    )
    assert _ok(jws) is False


@pytest.mark.parametrize(
    "edit",
    [
        lambda p: p.update(iss=sk.untagged_aid(ISSUER_SEED)),
        lambda p: p.update(aud=sk.untagged_aid(ISSUER_SEED)),
        lambda p: p.update(sub="aid:pubkey:ed25519:" + p["sub"][len("aid:pubkey:") :]),
        lambda p: p.update(cnf={"jkt": sk.jkt(sk.pk(ISSUER_SEED))}),
        lambda p: p.pop("cnf"),
    ],
)
def test_the_token_is_a_self_attestation_by_the_seal_key(edit):
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, edit=edit)) is False


def test_a_token_signed_by_the_issuer_over_the_seal_shape_is_refused():
    seal = sk.seeded_seal_seed(ISSUER_SEED)
    good = sk.mint(ISSUER_SEED, STATEMENT)
    h, p, _ = good.split(".")
    resigned = sk.sign(ISSUER_SEED, sk.unb64(h), sk.unb64(p))
    assert _ok(resigned) is False
    assert sk.sign(seal, sk.unb64(h), sk.unb64(p)) == good  # the control


def test_a_small_order_r_on_the_cert_signature_is_refused():
    m = _member()
    sig = sk.unb64(m["sig"])
    forged = bytes.fromhex("01" + "00" * 31) + sig[32:]
    assert (
        _ok(sk.mint(ISSUER_SEED, STATEMENT, member={**m, "sig": sk.b64(forged)}))
        is False
    )


def test_a_small_order_pinned_issuer_is_refused():
    """A weak pinned key verifies nothing, even a signature that holds under the plain equation."""
    weak = "aid:pubkey:" + sk.b64(bytes.fromhex("01" + "00" * 31))
    cert = sk.cert_bytes(sk.pk(bytes([3] * 32)), NB, NA, weak)
    # R = identity, S = 0 satisfies [S]B = R + [k]A for A = identity under cofactorless verify.
    sig = bytes.fromhex("01" + "00" * 31) + bytes(32)
    assert verify_seal_key_cert(weak, cert, sig) is None


def test_the_window_rule_does_not_depend_on_wall_clock_seconds_rounding():
    # not_before not on a second boundary: iat·1000 must still be >= it.
    nb = NB + 500
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, nb=nb, na=NA, iat=NB // 1000)) is False
    assert _ok(sk.mint(ISSUER_SEED, STATEMENT, nb=nb, na=NA, iat=NB // 1000 + 1))


def test_an_unrelated_signer_cannot_mint_with_a_copied_cert():
    """A copied (valid) certificate does not let another key sign: the JWS must verify under the
    certified seal key, and iss/cnf name it."""
    thief = bytes([0x44] * 32)
    good = sk.mint(ISSUER_SEED, STATEMENT)
    _, p, _ = good.split(".")
    resigned = sk.sign(thief, {"alg": "EdDSA", "typ": "aitp-tct+jwt"}, sk.unb64(p))
    assert _ok(resigned) is False
