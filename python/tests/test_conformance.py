"""The Python crypto shim must reproduce the Rust reference bytes exactly.

Vectors are generated from `seam-runtime` (`cargo run -p seam-client --example conformance_vectors`) and
pin the admission proof-of-possession the Seam server verifies. If this passes, the shim authenticates
against a real server.
"""

import json
import pathlib

import pytest

from seam_sdk.crypto import aid_from_pubkey, build_presentation, verify_tct

VECTORS = json.loads(
    (pathlib.Path(__file__).parents[2] / "conformance" / "vectors.json").read_text()
)


def test_pinned_key_presentation_is_byte_exact():
    adm = VECTORS["admission"]
    i = adm["inputs"]
    got = build_presentation(
        bytes.fromhex(i["agent_seed_hex"]),
        i["receiver_aid"],
        i["pop_nonce"],
        i["now_ms"],
    )
    assert got == adm["presentation"]
    # P8: the presentation carries exactly these five fields, no more.
    assert sorted(got) == sorted(
        ["sender_aid", "descriptor", "message_id", "timestamp", "pop_nonce"]
    )


def test_aid_derivation_matches():
    adm = VECTORS["admission"]
    seed = bytes.fromhex(adm["inputs"]["agent_seed_hex"])
    # Re-derive the public key from the seed and check the AID against the reference.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    assert aid_from_pubkey(pub) == adm["derived"]["sender_aid"]


def test_tct_verify_valid_and_tampered():
    t = VECTORS["tct"]
    c = t["inputs"]["commitment"]
    assert (
        verify_tct(t["issuer_aid"], t["signed_artifact_jws"], c, now_s=1_700_000_001)
        is True
    )
    assert (
        verify_tct(
            t["issuer_aid"],
            t["signed_artifact_jws"],
            {**c, "action": "ALLOW"},
            now_s=1_700_000_001,
        )
        is False
    )


def test_tct_verify_fails_closed():
    t = VECTORS["tct"]
    c, jws, iss = t["inputs"]["commitment"], t["signed_artifact_jws"], t["issuer_aid"]
    h, p, s = jws.split(".")
    cases = {
        "expired": (iss, jws, 9_999_999_999),
        "not-3-parts": (iss, "not.a", 1_700_000_001),
        "wrong-issuer-key": ("aid:pubkey:ed25519:" + "A" * 43, jws, 1_700_000_001),
        "unsupported-aid": ("did:web:example.com", jws, 1_700_000_001),
        "tampered-signature": (iss, f"{h}.{p}.{s[:-4]}AAAA", 1_700_000_001),
    }
    for name, (issuer, token, now) in cases.items():
        assert verify_tct(issuer, token, c, now_s=now) is False, (
            f"{name} must fail closed"
        )


def test_derived_uuid_vectors():
    """P9's one primitive, pinned by all three runtime-emitted vectors: the KAT, the PoP
    `message_id`, and the TCT `jti`."""
    from seam_sdk import derived_uuid

    blk = VECTORS["derived_uuid"]
    names = [k for k in blk if k != "rule"]
    assert names == ["kat_derived_uuid_001", "pop_message_id", "tct_jti"], names
    for name in names:
        v = blk[name]
        assert (
            str(derived_uuid(v["tag"], bytes.fromhex(v["input_hex"]))) == v["uuid"]
        ), name
    assert blk["kat_derived_uuid_001"]["uuid"] == "27b131ae-bcc6-4466-ab32-1d0f896453b1"


def test_pop_message_id_is_derived_from_the_nonce_text():
    """The admission `message_id` is `derived_uuid("seam-pop-mid-v1", nonce ASCII)`: a function of
    the nonce, so a replayed presentation carries the same id, and the presentation vector's own
    `message_id` is reproduced (it is not random)."""
    from seam_sdk import pop_message_id

    v = VECTORS["derived_uuid"]["pop_message_id"]
    nonce = bytes.fromhex(v["input_hex"]).decode("ascii")
    assert str(pop_message_id(nonce)) == v["uuid"]
    adm = VECTORS["admission"]
    assert adm["presentation"]["message_id"] == str(
        pop_message_id(adm["inputs"]["pop_nonce"])
    )


def test_chain_head_attestation_signature_verifies():
    """The chain-head attestation must verify against the pinned issuer AID, and a tamper must not (A14)."""
    from seam_sdk.crypto import verify_chain_head_attestation

    v = VECTORS["chain_head_attestation"]
    i = v["inputs"]
    ok = verify_chain_head_attestation(
        v["issuer_aid"],
        i["attested_len"],
        bytes.fromhex(i["attested_head_hex"]),
        i["attested_at"],
        i["digest_schema"],
        bytes.fromhex(v["signature_hex"]),
        tenant="",
    )
    assert ok is True
    # A tampered length must not verify (it is bound into the signed preimage).
    assert (
        verify_chain_head_attestation(
            v["issuer_aid"],
            i["attested_len"] + 1,
            bytes.fromhex(i["attested_head_hex"]),
            i["attested_at"],
            i["digest_schema"],
            bytes.fromhex(v["signature_hex"]),
            tenant="",
        )
        is False
    )


# ── Commitment-digest framing coverage (W5.4 / G4) ────────────────────────────────────────────────
#
# `seam-commitment-digest:v1` is implemented byte-for-byte in ALL FIVE SDK languages — the widest
# fan-out of any framing in this repo — and it has no vector section of its own. It cannot get one
# here either: seam-runtime's `sdk-digest-parity` job byte-diffs the whole of
# `conformance/vectors.json` against its own emitter, so a block added on this side turns the
# runtime's CI red. A vector for it must originate there.
#
# What is available is stronger than it first appears. `verify_tct` recomputes the digest and
# compares it to the `seam-commitment-digest:` grant inside the runtime-signed JWS, so the vector
# already carries a runtime-produced expected value for one commitment. The gap was never coverage
# of the digest — it was coverage of the FIELD TUPLE: the only pre-existing test tampered `action`,
# so exactly one of the seven framing inputs was proven bound.
#
# That gap is not theoretical, and the difference is demonstrable: an implementation that silently
# drops `supersedes` from the preimage passes the pre-existing KAT test — the vector's commitment
# has no `supersedes`, so the bytes are identical — and fails the first test below.

NOW_S = 1_700_000_001


def test_commitment_digest_binds_every_field():
    """Every field the digest binds must actually be bound.

    A field dropped from the preimage, or reordered, lets one artifact verify under another's
    signature — which is the whole point of the digest: it attests *who* committed and *how* they
    authed, not just the decision.
    """
    t = VECTORS["tct"]
    base, jws, iss = (
        t["inputs"]["commitment"],
        t["signed_artifact_jws"],
        t["issuer_aid"],
    )

    assert verify_tct(iss, jws, base, now_s=NOW_S) is True, (
        "the unmodified vector commitment must verify — nothing below means anything otherwise"
    )

    mutations = {
        "id": {"id": base["id"] + "-x"},
        "action": {"action": "ALLOW"},
        "authority": {"authority": base["authority"] + "-x"},
        # The vector's commitment omits `supersedes`, so absent is the branch already exercised.
        # This pins the PRESENT branch, which nothing covered: absent and present must differ, or a
        # supersession could be stripped from a sealed record undetected.
        "supersedes (absent -> present)": {"supersedes": "k-previous"},
        "auth_method": {"auth_method": base["auth_method"] + "-x"},
        "trust_basis": {"trust_basis": base["trust_basis"] + "-x"},
        # seam-commitment-digest:v2 (#802/#804): the committer and the sealed explanation are bound.
        "committer": {"committer": base["committer"] + "-x"},
        "explanation (reason)": {
            "explanation": [{**base["explanation"][0], "reason": "edited"}]
            + base["explanation"][1:]
        },
        "explanation (dropped entry)": {"explanation": base["explanation"][:-1]},
        "explanation (reordered)": {"explanation": base["explanation"][::-1]},
    }
    for field, change in mutations.items():
        assert verify_tct(iss, jws, {**base, **change}, now_s=NOW_S) is False, (
            f"changing {field} did not change the commitment digest — that field is not bound"
        )


def test_commitment_digest_is_injective_across_field_boundaries():
    """The length prefixes are load-bearing; this notices if someone "simplifies" them away.

    Both `seam-store` and `seam-trust-aitp` record the reason in their own source: without an
    8-byte big-endian length before each field, ``("a\\0b","c")`` and ``("a","b\\0c")`` produce
    identical preimages, letting one Commitment verify under another's TCT. The fields are arbitrary
    text that may itself contain NUL (UTF-8 permits U+0000, and it survives the JSON/prost decision
    path), so this is reachable rather than theoretical.
    """
    t = VECTORS["tct"]
    base, jws, iss = (
        t["inputs"]["commitment"],
        t["signed_artifact_jws"],
        t["issuer_aid"],
    )

    # Fold the id/action boundary into `id` with a NUL. Under a NUL-joined framing this collides
    # with the real commitment; under length-prefixing it cannot.
    shifted = {**base, "id": base["id"] + "\x00" + base["action"], "action": ""}

    assert verify_tct(iss, jws, shifted, now_s=NOW_S) is False, (
        "a boundary-shifted commitment verified — the framing is separator-joined, not "
        "length-prefixed, and one artifact can now verify under another's signature"
    )


# ── record_digest_v4 (P7) ─────────────────────────────────────────────────────────────────────────
#
# The v4 cases come from TWO runtime files, both vendored byte-identical:
#
#   * `conformance/vectors.json` carries `record_digest_v4` and `record_digest_v4_absent_policy`.
#     seam-runtime's `sdk-digest-parity` gate diffs that whole file against its own emitter, and
#     loads `seam_sdk/crypto.py` standalone to recompute both blocks.
#   * `conformance/vectors_extended.json` carries three more v4 cases (every optional present, every
#     optional absent, and `mode: ""` as distinct from `mode: null`), deliberately kept out of the
#     byte-diffed file upstream. It also carries `chain_head_attestation_v2`, which is tested where
#     that framing is.
#
# v1 to v3 are deleted, not dual-verified: a v3 record is "cannot verify", never a guess.

_CONF = pathlib.Path(__file__).parents[2] / "conformance"
EXTENDED = json.loads((_CONF / "vectors_extended.json").read_text())
RUNTIME_V4_BLOCKS = ("record_digest_v4", "record_digest_v4_absent_policy")
EXTENDED_V4_CASES = ("all_optionals_present", "optionals_none", "mode_empty_string")


def _v4_cases():
    cases = []
    for block in RUNTIME_V4_BLOCKS:
        # A renamed or dropped runtime block is a BROKEN CROSS-REPO CONTRACT, not a thinner set.
        assert block in VECTORS, f"conformance/vectors.json has no `{block}` block"
        cases.append({"name": block, **VECTORS[block]})
    for name in EXTENDED_V4_CASES:
        assert name in EXTENDED, (
            f"conformance/vectors_extended.json has no `{name}` case"
        )
        cases.append({"name": name, **EXTENDED[name]})
    return cases


def _args(i):
    rules = i["policy_rules_digest_hex"]
    return (
        i["decision_id"],
        i["tenant"],
        i["namespace"],
        bytes.fromhex(i["ciphertext_digest_hex"]),
        i["sealed_at"],
        i["outcome"],
        i["mode"],
        i["policy_version"],
        i["supersedes"],
        bytes.fromhex(i["context_digest_hex"]),
        bytes.fromhex(i["participation_digest_hex"]),
        None if rules is None else bytes.fromhex(rules),
        i["classification"],
        bytes.fromhex(i["participants_digest_hex"]),
        i["trust_basis_commitment"],
        i["auth_method"],
        i["schema_version"],
    )


def _recompute(case):
    from seam_sdk.crypto import record_digest_v4

    return record_digest_v4(*_args(case["inputs"]))


def test_record_digest_v4_matches_reference_all_cases():
    for case in _v4_cases():
        assert case["inputs"]["domain"] == "seam.audit.record-digest.v4"
        assert _recompute(case).hex() == case["digest_hex"], case["name"]


def test_participants_digest_v4_matches_every_case():
    from seam_sdk import participants_digest_v4

    for case in _v4_cases():
        i = case["inputs"]
        assert (
            participants_digest_v4(i["participants"]).hex()
            == i["participants_digest_hex"]
        )


def test_the_ciphertext_digest_is_sha256_of_the_ciphertext():
    import hashlib

    for case in _v4_cases():
        i = case["inputs"]
        assert (
            hashlib.sha256(bytes.fromhex(i["ciphertext_hex"])).hexdigest()
            == (i["ciphertext_digest_hex"])
        )


def test_the_v4_comparison_is_not_vacuous():
    """Every slot is bound: changing any one input moves the digest."""
    base = VECTORS["record_digest_v4"]
    i = base["inputs"]
    changes = {
        "decision_id": i["decision_id"] + "x",
        "tenant": i["tenant"] + "x",
        "namespace": i["namespace"] + "x",
        "ciphertext_digest_hex": "00" * 32,
        "sealed_at": i["sealed_at"] + 1,
        "outcome": "Expired",
        "mode": None,
        "policy_version": "p",
        "supersedes": "s",
        "context_digest_hex": "00" * 32,
        "participation_digest_hex": "00" * 32,
        "policy_rules_digest_hex": None,
        "classification": "Public",
        "participants_digest_hex": "00" * 32,
        "trust_basis_commitment": i["trust_basis_commitment"] + "x",
        "auth_method": i["auth_method"] + "x",
    }
    for k, v in changes.items():
        assert _recompute({"inputs": {**i, k: v}}).hex() != base["digest_hex"], k


def test_absent_and_empty_mode_are_different_vectors():
    by = {c["name"]: c for c in _v4_cases()}
    assert by["optionals_none"]["inputs"]["mode"] is None
    assert by["mode_empty_string"]["inputs"]["mode"] == ""
    assert by["optionals_none"]["digest_hex"] != by["mode_empty_string"]["digest_hex"]


@pytest.mark.parametrize(
    "slot, tag",
    [
        ("context_digest_hex", 11),
        ("participation_digest_hex", 12),
        ("classification", 14),
        ("participants_digest_hex", 15),
        ("trust_basis_commitment", 16),
        ("auth_method", 17),
    ],
)
def test_a_stripped_mandatory_slot_is_refused_as_a_strip(slot, tag):
    """Tags 11, 12, 14, 15, 16 and 17 are mandatory. Absent (or `len == 0`, which is how the wire
    says absent) is a STRIP, reported distinctly, never a quiet digest over an empty slot."""
    from seam_sdk.crypto import RecordDigestStripError, record_digest_v4

    i = VECTORS["record_digest_v4"]["inputs"]
    empty = b"" if slot.endswith("_hex") else ""
    for stripped in (None, empty):
        args = list(_args(i))
        args[_args_keys().index(slot)] = stripped
        with pytest.raises(RecordDigestStripError) as excinfo:
            record_digest_v4(*args)
        assert excinfo.value.wire_tag == tag


def _args_keys():
    return (
        "decision_id",
        "tenant",
        "namespace",
        "ciphertext_digest_hex",
        "sealed_at",
        "outcome",
        "mode",
        "policy_version",
        "supersedes",
        "context_digest_hex",
        "participation_digest_hex",
        "policy_rules_digest_hex",
        "classification",
        "participants_digest_hex",
        "trust_basis_commitment",
        "auth_method",
        "schema_version",
    )


@pytest.mark.parametrize("version", [1, 2, 3, 5, 0])
def test_any_other_schema_version_cannot_verify(version):
    """v4 is the only formula. A v3 record is refused as unsupported, never recomputed under v4
    (which would read as tamper) and never under a retained v3 (which no longer exists)."""
    from seam_sdk.crypto import UnsupportedRecordDigestVersion, record_digest_v4

    args = list(_args(VECTORS["record_digest_v4"]["inputs"]))
    args[-1] = version
    with pytest.raises(UnsupportedRecordDigestVersion) as excinfo:
        record_digest_v4(*args)
    assert excinfo.value.schema_version == version


def test_text_is_hashed_as_given_never_normalised():
    """NFC and NFD spellings of the same text are different digests: the digest binds bytes."""
    import unicodedata

    i = VECTORS["record_digest_v4"]["inputs"]
    nfc = unicodedata.normalize("NFC", "approuvé")
    nfd = unicodedata.normalize("NFD", "approuvé")
    assert nfc != nfd
    a = _recompute({"inputs": {**i, "outcome": nfc}})
    b = _recompute({"inputs": {**i, "outcome": nfd}})
    assert a != b


def test_the_retired_formulas_are_gone():
    import seam_sdk
    import seam_sdk.crypto as c

    for name in ("record_digest_v2", "record_digest_v3"):
        assert not hasattr(c, name) and not hasattr(seam_sdk, name), name
