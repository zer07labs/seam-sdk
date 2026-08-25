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


def test_record_digest_v2_matches_reference():
    """The v2 record-digest framing must reproduce the Rust reference byte-for-byte (A14 design-a)."""
    from seam_sdk.crypto import record_digest_v2

    v = VECTORS["record_digest_v2"]
    i = v["inputs"]
    got = record_digest_v2(
        i["decision_id"],
        i["tenant"],
        i["namespace"],
        bytes.fromhex(i["ciphertext_digest_hex"]),
        i["sealed_at"],
        i["outcome"],
        i["mode"],
        i["policy_version"],
        i["supersedes"],
        i["schema_version"],
    )
    assert got.hex() == v["digest_hex"]


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


# ── record_digest_v3 (issue #56, B3 Phase 2) ─────────────────────────────────────────────────────
#
# The v3 cases come from TWO files, and the split is deliberate:
#
#   * `conformance/vectors.json` carries `record_digest_v3` and `record_digest_v3_absent_policy`,
#     one `{inputs, digest_hex}` each. Those bytes are seam-runtime's — its `sdk-digest-parity` gate
#     runs `diff -u` between that whole file and its own emitter's output, so the two repos agree on
#     every byte, not merely on every digest. Reproducing them is what "four independent
#     implementations agree" actually means, and it is the check that must never be skipped.
#
#   * `conformance/record_digest_v3_extended.json` carries five more cases, emitted by THIS repo's
#     implementation. Two fixtures cannot express `mode: ""` vs `mode: null`, and carry no decomposed
#     non-ASCII — both traps the spec singles out. Adopting these upstream is proposed separately;
#     until then they live here so the coverage exists somewhere rather than nowhere.
#
# So the tests below are of two kinds: reproduce every case from both files, AND prove the extended
# file was not hand-edited.

EXTENDED_V3 = json.loads(
    (
        pathlib.Path(__file__).parents[2]
        / "conformance"
        / "record_digest_v3_extended.json"
    ).read_text()
)

#: block name in `vectors.json` → the name it takes once normalised into the extended shape.
RUNTIME_V3_BLOCKS = {
    "record_digest_v3": "runtime_bound_policy",
    "record_digest_v3_absent_policy": "runtime_absent_policy",
}


def _v3_cases():
    cases = []
    for block, name in RUNTIME_V3_BLOCKS.items():
        # A renamed or dropped runtime block is a BROKEN CROSS-REPO CONTRACT, not a thinner vector
        # set — fail loudly here rather than quietly testing five SDK-authored cases and calling it
        # parity.
        assert block in VECTORS, (
            f"conformance/vectors.json has no `{block}` block. That file is byte-diffed by "
            "seam-runtime's sdk-digest-parity gate; a missing block means this repo and the "
            "runtime have stopped agreeing on the vector set, not that a case was tidied away."
        )
        b = VECTORS[block]
        cases.append(
            {"name": name, "inputs": b["inputs"], "digest_hex": b["digest_hex"]}
        )
    extended = EXTENDED_V3["cases"]
    # Guard-the-guard: an empty or renamed block would make every loop below vacuous.
    assert extended, (
        "record_digest_v3_extended.json carries zero cases — the vector proves nothing"
    )
    cases.extend(extended)
    return cases


def _recompute(case):
    from seam_sdk.crypto import record_digest_v3

    i = case["inputs"]
    rules = i["policy_rules_digest_hex"]
    return record_digest_v3(
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
        i["schema_version"],
    )


def test_record_digest_v3_matches_reference_all_cases():
    for case in _v3_cases():
        assert _recompute(case).hex() == case["digest_hex"], (
            f"case {case['name']!r} disagrees"
        )


def test_the_v3_comparison_is_not_vacuous():
    # A loop that compared a value to itself, or a `bytes.fromhex` that silently produced the same
    # input for every case, would pass the test above forever. Corrupt one input and require the
    # recompute to move.
    case = dict(_v3_cases()[0])
    case["inputs"] = dict(case["inputs"], tenant="not-acme")
    assert _recompute(case).hex() != case["digest_hex"]


def test_the_v3_cases_cover_the_traps_they_exist_for():
    """Each case is here for a named reason; assert the set has not been quietly trimmed."""
    names = {c["name"] for c in _v3_cases()}
    assert {
        # seam-runtime's own two blocks — the cross-repo contract.
        "runtime_bound_policy",
        "runtime_absent_policy",
        # this repo's extended set.
        "all_optionals_present",
        "policy_rules_absent",
        "optionals_none",
        "mode_empty_string",
        "non_ascii_nfd",
    } <= names, f"a v3 vector case was removed: have {sorted(names)}"


def test_absent_and_empty_mode_are_different_vectors():
    # opt(None) is one byte, opt(Some("")) is five. Pinned cross-language here rather than only as a
    # Python unit test, because it is a distinction a TS or Rust transcription can collapse on its
    # own — `null` and `""` are easy to conflate at a JSON boundary.
    by_name = {c["name"]: c for c in _v3_cases()}
    none_case, empty_case = by_name["optionals_none"], by_name["mode_empty_string"]
    assert none_case["inputs"]["mode"] is None and empty_case["inputs"]["mode"] == ""
    assert none_case["digest_hex"] != empty_case["digest_hex"]


def test_the_two_mandatory_sub_digests_differ_in_every_case():
    # Slots 10 and 11 are adjacent and are offset by one from their wire tags, so an implementation
    # that wires them by tag number produces a swap. Equal fixtures would make that swap invisible —
    # this asserts the vectors can actually catch it.
    for case in _v3_cases():
        i = case["inputs"]
        assert i["context_digest_hex"] != i["participation_digest_hex"], case["name"]


def test_at_least_one_case_is_not_ascii():
    # The spec requires raw UTF-8 with no normalization and singles it out as the step
    # implementations get wrong. An all-ASCII vector set cannot distinguish a conforming
    # implementation from one that normalizes or uses the wrong codec.
    assert any(
        not str(v).isascii()
        for case in _v3_cases()
        for v in case["inputs"].values()
        if isinstance(v, str)
    ), (
        "every v3 vector input is ASCII — the normalization trap is untested cross-language"
    )


def test_the_non_ascii_case_is_still_in_a_decomposed_form():
    """Non-ASCII is necessary but nowhere near sufficient.

    `test_at_least_one_case_is_not_ascii` passes just as happily on NFC text — so if anything ever
    normalized either the emitter's source literal or this file, that guard stays green while the
    case quietly stops being able to fail a normalizing implementation. This asserts the property
    the case actually claims, against the committed bytes rather than against the emitter.
    """
    import unicodedata

    by_name = {c["name"]: c for c in _v3_cases()}
    strings = [
        v for v in by_name["non_ascii_nfd"]["inputs"].values() if isinstance(v, str)
    ]
    decomposed = [s for s in strings if unicodedata.normalize("NFC", s) != s]
    assert decomposed, (
        "the non_ascii_nfd vector carries no decomposed text any more — every string in it is "
        "unchanged by NFC normalization, so an implementation that normalizes before hashing "
        "would reproduce this case and the vector has stopped testing the spec rule it exists for."
    )


def test_the_case_loader_refuses_a_missing_runtime_block():
    """The property every v3 test above rests on: the loader cannot quietly stop testing anything.

    A guard that has never been watched to fire is not a guard — it is a comment with a keyword in
    it. So this doctors the loaded document and requires the refusal, per block: a version that
    checked only the first would let the second disappear in silence, which is the exact hole the
    Rust twin had before it was parametrized.
    """
    for block in RUNTIME_V3_BLOCKS:
        saved = VECTORS.pop(block)
        try:
            with pytest.raises(AssertionError, match=block):
                _v3_cases()
        finally:
            VECTORS[block] = saved


def test_the_case_loader_refuses_an_emptied_extended_set():
    # The other way the loop goes vacuous: the file is present and parses, but carries nothing.
    saved = EXTENDED_V3["cases"]
    EXTENDED_V3["cases"] = []
    try:
        with pytest.raises(AssertionError, match="zero cases"):
            _v3_cases()
    finally:
        EXTENDED_V3["cases"] = saved


def test_the_extended_v3_file_is_what_the_emitter_produces():
    """The committed extended file must be byte-identical to a fresh run of the emitter.

    This is the check that makes "vectors are never transcribed by hand" enforceable rather than
    aspirational: edit a `digest_hex` in the file and this goes red, because the emitter recomputes
    it. It also pins the RENDERING (indent, escaping, key order) — which is what makes adopting
    these cases into `conformance/vectors.json` upstream a copy rather than a re-render.

    `conformance/vectors.json` itself is deliberately NOT emitted here: those bytes are
    seam-runtime's. What proves them is recomputation — `test_record_digest_v3_matches_reference_
    all_cases` runs this repo's implementation against them like any other case.
    """
    import subprocess
    import sys

    repo = pathlib.Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [
            sys.executable,
            str(repo / "scripts" / "emit_record_digest_v3_vectors.py"),
            "--check",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, (
        "conformance/record_digest_v3_extended.json is not what "
        "scripts/emit_record_digest_v3_vectors.py emits.\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
