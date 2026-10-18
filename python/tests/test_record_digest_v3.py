"""`record_digest_v3` — the v3 `DECISION_SEALED` record digest, transcribed from the spec.

WHAT THIS PROVES, AND WHY EACH PART IS HERE
-------------------------------------------
v3 is `record_digest_v2` plus three columns that arrive as **opaque 32-byte sub-digests on the wire**
(tags 11/12/13). The sub-digest formulas belong to the runtime and to auditors; this SDK recomputes
only the outer digest, exactly as it does for v2.

The value of four independent implementations agreeing is that they were written independently. So
this suite never asserts a digest against a number someone copied from somewhere — it asserts
*structure*:

1. **Every input is bound.** Perturb any one of them and the digest must move. A formula that dropped
   a slot, or framed one it should have opted, passes a fixed-vector test and fails this one.
2. **The two orderings the spec warns about.** Digest slot indices are offset by one from the proto
   tags (`context_digest` is slot 10, wire tag 11), and the new slots are *inserted before*
   `schema_version` rather than appended after it. A swap of the two mandatory digests is the decoy
   for the first; only distinct values can catch it, so the fixtures are distinct by construction.
3. **`None` is not `b""`.** `opt(None)` is one byte, `opt(b"")` is five — so at this API the two are
   distinct inputs, and the empty one is REFUSED rather than hashed, because the empty digest is
   outside these slots' value domain. ("Present-but-empty is data" applies to the *string* slots,
   `mode`/`policy_version`/`supersedes`. On the WIRE, `len == 0` is absence for tags 10-13 — a total
   mapping — which the streamed helpers apply before calling in.)
4. **Strip is refused, and is not a mismatch.** The spec requires a v3 record missing tag 11 or 12 to
   be refused — never defaulted to an empty digest, never fallen back to v2 — and requires that
   refusal to be reported *distinctly* from a digest mismatch, because "someone removed a field" and
   "someone rewrote one" have different responses. Here that distinction is structural: a strip
   raises, a mismatch is an unequal return value.

The exact digest values live in `conformance/vectors.json` and are checked by `test_conformance.py`
against the same reference the other languages read. This file deliberately holds no hex constants of
its own except the frozen v2 regression pin — a second copy of a digest is a second thing to drift.
"""

from __future__ import annotations

import array
import hashlib
import inspect

import pytest

from seam_sdk.crypto import (
    RecordDigestStripError,
    record_digest_v2,
    record_digest_v3,
)

CTX = hashlib.sha256(b"context").digest()
PART = hashlib.sha256(b"participation").digest()
RULES = hashlib.sha256(b"policy-rules").digest()
CIPHERTEXT_DIGEST = hashlib.sha256(b"ciphertext").digest()

#: Every mandatory-and-optional slot populated, so a mutation test can move any one of them.
BASE = dict(
    decision_id="dec:unit",
    tenant="acme",
    namespace="fraud",
    ciphertext_digest=CIPHERTEXT_DIGEST,
    sealed_at=1_700_000_000_000,
    outcome="Resolved",
    mode="decision.v1",
    policy_version="policy-7",
    supersedes="dec:prior",
    context_digest=CTX,
    participation_digest=PART,
    policy_rules_digest=RULES,
)


def digest(**overrides) -> bytes:
    return record_digest_v3(**{**BASE, **overrides})


def test_the_fixtures_are_distinct_so_a_slot_swap_is_detectable():
    # Guard-the-guard for the swap decoy below: if context and participation held the SAME bytes,
    # swapping them would be a no-op and `test_swapping_the_two_mandatory_digests_changes_it` would
    # pass against an implementation that had them in the wrong order.
    assert CTX != PART != RULES
    assert len({CTX, PART, RULES, CIPHERTEXT_DIGEST}) == 4


# ── 1. every input is bound ──────────────────────────────────────────────────────────────────────

MUTATIONS = [
    ("decision_id", "dec:other"),
    ("tenant", "other"),
    ("namespace", "other"),
    ("ciphertext_digest", hashlib.sha256(b"other-ciphertext").digest()),
    ("sealed_at", 1_700_000_000_001),
    ("outcome", "Declined"),
    ("mode", "decision.v2"),
    ("policy_version", "policy-8"),
    ("supersedes", "dec:other-prior"),
    ("context_digest", hashlib.sha256(b"other-context").digest()),
    ("participation_digest", hashlib.sha256(b"other-participation").digest()),
    ("policy_rules_digest", hashlib.sha256(b"other-rules").digest()),
    ("schema_version", 4),
]


@pytest.mark.parametrize(("field", "value"), MUTATIONS, ids=lambda v: str(v)[:24])
def test_every_input_is_bound(field, value):
    assert digest() != digest(**{field: value}), (
        f"changing {field} did not change the digest — that slot is not in the preimage, or is "
        f"being written with a constant"
    )


def test_the_mutation_table_covers_every_parameter():
    # Guard-the-guard: the table above is hand-written, so a parameter added to the function later
    # would silently go untested. Derive the parameter list from the function itself.
    import inspect

    params = set(inspect.signature(record_digest_v3).parameters) - {"self"}
    assert params == {f for f, _ in MUTATIONS}, (
        "record_digest_v3's parameters and the MUTATIONS table have diverged: "
        f"untested={params - {f for f, _ in MUTATIONS}}, stale={ {f for f, _ in MUTATIONS} - params }"
    )


def test_swapping_the_two_mandatory_digests_changes_it():
    # The decoy for the slot/tag offset. `context_digest` is preimage slot 10 but wire tag 11; an
    # implementation that wired them by tag number rather than by slot produces this exact swap, and
    # it is invisible to any test that uses the same value for both.
    assert digest() != digest(context_digest=PART, participation_digest=CTX)


def test_dropping_the_optional_policy_rules_digest_changes_it():
    assert digest() != digest(policy_rules_digest=None)


# ── 2. None is not empty ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("field", ["mode", "policy_version", "supersedes"])
def test_none_is_not_the_empty_string(field):
    # opt(None) is one byte; opt(Some("")) is five. A present-but-empty string is data.
    assert digest(**{field: None}) != digest(**{field: ""})


def test_none_is_not_empty_bytes_for_the_optional_digest():
    # The bytes twin of the rule above, on the one `opt`-encoded digest slot. An empty
    # policy_rules_digest is malformed rather than merely different — so this asserts the refusal,
    # which is the stronger property: the two cannot collide because one of them cannot be built.
    with pytest.raises(RecordDigestStripError):
        digest(policy_rules_digest=b"")


# ── 3. strip refusal, and its distinctness from a mismatch ───────────────────────────────────────


@pytest.mark.parametrize(
    ("field", "tag"), [("context_digest", 11), ("participation_digest", 12)]
)
def test_a_missing_mandatory_digest_is_refused_as_a_strip(field, tag):
    with pytest.raises(RecordDigestStripError) as exc:
        digest(**{field: None})
    message = str(exc.value)
    assert field in message and f"tag {tag}" in message
    assert "STRIP" in message.upper()
    # The requirement is not merely "it fails" — it is that an operator can tell this from a
    # rewrite. Asserting the absence of the mismatch vocabulary is what pins that.
    assert "does not match" not in message.lower()


@pytest.mark.parametrize("field", ["context_digest", "participation_digest"])
@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_a_wrong_length_mandatory_digest_is_refused_not_hashed(field, length):
    with pytest.raises(RecordDigestStripError) as exc:
        digest(**{field: b"\x11" * length})
    assert str(length) in str(exc.value)


def test_a_present_but_wrong_length_policy_rules_digest_is_refused():
    with pytest.raises(RecordDigestStripError):
        digest(policy_rules_digest=b"\x11" * 31)


def test_the_refusal_is_a_typed_error_and_not_an_incidental_TypeError():
    # Without the explicit guard, passing None would reach `_frame(None)` and die inside `len()` as a
    # TypeError — fail-loud, but unactionable: an operator cannot tell a strip attack from a caller
    # bug. This asserts the guard is doing the work, not the interpreter.
    with pytest.raises(RecordDigestStripError) as exc:
        digest(context_digest=None)
    assert not isinstance(exc.value, TypeError)
    # It stays a ValueError so existing `except ValueError` handlers around these helpers keep working.
    assert isinstance(exc.value, ValueError)


def test_strip_and_mismatch_are_distinguishable_by_a_caller():
    # The property the spec actually asks for, written the way a consumer experiences it: a strip is
    # an exception, a mismatch is an unequal comparison. There is no code path that yields both.
    wire_digest = digest()
    assert (
        digest(outcome="Declined") != wire_digest
    )  # a rewrite: compares unequal, raises nothing
    with pytest.raises(RecordDigestStripError):  # a strip: raises, never compares
        digest(context_digest=None)


# ── 4. v2 is frozen ──────────────────────────────────────────────────────────────────────────────


def test_record_digest_v2_is_unchanged():
    # v2's bytes are frozen forever — every record ever sealed under it must keep recomputing. This
    # pins the committed conformance vector's inputs against its committed output, so a refactor that
    # touched the shared `_frame`/`_opt` helpers while adding v3 cannot pass unnoticed.
    got = record_digest_v2(
        decision_id="dec:conformance",
        tenant="acme",
        namespace="fraud",
        ciphertext_digest=bytes.fromhex(
            "67d9f6952981d85f7a2cabb0d5468e6934dc63ec55b480f18339277afc7635a6"
        ),
        sealed_at=1700000000000,
        outcome="Resolved",
        mode="decision.v1",
        policy_version=None,
        supersedes=None,
    )
    assert (
        got.hex() == "3817863521537d347c112bb95d7960d3d9f3007ee041f59c87bcaaf88ac40785"
    )


def test_v3_is_not_v2_with_a_different_domain_tag():
    # A transcription that changed only the domain string would produce a plausible-looking digest
    # that no other implementation reproduces. The three inserted slots must actually be in there.
    # Not an assertion about the whole preimage — just that v3's output cannot be reached by v2's
    # formula under any argument mapping, which is what "the slots are inserted" means observably.
    assert digest() != record_digest_v2(
        decision_id=BASE["decision_id"],
        tenant=BASE["tenant"],
        namespace=BASE["namespace"],
        ciphertext_digest=BASE["ciphertext_digest"],
        sealed_at=BASE["sealed_at"],
        outcome=BASE["outcome"],
        mode=BASE["mode"],
        policy_version=BASE["policy_version"],
        supersedes=BASE["supersedes"],
        schema_version=3,
    )


# ── 4b. strings hash as raw UTF-8, with no normalization ─────────────────────────────────────────

#: The same text in NFD (combining acute) and NFC (precomposed). Equal to a human and to any
#: normalizing comparison; different byte strings.
NFD = "cafe\u0301"
NFC = "caf\u00e9"


def test_the_normalization_fixtures_really_do_differ():
    # Guard-the-guard: if these two ever compared equal as Python strings, the tests below would be
    # asserting nothing. They are distinct strings whose NFC forms coincide.
    import unicodedata

    assert NFD != NFC
    assert unicodedata.normalize("NFC", NFD) == NFC
    assert NFD.encode() != NFC.encode()


@pytest.mark.parametrize(
    "field", ["decision_id", "tenant", "namespace", "outcome", "mode"]
)
def test_strings_are_hashed_as_raw_utf8_without_normalization(field):
    """The spec calls this out by name: strings hash as their raw UTF-8 bytes, with no Unicode
    NFC/NFD, no case folding, no trimming — because normalization is "a step three of four
    implementations would implement differently, or skip".

    Every other fixture in this file is ASCII, which cannot see the difference: an implementation
    that normalized, or that encoded as ASCII/UTF-16, reproduces every one of them. This is the only
    test that fails such an implementation, and it matters most as the template for the TypeScript
    and Rust transcriptions, where a codec mistake is the natural one to make.
    """
    assert digest(**{field: NFD}) != digest(**{field: NFC}), (
        f"{field} in NFD and NFC hashed the same — something is normalizing before encoding, and "
        f"this SDK will disagree with every other implementation on any non-ASCII input"
    )


def test_non_ascii_survives_at_all():
    # An `.encode("ascii")` would raise rather than mis-hash; assert the non-ASCII path is live so
    # the inequality above cannot pass by both sides erroring out identically.
    assert len(digest(decision_id=NFD)) == 32


# ── 5. the framing itself, transcribed a second time ─────────────────────────────────────────────


def test_the_preimage_is_assembled_exactly_as_the_spec_writes_it():
    """Build the preimage independently from the spec and compare.

    Everything above tests *relations* between outputs — which is what catches a dropped or
    misordered slot. It cannot catch `frame` where the spec says `opt`, or the reverse, on a value
    that is present: both encodings contain the value, so perturbing it moves the digest either way.
    That asymmetry is one of the traps the spec calls out by name (slots 10 and 11 are framed, slot
    12 is opted, precisely so "no participants" cannot alias with "field stripped"), so it needs a
    test that looks at the bytes.

    This is a second transcription, not a copy of the implementation: it is written from the spec's
    formula block, spelled out inline rather than reusing `crypto`'s helpers, so a bug in `_frame`
    or `_opt_bytes` shows up as a disagreement rather than cancelling out on both sides.
    """

    def fr(b: bytes) -> bytes:
        return len(b).to_bytes(4, "little") + b

    def op(b: bytes | None) -> bytes:
        return b"\x00" if b is None else b"\x01" + fr(b)

    for policy_rules in (RULES, None):
        expected = hashlib.sha256(
            fr(b"seam.audit.record-digest.v3")
            + fr(BASE["decision_id"].encode())
            + fr(BASE["tenant"].encode())
            + fr(BASE["namespace"].encode())
            + fr(BASE["ciphertext_digest"])
            + fr(BASE["sealed_at"].to_bytes(8, "little"))
            + fr(BASE["outcome"].encode())
            + op(BASE["mode"].encode())
            + op(BASE["policy_version"].encode())
            + op(BASE["supersedes"].encode())
            + fr(BASE["context_digest"])  # slot 10 — FRAMED, not opted
            + fr(BASE["participation_digest"])  # slot 11 — FRAMED, not opted
            + op(policy_rules)  # slot 12 — OPTED, not framed
            + fr((3).to_bytes(4, "little"))  # slot 13 — stays last
        ).digest()
        assert digest(policy_rules_digest=policy_rules) == expected


def test_the_new_slots_precede_schema_version():
    """The spec is explicit that the three new slots are *inserted before* `schema_version`, not
    appended after it — a verifier selects the whole formula by `schema_version`, so position is
    fixed by the spec rather than by append order. Appending is the natural mistake, and it produces
    a digest that nothing else in this file distinguishes."""

    def fr(b: bytes) -> bytes:
        return len(b).to_bytes(4, "little") + b

    def op(b: bytes | None) -> bytes:
        return b"\x00" if b is None else b"\x01" + fr(b)

    head = (
        fr(b"seam.audit.record-digest.v3")
        + fr(BASE["decision_id"].encode())
        + fr(BASE["tenant"].encode())
        + fr(BASE["namespace"].encode())
        + fr(BASE["ciphertext_digest"])
        + fr(BASE["sealed_at"].to_bytes(8, "little"))
        + fr(BASE["outcome"].encode())
        + op(BASE["mode"].encode())
        + op(BASE["policy_version"].encode())
        + op(BASE["supersedes"].encode())
    )
    new_slots = (
        fr(BASE["context_digest"]) + fr(BASE["participation_digest"]) + op(RULES)
    )
    version = fr((3).to_bytes(4, "little"))

    appended = hashlib.sha256(head + version + new_slots).digest()
    assert digest() != appended, (
        "the three v3 slots are being appended after schema_version instead of inserted before it"
    )


# ── 6. inputs that would otherwise produce a silently-wrong digest ───────────────────────────────


@pytest.mark.parametrize(
    "overrides,field,tag",
    [
        ({"context_digest": None}, "context_digest", 11),
        ({"participation_digest": None}, "participation_digest", 12),
        ({"context_digest": b"\x00" * 31}, "context_digest", 11),
        ({"policy_rules_digest": b"\x00" * 16}, "policy_rules_digest", 13),
    ],
)
def test_a_refusal_carries_the_field_and_tag_structurally(overrides, field, tag):
    """A caller routing a refusal — to an alert, a metric label, a retry decision — should never have
    to parse English to learn WHICH field was stripped. The TypeScript twin exposes the same two
    attributes; a divergence here would mean the two SDKs cannot be handled by one runbook."""
    with pytest.raises(RecordDigestStripError) as excinfo:
        digest(**overrides)
    assert excinfo.value.field == field
    assert excinfo.value.wire_tag == tag


@pytest.mark.parametrize(
    "key,tag",
    [
        ("context_digest", 11),
        ("participation_digest", 12),
        # Tag 13 is in this table because leaving it out is exactly the mistake that shipped once:
        # the first fix guarded tags 11 and 12, the test parametrized 11 and 12, and
        # `policy_rules_digest` kept the hole with a green suite three lines away from the guard.
        ("policy_rules_digest", 13),
    ],
)
@pytest.mark.parametrize(
    "decoy",
    ["x" * 32, ["x"] * 32, 32, object()],
    ids=["str", "list", "int", "object"],
)
def test_a_non_bytes_sub_digest_is_refused_as_a_named_field(key, tag, decoy):
    """A 32-character `str` has the right `len()`. Without a type check it reaches `_frame` and dies
    there as a bare `TypeError` naming neither the field nor the tag — a caller mistake reported as
    an internal one. The TypeScript twin has the sharper version of the same problem: there it
    coerces to 32 zero bytes and produces a digest that ALIASES a legitimate all-zeros one."""
    with pytest.raises(RecordDigestStripError) as excinfo:
        digest(**{key: decoy})
    assert excinfo.value.field == key
    assert excinfo.value.wire_tag == tag
    assert "not bytes" in str(excinfo.value)


@pytest.mark.parametrize(
    "key,tag",
    [("context_digest", 11), ("participation_digest", 12), ("policy_rules_digest", 13)],
)
def test_a_wide_element_memoryview_is_refused_rather_than_mismeasured(key, tag):
    """``len(memoryview)`` is the ELEMENT count, not the byte count. A ``memoryview`` over an
    ``array("H", [0] * 16)`` has ``len() == 16`` and ``nbytes == 32``, so a length check written over
    ``len()`` would frame it as 16 bytes and then append 32 — a length prefix that lies about its own
    content, which is exactly the property framing exists to provide."""
    # Exactly 32 BYTES, so the length check cannot catch it — only the itemsize check can. Two
    # hazards in one fixture: `len()` reports 16 where `nbytes` is 32 (a length prefix that would lie
    # about its own content), and the backing bytes are in HOST order, so accepting it would make the
    # digest depend on the endianness of the machine that computed it.
    wide = memoryview(array.array("H", [0] * 16))
    assert len(wide) == 16 and wide.nbytes == 32, (
        "the fixture no longer shows the hazard"
    )
    with pytest.raises(RecordDigestStripError) as excinfo:
        digest(**{key: wide})
    assert excinfo.value.field == key
    assert excinfo.value.wire_tag == tag


def test_any_one_byte_buffer_is_accepted_as_the_bytes_it_holds():
    """The guard must not overshoot. `bytes`, `bytearray`, a `memoryview` and a one-byte `array` are
    four spellings of the same 32 bytes and must digest identically — the TypeScript twin accepts the
    same set (`Buffer`, `Uint8Array`, `Uint8ClampedArray`, `Int8Array`) for the same reason: what is
    hashed is the bytes the caller holds, however they chose to hold them."""
    expected = digest()
    for spelling in (
        bytearray(CTX),
        memoryview(CTX),
        array.array("b", CTX),
        array.array("B", CTX),
    ):
        assert digest(context_digest=spelling) == expected


@pytest.mark.parametrize(
    "overrides,exc",
    [
        ({"sealed_at": -1}, ValueError),
        ({"sealed_at": 1 << 64}, ValueError),
        ({"sealed_at": 1.5}, TypeError),
        ({"sealed_at": True}, TypeError),
        ({"schema_version": -1}, ValueError),
        ({"schema_version": 1 << 32}, ValueError),
        ({"schema_version": "3"}, TypeError),
    ],
)
def test_an_out_of_range_integer_is_refused(overrides, exc):
    """Python's ``struct.pack`` refuses these anyway, but less legibly — and the TypeScript twin does
    NOT refuse them at all without help: ``DataView`` applies ToBigUint64/ToUint32 and wraps
    silently, so ``2**64 + 5`` writes the same bytes as ``5``. Checking in both keeps the two
    implementations agreeing on which inputs have a digest at all."""
    with pytest.raises(exc):
        digest(**overrides)


@pytest.mark.parametrize("slot", ["decision_id", "tenant", "namespace", "outcome"])
@pytest.mark.parametrize(
    "bad", [None, 5, b"bytes", object()], ids=["none", "int", "bytes", "obj"]
)
def test_a_non_string_in_a_mandatory_string_slot_is_refused(slot, bad):
    """`.encode()` on a non-str raises `AttributeError` — a traceback, not a diagnosis. The named
    `TypeError` says which slot. In TypeScript the same inputs are far worse: `TextEncoder` encodes
    whatever ToString gives it, so `None` would hash as the four-byte string "null"."""
    with pytest.raises(TypeError):
        digest(**{slot: bad})


@pytest.mark.parametrize("slot", ["mode", "policy_version", "supersedes"])
def test_an_optional_string_slot_takes_none_as_absence_but_refuses_a_non_string(slot):
    """`None` is data here (the `opt` presence byte), not a type error — so the type check must not
    swallow the distinction the whole `opt` encoding exists to express."""
    assert digest(**{slot: None}) != digest()
    with pytest.raises(TypeError):
        digest(**{slot: 5})


def test_a_non_bytes_ciphertext_digest_is_refused():
    """Wire tag 10 coerces exactly as the v3 sub-digests do, and is refused for the same reason."""
    with pytest.raises(TypeError):
        digest(ciphertext_digest="x" * 32)


@pytest.mark.parametrize(
    "slot",
    [
        "decision_id",
        "tenant",
        "namespace",
        "outcome",
        "mode",
        "policy_version",
        "supersedes",
    ],
)
def test_a_lone_surrogate_cannot_be_digested(slot):
    """``"\\ud800".encode()`` raises, so Python refuses this for free — but "for free" is exactly the
    kind of property that disappears in a refactor. TypeScript had to add an explicit guard (its
    ``TextEncoder`` silently substitutes U+FFFD instead), so this asserts the two languages agree
    that a string with no valid UTF-8 encoding produces no digest at all, rather than two different
    ones."""
    with pytest.raises(UnicodeEncodeError):
        digest(**{slot: "ctx-\ud800-tail"})


# ── 7. the class of defect, closed structurally ──────────────────────────────────────────────────
#
# Three verification rounds each found ONE more coercion path — tag 13 after tags 11 and 12, then
# `BigInt("5")` in the TypeScript twin after the range checks. Each fix was correct and each left the
# same class open, because "did I guard every slot against every wrong-typed value" is not a question
# hand-written per-slot tests can answer. This does answer it: every parameter is declared with the
# KIND of value it accepts, and every kind is driven with a corpus of values of the other kinds.
#
# The property is refusal, not correctness-of-digest: for anything outside a slot's declared kind
# there IS no correct digest, so returning one at all is the defect. The opposite direction — that
# legitimate values are still accepted, and that equivalent spellings of the same bytes agree — is
# what the vector loop and `test_any_one_byte_buffer_is_accepted_as_the_bytes_it_holds` cover.

SLOT_KINDS = {
    "decision_id": "text",
    "tenant": "text",
    "namespace": "text",
    "outcome": "text",
    "mode": "text",
    "policy_version": "text",
    "supersedes": "text",
    "ciphertext_digest": "bytes",
    "context_digest": "bytes",
    "participation_digest": "bytes",
    "policy_rules_digest": "bytes",
    "sealed_at": "uint",
    "schema_version": "uint",
}

#: Values that are NOT of the given kind. Python is far less eager to coerce than JavaScript, so most
#: of these already raise — but "already raises" is a property that disappears in a refactor, and the
#: two implementations have to agree on the refusal set, not merely each refuse something.
WRONG_KIND = {
    "bytes": [
        ("a 32-char str", "x" * 32),
        ("a list of 32", ["x"] * 32),
        ("an int", 32),
        ("a bool", True),
        ("a 32-byte wide-element view", memoryview(array.array("H", [0] * 16))),
    ],
    "text": [
        ("an int", 5),
        ("a bool", True),
        ("a list", ["a"]),
        ("bytes", b"abcd"),
        ("an object with __str__", type("S", (), {"__str__": lambda self: "a"})()),
    ],
    "uint": [
        ("a numeric str", "5"),
        # proto3 JSON renders int64 as a string. The TypeScript twin coerced this into the LEGITIMATE
        # digest via `BigInt("1700000000000")` until round 3 caught it; Python must refuse it too, or
        # the two SDKs disagree about whether a proto3-JSON caller gets a digest.
        ("a proto3-JSON int64 str", "1700000000000"),
        ("an empty str", ""),
        ("a bool", True),
        ("a float", 5.0),
        ("bytes", b"\x05"),
    ],
}


def test_no_slot_accepts_a_value_outside_its_declared_kind():
    baseline = digest()

    # Completeness: a parameter added to the signature and not classified here would be silently
    # exempt from every check below — which is precisely how tag 13 was missed the first time.
    params = set(inspect.signature(record_digest_v3).parameters)
    assert params == set(SLOT_KINDS), (
        f"SLOT_KINDS and the signature disagree: "
        f"missing {params - set(SLOT_KINDS)}, stale {set(SLOT_KINDS) - params}"
    )

    for slot, kind in SLOT_KINDS.items():
        for label, value in WRONG_KIND[kind]:
            try:
                got = digest(**{slot: value})
            except Exception:
                continue  # refused — the only acceptable outcome
            alias = (
                " (BYTE-IDENTICAL to the legitimate digest)" if got == baseline else ""
            )
            raise AssertionError(
                f"{slot} (declared {kind}) accepted {label} and returned a digest{alias}"
            )


def test_a_str_subclass_cannot_choose_its_own_bytes():
    """The Python analogue of the TypeScript twin's shadowed-``length`` hole, and the same discipline
    closes both: measure what you hash.

    ``value.encode()`` asks the VALUE what bytes it would like to be hashed as; a ``str`` subclass
    that overrides ``encode`` therefore controls the preimage while still passing every type check,
    every length check and every normalization check — it really is a ``str``, it is simply lying
    about its UTF-8. ``str.encode(value)`` asks the string. The digest must come out as though the
    override were not there."""

    class Liar(str):
        def encode(self, *a, **kw):  # noqa: ANN002, ANN003, ANN201
            return b"totally-different-bytes"

    for slot in (
        "decision_id",
        "tenant",
        "namespace",
        "outcome",
        "mode",
        "policy_version",
        "supersedes",
    ):
        honest = BASE[slot]
        assert isinstance(honest, str), f"{slot} is not a text slot"
        assert digest(**{slot: Liar(honest)}) == digest(), (
            f"{slot} hashed the bytes its value CHOSE rather than the bytes it IS"
        )


def test_a_bytes_subclass_cannot_choose_its_own_bytes():
    """The bytes-side twin of :func:`test_a_str_subclass_cannot_choose_its_own_bytes`, and the reason
    ``_as_bytes`` has no ``isinstance(value, bytes)`` fast path.

    ``bytes(value)`` honors ``__bytes__``. A ``bytes`` subclass whose real buffer is 32 zeros but
    whose ``__bytes__`` returns 32 ``0xff``s would therefore be hashed as the bytes it CLAIMS rather
    than the bytes it HOLDS — the same "ask the object what it would like to be hashed as" mistake,
    one type over. ``memoryview(...).tobytes()`` reads the C buffer, which no Python method can
    override."""

    class Liar(bytes):
        def __bytes__(self):  # noqa: ANN204
            return b"\xff" * 32

    honest = bytes(32)
    liar = Liar(honest)
    assert bytes(liar) == b"\xff" * 32, "the fixture no longer demonstrates the hazard"

    for slot in ("context_digest", "participation_digest", "policy_rules_digest"):
        assert digest(**{slot: liar}) == digest(**{slot: honest}), (
            f"{slot} hashed the bytes its value CLAIMED rather than the bytes it HOLDS"
        )
        assert digest(**{slot: liar}) != digest(**{slot: b"\xff" * 32}), (
            f"{slot} was hashed as 0xff*32 — the __bytes__ override won"
        )
