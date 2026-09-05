"""The Python half of the alias sweep — a different defect from TypeScript's, in the same place.

TypeScript's `DataView.setBigUint64` applies ToBigUint64, so `2**64 + 5` wrote the same eight bytes
as `5` and two distinct inputs reached one digest. Python's `struct.pack("<Q", ...)` never had that
bug: it raises `struct.error` rather than wrapping, so **Python has no alias**. Conflating the two
would be easy and wrong, so it is worth stating plainly.

What Python had instead was an escape route. `verify_chain_head_attestation` computed the digest
*outside* its `try`, so that `struct.error` propagated out of a function whose docstring promises
``False`` on any tamper — and an out-of-range length IS tampered input, not a caller bug. A caller
who wrote the obvious ``if not verify(...): reject()`` got an exception instead of a rejection.

The fix is an explicit range comparison rather than moving the recompute inside the `try`, because
that block ends in a blanket ``except Exception: return False``. Moving it would have swallowed the
`TypeError` a genuinely wrong TYPE raises, converting a caller bug into a silent "unverified" — the
one outcome worse than the crash being fixed. The tests below pin BOTH halves of that: out-of-range
returns ``False``, wrong-type still raises. The second is the one that would rot quietly, because
nothing about a green suite tells you a blanket except has widened underneath it.
"""

from __future__ import annotations

import base64
import collections
import datetime
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_sdk import crypto
from seam_sdk.crypto import jcs_canonicalize


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# A well-formed but unverifiable attestation. The signature is zeros, so anything reaching the
# Ed25519 check returns False on its own merits — which is why the assertions using it are about
# WHICH answer arrives (False vs. an exception) rather than about True. The one test that needs to
# distinguish "passed the range check" from "failed it quietly" signs for real instead.
_AID = "did:seam:x"
_HEAD = b"\x00" * 32
_SIG = b"\x00" * 64

U64 = 1 << 64
U32 = 1 << 32


@pytest.mark.parametrize(
    ("label", "attested_len", "attested_at", "digest_schema"),
    [
        ("attested_len above 2^64", U64 + 5, 0, 2),
        ("attested_len at 2^64 exactly", U64, 0, 2),
        ("attested_len negative", -1, 0, 2),
        ("attested_at above 2^64", 5, U64 + 5, 2),
        ("digest_schema above 2^32", 5, 0, U32 + 2),
        ("digest_schema negative", 5, 0, -1),
    ],
)
def test_an_out_of_range_slot_returns_false_rather_than_raising(
    label: str, attested_len: int, attested_at: int, digest_schema: int
) -> None:
    """The docstring says "``False`` on any tamper". Before this phase these raised `struct.error`.

    Asserted as `is False` rather than `not ...` on purpose: a function that returned `None` on this
    path would satisfy a falsiness check while breaking every caller that logs the verdict.
    """
    assert (
        crypto.verify_chain_head_attestation(
            _AID, attested_len, _HEAD, attested_at, digest_schema, _SIG
        )
        is False
    ), label


def test_the_range_boundary_is_inclusive_at_the_top_of_the_slot() -> None:
    """2^64-1 is a legal u64 and must still VERIFY, not be rejected as out of range.

    A guard that refuses the largest legal value is the same class of bug as one that accepts the
    smallest illegal one — it just fails in the direction nobody notices until a real chain gets
    long. Asserting `False` here would prove nothing, since `False` is also what a wrongly-rejecting
    guard returns; so this signs the boundary values for real and asserts `True`. That is the only
    assertion in this file that can tell "passed the range check" from "failed it quietly".
    """
    sk = Ed25519PrivateKey.generate()
    aid = "aid:pubkey:ed25519:" + _b64url(sk.public_key().public_bytes_raw())
    digest = crypto._chain_head_attestation_digest(
        U64 - 1, _HEAD, U64 - 1, U32 - 1, aid
    )
    sig = sk.sign(digest)
    assert (
        crypto.verify_chain_head_attestation(aid, U64 - 1, _HEAD, U64 - 1, U32 - 1, sig)
        is True
    ), "the largest legal value in every slot must still verify"
    # One past the top of the u64 slot, with the same signature: refused, and not by wrapping to a
    # value that would have verified. This is the alias TypeScript actually had, asserted negatively
    # here to pin that Python never grows it.
    assert (
        crypto.verify_chain_head_attestation(aid, U64, _HEAD, U64 - 1, U32 - 1, sig)
        is False
    )


@pytest.mark.parametrize(
    ("label", "args"),
    [
        ("non-bytes attested_head", (_AID, 5, "not-bytes", 0, 2, _SIG)),
        ("str attested_len", (_AID, "5", _HEAD, 0, 2, _SIG)),
        ("str attested_at", (_AID, 5, _HEAD, "0", 2, _SIG)),
        ("None digest_schema", (_AID, 5, _HEAD, 0, None, _SIG)),
    ],
)
def test_a_wrong_type_still_raises_and_is_not_swallowed_as_false(
    label: str, args: tuple
) -> None:
    """Criterion 5. This is the assertion that stops the fix from becoming a worse bug.

    Returning `False` here would tell a caller "this attestation did not verify" when the truth is
    "you passed a string where an integer goes" — a program error reported as a security verdict.
    The range check is a comparison for exactly this reason: `0 <= "5"` raises, it does not return
    a falsy answer.
    """
    with pytest.raises(TypeError):
        crypto.verify_chain_head_attestation(*args)


def test_python_refuses_a_lone_surrogate_object_key() -> None:
    """The other half of a cross-language agreement TypeScript only just started keeping.

    Python has always raised here, via `UnicodeEncodeError` on the UTF-8 encode. TypeScript checked
    string VALUES and never keys, so `{"\\ud800": 1}` canonicalized there and raised here — one
    implementation able to digest an object the other cannot represent, in a value whose entire
    purpose is to be identical everywhere. `ts/tests/digest_aliasing.test.ts` pins the TS side.

    Pinned here too, because "the languages agree" is a property of the pair: if Python's refusal
    ever softened, the agreement would break with the TypeScript test still green.
    """
    with pytest.raises(UnicodeEncodeError):
        crypto.jcs_canonicalize({"\ud800": 1})
    with pytest.raises(UnicodeEncodeError):
        crypto.jcs_canonicalize({"k": "\ud800"})
    # A correct surrogate PAIR is valid Unicode and must still canonicalize.
    assert crypto.jcs_canonicalize({"\U0001f600": 1}) == b'{"\xf0\x9f\x98\x80":1}'


@pytest.mark.parametrize(
    ("label", "args"),
    [
        ("bool attested_len (bool subclasses int)", (_AID, True, _HEAD, 0, 2, _SIG)),
        ("bool attested_at", (_AID, 5, _HEAD, False, 2, _SIG)),
        ("bool digest_schema", (_AID, 5, _HEAD, 0, True, _SIG)),
        ("float attested_len, integral value", (_AID, 5.0, _HEAD, 0, 2, _SIG)),
        ("float attested_at, fractional", (_AID, 5, _HEAD, 0.5, 2, _SIG)),
    ],
)
def test_bool_and_float_are_refused_rather_than_narrowed_to_an_int(
    label: str, args: tuple
) -> None:
    """Two ways to reach a digest that is not the one the caller meant, both closed by the type check.

    ``bool`` subclasses ``int``, so a range comparison alone accepts ``True`` and digests it as ``1``
    — while TypeScript's ``uintSlot`` refuses a non-number/bigint outright. That is a cross-language
    divergence in a signed value, which is the whole subject of this phase, so it is closed here
    rather than recorded as a wart.

    ``float`` is the same shape one slot along, and it was the more embarrassing of the two: ``5.0``
    passed the range comparison, reached ``struct.pack``, and raised ``struct.error``. A verifier
    that can answer ``True``, ``False``, ``TypeError`` *or* ``struct.error`` has a contract nobody
    can write a caller against. Now there are two answers, plus ``TypeError`` for caller bugs.
    """
    with pytest.raises(TypeError):
        crypto.verify_chain_head_attestation(*args)


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [
        ("sealed_at=True", {"sealed_at": True}),
        ("sealed_at=False", {"sealed_at": False}),
        ("schema_version=True", {"sealed_at": 1, "schema_version": True}),
        ("sealed_at=5.0", {"sealed_at": 5.0}),
        ("sealed_at='5'", {"sealed_at": "5"}),
    ],
)
def test_record_digest_v2_refuses_what_typescript_refuses(
    label: str, kwargs: dict
) -> None:
    """The divergence the *first* cut of this phase created, in the sibling function.

    Tightening `verify_chain_head_attestation` alone left `record_digest_v2(sealed_at=True)` digesting
    as `1` — `bool` subclasses `int`, `struct.pack` packs it happily — while TypeScript's `uintSlot`
    had just started refusing `true`. Both languages agreed *before* the phase (both digested it as
    1) and disagreed *after*, which is worse than either consistent answer: the phase would have
    closed three cross-language divergences by opening a fourth.

    `record_digest_v3` refused all of this from the day it was written, via the same validator. What
    changed is that v2 now shares it instead of trusting `struct.pack` to catch everything — which it
    did, except for the one case where `bool` is an `int`.
    """
    base = dict(
        decision_id="d",
        tenant="t",
        namespace="n",
        ciphertext_digest=b"\x00" * 32,
        outcome="OK",
        mode=None,
        policy_version=None,
        supersedes=None,
    )
    with pytest.raises(TypeError):
        crypto.record_digest_v2(**{**base, **kwargs})


def test_record_digest_v2_still_produces_the_frozen_digest_for_a_legal_value() -> None:
    """The control. Every refusal above is worthless if the accepted path moved by a byte.

    Measured against `git show HEAD:python/seam_sdk/crypto.py` over 20,000 randomized in-range
    inputs: 20,000 identical, 0 diverged. This pins one of them so the claim survives in the suite
    rather than only in a commit message.
    """
    got = crypto.record_digest_v2(
        decision_id="d",
        tenant="t",
        namespace="n",
        ciphertext_digest=b"\x00" * 32,
        sealed_at=1,
        outcome="OK",
        mode=None,
        policy_version=None,
        supersedes=None,
    )
    assert (
        got.hex() == "c61843a5fd08efe3de27a0e2bc2666064b905f158cc315bbf6d44aa008508447"
    )


@pytest.mark.parametrize(
    ("label", "args"),
    [
        ("out-of-range len + str attested_at", (_AID, U64, _HEAD, "7", 2, _SIG)),
        ("out-of-range len + str attested_head", (_AID, U64, "nope", 0, 2, _SIG)),
        ("out-of-range len + non-str issuer_aid", (5, U64, _HEAD, 0, 2, _SIG)),
        ("out-of-range at + bool digest_schema", (_AID, 5, _HEAD, U64, True, _SIG)),
    ],
)
def test_a_caller_bug_is_not_masked_by_tampered_input_in_another_slot(
    label: str, args: tuple
) -> None:
    """Types for every argument are checked before any range is.

    The first cut of this guard interleaved them, returning `False` on the first out-of-range slot —
    so `attested_len=2**64` alongside `attested_at="7"` answered "this attestation did not verify"
    about a call that never had a chance to. The guard's own comment claimed a wrong type always
    raises, and that claim held for every single-fault input and failed for every double-fault one:
    the combination nobody writes a test for, which is why there is now a test for it.

    Tampered-input-wins would have been a defensible rule too. What was not defensible was the
    comment asserting the opposite of what the code did.
    """
    with pytest.raises(TypeError):
        crypto.verify_chain_head_attestation(*args)


def test_out_of_range_alone_still_returns_false() -> None:
    """The control for the test above: reordering must not turn tampered input into an exception.

    Without this, the previous test is satisfied by a guard that raises on everything — which would
    break the documented `False`-on-any-tamper contract in the name of fixing it.
    """
    assert crypto.verify_chain_head_attestation(_AID, U64, _HEAD, 0, 2, _SIG) is False
    assert crypto.verify_chain_head_attestation(_AID, 5, _HEAD, U64, 2, _SIG) is False
    assert crypto.verify_chain_head_attestation(_AID, 5, _HEAD, 0, U32, _SIG) is False


def test_any_byte_sequence_is_still_accepted_for_attested_head() -> None:
    """The regression the `attested_head` type check introduced, and the reason it existed.

    That check was added so a wrong-typed argument could not hide behind an out-of-range one. Written
    as `isinstance(attested_head, (bytes, bytearray, memoryview))` it also narrowed the argument from
    *any* buffer-protocol object: `array.array("B", ...)` and a `ctypes` buffer both verified `True`
    before and raised `TypeError` after. A caller who was getting a correct verdict stopped getting
    one, to fix a bug they did not have.

    It now goes through `_as_bytes`, which is the module's single definition of "is this a byte
    sequence" and is what `record_digest_v3` already used — so the two functions cannot disagree
    about what bytes are, and the `memoryview` itemsize trap `_as_bytes` documents is handled in one
    place rather than endorsed in two.
    """
    import array
    import ctypes

    sk = Ed25519PrivateKey.generate()
    aid = "aid:pubkey:ed25519:" + _b64url(sk.public_key().public_bytes_raw())
    head = bytes(range(32))
    sig = sk.sign(crypto._chain_head_attestation_digest(5, head, 0, 2, aid))

    for label, value in [
        ("bytes", head),
        ("bytearray", bytearray(head)),
        ("memoryview", memoryview(head)),
        ("array.array('B')", array.array("B", head)),
        ("ctypes buffer", (ctypes.c_char * 32).from_buffer_copy(head)),
    ]:
        assert crypto.verify_chain_head_attestation(aid, 5, value, 0, 2, sig) is True, (
            label
        )

    # And the refusal the check was actually for still holds.
    for value in ("nope", 5, None, [1, 2, 3]):
        with pytest.raises(TypeError):
            crypto.verify_chain_head_attestation(aid, 5, value, 0, 2, sig)


# ── The other side of the JCS type rule ──────────────────────────────────────────────────────────
# TypeScript's `typeof v === "object"` admitted `Date`, `Map`, `Set`, `RegExp`, typed arrays, boxed
# primitives and class instances into `jcsCanonicalize`, all of which canonicalized to `{}` because
# none of them carry state in own enumerable properties. Python never had that bug: `_jcs_write` is
# an allowlist (`None`/`bool`/`str`/`int`/`float`/`list`/`tuple`/`dict`) and everything else raises.
#
# These tests exist anyway, and not as ceremony. The cross-language invariant this module claims is
# that the implementations agree on WHICH INPUTS HAVE A DIGEST AT ALL, and an invariant asserted on
# only one side is half an invariant: if Python were ever loosened to be helpful — a `default=str`,
# a `dataclasses.asdict` fallback, an `isinstance(v, Mapping)` widening — TypeScript's guard would
# still be green and the divergence would reopen from the language that was never the problem.


def test_jcs_refuses_every_non_json_type_typescript_now_refuses() -> None:
    """The Python-side analogue of each type TS silently emitted as ``{}``."""
    import array
    import decimal
    import re

    for label, value in [
        ("datetime", datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)),
        ("date", datetime.date(2026, 1, 1)),
        ("set", {1, 2}),
        ("frozenset", frozenset({1})),
        ("bytes", b"ab"),
        ("bytearray", bytearray(b"ab")),
        ("memoryview", memoryview(b"ab")),
        ("array", array.array("B", [1, 2])),
        ("regex", re.compile("x")),
        ("Decimal", decimal.Decimal("1.5")),
        ("complex", 1 + 2j),
        ("object", object()),
        ("class instance", type("Thing", (), {"x": 1})()),
    ]:
        with pytest.raises(TypeError, match="not JSON-serializable"):
            jcs_canonicalize(value)
        with pytest.raises(TypeError, match="not JSON-serializable"):
            jcs_canonicalize({"field": value})


def test_the_alias_that_made_this_urgent_cannot_occur_in_python() -> None:
    """Two different timestamps must never reach one digest — the TS failure, asserted from here."""
    a = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    b = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
    for value in (a, b):
        with pytest.raises(TypeError):
            jcs_canonicalize({"deadline": value})
    # And the shape a caller must move to still digests, distinctly — the refusal is not a dead end.
    assert jcs_canonicalize({"deadline": a.isoformat()}) != jcs_canonicalize(
        {"deadline": b.isoformat()}
    )


def test_plain_json_data_still_canonicalizes_unchanged() -> None:
    """The accepting side, pinned as hard as the refusing side.

    A type guard that refuses ordinary data to fix a bug callers do not have is the worse defect.
    """
    assert jcs_canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert jcs_canonicalize([1, {"a": None}, "x"]) == b'[1,{"a":null},"x"]'
    assert jcs_canonicalize((1, 2)) == b"[1,2]", (
        "a tuple is a JSON array, as it always was"
    )
    assert jcs_canonicalize(collections.OrderedDict(b=1, a=2)) == b'{"a":2,"b":1}', (
        "a dict SUBCLASS is still a dict; the allowlist is nominal, and narrowing it to exactly "
        "`type(v) is dict` would break callers for no cross-language gain"
    )


# ── `signature` joins the type pass ──────────────────────────────────────────────────────────────
# Every other argument answered a wrong TYPE with ``TypeError``. ``signature`` did not: it is only
# touched by the Ed25519 verify inside the blanket ``except``, so a wrong-typed one came back
# ``False`` — "this attestation did not verify" — when the truth was "you passed a str". The slip
# that produces it is the ordinary one: handing over the hex STRING instead of the decoded bytes.
#
# TypeScript's twin had the whole of this problem rather than one sixth of it; see
# ``ts/tests/digest_aliasing.test.ts``. What both now implement is one rule: a wrong TYPE is a caller
# bug and raises, and everything an attacker or a corrupt record can actually produce still returns
# ``False``. Raising cannot turn an attack into a crash — attacker-controlled bytes decode, through
# protobuf, into correctly-typed values with hostile CONTENTS.


#: The runtime's committed chain-head KAT — the same entry `test_conformance.py` and the TypeScript
#: twin read, so a runtime regen updates one file and reddens every consumer rather than leaving a
#: hand-copied signature here to go quietly stale.
_KAT = json.loads(
    (pathlib.Path(__file__).parents[2] / "conformance" / "vectors.json").read_text()
)["chain_head_attestation"]
_ATTESTATION_KAT = {
    "issuer_aid": _KAT["issuer_aid"],
    "attested_len": _KAT["inputs"]["attested_len"],
    "attested_head": bytes.fromhex(_KAT["inputs"]["attested_head_hex"]),
    "attested_at": _KAT["inputs"]["attested_at"],
    "digest_schema": _KAT["inputs"]["digest_schema"],
    "signature": bytes.fromhex(_KAT["signature_hex"]),
}


def test_a_wrong_typed_signature_raises_rather_than_reporting_a_failed_attestation() -> (
    None
):
    v = _ATTESTATION_KAT
    # The control. Without it, a verifier that raised unconditionally would satisfy everything below.
    assert crypto.verify_chain_head_attestation(**v) is True

    for label, bad in [
        ("hex str", v["signature"].hex()),
        ("int", 5),
        ("None", None),
        ("list of ints", list(v["signature"])),
    ]:
        with pytest.raises(TypeError, match="signature must be a byte sequence"):
            crypto.verify_chain_head_attestation(**{**v, "signature": bad})

    # Any byte SEQUENCE is still accepted, through the module's one definition of that — the same
    # `_as_bytes` `attested_head` and `record_digest_v3` use. Narrowing to `bytes` alone here would
    # reintroduce, one argument over, the exact defect the `attested_head` check was fixed for.
    assert (
        crypto.verify_chain_head_attestation(
            **{**v, "signature": bytearray(v["signature"])}
        )
        is True
    )
    assert (
        crypto.verify_chain_head_attestation(
            **{**v, "signature": memoryview(v["signature"])}
        )
        is True
    )


def test_untrusted_input_still_returns_false_and_never_raises() -> None:
    """The half that makes promoting caller bugs to exceptions safe to ship.

    A caller writing ``if not verify(...): reject()`` must keep working against everything an
    attacker can actually send. Only genuine caller bugs became exceptions.
    """
    v = _ATTESTATION_KAT
    for label, over in [
        ("out-of-range attested_len", {"attested_len": (1 << 64) + 5}),
        ("out-of-range attested_at", {"attested_at": 1 << 64}),
        ("out-of-range digest_schema", {"digest_schema": 1 << 32}),
        ("tampered attested_len", {"attested_len": v["attested_len"] + 1}),
        ("tampered head", {"attested_head": bytes(32)}),
        ("wrong-length signature", {"signature": bytes(10)}),
        ("forged signature", {"signature": bytes(64)}),
        ("malformed issuer AID", {"issuer_aid": "nope"}),
        ("wrong issuer AID", {"issuer_aid": v["issuer_aid"][:-1] + "x"}),
        # 2^60 is an ordinary exact integer in Python. TypeScript refuses it as a *number* because
        # its neighbours are not representable, but reaches this same `False` — the refusal happens
        # inside its catch, on purpose. See the TS twin for why that placement is load-bearing.
        ("2^60 attested_len", {"attested_len": 2**60}),
    ]:
        assert crypto.verify_chain_head_attestation(**{**v, **over}) is False, label
