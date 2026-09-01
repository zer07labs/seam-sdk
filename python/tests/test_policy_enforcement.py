"""``policy_enforcement_of`` — the three-state read, and the one inversion that fails open.

The hazard is not that the field is hard to read. It is that **two of the three states are
value-identical**, so the natural spelling silently collapses them:

======================================  ===================  ================================
state                                   ``HasField``         ``.policy_enforcement.enforced``
======================================  ===================  ================================
absent                                  ``False``            ``False``
present, ``enforced=False``             ``True``             ``False``
present, ``enforced=True``              ``True``             ``True``
======================================  ===================  ================================

Rows 1 and 2 compare **equal** — ``a.policy_enforcement == b.policy_enforcement`` is ``True`` — and
only ``HasField`` separates them. A caller that reads ``resp.policy_enforcement.enforced`` directly
therefore reads "the runtime did not tell me" as "the runtime told me no policy was enforced", which
is the fail-open direction.

Every message here is **constructed in the test**. Nothing reads a stub tree or depends on the
ambient generated surface beyond the two message classes it instantiates, so these tests say the same
thing on any machine and cannot pass because of what happens to be generated locally.
"""

from __future__ import annotations

import dataclasses

import pytest

from seam_sdk import PolicyEnforcement, policy_enforcement_of
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb


def test_absent_is_none_not_a_falsey_instance() -> None:
    """Criterion 1, and the whole point of the module.

    ``None`` **identically** — not an instance that happens to be false-y. An object whose
    ``enforced`` is ``False`` is a claim; absence is the absence of a claim, and a caller must be
    able to tell which one it holds.
    """
    step = pb.SessionStep(state="Proposed")
    assert policy_enforcement_of(step) is None


def test_present_and_false_is_an_instance_not_none() -> None:
    """Criterion 2. Together with the test above this is the entire phase: the **same**
    ``enforced=False`` value, two different return values, decided by presence alone."""
    step = pb.SessionStep(
        state="Resolved", policy_enforcement=pb.PolicyEnforcement(enforced=False)
    )
    result = policy_enforcement_of(step)
    assert result is not None
    assert result.enforced is False


def test_the_two_states_this_module_separates_are_value_identical() -> None:
    """The measurement the module exists for, asserted rather than assumed.

    If this ever stops holding — if the generated surface grows real presence on ``enforced``, say —
    the module's reason for existing has changed and someone should find out from a red test rather
    than from a docstring that quietly went stale.
    """
    absent = pb.SessionStep(state="Proposed")
    present = pb.SessionStep(
        state="Resolved", policy_enforcement=pb.PolicyEnforcement(enforced=False)
    )
    assert absent.policy_enforcement == present.policy_enforcement, (
        "the two states are supposed to be indistinguishable by value — that is the trap"
    )
    assert absent.HasField("policy_enforcement") is False
    assert present.HasField("policy_enforcement") is True
    # ...and the decoder is what turns an indistinguishable pair into a distinguishable one.
    assert policy_enforcement_of(absent) is not policy_enforcement_of(present)
    assert policy_enforcement_of(absent) is None
    assert policy_enforcement_of(present) is not None


def test_policy_id_absent_is_none_never_empty_string() -> None:
    """The same three-state trap, one level down.

    ``policy_id`` has explicit presence: unset gives ``HasField == False`` and ``''``; an explicitly
    encoded empty string gives ``True`` and ``''``. Mapping both to ``""`` would reintroduce the outer
    bug inside the fix for it.
    """
    step = pb.SessionStep(
        state="Resolved", policy_enforcement=pb.PolicyEnforcement(enforced=True)
    )
    result = policy_enforcement_of(step)
    assert result is not None
    assert result.policy_id is None


def test_policy_id_explicitly_empty_is_empty_string_not_none() -> None:
    """The other half of the pair above. An id the runtime *sent* as empty is a different fact from
    an id it did not send, and the decoder must not launder one into the other."""
    pe = pb.PolicyEnforcement(enforced=True)
    pe.policy_id = ""  # explicitly encoded, so HasField becomes True
    assert pe.HasField("policy_id") is True, (
        "the fixture must set presence, not just the value"
    )
    result = policy_enforcement_of(
        pb.SessionStep(state="Resolved", policy_enforcement=pe)
    )
    assert result is not None
    assert result.policy_id == ""


def test_enforced_true_carries_its_policy_id() -> None:
    """Criterion 3's ordinary case — the one that is supposed to be boring."""
    step = pb.SessionStep(
        state="Resolved",
        policy_enforcement=pb.PolicyEnforcement(enforced=True, policy_id="p-1"),
    )
    result = policy_enforcement_of(step)
    assert result == PolicyEnforcement(enforced=True, policy_id="p-1")


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            pb.PolicyEnforcement(enforced=True, policy_id="p-1"), id="enforced-with-id"
        ),
        pytest.param(pb.PolicyEnforcement(enforced=False), id="not-enforced"),
        pytest.param(pb.PolicyEnforcement(enforced=True), id="enforced-no-id"),
    ],
)
def test_both_message_types_decode_identically(payload: pb.PolicyEnforcement) -> None:
    """Criterion 4. One decoder, two message types — and the field number differs between them
    (7 on ``DecisionResponse``, 3 on ``SessionStep``), so this is not a tautology.

    A second implementation per message type would be a second place for the fail-open inversion to
    reappear, which is why there is one.
    """
    from_step = policy_enforcement_of(
        pb.SessionStep(state="Resolved", policy_enforcement=payload)
    )
    from_response = policy_enforcement_of(
        pb.DecisionResponse(decision_id="d-1", policy_enforcement=payload)
    )
    assert from_step == from_response
    assert from_step is not None


def test_a_decision_response_without_the_field_is_none_too() -> None:
    """The absent case on the other message type. ``DecisionResponse`` carries the field at a
    different number, so presence has to be re-verified rather than inferred from the SessionStep
    arm passing."""
    assert policy_enforcement_of(pb.DecisionResponse(decision_id="d-1")) is None


def test_state_does_not_influence_the_decoder() -> None:
    """``state`` is a free-form string and the decoder never reads it. Worth pinning, and worth NOT
    dressing up.

    An earlier version of this file parametrized four session states over a single ``is None``
    assertion. That reads like four cases and is one: ``pb.SessionStep(state="Banana")`` behaves
    identically, because presence of ``policy_enforcement`` is the only input. Asserting the
    irrelevance directly says the true thing; four inert parameters inflate a count.
    """
    outcomes = {
        state: policy_enforcement_of(pb.SessionStep(state=state))
        for state in (
            "Proposed",
            "Open",
            "Voting",
            "Suspended",
            "Expired",
            "Banana",
            "",
        )
    }
    assert set(outcomes.values()) == {None}, (
        "absence, not state, is what makes this None — if a state ever mattered, the decoder grew a "
        "branch it should not have"
    )


def test_decision_id_present_with_enforcement_absent_is_decodable() -> None:
    """The shape that makes the proto comment's ``decision_id`` analogy backwards.

    The expiry seal carries a ``decision_id`` and no ``policy_enforcement``, so a reader who infers
    one from the other infers the opposite of the truth (seam-runtime#526).

    **What this can and cannot assert.** It cannot test the runtime's behaviour — that is a claim
    about another repository, measured in #526, and nothing here could falsify it. What it pins is
    that the combination is representable and decodes the way the docstring says, so the SDK cannot
    acquire a shortcut that reads ``decision_id`` as a proxy for enforcement. An earlier version also
    asserted ``expired.decision_id == "d-expired"``, which tests the protobuf constructor.
    """
    expired = pb.SessionStep(state="Expired", decision_id="d-expired")
    assert expired.HasField("policy_enforcement") is False
    assert policy_enforcement_of(expired) is None
    # ...and the converse combination is equally representable, so neither implies the other.
    enforced_without_id = pb.SessionStep(
        state="Resolved", policy_enforcement=pb.PolicyEnforcement(enforced=True)
    )
    assert enforced_without_id.decision_id == ""
    assert policy_enforcement_of(enforced_without_id) is not None


def test_the_type_is_frozen_and_has_no_second_boolean() -> None:
    """``enforced`` is already the boolean and ``None`` is already the unsafe-to-guess case.

    A convenience twin — an ``allowed`` or ``unenforced`` property — would be a truthiness that can
    go the wrong way, which is the same argument ``_collective.py`` makes for exposing ``approved``
    with no ``declined``. Frozen for the same reason a decoded verdict is: a caller must not be able
    to edit the runtime's claim and pass it on.
    """
    result = PolicyEnforcement(enforced=True, policy_id="p-1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.enforced = False  # type: ignore[misc]

    # `dir()` on a frozen dataclass whose fields carry no defaults lists NO public names — the fields
    # are instance attributes, not class ones. So the exclusion set an earlier version carried
    # ({"enforced", "policy_id", "count", "index"}) was entirely dead: `count`/`index` are namedtuple
    # artifacts that never appear here, and the two field names never appear either. It read as
    # though it enumerated the type's real surface. It did not, and now nothing pretends to.
    public = [name for name in dir(PolicyEnforcement) if not name.startswith("_")]
    assert public == [], f"PolicyEnforcement grew class-level surface: {public}"
    assert [f.name for f in dataclasses.fields(PolicyEnforcement)] == [
        "enforced",
        "policy_id",
    ], (
        "the type grew a field — if it is another boolean, see the docstring above for why not"
    )


def test_it_is_exported_from_the_package_root() -> None:
    """Criterion 5. A module exported from the import block but not ``__all__`` — or the reverse —
    is the half-adoption ``test_packaging.py`` exists over."""
    import seam_sdk

    assert "PolicyEnforcement" in seam_sdk.__all__
    assert "policy_enforcement_of" in seam_sdk.__all__
    assert seam_sdk.policy_enforcement_of is policy_enforcement_of


def test_an_empty_submessage_on_the_wire_decodes_to_an_instance() -> None:
    """The most realistic production shape, and the only one these tests could not reach by
    construction alone.

    A runtime that emits ``policy_enforcement { }`` — the field present, every scalar at its default —
    sends bytes that carry a zero-length submessage. Constructed in-process that is
    ``pb.PolicyEnforcement()``; over the wire it is the tag ``1a00``. It must decode to an *instance*,
    not ``None``: the runtime said "no policy was enforced", which is a different fact from saying
    nothing. Everything else in this file builds messages in-process, so nothing else exercises the
    parser, and this is exactly where an absent/empty confusion would hide.
    """
    sent = pb.SessionStep(state="Resolved", policy_enforcement=pb.PolicyEnforcement())
    raw = sent.SerializeToString()
    assert bytes.fromhex("1a00") in raw, (
        "the empty submessage must actually be on the wire"
    )

    received = pb.SessionStep()
    received.ParseFromString(raw)
    result = policy_enforcement_of(received)
    assert result is not None, (
        "an empty submessage is PRESENT — this is the fail-open direction"
    )
    assert result == PolicyEnforcement(enforced=False, policy_id=None)

    # ...and a step that never carried the field at all is the other side of the same parse.
    bare = pb.SessionStep()
    bare.ParseFromString(pb.SessionStep(state="Resolved").SerializeToString())
    assert policy_enforcement_of(bare) is None


def test_an_explicitly_empty_policy_id_survives_the_wire() -> None:
    """The inner three-state trap, through the parser rather than the constructor.

    An explicitly encoded ``policy_id=""`` occupies bytes (``1200``); an unset one occupies none. If
    the distinction only held for in-process messages it would be a property of the object model, not
    of the decoder, and every real caller reads parsed messages.
    """
    pe = pb.PolicyEnforcement(enforced=True)
    pe.policy_id = ""
    raw = pb.SessionStep(state="Resolved", policy_enforcement=pe).SerializeToString()

    received = pb.SessionStep()
    received.ParseFromString(raw)
    assert policy_enforcement_of(received) == PolicyEnforcement(
        enforced=True, policy_id=""
    )

    unset = pb.SessionStep(
        state="Resolved", policy_enforcement=pb.PolicyEnforcement(enforced=True)
    )
    round_tripped = pb.SessionStep()
    round_tripped.ParseFromString(unset.SerializeToString())
    assert policy_enforcement_of(round_tripped) == PolicyEnforcement(
        enforced=True, policy_id=None
    )


def test_it_returns_the_sdk_type_not_the_generated_one() -> None:
    """The design the plan explicitly rejected: handing back ``pb.PolicyEnforcement``.

    That type's default instance is the trap itself, so returning it would re-expose the
    ``enforced=False`` ambiguity to the caller and leave the docstring nowhere to live. Without this,
    the substitution is caught only incidentally, by two field assertions that happen to still pass.
    """
    result = policy_enforcement_of(
        pb.SessionStep(
            state="Resolved", policy_enforcement=pb.PolicyEnforcement(enforced=True)
        )
    )
    assert isinstance(result, PolicyEnforcement)
    assert not isinstance(result, pb.PolicyEnforcement)


@pytest.mark.parametrize(
    "message", ["AuthorizeResponse", "TerminalResponse", "SessionStatusResponse"]
)
def test_a_message_without_the_field_raises_rather_than_answering(message: str) -> None:
    """``Never raises`` would be false, so the docstring does not say it unqualified — and this is
    what makes that qualification honest.

    Python does not enforce the ``Union`` annotation, so a caller *can* pass a message type that has
    no ``policy_enforcement`` field. ``HasField`` raises ``ValueError`` there, and that is the right
    outcome: a programming error surfacing as one, rather than a ``None`` that reads as "the runtime
    did not say" and quietly joins the fail-open path this module exists to close.
    """
    with pytest.raises(ValueError, match='no "policy_enforcement" field'):
        policy_enforcement_of(getattr(pb, message)())


def test_the_descriptor_claims_in_the_docstring_are_true() -> None:
    """The module's prose makes three checkable claims about the generated surface. Two of them had
    no test.

    ``test_the_two_states_this_module_separates_are_value_identical`` was written so a descriptor
    change goes red rather than leaving a docstring quietly stale — that reasoning applies just as
    much to the field numbers and to ``enforced`` having no presence, both of which the docstring
    asserts and one of which is the stated reason a test elsewhere "is not a tautology".
    """
    assert (
        pb.DecisionResponse.DESCRIPTOR.fields_by_name["policy_enforcement"].number == 7
    )
    assert pb.SessionStep.DESCRIPTOR.fields_by_name["policy_enforcement"].number == 3
    for carrier in (pb.DecisionResponse, pb.SessionStep):
        field = carrier.DESCRIPTOR.fields_by_name["policy_enforcement"]
        assert field.has_presence, (
            f"{carrier.__name__} lost presence — the HasField gate is moot"
        )

    fields = pb.PolicyEnforcement.DESCRIPTOR.fields_by_name
    assert fields["enforced"].has_presence is False, (
        "the code reads `enforced` directly and says why; if it gained presence, that comment is now "
        "wrong and the read should be gated"
    )
    assert fields["policy_id"].has_presence is True, (
        "policy_id's presence is the whole reason absent maps to None rather than ''"
    )
    with pytest.raises(ValueError, match="does not have presence"):
        pb.PolicyEnforcement().HasField("enforced")
