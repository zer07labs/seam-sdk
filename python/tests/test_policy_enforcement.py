"""``policy_enforcement_of`` — the three-state read, and the one inversion that fails open.

The hazard is not that the field is hard to read. It is that **two of the three states are
value-identical**, so the natural spelling silently collapses them:

======================================  ===================  ==========================
state                                   ``HasField``         ``.policy_enforcement.enforced``
======================================  ===================  ==========================
absent                                  ``False``            ``False``
present, ``enforced=False``             ``True``             ``False``
present, ``enforced=True``              ``True``             ``True``
======================================  ===================  ==========================

Rows 1 and 2 compare **equal** — ``a.policy_enforcement == b.policy_enforcement`` is ``True`` — and
only ``HasField`` separates them. A caller that reads ``resp.policy_enforcement.enforced`` directly
therefore reads "the runtime did not tell me" as "the runtime told me no policy was enforced", which
is the fail-open direction.

Every message here is **constructed in the test**. Nothing reads a stub tree or depends on the
ambient generated surface beyond the two message classes it instantiates, so these tests say the same
thing on any machine and cannot pass because of what happens to be generated locally.
"""

from __future__ import annotations

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


@pytest.mark.parametrize("state", ["Proposed", "Open", "Voting", "Suspended"])
def test_a_non_commit_step_behaves_exactly_like_an_absent_field(state: str) -> None:
    """Absence is the *common* case on a ``SessionStep``, not an error and not a missing feature.

    The field is populated on exactly three steps (see the module docstring). Everything else — every
    non-terminal step, and the expiry seal — carries nothing, and reads as ``None``.
    """
    assert policy_enforcement_of(pb.SessionStep(state=state)) is None


def test_the_expiry_seal_shape_carries_a_decision_id_without_enforcement() -> None:
    """The counterexample that makes the proto comment's ``decision_id`` analogy backwards.

    The expiry seal sets ``decision_id`` and leaves ``policy_enforcement`` absent, so a reader who
    infers one from the other infers the opposite of the truth (seam-runtime#526). Asserted here
    because the module docstring says it, and a docstring nothing tests is a comment.
    """
    expired = pb.SessionStep(state="Expired", decision_id="d-expired")
    assert expired.decision_id == "d-expired"
    assert policy_enforcement_of(expired) is None


def test_the_type_is_frozen_and_has_no_second_boolean() -> None:
    """``enforced`` is already the boolean and ``None`` is already the unsafe-to-guess case.

    A convenience twin — an ``allowed`` or ``unenforced`` property — would be a truthiness that can
    go the wrong way, which is the same argument ``_collective.py`` makes for exposing ``approved``
    with no ``declined``. Frozen for the same reason a decoded verdict is: a caller must not be able
    to edit the runtime's claim and pass it on.
    """
    result = PolicyEnforcement(enforced=True, policy_id="p-1")
    with pytest.raises(Exception):
        result.enforced = False  # type: ignore[misc]
    booleans = [
        name
        for name in dir(PolicyEnforcement)
        if not name.startswith("_")
        and name not in {"enforced", "policy_id", "count", "index"}
    ]
    assert booleans == [], f"PolicyEnforcement grew extra surface: {booleans}"


def test_it_is_exported_from_the_package_root() -> None:
    """Criterion 5. A module exported from the import block but not ``__all__`` — or the reverse —
    is the half-adoption ``test_packaging.py`` exists over."""
    import seam_sdk

    assert "PolicyEnforcement" in seam_sdk.__all__
    assert "policy_enforcement_of" in seam_sdk.__all__
    assert seam_sdk.policy_enforcement_of is policy_enforcement_of
