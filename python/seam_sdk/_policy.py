"""Presence-aware decoding of ``policy_enforcement`` — on a ``DecisionResponse`` or a ``SessionStep``.

This is the ``PolicyEnforcement`` sibling of :mod:`seam_sdk._collective`, and it exists for a
narrower reason. There is no enum here, no growth policy, and nothing to fail closed on. There is one
hazard, and it is entirely about **presence**:

======================================  ===================  ================================
state                                   ``HasField``         ``.policy_enforcement.enforced``
======================================  ===================  ================================
absent                                  ``False``            ``False``
present, ``enforced=False``             ``True``             ``False``
present, ``enforced=True``              ``True``             ``True``
======================================  ===================  ================================

**The first two rows are value-identical.** ``resp.policy_enforcement`` compares equal across them;
only ``HasField`` tells them apart. So the natural spelling —

    if resp.policy_enforcement.enforced:   # WRONG
        ...

reads "the runtime did not tell me whether a policy was enforced" as "the runtime told me none was",
which is the fail-open direction. Returning ``None`` for absent is the only shape with no truthiness
that can go the wrong way; a caller must decide what "not answered" means for its own fail policy
rather than being handed a value that answers it wrongly.

When the field is present
=========================
On a ``SessionStep``, **absence is the common case**, not an error and not a missing feature. The
field is populated on exactly three steps:

* the **commit-terminal** step,
* the **sealed-idempotent replay** — a resubmit of any verb against an already-sealed session, which
  re-reports a seal that this call did not perform,
* the **pending-commitment seal retry**.

It is absent on every non-terminal step — open, propose, vote, ballot, and **both suspended shapes**
(awaiting an approver, and the budget breach) — and absent on the **expiry seal**. The four-verb
parenthetical is the proto comment's own list and is not exhaustive; #526's matrix measures the two
suspended sites as absent too.

Two things about that list are worth stating plainly, because both contradict what the proto's own
comment for this field says (``seam.api.v1``, ``SessionStep.policy_enforcement`` field 3 — cited by
field, not by line: the proto lives in another repository that nothing here tracks or gates):

1. It is **not** "only on a step that resolves the session via commit". The sealed-idempotent replay
   resolves nothing and carries the field anyway.
2. **Presence is not tied to ``decision_id``.** The proto comment offers ``decision_id``'s
   terminal-only presence as the analogy; the expiry seal is the counterexample, carrying a
   ``decision_id`` with no ``policy_enforcement``. A reader who follows the analogy infers the
   opposite of the truth.

The three sites are **enumerated rather than generalised**, deliberately. Every short general rule
anyone has written for this field has been wrong — including the two in the proto comment, and
including a draft of the issue that measured them, which proposed "populated on any step that reports
a seal" and is self-contradictory because the expiry seal does report a seal. The enumeration and the
matrix behind it are measured in **zer07labs/seam-runtime#526**, which is the citation this module
carries: ``PROGRESS.md``'s clean-room constraint forbids reading that repository's Rust sources, and
the issue publishes the matrix in its own body.

This list describes the runtime as measured at the time of writing. It is not enforced by anything
here, and it is not a contract the SDK can check — treat it as orientation for reading a ``None``,
never as a guarantee to branch on.

Field numbers differ between the two carriers (7 on ``DecisionResponse``, 3 on ``SessionStep``), and
both have explicit presence, so one ``HasField`` gate covers both — verified against the descriptors
rather than assumed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb


@dataclass(frozen=True)
class PolicyEnforcement:
    """The runtime's statement about whether a policy was enforced on this decision.

    Frozen for the same reason a decoded verdict is: this is the runtime's claim, and a caller must
    not be able to edit it and pass it on as though it came from the wire.

    Deliberately **two fields and no convenience booleans**. ``enforced`` is already the boolean, and
    the unsafe-to-guess case is already expressed by :func:`policy_enforcement_of` returning ``None``
    rather than an instance. An ``allowed``-style twin would be a second truthiness that can go the
    wrong way — the same argument :mod:`seam_sdk._collective` makes for exposing ``approved`` with no
    ``declined`` counterpart.
    """

    enforced: bool
    #: ``None`` **iff the id is absent**, never ``""``. ``policy_id`` has explicit presence of its
    #: own: unset gives ``HasField == False`` and ``''``, while an explicitly encoded empty string
    #: gives ``True`` and ``''``. Collapsing both to ``""`` would reintroduce this module's own bug
    #: one level down, inside the fix for it.
    policy_id: Optional[str]


def policy_enforcement_of(
    resp: Union["pb.DecisionResponse", "pb.SessionStep"],
) -> Optional[PolicyEnforcement]:
    """Decode ``resp.policy_enforcement``. Accepts a ``DecisionResponse`` **or** a ``SessionStep``.

    Returns ``None`` **iff the field is absent**, and an instance otherwise — including when that
    instance carries ``enforced=False``. Those two cases are indistinguishable by value on the wire
    and this function is the one place that keeps them apart; see the module docstring for the
    three-state table and for when the field is populated at all.

    One decoder, two message types, on purpose: the hazard is a property of the **field** —
    ``optional`` presence over a message whose default instance is false-y — not of the message that
    carries it. A second implementation per carrier would be a second place for the same inversion to
    reappear.

    **Never raises on a message that carries the field** — and that qualification is load-bearing.
    Unlike :func:`seam_sdk.collective_outcome_of` there is no enum here and no growth policy, so
    there is no unrecognized *value* to fail closed on: the only distinction to preserve is
    present-versus-absent, and ``None`` preserves it. But Python does not enforce the ``Union``
    annotation, and ``HasField`` raises ``ValueError`` for a message type that has no
    ``policy_enforcement`` field at all — ``AuthorizeResponse``, ``TerminalResponse``,
    ``SessionStatusResponse``. That is a programming error surfacing as one, which is correct; it is
    recorded here because an unqualified "never raises" would be exactly the kind of absolute claim
    about this field that has been wrong every previous time someone wrote one.
    """
    if not resp.HasField("policy_enforcement"):
        return None

    enforcement = resp.policy_enforcement
    return PolicyEnforcement(
        # `enforced` has NO presence of its own — it is a plain proto3 bool, so it is read directly.
        # A `HasField` on it raises ValueError rather than returning False.
        enforced=enforcement.enforced,
        policy_id=(
            enforcement.policy_id if enforcement.HasField("policy_id") else None
        ),
    )
