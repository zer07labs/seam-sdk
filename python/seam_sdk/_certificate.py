"""cert-ref (runtime 0.91.0, #1638 part 1): ``DecisionSealed.certificate`` (``seam.event.v1`` tag 19).

The decision certificate a sealed decision's evaluations name, as a ``CertificateRef {id, provenance}``.
It is set only on a RESOLVED seal whose accepted evaluations carry exactly one distinct typed
``rationale_ref = "decision-cert:sha256:<64 lowercase hex>"``. It is **outside** record digest v4 and
commitment digest v5: the sealed binding is the evaluation's ``rationale_ref``, inside the TCT, never this
field. So a consumer must not treat it as evidence, and the runtime never dereferences or verifies the
certificate.

``provenance`` is a CLOSED set carried as ``int32``, not a proto enum (the event descriptor encoding has
no enum form; the wire bytes are those of a proto3 enum). Read it only through :func:`certificate_provenance`:
any value outside the set reads as :data:`CERTIFICATE_PROVENANCE_UNSPECIFIED`, the least trusted reading,
never as evidence.
"""

from __future__ import annotations

import re
from typing import NamedTuple, Optional

#: Unknown or unset: the least trusted reading.
CERTIFICATE_PROVENANCE_UNSPECIFIED = 0
#: The evaluating agent asserted the reference; the runtime checked only its shape.
CERTIFICATE_PROVENANCE_AGENT_ASSERTED = 1
#: Every provenance this SDK knows. Additive values may follow (a runtime-evaluated one arrives with Gate).
CERTIFICATE_PROVENANCES = (
    CERTIFICATE_PROVENANCE_UNSPECIFIED,
    CERTIFICATE_PROVENANCE_AGENT_ASSERTED,
)


_ID = re.compile(r"sha256:[0-9a-f]{64}")


def certificate_provenance(value: int) -> int:
    """The provenance as this SDK reads it: a known value as is, anything else as UNSPECIFIED."""
    if isinstance(value, bool) or not isinstance(value, int):
        return CERTIFICATE_PROVENANCE_UNSPECIFIED
    return (
        value
        if value in CERTIFICATE_PROVENANCES
        else CERTIFICATE_PROVENANCE_UNSPECIFIED
    )


class CertificateRef(NamedTuple):
    """``DecisionSealed.certificate``: ``id`` is ``sha256:<64 lowercase hex>`` (the suffix after
    ``decision-cert:``), ``provenance`` already normalised by :func:`certificate_provenance`."""

    id: str
    provenance: int


def certificate_ref_of(decision_sealed) -> Optional[CertificateRef]:
    """The certificate a generated ``seam.event.v1`` ``DecisionSealed`` names, or ``None`` when it names none
    (always on a row sealed before runtime 0.91.0). A certificate whose ``id`` is not
    ``sha256:<64 lowercase hex>`` reads exactly as absent (``seam-event.v1.md``). Not evidence: see the
    module docstring."""
    if not decision_sealed.HasField("certificate"):
        return None
    c = decision_sealed.certificate
    if _ID.fullmatch(c.id) is None:
        return None
    return CertificateRef(c.id, certificate_provenance(c.provenance))
