"""Option selection (`seam.selection.weighted_plurality` v1): the sealed block and the offline verifier.

Written from seam-runtime ``docs/specs/selection-rule.v1.md`` (runtime 0.90.0, option selection S1),
pinned by ``conformance/selection_rule_v1_vectors.json``. Nothing here trusts the server: given the
sealed ``Commitment`` (its ``selection`` block, ``explanation`` and ``action``) a verifier recomputes the
winner and checks that the committed action is that winner's option, and that every vote signed it.

* :func:`selection_body` / :func:`decode_selection_body` — the one canonical encoding (§4.2), hashed and
  stored. The decoder is strict: anything the runtime could not have sealed is a
  :class:`SelectionDecodeError`, never a guess.
* :func:`selection_digest` — v5 field 9, ``SHA-256(F("seam-selection-digest:v1") ‖ body)``.
* :func:`decide` — the rule (§3), a pure function of the record and the sealed entries.
* :func:`verify_selection` — the verifier's selection steps (§5 steps 4 and 6-9).

**Absent means "not a selection decision", and only that.** A commitment with no block did not run under
selection: field 9 is ``0x00`` and none of this applies. It is never reported as "passed". A block that is
present but malformed fails closed; it is never downgraded to "not a selection decision".
"""

from __future__ import annotations

from .crypto import (  # noqa: F401 -- the public home of the selection API
    SELECTION_DIGEST_DOMAIN,
    SELECTION_RULE,
    SELECTION_RULE_VERSION,
    SELECTION_TIE,
    SELECTION_ABSTENTION,
    SELECTION_MODE,
    SELECTION_TRAILER_MARKER,
    SELECTION_BODY_V1,
    VOTE_VALUES,
    SelectionDecodeError,
    SelectionResult,
    selection_block_of,
    selection_body,
    selection_digest,
    decode_selection_body,
    decode_selection_trailer,
    decide,
    verify_selection,
)

__all__ = [
    "SELECTION_DIGEST_DOMAIN",
    "SELECTION_RULE",
    "SELECTION_RULE_VERSION",
    "SELECTION_TIE",
    "SELECTION_ABSTENTION",
    "SELECTION_MODE",
    "SELECTION_TRAILER_MARKER",
    "SELECTION_BODY_V1",
    "VOTE_VALUES",
    "SelectionDecodeError",
    "SelectionResult",
    "selection_block_of",
    "selection_body",
    "selection_digest",
    "decode_selection_body",
    "decode_selection_trailer",
    "decide",
    "verify_selection",
]
