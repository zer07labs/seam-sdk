"""Retracted claims must stay retracted, and load-bearing caveats must stay present.

This repo's own history is the argument for a test rather than a convention. A plan file asserted
that a live consumer pinned `seam-sdk >=0.7,<0.8` and resolved 0.7.9 — i.e. sat inside the
wire-broken band — and it stayed there after the consumer raised its floor to `>=0.7.20`, generating
false alarms against a consumer that was fine.

Two properties are checked, and the second matters more than the first:

1. **A retracted claim does not come back.** Prose gets copy-pasted forward; a grep does not.
2. **A caveat this repo is not entitled to drop does not quietly vanish.** The truncation caveat in
   particular is a *capability* limit, not a wording preference — the published verifier genuinely
   cannot detect a truncated chain, and a doc that stops saying so starts overclaiming.

`seam-adapters` uses the same technique (`core/tests/test_doc_claims.py`), for the same reason.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).parents[2]


def _docs() -> list[pathlib.Path]:
    """Every markdown file this repo authors. Excludes vendored trees, which are not ours to police."""
    skip = {"node_modules", ".venv", "target", "dist", ".git", "_gen", "gen"}
    return [p for p in REPO.rglob("*.md") if not skip & set(p.parts)]


#: Markers that identify a passage as *discussing* a claim rather than *making* it — a retraction, a
#: prohibition, or a correction table. Matching on paragraphs rather than lines matters here: these
#: markers routinely sit a line or two away from the words they qualify, and a line-scoped grep
#: reads "do not claim the published verifier / detects truncation" as an assertion because the
#: negation landed on the previous line. That false positive is not hypothetical — it is what this
#: guard did on its first run, against the very plan that forbids the claim.
DISCUSSING_NOT_CLAIMING = (
    "retraction",
    "retracted",
    "do not claim",
    "must not claim",
    "previously read",
    "is stale",
    "was wrong",
)

#: Words that make a mention of truncation detection a DENIAL of the capability rather than an
#: assertion of it. Matched on WORD BOUNDARIES, which is the whole point and was the whole bug.
#:
#: These were substrings. Measured, before this change, every one of these sentences was accepted
#: into a repo document by the guard whose entire job is to refuse it:
#:
#:     "The notarised feed detects truncation for every chain."     -- "notarised" contains "not"
#:     "Note: seam-sdk detects truncation end to end."              -- "Note" contains "not"
#:     "The verifier detects truncation until you disable it."      -- "until" was a negation marker
#:     "The claim is simple: the verifier detects truncation."      -- "the claim" was an excuse
#:
#: The first two are the substring bug in its purest form: `"not" in "notarised"`. "nothing" and
#: "annotation" do it too, and all three are words a technical document reaches for constantly.
#:
#: `"until"` is gone rather than word-bounded. It was never a negation — "until seam-runtime#422
#: lands" reads as one only because a real denial sits beside it, and that denial always carries
#: `cannot` or `not` of its own. As a marker it excused any sentence with an ordinary temporal
#: clause in it.
#:
#: `"the claim"` is gone from DISCUSSING_NOT_CLAIMING for the sharper version of the same fault: it
#: excused a sentence that MAKES the claim while using the phrase. A guard whose exemption list
#: contains the words its subject is most likely to be written with is not a guard.
NEGATION_WORDS = ("not", "cannot", "no", "never", "none", "nor")

#: The three spellings of the capability. Hoisted so the guard and its calibration cannot drift.
CAPABILITY_PHRASES = ("detects truncation", "detect truncation", "truncation detection")

#: Clause boundaries. NOT newlines — `does not\ndetect truncation` is one clause wrapped by a
#: formatter, and splitting on the wrap would refuse the denial this repo is required to carry.
_CLAUSE_SPLIT = re.compile(r"[.;:!?]+")


def _is_exempt(text: str) -> bool:
    """True when this block may mention the capability. THE predicate — there is only one.

    It used to exist twice: once inline in the guard and once in the calibration helper, sharing
    only the word tuples. Reverting the guard alone then killed nothing, so the calibration proved
    a copy rather than the thing that runs. That is this repo's named failure class, and Phase 4
    reproduced it inside the fix for Phase 4.

    Two scopes, deliberately different:

    * `DISCUSSING_NOT_CLAIMING` is **paragraph**-scoped. These are explicit meta-discussion markers,
      and `RETRACTED: an earlier note said seam-sdk detects truncation.` puts the marker in a
      different clause from the claim by construction.
    * A negation is **clause**-scoped. Paragraph scope let a denial anywhere excuse a claim
      anywhere, so `The verifier detects truncation. No further work is required.` passed — the
      `no` of an unrelated sentence vouching for the sentence beside it.

    Known and deliberate limitation: a negation inside the claim's OWN clause always exempts it, so
    `detects truncation, no exceptions` and `detects truncation whether or not X` still pass.
    Deciding whether a same-clause negation attaches to the claim is a parsing problem this guard
    does not attempt; it is recorded here rather than left for someone to rediscover.
    """
    low = text.lower()
    if any(m in low for m in DISCUSSING_NOT_CLAIMING):
        return True
    claims = [
        c for c in _CLAUSE_SPLIT.split(low) if any(p in c for p in CAPABILITY_PHRASES)
    ]
    if not claims:
        return True
    negation = re.compile(rf"\b(?:{'|'.join(NEGATION_WORDS)})\b")
    return all(negation.search(c) is not None for c in claims)


def _paragraphs(path: pathlib.Path) -> list[tuple[int, str]]:
    """(starting line number, text) for each blank-line-separated block."""
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    blocks, start, buf = [], 1, []
    for n, line in enumerate(lines, 1):
        if line.strip():
            if not buf:
                start = n
            buf.append(line)
        elif buf:
            blocks.append((start, "\n".join(buf)))
            buf = []
    if buf:
        blocks.append((start, "\n".join(buf)))
    return blocks


# ── 1. Retracted claims stay retracted ────────────────────────────────────────────────────────────


def test_the_stale_adapters_pin_claim_does_not_return() -> None:
    """`seam-adapters/core/pyproject.toml:22` pins `>=0.7.20,<0.8`, not `>=0.7,<0.8`.

    The retraction is deliberately narrow: the *lock* observation (uv.lock resolves 0.7.9) is still
    true, because the root pyproject overrides with an editable path source. Only the *pin* claim was
    wrong. So this greps for the stale pin string, not for the whole sentence — retracting a true
    statement would be its own false claim.
    """
    offenders = []
    for doc in _docs():
        for start, block in _paragraphs(doc):
            if "seam-sdk >=0.7,<0.8" not in block and "seam-sdk>=0.7,<0.8" not in block:
                continue
            # A passage that QUOTES the stale pin in order to retract or correct it is exactly what
            # should exist. Only an unqualified restatement is a regression.
            if any(m in block.lower() for m in DISCUSSING_NOT_CLAIMING):
                continue
            offenders.append(f"{doc.relative_to(REPO)}:{start}: {block.strip()[:160]}")

    assert not offenders, (
        "The retracted `seam-sdk >=0.7,<0.8` pin claim has reappeared:\n  "
        + "\n  ".join(offenders)
        + "\n\nThe real constraint is `seam-sdk>=0.7.20,<0.8` "
        "(seam-adapters/core/pyproject.toml:22). See COMPATIBILITY.md §2."
    )


# ── 2. Caveats this repo is not entitled to drop ──────────────────────────────────────────────────

COMPATIBILITY = REPO / "COMPATIBILITY.md"


def test_the_truncation_caveat_is_present_and_unhedged() -> None:
    """The published verifier CANNOT detect truncation, and the doc must keep saying so.

    A stream cut at the tail is internally consistent and verifies green. Detecting truncation needs
    a third-party-observable append-only feed, and none is published (seam-runtime#422). Until that
    lands, any claim that "independently verifiable" covers completeness is false.

    This is the §9 rule "do not claim the published verifier detects truncation", made enforceable.
    """
    text = COMPATIBILITY.read_text(encoding="utf-8")
    lowered = text.lower()

    assert "truncation" in lowered, (
        "COMPATIBILITY.md no longer mentions truncation. The verifier still cannot detect it "
        "(seam-runtime#422 is open), so removing the caveat makes the document overclaim."
    )
    assert (
        "cannot detect it" in lowered or "cannot prove it is the whole chain" in lowered
    ), (
        "COMPATIBILITY.md mentions truncation but no longer states plainly that the verifier cannot "
        "detect it. Hedging this is the overclaim the caveat exists to prevent."
    )


def test_no_document_claims_the_verifier_detects_truncation() -> None:
    """The inverse guard: nobody may assert the capability anywhere in the repo."""
    offenders = []
    for doc in _docs():
        for start, block in _paragraphs(doc):
            low = block.lower()
            if not any(c in low for c in CAPABILITY_PHRASES):
                continue
            # A negated or prohibitive mention is the correct thing to have — indeed it is what this
            # repo is required to carry while there is no published anchor feed (seam-runtime#422).
            # The predicate lives in ONE place (`_is_exempt`) so the calibration below exercises
            # what actually runs here, not a second copy of it.
            if _is_exempt(block):
                continue
            offenders.append(f"{doc.relative_to(REPO)}:{start}: {block.strip()[:160]}")

    assert not offenders, (
        "A document claims truncation detection, which the published verifier does not have:\n  "
        + "\n  ".join(offenders)
        + "\n\nThere is no published anchor feed (seam-runtime#422). Fix the capability before "
        "making the claim."
    )


def test_the_commitment_digest_exclusion_is_stated() -> None:
    """`verify/` does not implement `seam-commitment-digest:v1`, and the doc must not imply it does."""
    text = COMPATIBILITY.read_text(encoding="utf-8").lower()
    assert "commitment digest" in text, (
        "COMPATIBILITY.md no longer says what the published verifier does NOT cover. The commitment "
        "digest is implemented by the five crypto shims and NOT by verify/; a reader who assumes "
        "otherwise overestimates what running the verifier proved."
    )


#: The §3 known-bad bands, each as (row prefix, the facts a reader acts on).
#:
#: One list, three bands. The previous shape was a weak substring parametrize over four version
#: strings PLUS a strong row test special-cased to one band — the same rule in two places with one
#: copy incomplete, which is this repo's recurring defect and was live here: a verification round
#: mutation-tested the guard and found that deleting the `0.7.16 – 0.7.19` row, or the
#: `**Floor: 0.7.20.**` line, left the whole suite green. `"0.7.17"` never appears in the table at
#: all (the row is spelled `0.7.16 – 0.7.19`) and matched only unrelated prose; `"0.7.20"` appears
#: five times elsewhere. So two of the three bands the substring check named were unguarded while
#: reading as covered.
#:
#: The needles are per-band because the rows genuinely differ: only the skew band names a fixing
#: release. Each needle is the thing a consumer uses to recognise they are hitting the band.
KNOWN_BAD_BANDS = (
    (
        "| **0.7.13 – 0.7.15**",
        (("ModuleNotFoundError", "the symptom — how a consumer recognises this band"),),
    ),
    (
        "| **0.7.16 – 0.7.19**",
        (("UNAUTHENTICATED", "the symptom — the error a consumer actually sees"),),
    ),
    (
        "| **0.7.39 – 0.7.43**",
        (
            (
                "0.7.47",
                "the release that fixes it — without it the row tells a reader nothing to do",
            ),
            (
                "VersionError",
                "the symptom, which is how a consumer recognises they are hitting this",
            ),
        ),
    ),
)


@pytest.mark.parametrize(
    "prefix,needles", KNOWN_BAD_BANDS, ids=lambda v: v if isinstance(v, str) else ""
)
def test_each_known_bad_band_is_a_table_row_not_merely_a_mention(
    prefix: str, needles: tuple[tuple[str, str], ...]
) -> None:
    """Every §3 band must survive as a ROW, and carry the facts a reader acts on.

    Nothing was yanked (see CHANGELOG.md's "No yank" entry), so these versions remain installable
    from Cloudsmith and this document is the only barrier. A substring check cannot enforce that:
    a version number appears for unrelated reasons, so the row can be deleted outright with the
    suite green. That was measured, twice — first for 0.7.39-0.7.43 (557 green with the row gone),
    then for 0.7.16-0.7.19 and the 0.7.20 floor, which is why this test is now parametrized over
    every band instead of guarding one and trusting a substring for the others.
    """
    rows = [
        line
        for line in COMPATIBILITY.read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]
    assert len(rows) == 1, (
        f"COMPATIBILITY.md §3 no longer carries exactly one table row starting {prefix!r} "
        f"(found {len(rows)}). None of these versions was yanked, so this row is the only barrier "
        "between a consumer and a broken wheel. If the band was re-derived, update this test "
        "deliberately — do not delete it."
    )
    for needle, why in needles:
        assert needle in rows[0], (
            f"the {prefix!r} row no longer states {needle!r}: {why}"
        )


@pytest.mark.parametrize("prefix", [p for p, _ in KNOWN_BAD_BANDS])
def test_each_known_bad_row_renders_inside_the_table(prefix: str) -> None:
    """A blank line before a row would end the GFM table and render it as literal pipes.

    That is not hypothetical: the skew-band row was first committed with exactly that defect and
    read fine in the diff. Markdown tables are whitespace-terminated, so this is a one-character
    failure that no prose review catches and no substring check notices.
    """
    lines = COMPATIBILITY.read_text(encoding="utf-8").splitlines()
    # Not a bare `next(...)`: with the row absent that raises StopIteration carrying no message,
    # and a guard whose failure explains nothing is half a guard.
    idx = next((i for i, ln in enumerate(lines) if ln.startswith(prefix)), None)
    assert idx is not None, (
        f"COMPATIBILITY.md §3 has no row starting {prefix!r} at all, so its rendering cannot be "
        "checked. The sibling test above says why the row has to exist."
    )
    assert lines[idx - 1].startswith("|"), (
        f"the {prefix!r} row is not contiguous with the rows above it — the preceding line is "
        f"{lines[idx - 1]!r}. A GFM table ends at the first non-table line, so this row would "
        "render as literal pipe characters in a paragraph rather than as a row of the known-bad "
        "table."
    )


def test_the_floor_is_stated_as_its_own_line() -> None:
    """`Floor: 0.7.20` is the one instruction a reader can act on without reading the table.

    Guarded as a whole LINE because the substring `0.7.20` occurs five times elsewhere in this
    document — so the sentence that makes it the floor was deletable with every test green, which
    a verification round demonstrated. The floor is what `seam-adapters` pins against; losing the
    statement loses the reason the pin is what it is.
    """
    lines = COMPATIBILITY.read_text(encoding="utf-8").splitlines()
    assert any(ln.startswith("**Floor: 0.7.20.**") for ln in lines), (
        "COMPATIBILITY.md §3 no longer states `**Floor: 0.7.20.**` as its own line. 0.7.20 is the "
        "first release that is both importable and wire-correct; if the floor genuinely moved, "
        "change it here deliberately rather than deleting the statement."
    )


# ── Calibration: does the guard catch the thing it is named after? ───────────────────────────────
# The module had no such test, and that is exactly how it came to miss four ordinary spellings of
# the claim it exists to forbid. Every guard in this repo is one refactor away from being excused by
# its own exemption list; the only defence is a case that FAILS if the guard stops working.
#
# These run the real guard against synthetic documents rather than against the repo, so they neither
# depend on what the repo currently says nor go stale when it changes.

_CLAIMS_THAT_MUST_BE_CAUGHT = [
    # (label, paragraph) — each was ACCEPTED before the word-boundary fix.
    (
        "substring 'not' inside 'notarised'",
        "The notarised feed detects truncation for every chain.",
    ),
    ("substring 'not' inside 'Note'", "Note: seam-sdk detects truncation end to end."),
    (
        "substring 'not' inside 'nothing'",
        "Nothing else matters: the verifier detects truncation.",
    ),
    (
        "'until' was treated as a negation",
        "The verifier detects truncation until you disable it.",
    ),
    (
        "'the claim' was an exemption",
        "The claim is simple: the published verifier detects truncation.",
    ),
    ("plain assertion", "seam-sdk detects truncation."),
    ("the noun form", "Truncation detection is implemented by the published verifier."),
]

_DENIALS_THAT_MUST_BE_ALLOWED = [
    ("the required denial", "The published verifier cannot detect truncation."),
    (
        "'no' as a word",
        "There is no anchor feed, so truncation detection is unavailable.",
    ),
    ("'does not'", "verify/ does not perform truncation detection."),
    ("'never'", "The verifier never claimed truncation detection."),
    (
        "a negation a line away from the claim",
        "The published verifier does not\ndetect truncation, and cannot until an anchor feed exists.",
    ),
    (
        "an explicit retraction",
        "RETRACTED: an earlier note said seam-sdk detects truncation.",
    ),
]

#: Found by the Phase 4 verification gate, which asked the question the four known cases did not:
#: what does a negation somewhere ELSE in the paragraph excuse? Under paragraph scope, everything.
#: Each of these has a real denial in one clause and an undenied claim in another, and each passed.
_CLAIMS_IN_A_CLAUSE_THE_DENIAL_DOES_NOT_COVER = [
    (
        "a denial in the next sentence",
        "The verifier detects truncation. No further work is required.",
    ),
    (
        "a denial after a semicolon",
        "The published verifier detects truncation for chains of any length; there is no caveat.",
    ),
    (
        "a denial after a colon",
        "Truncation detection is complete: none of the known gaps remain.",
    ),
]

_CLAIMS_THAT_MUST_BE_CAUGHT += _CLAIMS_IN_A_CLAUSE_THE_DENIAL_DOES_NOT_COVER


def _guard_accepts(paragraph: str) -> bool:
    """Run THE predicate over one synthetic paragraph. True = the guard let it through.

    Calls `_is_exempt` — the same function the guard itself calls. It must never grow a local copy
    of the logic: a calibration that exercises its own reimplementation stays green through exactly
    the narrowing it was written to prevent, which is what happened here once already.
    """
    low = paragraph.lower()
    if not any(c in low for c in CAPABILITY_PHRASES):
        raise AssertionError(
            f"test bug: {paragraph!r} does not mention the capability at all"
        )
    return _is_exempt(paragraph)


@pytest.mark.parametrize(
    "label,paragraph",
    _CLAIMS_THAT_MUST_BE_CAUGHT,
    ids=[c[0] for c in _CLAIMS_THAT_MUST_BE_CAUGHT],
)
def test_the_guard_catches_each_spelling_of_the_forbidden_claim(
    label: str, paragraph: str
) -> None:
    assert not _guard_accepts(paragraph), (
        f"the guard would accept a document claiming truncation detection ({label}):\n  {paragraph}\n"
        "This is the exact class the guard exists for. Do not widen the exemption list to make a "
        "real document pass — reword the document."
    )


@pytest.mark.parametrize(
    "label,paragraph",
    _DENIALS_THAT_MUST_BE_ALLOWED,
    ids=[d[0] for d in _DENIALS_THAT_MUST_BE_ALLOWED],
)
def test_the_guard_still_allows_a_genuine_denial(label: str, paragraph: str) -> None:
    # The accepting side matters as much: this repo is REQUIRED to carry the denial while there is
    # no published anchor feed, so a guard that refused it would forbid the correct document.
    assert _guard_accepts(paragraph), (
        f"the guard would reject a legitimate denial ({label}):\n  {paragraph}\n"
        "Tightening the negation words must not make the required caveat unwritable."
    )
