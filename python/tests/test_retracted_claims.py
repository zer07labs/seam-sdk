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
    "the claim",
)


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
            if not any(
                c in low
                for c in (
                    "detects truncation",
                    "detect truncation",
                    "truncation detection",
                )
            ):
                continue
            # A negated or prohibitive mention is the correct thing to have — indeed it is what this
            # repo is required to carry until seam-runtime#422 lands.
            negated = any(
                neg in low
                for neg in ("not", "cannot", "no ", "until", "never", "does not")
            )
            if negated or any(m in low for m in DISCUSSING_NOT_CLAIMING):
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


@pytest.mark.parametrize(
    "required",
    [
        "0.7.20",  # the floor
        "0.7.13",  # unimportable band
        "0.7.17",  # wire-broken band
        "0.7.39",  # gencode/floor skew band — the lower edge, proven by the CI red/green boundary
    ],
)
def test_the_known_bad_bands_stay_documented(required: str) -> None:
    """Nothing was yanked (see CHANGELOG.md's "No yank" entry), so these versions remain installable
    document is the only barrier. Dropping a band silently re-exposes it.

    This is a WEAK check by construction — a version string can appear for unrelated reasons, so
    passing here does not prove the band is documented, only that the number is mentioned
    somewhere. The band itself is guarded by the test below, which exists because this one
    demonstrably was not enough.
    """
    assert required in COMPATIBILITY.read_text(encoding="utf-8"), (
        f"COMPATIBILITY.md no longer mentions {required}. Nothing was yanked, so these versions are "
        f"still installable from Cloudsmith and the document is the only mitigation."
    )


def test_the_gencode_skew_band_is_a_table_row_not_merely_a_mention() -> None:
    """The §3 row for 0.7.39-0.7.43 must survive as a ROW, not as a passing reference.

    Written after the parametrize above was caught being vacuous for this band: "0.7.43" already
    appeared in COMPATIBILITY.md for unrelated reasons, so the row could be deleted outright and
    the whole suite still passed — 557 green with the band gone. A guard that cannot fail for the
    thing it guards is worse than no guard, because it is read as coverage.

    It also pins the two facts a reader acts on, which a substring check cannot: the release that
    fixes it, and the symptom that identifies it.
    """
    rows = [
        line
        for line in COMPATIBILITY.read_text(encoding="utf-8").splitlines()
        if line.startswith("| **0.7.39 – 0.7.43**")
    ]
    assert len(rows) == 1, (
        "COMPATIBILITY.md §3 no longer carries exactly one table row for the 0.7.39-0.7.43 "
        f"gencode/floor skew band (found {len(rows)}). Five releases shipped that defect on red "
        "CI and none was yanked, so this row is the only barrier between a consumer and a wheel "
        "whose declared protobuf floor is lower than the gencode it bundles. If the band was "
        "re-derived, update this test deliberately — do not delete it."
    )
    row = rows[0]
    for needle, why in (
        (
            "0.7.47",
            "the release that fixes it — without it the row tells a reader nothing to do",
        ),
        (
            "VersionError",
            "the symptom, which is how a consumer recognises they are hitting this",
        ),
    ):
        assert needle in row, (
            f"the 0.7.39-0.7.43 row no longer states {needle!r}: {why}"
        )


def test_the_skew_band_row_renders_inside_the_table() -> None:
    """A blank line before the row would end the GFM table and render it as literal pipes.

    That is not hypothetical: the row was first committed with exactly that defect and read fine
    in the diff. Markdown tables are whitespace-terminated, so this is a one-character failure
    that no prose review catches and no substring check notices.
    """
    lines = COMPATIBILITY.read_text(encoding="utf-8").splitlines()
    # Not a bare `next(...)`: with the row absent that raises StopIteration carrying no message,
    # and a guard whose failure explains nothing is half a guard.
    idx = next(
        (i for i, ln in enumerate(lines) if ln.startswith("| **0.7.39 – 0.7.43**")),
        None,
    )
    assert idx is not None, (
        "COMPATIBILITY.md §3 has no 0.7.39-0.7.43 row at all, so its rendering cannot be checked. "
        "The sibling test above says why the row has to exist."
    )
    assert lines[idx - 1].startswith("|"), (
        "the 0.7.39-0.7.43 row is not contiguous with the rows above it — the preceding line is "
        f"{lines[idx - 1]!r}. A GFM table ends at the first non-table line, so this row would "
        "render as literal pipe characters in a paragraph rather than as a row of the known-bad "
        "table."
    )
