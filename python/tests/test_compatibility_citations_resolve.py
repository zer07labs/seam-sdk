"""Every `file:line` citation in `COMPATIBILITY.md` and `DECISIONS.md` must actually resolve.

`COMPATIBILITY.md` closes by stating its own rule:

    Every row must cite a `file:line` that resolves. If a claim cannot be verified, **delete it** — a
    compatibility matrix with aspirational rows is worse than a short one, because a reader cannot
    tell which rows were checked.

That rule is self-defeating without enforcement, and not hypothetically: **six citations were stale
the day the document was written**, because the same PR that wrote them also inserted lines into
`publish.yml`, `release-on-runtime.yml` and `CHANGELOG.md` and shifted the targets underneath. A
citation that points at the wrong line is worse than no citation — it looks checked.

Two levels of check, because line numbers rot in two different ways:

1. **Structural** — the file exists and the cited line is in range. Catches a deleted file or a
   citation past EOF.
2. **Anchored** — for the load-bearing claims, the cited line must still contain the thing it is
   cited *for*. This is what catches the failure that actually happened: the line existing, but now
   holding something else entirely.

`DECISIONS.md` was brought under the same checks later, and the argument for it is the argument
against ever scoping a check to the tidiest document. It is a live record a reader trusts exactly as
much as COMPATIBILITY.md, and it had rotted the same way in three distinct ways at once:

* **A drifted line.** It cited `.github/workflows/ci.yml:289-297` for the zero-Seam-crates gate.
  COMPATIBILITY.md cited *the same claim in the same file*, and that copy was repaired — by this
  test — while this one stayed stale, because nothing was reading this document. Both are now
  anchored, and `cited` is scoped per document precisely so one cannot cover for the other.
* **Bare paths.** Five citations named sibling-repo files with no repo prefix
  (`scripts/sdk-digest-parity.sh`, `crates/seam-store/src/lib.rs`, three adapter `pyproject.toml`s).
  Those are not merely untidy — `scripts/sdk-digest-parity.sh` reads as a local file, this repo has
  its own `scripts/` directory, and nothing mechanical can tell the two apart. Unresolvable
  citations are why the rot was invisible.
* **A citation repointed by hand three times in one session**, as the vendored spec it pointed into
  was refreshed and its header rewritten. That is the same signal that made the anchored check find
  its needle rather than pin a line; it just took a second document to notice it applied here too.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).parents[2]

#: Every document whose `file:line` citations are checked, and the minimum each must carry.
#:
#: `DECISIONS.md` was added after a citation in it had to be hand-repointed three times in a single
#: session — the same signal that motivated rewriting the anchored check below to find its needle
#: instead of pinning a line. It is a live document that a reader trusts exactly as much as
#: COMPATIBILITY.md, and it had drifted the same way: one citation pointed at a line that had moved
#: 26 lines, and five more were **bare paths with no repo prefix** (`scripts/sdk-digest-parity.sh`,
#: which reads as a local file and is seam-runtime's) — unresolvable by anything mechanical, which
#: is why nothing had noticed.
#:
#: The floor per document is a guard-the-guard: a gutted document, or a regex that stopped matching
#: its format, would otherwise make every check below pass vacuously.
DOCS = {
    "COMPATIBILITY.md": 10,
    "DECISIONS.md": 10,
}

#: `path/to/file.ext:12` or `path/to/file.ext:12-34`, inside backticks.
CITATION = re.compile(r"`([\w./-]+\.\w+):(\d+)(?:-(\d+))?`")

#: Paths that live in sibling repos — real citations, but not resolvable from this checkout.
#: Named explicitly rather than pattern-skipped, so a typo'd local path cannot hide among them.
#:
#: This list is also why a citation must carry its repo prefix. An unprefixed sibling path is not
#: merely untidy: `scripts/sdk-digest-parity.sh` and `crates/seam-store/src/lib.rs` both look local,
#: so they would be asserted against THIS repo and fail — or worse, collide with a real local file
#: of the same name and be checked against the wrong one entirely.
SIBLING_PREFIXES = ("seam-adapters/", "seam-aegis/", "seam-runtime/")


def _citations(doc: str) -> list[tuple[str, str, int, int]]:
    out = []
    for m in CITATION.finditer((REPO / doc).read_text(encoding="utf-8")):
        path, start, end = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
        out.append((doc, path, start, end))
    return out


def _all_citations() -> list[tuple[str, str, int, int]]:
    return [c for doc in DOCS for c in _citations(doc)]


@pytest.mark.parametrize(("doc", "floor"), DOCS.items())
def test_the_document_actually_cites_things(doc: str, floor: int) -> None:
    """Guard the guard — an empty citation list would make every test below pass vacuously."""
    assert len(_citations(doc)) >= floor, (
        f"{doc} carries almost no file:line citations. Either the document was gutted or the "
        f"citation regex no longer matches its format; both need looking at."
    )


@pytest.mark.parametrize(
    "citation", _all_citations(), ids=lambda c: f"{c[0]}~{c[1]}:{c[2]}"
)
def test_each_citation_resolves(citation: tuple[str, str, int, int]) -> None:
    doc, path, start, end = citation

    if path.startswith(SIBLING_PREFIXES):
        sibling = REPO.parent / path
        if not sibling.exists():
            pytest.skip(f"{path} is in a sibling repo not checked out here")
        target = sibling
    else:
        target = REPO / path
        assert target.exists(), (
            f"{doc} cites `{path}:{start}`, but that file does not exist. Fix or delete the "
            f"claim — COMPATIBILITY.md's rule, which this applies to every checked document, is "
            f"that an unverifiable claim gets deleted. If the file lives in a sibling repo, the "
            f"citation must carry its repo prefix ({'/, '.join(SIBLING_PREFIXES)}) or nothing can "
            f"tell it apart from a broken local path."
        )

    line_count = len(target.read_text(encoding="utf-8", errors="ignore").splitlines())
    assert end <= line_count, (
        f"{doc} cites `{path}:{start}-{end}`, but {path} has only {line_count} lines. "
        f"The citation is stale."
    )


#: The claims whose citations MUST still point at the right content — the six that went stale once.
#:
#: Each entry is (cited path, a needle that must be UNIQUE in that file). **There is deliberately no
#: line number here.** An earlier version of this table pinned one, and it had to be repointed four
#: times in a single working session — every repoint an opportunity to "fix" the test by pointing it
#: at the wrong line, which is precisely the failure it exists to catch. The line number was also pure
#: duplication: it is derivable from the needle, and a fact stored in two places is a fact that can
#: disagree with itself.
#:
#: What the check does instead: find the needle's line in the target file, then assert COMPATIBILITY.md
#: cites *that* line. So the document is checked against the code rather than against a copy of the
#: line number kept here — which is the direction that catches a stale citation, and the direction that
#: needs no maintenance when unrelated edits shift a file.
ANCHORED = [
    ("COMPATIBILITY.md", "CHANGELOG.md", "No yank"),
    (
        "COMPATIBILITY.md",
        ".github/workflows/publish.yml",
        'registry-url: "https://npm.cloudsmith.io',
    ),
    (
        "COMPATIBILITY.md",
        ".github/workflows/publish.yml",
        'TWINE_REPOSITORY_URL: "https://python.cloudsmith.io',
    ),
    (
        "COMPATIBILITY.md",
        ".github/workflows/release-on-runtime.yml",
        'git tag -a "go/v$VER"',
    ),
    ("COMPATIBILITY.md", "README.md", "crypto shims + conformance tests only"),
    ("COMPATIBILITY.md", ".github/workflows/ci.yml", "must link NOTHING"),
    # DECISIONS.md's own load-bearing three. The zero-Seam-crates gate is cited from BOTH
    # documents and drifted in both — it was repaired in COMPATIBILITY.md and left stale here,
    # which is exactly the argument for checking every document rather than the tidiest one.
    ("DECISIONS.md", ".github/workflows/ci.yml", "must link NOTHING"),
    # The sentence the whole v1-skip decision rests on. Repointed three times in one session as
    # the vendored spec was refreshed and its header rewritten; nothing caught any of them.
    (
        "DECISIONS.md",
        "verify/docs/seam-event.v1.md",
        "is absent (no wire bytes) only on",
    ),
    ("DECISIONS.md", "CHANGELOG.md", "this SDK cannot express its own"),
]

#: How far a citation may sit from the needle's true line and still count. A citation naming a block
#: usually points at its heading or its first line, not at the exact line carrying the string.
CITATION_SLACK = 3


@pytest.mark.parametrize(("doc", "path", "needle"), ANCHORED, ids=lambda v: str(v))
def test_the_load_bearing_citations_still_point_at_the_right_thing(
    doc: str, path: str, needle: str
) -> None:
    """A line that exists but no longer says what it was cited for is the failure that happened.

    **Known limit, accepted deliberately:** within a document, citations are matched to a claim by
    PATH only, so if a document cites one file more than once, any of those citations landing within
    `CITATION_SLACK` of the needle satisfies the check — a drifted citation could in principle be
    masked by an unrelated one. Binding each claim to its own citation would mean parsing the
    document's prose structure, which is materially more machinery than the risk earns. Documents do
    NOT mask each other: `cited` is scoped to `doc`, so `ci.yml` being correctly cited in
    COMPATIBILITY.md cannot cover for its being stale in DECISIONS.md — which is not hypothetical,
    it is exactly the state this entry was added in. Today the duplicated paths within a single
    document are `CHANGELOG.md` and `publish.yml` in COMPATIBILITY.md, whose citations sit 125+
    lines apart against a slack of 3, so every anchored entry is satisfied by exactly its own
    citation. Revisit this if that stops being true.
    """
    lines = (REPO / path).read_text(encoding="utf-8", errors="ignore").splitlines()
    hits = [i + 1 for i, line in enumerate(lines) if needle in line]

    # Absent and ambiguous are BOTH failures, and the second is the one worth being strict about.
    # Four of these six needles were substrings occurring 2-4 times in their file when this check was
    # rewritten (`npm.cloudsmith.io` appeared on four lines of publish.yml). A search that accepts any
    # match would have let a citation drift hundreds of lines and still call itself resolved — passing
    # vacuously, which is the same defect as the stale pin, just quieter. Uniqueness is what makes
    # "the needle is at line N" a fact rather than a guess, so it is asserted, not assumed.
    assert len(hits) == 1, (
        f"{needle!r} occurs {len(hits)} times in {path} (lines {hits or 'none'}); this check needs "
        f"exactly one. If it is 0, the cited content is gone — re-resolve or delete the claim, per "
        f"COMPATIBILITY.md's own rule. If it is >1, the needle is too weak to identify a line: "
        f"lengthen it here until it is unique, do NOT relax this assertion."
    )
    true_line = hits[0]

    cited = [(start, end) for _d, p, start, end in _citations(doc) if p == path]
    assert cited, (
        f"ANCHORED pins {needle!r} in {path}, but {doc} no longer cites {path} at all. Either the "
        f"claim was dropped (then drop this entry too) or the citation format changed."
    )
    assert any(
        start - CITATION_SLACK <= true_line <= end + CITATION_SLACK
        for start, end in cited
    ), (
        f"{needle!r} is at {path}:{true_line}, but {doc} cites {path} only at "
        f"{[str(a) if a == b else f'{a}-{b}' for a, b in cited]}. The citation has drifted — update "
        f"{doc} to {path}:{true_line}."
    )
