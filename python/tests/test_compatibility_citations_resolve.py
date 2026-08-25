"""Every `file:line` citation in `COMPATIBILITY.md` must actually resolve.

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
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).parents[2]
DOC = REPO / "COMPATIBILITY.md"

#: `path/to/file.ext:12` or `path/to/file.ext:12-34`, inside backticks.
CITATION = re.compile(r"`([\w./-]+\.\w+):(\d+)(?:-(\d+))?`")

#: Paths that live in sibling repos — real citations, but not resolvable from this checkout.
#: Named explicitly rather than pattern-skipped, so a typo'd local path cannot hide among them.
SIBLING_PREFIXES = ("seam-adapters/", "seam-aegis/", "seam-runtime/")


def _citations() -> list[tuple[str, int, int]]:
    out = []
    for m in CITATION.finditer(DOC.read_text(encoding="utf-8")):
        path, start, end = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
        out.append((path, start, end))
    return out


def test_the_document_actually_cites_things() -> None:
    """Guard the guard — an empty citation list would make every test below pass vacuously."""
    assert len(_citations()) >= 10, (
        "COMPATIBILITY.md carries almost no file:line citations. Either the document was gutted or "
        "the citation regex no longer matches its format; both need looking at."
    )


@pytest.mark.parametrize("citation", _citations(), ids=lambda c: f"{c[0]}:{c[1]}")
def test_each_citation_resolves(citation: tuple[str, int, int]) -> None:
    path, start, end = citation

    if path.startswith(SIBLING_PREFIXES):
        sibling = REPO.parent / path
        if not sibling.exists():
            pytest.skip(f"{path} is in a sibling repo not checked out here")
        target = sibling
    else:
        target = REPO / path
        assert target.exists(), (
            f"COMPATIBILITY.md cites `{path}:{start}`, but that file does not exist. Fix or delete "
            f"the claim — the document's own rule is that an unverifiable claim gets deleted."
        )

    line_count = len(target.read_text(encoding="utf-8", errors="ignore").splitlines())
    assert end <= line_count, (
        f"COMPATIBILITY.md cites `{path}:{start}-{end}`, but {path} has only {line_count} lines. "
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
    ("CHANGELOG.md", "No yank"),
    (".github/workflows/publish.yml", 'registry-url: "https://npm.cloudsmith.io'),
    (
        ".github/workflows/publish.yml",
        'TWINE_REPOSITORY_URL: "https://python.cloudsmith.io',
    ),
    (".github/workflows/release-on-runtime.yml", 'git tag -a "go/v$VER"'),
    ("README.md", "crypto shims + conformance tests only"),
    (".github/workflows/ci.yml", "must link NOTHING"),
]

#: How far a citation may sit from the needle's true line and still count. A citation naming a block
#: usually points at its heading or its first line, not at the exact line carrying the string.
CITATION_SLACK = 3


@pytest.mark.parametrize(("path", "needle"), ANCHORED, ids=lambda v: str(v))
def test_the_load_bearing_citations_still_point_at_the_right_thing(
    path: str, needle: str
) -> None:
    """A line that exists but no longer says what it was cited for is the failure that happened.

    **Known limit, accepted deliberately:** citations are matched to a claim by PATH only, so if a file
    is cited more than once, any of its citations landing within `CITATION_SLACK` of the needle
    satisfies the check — a drifted citation could in principle be masked by an unrelated one. Binding
    each claim to its own citation would mean parsing the document's table rows, which is materially
    more machinery than the risk earns. Today only two paths are cited twice (`CHANGELOG.md` and
    `publish.yml`) and their citations sit 125+ lines apart against a slack of 3, so every anchored
    entry is satisfied by exactly its own citation. Revisit this if that stops being true.
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

    cited = [(s, e) for p, s, e in _citations() if p == path]
    assert cited, (
        f"ANCHORED pins {needle!r} in {path}, but COMPATIBILITY.md no longer cites {path} at all. "
        f"Either the claim was dropped (then drop this entry too) or the citation format changed."
    )
    assert any(
        s - CITATION_SLACK <= true_line <= e + CITATION_SLACK for s, e in cited
    ), (
        f"{needle!r} is at {path}:{true_line}, but COMPATIBILITY.md cites {path} only at "
        f"{[str(s) if s == e else f'{s}-{e}' for s, e in cited]}. The citation has drifted — update "
        f"COMPATIBILITY.md to {path}:{true_line}."
    )
