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


#: The claims whose citations MUST still point at the right content. Each entry is
#: (cited path, cited line, a substring that must appear on or near that line).
#: These are exactly the six that went stale once — pinned so they cannot again.
ANCHORED = [
    ("CHANGELOG.md", 227, "No yank"),
    (".github/workflows/publish.yml", 130, "npm.cloudsmith.io"),
    (".github/workflows/publish.yml", 255, "python.cloudsmith.io"),
    (".github/workflows/release-on-runtime.yml", 120, "go/v$VER"),
    ("README.md", 124, "crypto shims"),
    (".github/workflows/ci.yml", 289, "must link NOTHING"),
]


@pytest.mark.parametrize(("path", "line", "needle"), ANCHORED, ids=lambda v: str(v))
def test_the_load_bearing_citations_still_point_at_the_right_thing(
    path: str, line: int, needle: str
) -> None:
    """A line that exists but no longer says what it was cited for is the failure that happened.

    Checked with a small window rather than an exact line, so ordinary edits nearby do not cause
    churn — but a citation that has drifted to an unrelated part of the file still fails.
    """
    lines = (REPO / path).read_text(encoding="utf-8", errors="ignore").splitlines()
    window = "\n".join(lines[max(0, line - 4) : line + 3])
    assert needle in window, (
        f"COMPATIBILITY.md cites `{path}:{line}` for {needle!r}, but that is no longer what is "
        f"there. Someone inserted or removed lines above it. Re-resolve the citation:\n"
        f"--- {path}:{max(1, line - 3)}-{line + 3} ---\n{window}"
    )
