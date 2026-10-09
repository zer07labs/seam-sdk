#!/usr/bin/env python3
"""Shift `CHANGELOG.md:N` / `CHANGELOG.md:A-B` citations after retitle_changelog.sh inserts lines.

The retitle opens a fresh "## Unreleased" heading, which inserts lines near the top of CHANGELOG.md
and moves every line below it. The citation gate (python/tests/test_compatibility_citations_resolve.py)
checks the docs' `CHANGELOG.md:` line citations with a 3-line slack, so every release commit used to
drift them and, once the drift outran the slack, went red. publish.yml refuses a tag whose commit is
red, and a tag cannot be re-cut, so 0.43.0 was lost that way. Shifting the citations in the same
commit as the retitle keeps the release commit exactly as green as the main commit it was cut from.

Usage: shift_changelog_citations.py <repo_root> <after_line> <delta>
  Every cited line strictly greater than <after_line> moves by <delta>; a range that straddles it
  keeps its start and moves its end.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

#: The docs the citation gate reads — keep in step with DOCS in test_compatibility_citations_resolve.py.
DOCS = ("COMPATIBILITY.md", "DECISIONS.md", "PROGRESS.md")

CITE = re.compile(r"CHANGELOG\.md:(\d+)(?:-(\d+))?")


def shift_text(text: str, after: int, delta: int) -> tuple[str, int]:
    changed = 0

    def repl(m: re.Match[str]) -> str:
        nonlocal changed
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) else None
        na = a + delta if a > after else a
        nb = None if b is None else (b + delta if b > after else b)
        if (na, nb) == (a, b):
            return m.group(0)
        changed += 1
        return f"CHANGELOG.md:{na}" + ("" if nb is None else f"-{nb}")

    return CITE.sub(repl, text), changed


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    root, after, delta = Path(argv[1]), int(argv[2]), int(argv[3])
    total = 0
    for name in DOCS:
        path = root / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        new, n = shift_text(text, after, delta)
        if n:
            path.write_text(new, encoding="utf-8")
            print(f"shifted {n} CHANGELOG.md citation(s) in {name} by {delta:+d}")
        total += n
    if not total:
        print("no CHANGELOG.md citations below the insertion point")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
