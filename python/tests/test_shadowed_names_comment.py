"""``ts/src/index.ts``'s shadowed-names comment must name every shadowed type, and count them right.

Why this is a test and not a convention
---------------------------------------
The comment tells a consumer which generated names are unreachable from the package root because a
hand-written export of the same name won that slot. It is the only place that says so — the exports
map exposes only ``"."``, so a consumer who wants ``pb.PolicyEnforcement`` has no other way to learn
that ``PolicyEnforcement`` from the root is a different type.

It had already gone wrong twice by the time this file was written, in both of the two ways such a
comment can:

* **A name went missing.** ``CollectiveOutcome`` was shadowed by ``client.ts`` in an earlier phase
  and never added to the list, so the comment enumerated three of the four shadows that existed.
* **The count went stale.** The comment opened with the word "Two" and then listed three names,
  counting ``pb.BudgetLimits`` / ``pb.StepUsage`` as one entry. A count that must be *decoded* before
  it can be checked is a count that cannot go stale loudly — which is why this file requires it to be
  one per name, and asserts the word.

Neither break is visible to ``tsc``: a stale comment compiles. The failure it causes is a consumer
reading ``PolicyEnforcement`` from the root, getting the decoded DTO instead of the wire message, and
finding out at the point where the shapes differ.

What "shadowed" means here, precisely
--------------------------------------
A name declared by BOTH ``ts/src/*.ts`` (excluding ``index.ts`` itself, which only re-exports) and
``ts/gen/seam/api/v1/seam_pb.ts``. ``index.ts`` does ``export * from "./client.js"`` before
``export * as pb``, so the hand-written declaration is what the root name resolves to and the
generated one is reachable only under ``pb.``.

The detector is calibrated against both sets rather than trusted: a regex that silently matches
nothing would make this file pass while checking nothing at all, which is the same defect as the
stale comment, just quieter.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).parents[2]
SRC = REPO / "ts" / "src"
GEN = REPO / "ts" / "gen" / "seam" / "api" / "v1" / "seam_pb.ts"
INDEX = SRC / "index.ts"

#: A top-level `export <kind> <Name>`. Anchored at column 0 on purpose — a nested or indented
#: declaration is not a module export and must not count toward either side.
DECL = re.compile(
    r"^export\s+(?:declare\s+)?(?:interface|type|class|const|function|enum)\s+([A-Za-z_$][\w$]*)"
)

#: Count words this file accepts, lowercased. Deliberately small: if the list ever outgrows twelve,
#: the comment has bigger problems than its adjective and a human should look at it.
WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
}


def _declared(path: pathlib.Path) -> set[str]:
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        m = DECL.match(line)
        if m:
            out.add(m.group(1))
    return out


def _hand_written() -> set[str]:
    names: set[str] = set()
    for f in sorted(SRC.glob("*.ts")):
        if f.name == "index.ts":
            continue
        names |= _declared(f)
    return names


def _shadowed() -> set[str]:
    return _hand_written() & _declared(GEN)


def _comment() -> str:
    """The shadowed-names block: from the line introducing it to the first blank non-comment line."""
    lines = INDEX.read_text(encoding="utf-8").splitlines()
    starts = [
        i for i, line in enumerate(lines) if "generated names are shadowed" in line
    ]
    assert len(starts) == 1, (
        f"expected exactly one shadowed-names introduction in {INDEX.name}, found {len(starts)}"
    )
    i = starts[0]
    out = []
    while i < len(lines) and lines[i].startswith("//"):
        out.append(lines[i])
        i += 1
    return "\n".join(out)


# ── The detector must be able to see anything at all ─────────────────────────────────────────────


def test_both_sides_of_the_comparison_are_populated() -> None:
    """A regex matching nothing would make every assertion below vacuously true.

    The floors are far below the measured values (49 hand-written, 197 generated when written), so
    they survive ordinary churn and fail only on a detector that has actually stopped working.
    """
    hand, gen = _hand_written(), _declared(GEN)
    assert len(hand) >= 20, (
        f"only {len(hand)} hand-written exports found — DECL has stopped matching"
    )
    assert len(gen) >= 80, (
        f"only {len(gen)} generated exports found — is ts/gen/ present?"
    )


def test_the_shadow_set_is_not_empty() -> None:
    """If this ever legitimately empties, delete the comment and this file together — do not let a
    comment describing an empty set keep passing because the set is empty."""
    assert _shadowed(), (
        "no shadowed names found; the comment in index.ts now describes nothing"
    )


# ── The comment itself ───────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(_shadowed()))
def test_every_shadowed_name_is_listed(name: str) -> None:
    assert f"`pb.{name}`" in _comment(), (
        f"{name} is declared in both ts/src/ and the generated surface, so the root-level export "
        f"shadows pb.{name} — but index.ts's shadowed-names comment does not mention it. Add it, "
        f"and update the count word in the same edit."
    )


def test_the_count_word_matches_the_number_of_shadowed_names() -> None:
    """The half-done fix — append the name, leave the count — is what this asserts against."""
    comment = _comment()
    m = re.search(r"(\w+)\s+generated names are shadowed", comment)
    assert m, "could not find the count word in the shadowed-names comment"
    word = m.group(1).lower()
    assert word in WORDS or word.isdigit(), (
        f"unrecognized count word {m.group(1)!r}; use a digit or one of {sorted(WORDS)}"
    )
    stated = int(word) if word.isdigit() else WORDS[word]
    actual = len(_shadowed())
    assert stated == actual, (
        f"index.ts says {m.group(1)!r} generated names are shadowed, but {actual} are: "
        f"{sorted(_shadowed())}. Count one per NAME, not one per group."
    )


def test_the_comment_lists_nothing_that_is_not_shadowed() -> None:
    """Drift in the other direction: a name removed from the code but left in the comment."""
    listed = set(re.findall(r"`pb\.([A-Za-z_$][\w$]*)`", _comment()))
    extra = listed - _shadowed()
    assert not extra, (
        f"index.ts's shadowed-names comment lists {sorted(extra)}, which are no longer shadowed "
        f"(either the hand-written export or the generated one is gone). Remove them and fix the "
        f"count."
    )
