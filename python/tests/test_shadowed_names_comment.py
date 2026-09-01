"""``ts/src/index.ts``'s dual-declaration comment must name every such type, and count them right.

Why this is a test and not a convention
---------------------------------------
The comment tells a consumer which generated names are unreachable from the package root because a
hand-written export of the same name occupies that slot. It is the only place that says so — the
exports map exposes only ``"."``, so a consumer who wants ``pb.PolicyEnforcement`` has no other way
to learn that ``PolicyEnforcement`` from the root is a different type.

It had already gone wrong twice by the time this file was written, in both of the two ways such a
comment can:

* **A name went missing.** ``CollectiveOutcome`` became dual-declared in an earlier phase and was
  never added, so the comment enumerated three of the four that existed.
* **The count went stale.** It opened with the word "Two" and then listed three names, counting
  ``pb.BudgetLimits`` / ``pb.StepUsage`` as one entry. A count that must be *decoded* before it can
  be checked is a count that cannot go stale loudly — which is why this file requires one entry per
  name, and asserts the word.

Neither break is visible to ``tsc``: a stale comment compiles. The failure it causes is a consumer
reading ``PolicyEnforcement`` from the root, getting the decoded DTO instead of the wire message, and
finding out at the point where the shapes differ.

The mechanism, stated correctly
--------------------------------
"Shadowed" was this file's original word for it and it was the wrong one, so it is not used here.
``index.ts`` never star-exports a generated module: ``export * as pb`` exports exactly one name
(``pb``) and contributes none of the module's inner names to the root. Every generated name that
*does* reach the root gets there through an explicit named list — a deliberately small subset (40 of
the 167 the two modules declare, measured at the time of writing; the rest are ``pb.``/``ev.``-only
and always were). These types are ``pb.``-only because they are simply **not on those lists** — not
because one export beat another, and not because of ordering. Had two star exports genuinely
collided, ESM would have *excluded* the ambiguous name rather than resolving it to the first.

That matters for what a future editor might try: adding one of these names to the explicit
``export type { … }`` list would not surface it — it would make the **generated** type win the root
name and silently displace the hand-written one, which is the opposite of the intent.

What "dual-declared" means here, precisely
-------------------------------------------
A name declared at top level by BOTH the hand-written surface (``ts/src/**/*.ts``, excluding
``index.ts`` itself, which only re-exports) and a generated module (``seam_pb.ts`` **or**
``seam_event_pb.ts`` — ``index.ts`` namespaces both, as ``pb`` and ``ev``).

How this file avoids being the thing it guards against
-------------------------------------------------------
Two calibrations, because it has already failed one of them once. **The detector must see something**
— a regex that silently matches nothing would make every assertion below vacuously true, so both
input sets carry floors. And **the list is read as a list, not as prose**: the first version of this
file substring-searched the whole comment block for ``` `pb.X` ```, which the block's own
historical-rationale sentence satisfied for two names — so deleting their list entry outright left
"FIVE" above a list of three and every test still passed. That is verbatim the rot this file exists
to catch, so `test_a_name_mentioned_only_in_prose_does_not_count_as_listed` pins the distinction.
"""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).parents[2]
SRC = REPO / "ts" / "src"
GEN = (
    REPO / "ts" / "gen" / "seam" / "api" / "v1" / "seam_pb.ts",
    REPO / "ts" / "gen" / "seam" / "event" / "v1" / "seam_event_pb.ts",
)
INDEX = SRC / "index.ts"

#: A top-level `export <kind> <Name>`. Anchored at column 0 on purpose — a nested or indented
#: declaration is not a module export and must not count toward either side.
DECL = re.compile(
    r"^export\s+(?:declare\s+|abstract\s+|async\s+)*"
    # `const enum` first, or the alternation matches `const` and captures the word "enum".
    r"(?:const\s+enum|interface|type|class|const|let|var|function\*?|enum)"
    r"\s+([A-Za-z_$][\w$]*)"
)
#: `export default class Foo` is deliberately NOT matched: it binds the root name `default`, not
#: `Foo`, so it cannot collide with a generated name and counting it would inflate both sides.

#: One entry of the comment's list: a comment line whose first content is an indented
#: `` `pb.Name` `` or `` `ev.Name` ``. Indentation is what separates a list entry from prose, and that
#: separation is the whole fix for the blindness described in the module docstring — a prose sentence
#: naming `pb.StepUsage` starts at `// ` with no indent and must not count. **Both namespaces**,
#: because `GEN` covers both generated modules and `index.ts` namespaces them differently (`pb` for
#: `seam.api.v1`, `ev` for `seam.event.v1`); matching only `pb.` would make the one correct spelling
#: of an event-module entry unsatisfiable.
LIST_ENTRY = re.compile(r"^//\s{3,}`(pb|ev)\.([A-Za-z_$][\w$]*)`")

#: The sentence that introduces the list. Its leading word is the count under test.
INTRO = re.compile(r"^// (\w+) generated names are declared on BOTH sides", re.M)

#: Count words accepted, lowercased. Deliberately small: if the list ever outgrows twelve, the
#: comment has bigger problems than its adjective and a human should look at it.
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
    return {
        m.group(1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if (m := DECL.match(line))
    }


def _hand_written() -> set[str]:
    names: set[str] = set()
    for f in sorted(SRC.rglob("*.ts")):
        if f.name == "index.ts":
            continue
        names |= _declared(f)
    return names


def _generated() -> set[str]:
    names: set[str] = set()
    for f in GEN:
        names |= _declared(f)
    return names


def _dual_declared() -> set[str]:
    return _hand_written() & _generated()


def _comment() -> str:
    """The comment block: from the introducing line to the first line that is not a `//` comment."""
    lines = INDEX.read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if INTRO.match(line)]
    assert len(starts) == 1, (
        f"expected exactly one introducing line in {INDEX.name}, found {len(starts)}. The block is "
        f"located by that sentence; if it was reworded, update INTRO here in the same edit."
    )
    i = starts[0]
    out = []
    while i < len(lines) and lines[i].startswith("//"):
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def _listed_entries(text: str) -> set[tuple[str, str]]:
    """``(namespace, name)`` for each LIST entry — never a name mentioned in the surrounding prose."""
    return {
        (m.group(1), m.group(2))
        for line in text.splitlines()
        if (m := LIST_ENTRY.match(line))
    }


def _listed(text: str) -> set[str]:
    """Just the names the comment lists, dropping the namespace."""
    return {name for _ns, name in _listed_entries(text)}


def _namespaces_of(name: str) -> set[str]:
    """The namespace(s) a dual-declared name is actually reachable under, from the code."""
    return {ns for ns, path in zip(("pb", "ev"), GEN) if name in _declared(path)}


# ── Calibration: this file must be able to fail ──────────────────────────────────────────────────


def test_both_sides_of_the_comparison_are_populated() -> None:
    """A regex matching nothing would make every assertion below vacuously true.

    Measured at the time of writing by calling these functions, not estimated: **47** hand-written,
    **167** generated (144 in ``seam_pb.ts`` plus 23 in ``seam_event_pb.ts``). The floors sit far
    below both, so they survive ordinary churn and fire only on a detector that has actually stopped
    working.
    """
    hand, gen = _hand_written(), _generated()
    assert len(hand) >= 20, (
        f"only {len(hand)} hand-written exports found — DECL has stopped matching"
    )
    assert len(gen) >= 80, (
        f"only {len(gen)} generated exports found — is ts/gen/ present?"
    )


def test_the_dual_declared_set_is_not_empty() -> None:
    """If this ever legitimately empties, delete the comment and this file together — do not let a
    comment describing an empty set keep passing because the set is empty."""
    assert _dual_declared(), (
        "no dual-declared names found; the comment in index.ts now describes nothing"
    )


def test_a_name_mentioned_only_in_prose_does_not_count_as_listed() -> None:
    """The regression test for this file's own first version, which had exactly this hole.

    A prose sentence naming ``pb.StepUsage`` satisfied a substring search over the whole block, so
    the list entry could be deleted with every test still green — "FIVE" above a list of three, which
    is the precise rot the module docstring says this file exists to catch.
    """
    blinding_prose = (
        "// FIVE generated names are declared on BOTH sides — see below.\n"
        "// It once said 'Two' while listing `pb.BudgetLimits` / `pb.StepUsage` as one entry.\n"
        "//\n"
        "//   `pb.Commitment`  — a real list entry, indented.\n"
    )
    assert _listed(blinding_prose) == {"Commitment"}, (
        "LIST_ENTRY is matching prose; the indentation requirement is what separates the two and it "
        "is the only thing standing between this file and passing on the defect it guards"
    )


def test_the_real_comment_lists_more_than_one_name() -> None:
    """Guards the opposite failure of the test above: an over-strict LIST_ENTRY that matches nothing
    would make the set comparison compare two empty sets in a world where the shadow set is empty —
    and, more plausibly, silently reduce the real list to a subset."""
    assert len(_listed(_comment())) >= 2


# ── The comment itself ───────────────────────────────────────────────────────────────────────────


def test_the_list_is_exactly_the_dual_declared_set() -> None:
    """Both directions in one assertion: a name that appeared in the code and not the list, and a
    name left in the list after the code dropped it, are the same defect seen from two sides."""
    listed, actual = _listed(_comment()), _dual_declared()
    assert listed == actual, (
        f"ts/src/index.ts's list and the code disagree.\n"
        f"  declared in both ts/src and ts/gen but NOT listed: {sorted(actual - listed) or 'none'}\n"
        f"  listed but no longer dual-declared:                {sorted(listed - actual) or 'none'}\n"
        f"Fix the list and the count word in the same edit."
    )


def test_the_count_word_matches_the_number_of_names() -> None:
    """The half-done fix — append the name, leave the count — is what this asserts against."""
    m = INTRO.search(_comment())
    assert m, "could not find the count word in the comment"
    word = m.group(1).lower()
    assert word in WORDS or word.isdigit(), (
        f"unrecognized count word {m.group(1)!r}; use a digit or one of {sorted(WORDS)}"
    )
    stated = int(word) if word.isdigit() else WORDS[word]
    actual = len(_dual_declared())
    assert stated == actual, (
        f"index.ts says {m.group(1)!r} generated names are dual-declared, but {actual} are: "
        f"{sorted(_dual_declared())}. Count one per NAME, not one per group."
    )


def test_the_count_word_also_matches_the_list_it_introduces() -> None:
    """Deliberately redundant with the two above, and cheap. If the detector ever regresses so that
    `_dual_declared()` and `_listed()` are both wrong in the same direction, this still catches a
    count that does not match the list a human can see."""
    m = INTRO.search(_comment())
    assert m
    word = m.group(1).lower()
    stated = int(word) if word.isdigit() else WORDS[word]
    assert stated == len(_listed(_comment())), (
        f"index.ts says {m.group(1)!r} but its list has {len(_listed(_comment()))} entries: "
        f"{sorted(_listed(_comment()))}"
    )


#: `export … { A, B } from "../gen/…"` — the explicit re-export lists. A dual-declared name appearing
#: in one of these is the hazard the comment warns about, so it is asserted rather than described.
#: `[^{}]*?` rather than `.*?`: a non-greedy dot with `re.S` happily spans from one `export {` to a
#: LATER block's `} from "../gen/`, swallowing an intervening local re-export and garbling the first
#: name of the generated list. Excluding braces confines each match to one block.
GEN_REEXPORT = re.compile(
    r"^export\s+(?:type\s+)?\{([^{}]*?)\}\s*from\s*\"\.\./gen/", re.S | re.M
)

#: An inline `//` comment runs to end of line, so it must be stripped BEFORE splitting on commas —
#: otherwise `Anchor, // the party anchor` swallows the next entry, which is the following line.
_LINE_COMMENT = re.compile(r"//[^\n]*")


def _explicitly_reexported() -> set[str]:
    """Every generated name re-exported at the root by an explicit list.

    Three spellings defeated the first version of this, and all three are ordinary rather than
    exotic — the first is what `verbatimModuleSyntax` encourages people to write:

    * ``export { BallotChoice, type PolicyEnforcement } from "../gen/…"`` — an inline ``type``
      modifier inside the braces, which left the token as ``"type PolicyEnforcement"``,
    * an inline ``//`` comment after a name, which hid the name on the following line,
    * a local ``export { X } from "./y.js"`` sitting above a generated list, which the old
      ``.*?`` spanned straight across.
    """
    src = INDEX.read_text(encoding="utf-8")
    names: set[str] = set()
    for block in GEN_REEXPORT.findall(src):
        for raw in _LINE_COMMENT.sub("", block).split(","):
            token = raw.strip().split(" as ")[0].strip()
            token = re.sub(r"^(?:type|typeof)\s+", "", token).strip()
            if token:
                names.add(token)
    return names


def test_the_explicit_lists_do_not_contain_a_dual_declared_name() -> None:
    """The hazard the comment names, asserted instead of merely described — because `tsc` is silent.

    Adding one of these names to `export type { … }` does not "surface" the generated type alongside
    the hand-written one: it makes the **generated** type win the root name and displaces the DTO,
    with no error and no warning. Verified by doing it in a scratch tree — `tsc --noEmit` exits 0 and
    the root `CollectiveOutcome` silently becomes the wire message. A consumer would find out where
    the shapes differ, which is exactly the failure this whole comment exists to prevent.
    """
    collision = _explicitly_reexported() & _dual_declared()
    assert not collision, (
        f"ts/src/index.ts re-exports {sorted(collision)} from ../gen/, but the same name(s) are also "
        f"declared by hand in ts/src/. The generated type now wins the root name and the hand-written "
        f"one is unreachable — silently, since tsc does not flag it. Remove them from the explicit "
        f"list; `pb.`/`ev.` is how the wire type stays reachable."
    )


def test_the_reexport_detector_sees_the_lists_it_is_scanning() -> None:
    """The calibration for the check above: a regex that matched nothing would make it vacuous, and
    an empty intersection is exactly what "no collision" looks like."""
    reexported = _explicitly_reexported()
    assert len(reexported) >= 20, (
        f"only {len(reexported)} explicitly re-exported names found — GEN_REEXPORT has stopped "
        f"matching, so the collision check above proves nothing"
    )
    # A name known to be on the list, so the parse is not merely returning noise.
    assert "SessionStep" in reexported, sorted(reexported)[:10]


def test_every_listed_entry_uses_the_namespace_its_module_is_bound_to() -> None:
    """`seam_pb.ts` is namespaced `pb` and `seam_event_pb.ts` is `ev`; a right name under the wrong
    prefix sends a reader to a symbol that does not exist."""
    for ns, name in sorted(_listed_entries(_comment())):
        actual = _namespaces_of(name)
        assert ns in actual, (
            f"index.ts lists `{ns}.{name}`, but {name} is declared in "
            f"{sorted(actual) or 'neither generated module'} — `{ns}.{name}` does not resolve."
        )
