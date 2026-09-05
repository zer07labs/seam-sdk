"""The three pass-through docstrings name every ACDP slot the contract declares.

`ResolveContext` returns the generated `ContextBinding` unchanged, and three docstrings tell a reader
which fields that means — `python/seam_sdk/client.py`, `python/seam_sdk/aio.py`, `ts/src/client.ts`.
Each currently enumerates exactly five.

When tags 7-10 were adopted, both client docstrings "enumerated four of the eleven as if that were
the set", and the staleness was caught BY HAND. Nothing checked them, so nothing would have caught it
a second time. This is that check, and it exists in the phase BEFORE the adoption that will need it —
a guard added after the mistake is documentation of the mistake, not a guard.

The expected set is DERIVED from `contract/field-manifest.txt`, never hardcoded: a test carrying its
own copy of the answer is self-calibrating and proves nothing. It reddens automatically the moment
`ContextBinding` grows a field, which is the whole point.
"""

from __future__ import annotations

import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = REPO / "contract" / "field-manifest.txt"

#: The docstrings that enumerate the pass-through slots, and the spelling each uses.
#: TS is camelCase because that is what protobuf-es emits and what a TS caller actually types; the
#: mapping is derived below rather than listed, so a field cannot hide in a hand-written table.
SOURCES = (
    ("python/seam_sdk/client.py", "snake"),
    ("python/seam_sdk/aio.py", "snake"),
    ("ts/src/client.ts", "camel"),
)

#: `ContextBinding`'s ORIGINAL six fields — the message as it stood before ACDP added anything.
#: Everything else in the manifest is an ACDP slot this SDK passes through and must therefore name.
#:
#: Hardcoded, and that is a real weakness: adding a new field to THIS tuple would silence the
#: tripwire just as effectively as updating the docstrings. Nothing can make a hardcoded list
#: mutation-proof. What the exact-equality test below buys is that widening it is a loud, reviewable
#: edit to a tuple named "frozen" with this comment attached — not a one-word change nobody notices.
FROZEN_BASE_SIX = (
    "classification",
    "ctx_ref",
    "derived_from",
    "fidelity",
    "lineage_id",
    "version",
)


def _manifest_context_binding_fields(manifest: pathlib.Path) -> set[str]:
    return {
        line.split("/", 1)[1].strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.startswith("ContextBinding/")
    }


def _expected_pass_through(manifest: pathlib.Path) -> set[str]:
    return _manifest_context_binding_fields(manifest) - set(FROZEN_BASE_SIX)


def _camel(snake: str) -> str:
    head, *rest = snake.split("_")
    return head + "".join(w.capitalize() for w in rest)


def _docstring_names(path: pathlib.Path, field: str, spelling: str) -> bool:
    """Is `field` named, in backticks, in this file? Backticks because prose mentions are not claims."""
    wanted = _camel(field) if spelling == "camel" else field
    return f"`{wanted}`" in path.read_text(encoding="utf-8")


def test_the_base_six_are_exactly_the_pre_acdp_fields() -> None:
    """The frozen tuple, pinned by exact equality so widening it is a loud, reviewable edit.

    Two separate assertions, and neither is decoration. The first is a live consistency check: every
    name in the tuple must still be declared by the manifest, so a RENAMED base field fails here
    rather than silently shrinking the expected pass-through set. The second is the exact-equality
    pin — a literal repeated on purpose, because the value of a frozen list is precisely that
    changing it cannot be done quietly.
    """
    declared = _manifest_context_binding_fields(MANIFEST)
    assert set(FROZEN_BASE_SIX) <= declared, (
        f"the frozen base list names fields the manifest does not declare: "
        f"{sorted(set(FROZEN_BASE_SIX) - declared)}"
    )
    assert set(FROZEN_BASE_SIX) == {
        "classification",
        "ctx_ref",
        "derived_from",
        "fidelity",
        "lineage_id",
        "version",
    }, (
        "FROZEN_BASE_SIX changed. It is `ContextBinding` as it stood BEFORE ACDP, and it is frozen "
        "by definition — a new field is an ACDP slot the SDK passes through, and belongs in the "
        "docstrings, not in this exclusion list. Adding one here silences the tripwire."
    )


@pytest.mark.parametrize("source,spelling", SOURCES, ids=[s for s, _ in SOURCES])
def test_every_pass_through_slot_is_named_in_the_docstring(
    source: str, spelling: str
) -> None:
    path = REPO / source
    expected = _expected_pass_through(MANIFEST)
    assert expected, (
        "the manifest declares no ACDP slots — this guard would check nothing"
    )
    missing = sorted(f for f in expected if not _docstring_names(path, f, spelling))
    assert not missing, (
        f"{source} does not name {missing}, which `contract/field-manifest.txt` declares on "
        f"ContextBinding. `ResolveContext` returns the binding UNCHANGED, so every one of these "
        f"reaches a caller whether or not the docstring admits it. Name them (in "
        f"{'camelCase' if spelling == 'camel' else 'snake_case'}, in backticks) or explain in the "
        f"PR why this SDK now hides a field it passes through."
    )


# ── The tripwire, proved to fire ──────────────────────────────────────────────────────────────────
# The three tests above all pass today. That is exactly what a tripwire is supposed to do before it
# trips, and it is also what a broken one does — so the cases below construct the future the guard
# exists for and check that it actually goes off.
#
# `ContextBinding/revocation` and `ContextBinding/revocation_trust_class` are not hypothetical: they
# are ACDP P3 tags 12-13, already merged in seam-runtime and already on the BSR. The adoption is
# tracked in this repo's #96. They are used here because they are the real next fields, so this test
# is a rehearsal of the actual event rather than an invented one.

_P3 = ("revocation", "revocation_trust_class")


@pytest.fixture
def manifest_with_p3(tmp_path: pathlib.Path) -> pathlib.Path:
    """A COPY of the committed manifest with tags 12-13 added. The real file is never touched."""
    scratch = tmp_path / "field-manifest.txt"
    lines = MANIFEST.read_text(encoding="utf-8").splitlines(keepends=True)
    out, inserted = [], False
    for line in lines:
        if line.startswith("ContextBinding/") and not inserted:
            out.extend(f"ContextBinding/{f}\n" for f in _P3)
            inserted = True
        out.append(line)
    assert inserted, (
        "no ContextBinding entries in the manifest — the fixture built nothing"
    )
    scratch.write_text("".join(out), encoding="utf-8")
    return scratch


def test_the_expected_set_grows_when_the_manifest_declares_a_new_slot(
    manifest_with_p3: pathlib.Path,
) -> None:
    """The derivation, not the assertion — checked separately so a failure says which half broke."""
    before = _expected_pass_through(MANIFEST)
    after = _expected_pass_through(manifest_with_p3)
    assert after - before == set(_P3), (
        f"adding tags 12-13 to the manifest must add exactly those two to the expected set, got "
        f"{sorted(after - before)}"
    )


@pytest.mark.parametrize("source,spelling", SOURCES, ids=[s for s, _ in SOURCES])
def test_a_new_slot_reddens_every_docstring_that_has_not_named_it(
    source: str, spelling: str, manifest_with_p3: pathlib.Path
) -> None:
    """All three files must be named, not just the first one found.

    A guard that reported only one would send someone to fix that file and ship the other two — the
    Python pair and the TS client are three separate enumerations of the same set, and when tags
    7-10 landed the staleness was in more than one of them at once.
    """
    path = REPO / source
    missing = sorted(
        f
        for f in _expected_pass_through(manifest_with_p3)
        if not _docstring_names(path, f, spelling)
    )
    assert missing == sorted(_P3), (
        f"{source} names {sorted(set(_P3) - set(missing))} of the new slots already, or reports "
        f"the wrong set: {missing}. This test is the rehearsal for #96's adoption; if it does not "
        "fire here it will not fire then."
    )


def test_widening_the_frozen_list_is_what_silences_the_tripwire() -> None:
    """The honest limit of criterion 3, stated as a test rather than left in a comment.

    `FROZEN_BASE_SIX` is hardcoded, so adding a field to IT silences the guard just as effectively
    as updating the docstrings would satisfy it. Nothing makes a hardcoded list mutation-proof. What
    the exact-equality pin buys is that the silencing edit is loud and reviewable — this test
    demonstrates the mechanism explicitly so nobody has to rediscover that the exclusion list is the
    soft spot.
    """
    widened = set(FROZEN_BASE_SIX) | {"revocation"}
    declared_with_p3 = _manifest_context_binding_fields(MANIFEST) | set(_P3)
    assert "revocation" not in (declared_with_p3 - widened), (
        "widening the frozen list removes the field from the expected set — which is precisely why "
        "test_the_base_six_are_exactly_the_pre_acdp_fields pins it by exact equality"
    )


#: The phrase every pass-through docstring uses. Searched for rather than assumed, because `SOURCES`
#: is a hardcoded list and a hardcoded list of things-to-check is silenced by DELETING an entry — not
#: by breaking one. Measured: removing `ts/src/client.ts` from `SOURCES` left every test in this file
#: green, since the parametrized cases simply ran over less. A guard that checks fewer things passes.
MARKER = "ACDP receipt slots"

#: Where a hand-written client could live. Deliberately wider than `SOURCES`: the point is to notice
#: a FOURTH enumeration appearing, which is the realistic way this guard would go stale — Go, Java
#: and Kotlin have no hand-written client layer today, but that is a fact about today.
SEARCH_ROOTS = ("python/seam_sdk", "ts/src", "go", "verify/src")


def test_sources_covers_every_docstring_that_makes_this_claim() -> None:
    """Anti-vacuity for `SOURCES` itself — derived from the tree, not from the list.

    Every other test here is parametrized over `SOURCES`, so they are all satisfied by a `SOURCES`
    that has been quietly shortened. This is the one test that would notice, and it is also what
    catches a new client layer being added with its own copy of the enumeration.
    """
    found = set()
    for root in SEARCH_ROOTS:
        base = REPO / root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".ts", ".go", ".rs"}:
                if MARKER in path.read_text(encoding="utf-8", errors="ignore"):
                    found.add(str(path.relative_to(REPO)))
    listed = {s for s, _ in SOURCES}
    assert found == listed, (
        f"the files claiming to pass ACDP slots through are {sorted(found)}, but SOURCES checks "
        f"{sorted(listed)}. Unchecked: {sorted(found - listed)}. Listed but no longer making the "
        f"claim: {sorted(listed - found)}. Every enumeration of this set needs the tripwire on it — "
        "three copies of one list is why the guard exists at all."
    )
    assert len(listed) >= 3, (
        f"only {len(listed)} source(s) checked; the Python pair and the TS client are three separate "
        "enumerations and all three must be covered"
    )
