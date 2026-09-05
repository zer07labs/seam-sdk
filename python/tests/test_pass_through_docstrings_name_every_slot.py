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
import re

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


def _enumeration(path: pathlib.Path) -> str:
    """The one SENTENCE that makes the pass-through claim — the one carrying `MARKER`.

    Scoped this tightly on purpose, after two successive weakenings were measured:

    * The original read the WHOLE FILE, so any backticked mention anywhere satisfied it — a code
      comment elsewhere in `client.py` naming a field would have proved the docstring admits it.
    * Scoping to the enclosing docstring is still not enough: this docstring's *next* sentence
      independently discusses `key_status` and `resolved_status`, so both could be deleted from the
      enumeration and the guard would still find them. That mutation was run and passed 10/10.

    The claim being guarded is "every field the contract carries arrives", made once, in one
    sentence, with a list. That sentence is what has to stay true, so that sentence is what is read.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    idx = next((i for i, ln in enumerate(lines) if MARKER in ln), None)
    assert idx is not None, f"{path} no longer contains {MARKER!r}"
    # The enclosing block: python `"""…"""` or TS `/** … */`. Walk out from the marker line.
    start = next(
        i for i in range(idx, -1, -1) if '"""' in lines[i] or "/**" in lines[i]
    )
    end = next(
        (
            i
            for i in range(idx + 1, len(lines))
            if '"""' in lines[i] or "*/" in lines[i]
        ),
        len(lines) - 1,
    )
    flat = " ".join(
        ln.strip().lstrip("*").strip().strip('"') for ln in lines[start : end + 1]
    )
    # Sentence boundaries: a period followed by whitespace. The parenthesised asides in these
    # docstrings ("(closed, PascalCase)") carry no periods, so this does not split inside one.
    sentences = re.split(r"(?<=\.)\s+", flat)
    hit = [s for s in sentences if MARKER in s]
    assert len(hit) == 1, (
        f"{path} has {len(hit)} sentences carrying {MARKER!r}; this guard reads exactly one. "
        "If the claim was split across sentences, re-scope this helper deliberately."
    )
    return hit[0]


def _docstring_names(path: pathlib.Path, field: str, spelling: str) -> bool:
    """Is `field` named, in backticks, in the enumeration sentence? Backticks because a prose
    mention is not a claim."""
    wanted = _camel(field) if spelling == "camel" else field
    return f"`{wanted}`" in _enumeration(path)


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
# This fixture used to inject `revocation` / `revocation_trust_class` — ACDP P3 tags 12-13 — because
# they were the REAL next fields, making the test a rehearsal of a known-coming event rather than an
# invented one. Phase 8 adopted them, so they are now declared in the committed manifest and
# injecting them adds nothing: the tripwire would assert that adding two fields changes the expected
# set, get an empty diff, and fail. The rehearsal succeeded and is over.
#
# So the probe is now SYNTHETIC, deliberately, and named to be unmistakable. There is no announced
# P4 `ContextBinding` field to point at; inventing a plausible-looking one (`attestation_freshness`)
# would read like a real contract field to the next person and is exactly the sort of thing that
# gets copied into a manifest by accident. When a real next field IS announced, move this back to it
# — a rehearsal against the real thing is worth more than one against a placeholder.
#
# The name must not collide with a real field, and `test_the_probe_slot_is_not_a_real_field` below
# fails if it ever does.
_PROBE = ("zz_probe_unadopted_slot",)


@pytest.fixture
def manifest_with_p3(tmp_path: pathlib.Path) -> pathlib.Path:
    """A COPY of the committed manifest with the synthetic probe slot added. The real file is never
    touched."""
    scratch = tmp_path / "field-manifest.txt"
    lines = MANIFEST.read_text(encoding="utf-8").splitlines(keepends=True)
    out, inserted = [], False
    for line in lines:
        if line.startswith("ContextBinding/") and not inserted:
            out.extend(f"ContextBinding/{f}\n" for f in _PROBE)
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
    assert after - before == set(_PROBE), (
        f"adding {sorted(_PROBE)} to the manifest must add exactly that to the expected set, got "
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
    assert missing == sorted(_PROBE), (
        f"{source} names {sorted(set(_PROBE) - set(missing))} of the new slots already, or reports "
        f"the wrong set: {missing}. This is the tripwire's own proof that it fires; it rehearsed "
        "#96's adoption for real (Phase 8) and now runs against a synthetic probe slot."
    )


def test_widening_the_frozen_list_is_what_silences_the_tripwire() -> None:
    """The honest limit of criterion 3, stated as a test rather than left in a comment.

    `FROZEN_BASE_SIX` is hardcoded, so adding a field to IT silences the guard just as effectively
    as updating the docstrings would satisfy it. Nothing makes a hardcoded list mutation-proof. What
    the exact-equality pin buys is that the silencing edit is loud and reviewable — this test
    demonstrates the mechanism explicitly so nobody has to rediscover that the exclusion list is the
    soft spot.
    """
    probe = _PROBE[0]
    widened = set(FROZEN_BASE_SIX) | {probe}
    declared_with_probe = _manifest_context_binding_fields(MANIFEST) | set(_PROBE)
    assert probe not in (declared_with_probe - widened), (
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


def test_the_probe_slot_is_not_a_real_field() -> None:
    """The synthetic probe must stay synthetic.

    `manifest_with_p3` proves the tripwire fires by adding a slot the docstrings do not name. If the
    probe name ever became a REAL `ContextBinding` field, the fixture would add nothing, the
    expected-set diff would be empty, and the three rehearsal tests would fail confusingly rather
    than tell you why. That is exactly what happened to the previous probe: it named ACDP P3's
    `revocation` pair, which was the right choice while they were coming and the wrong one the day
    they landed.
    """
    declared = _manifest_context_binding_fields(MANIFEST)
    collided = sorted(set(_PROBE) & declared)
    assert not collided, (
        f"the synthetic probe slot(s) {collided} are now REAL fields in "
        "contract/field-manifest.txt. Pick a new probe name — or better, if a real unadopted "
        "ContextBinding field now exists, point the probe at that instead: rehearsing against the "
        "real next field is worth more than rehearsing against a placeholder."
    )
