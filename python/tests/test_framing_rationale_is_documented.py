"""Every shim that implements the commitment digest must carry the length-prefix rationale.

The framing is mirrored byte-for-byte in five languages, and the length prefixes are the one part a
maintainer is most likely to read as noise. Without them, ``("a\\0b","c")`` and ``("a","b\\0c")``
produce identical preimages — so one artifact can verify under another's signature. Both
``seam-store`` and ``seam-trust-aitp`` record that reason in their own source, and
``plans/archive/sdk-exec-w1-w7.md`` §9 names "simplifying" the framing as a thing never to do.

Go, Python and TypeScript carried that rationale. **Java and Kotlin carried none** — a maintainer
opening `SeamCrypto.java` saw a loop over byte arrays with a length prefix and no stated reason for
it, which is exactly the condition under which a "cleanup" happens.

A comment is not enforceable, so this test is what keeps it present: the rationale is load-bearing
documentation, and documentation that can silently disappear is documentation nobody can rely on.
The conformance suites prove the framing is *correct today*; this proves the *reason* survives, which
is what protects it tomorrow.
"""

from __future__ import annotations

import pathlib

import pytest

REPO = pathlib.Path(__file__).parents[2]

#: The implementations of `seam-commitment-digest:v2`, and where each is expected to explain itself:
#: the five SDK shims, and since seam-sdk#225 the published verifier, whose `bundle` step 4 recomputes
#: the digest to check a bundle's TCT (`verify/src/commitment.rs`).
SHIMS = {
    "go": REPO / "go" / "crypto" / "crypto.go",
    "java": REPO
    / "java"
    / "src"
    / "main"
    / "java"
    / "com"
    / "zer07labs"
    / "seam"
    / "SeamCrypto.java",
    "kotlin": REPO
    / "kotlin"
    / "src"
    / "main"
    / "kotlin"
    / "com"
    / "zer07labs"
    / "seam"
    / "SeamCrypto.kt",
    "python": REPO / "python" / "seam_sdk" / "crypto.py",
    "typescript": REPO / "ts" / "src" / "crypto.ts",
    "verify": REPO / "verify" / "src" / "commitment.rs",
}


@pytest.mark.parametrize("language", sorted(SHIMS))
def test_the_shim_implements_the_commitment_digest(language: str) -> None:
    """Guard the guard: if a shim stops implementing the digest, the assertions below would pass
    vacuously. This is what makes the rationale check mean something."""
    source = SHIMS[language].read_text(encoding="utf-8")
    assert "seam-commitment-digest:v2" in source, (
        f"{language} no longer references the commitment-digest domain tag — either it stopped "
        f"implementing the framing (update SHIMS) or the domain was renamed without updating this "
        f"guard"
    )
    # v1 is DELETED, not dual-verified (seam-runtime#1255, pre-GA no-backward-compatibility). A
    # quoted v1 tag in code means a fallback crept back in; prose mentioning v1 is fine.
    assert '"seam-commitment-digest:v1"' not in source, (
        f"{language} still carries the v1 domain tag as a literal — v1 is deleted, not dual-verified"
    )


@pytest.mark.parametrize("language", sorted(SHIMS))
def test_the_shim_explains_why_the_framing_is_length_prefixed(language: str) -> None:
    source = SHIMS[language].read_text(encoding="utf-8").lower()

    # It must say the framing is length-prefixed...
    assert "length-prefix" in source or "length prefix" in source, (
        f"{language}'s commitment-digest implementation does not describe its framing as "
        f"length-prefixed. The prefixes are what make the digest injective over the field tuple; "
        f"a reader who does not know that is a reader who might remove them."
    )

    # ...and, crucially, WHY — the collision a separator would allow. A bare "length-prefixed"
    # restates the code; the consequence is what stops someone changing it.
    #
    # Two phrasings are accepted because both genuinely state it, and forcing one wording would be
    # style enforcement rather than a guard: Go/Python/TypeScript say a separator would let
    # boundary-shifted fields "collide"; Java/Kotlin say the tuples produce "identical preimages".
    states_the_consequence = (
        "collide" in source or "collision" in source or "identical preimage" in source
    )
    assert states_the_consequence, (
        f"{language}'s commitment-digest implementation says the framing is length-prefixed but "
        f"not what that prevents. State it explicitly: with a NUL separator, the tuples "
        f'("a\\0b","c") and ("a","b\\0c") produce identical preimages, letting one artifact verify '
        f"under another's signature. The consequence is what survives a code review; the mechanism "
        f"alone reads as trivia."
    )


def test_verify_implements_it_in_exactly_one_place() -> None:
    """`verify/` implements the commitment digest in `src/commitment.rs` and nowhere else.

    Until seam-sdk#225 the published verifier did not implement this digest at all, and this test
    guarded against any doc implying it did. `bundle` now needs it for step 4, so the guard moves:
    the verifier is a sixth implementation (it is in `SHIMS` above and carries the rationale), and a
    second copy inside `verify/` would be a second thing to drift.
    """

    # The domain tag as a string literal of its own (`b"seam-commitment-digest:v2"`, or the grant's
    # `"seam-commitment-digest:{}"`), never as prose: docs, and user-facing messages that merely NAME
    # the digest mid-sentence, may mention it freely.
    def implements_it(path: pathlib.Path) -> bool:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.lstrip()
            if stripped.startswith(("//", "#", "*", "/*")):
                continue
            if '"seam-commitment-digest:' in line:
                return True
        return False

    hits = sorted(
        p.relative_to(REPO).as_posix()
        for p in (REPO / "verify").rglob("*")
        if p.is_file()
        and p.suffix in {".rs", ".toml"}
        and "target" not in p.parts
        and "tests" not in p.parts
        and implements_it(p)
    )
    assert hits == ["verify/src/commitment.rs"], (
        f"`seam-commitment-digest` appears as code under verify/ in {hits}; it belongs in "
        f"verify/src/commitment.rs alone."
    )
