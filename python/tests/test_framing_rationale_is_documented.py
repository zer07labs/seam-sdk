"""Every shim that implements the commitment digest must carry the length-prefix rationale.

The framing is mirrored byte-for-byte in five languages, and the length prefixes are the one part a
maintainer is most likely to read as noise. Without them, ``("a\\0b","c")`` and ``("a","b\\0c")``
produce identical preimages — so one artifact can verify under another's signature. Both
``seam-store`` and ``seam-trust-aitp`` record that reason in their own source, and
``plans/sdk-exec-w1-w7.md`` §9 names "simplifying" the framing as a thing never to do.

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

#: The five implementations of `seam-commitment-digest:v1`, and where each is expected to explain
#: itself. `verify/` is deliberately NOT here: it does not implement the commitment digest at all.
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
}


@pytest.mark.parametrize("language", sorted(SHIMS))
def test_the_shim_implements_the_commitment_digest(language: str) -> None:
    """Guard the guard: if a shim stops implementing the digest, the assertions below would pass
    vacuously. This is what makes the rationale check mean something."""
    source = SHIMS[language].read_text(encoding="utf-8")
    assert "seam-commitment-digest:v1" in source, (
        f"{language} no longer references the commitment-digest domain tag — either it stopped "
        f"implementing the framing (update SHIMS) or the domain was renamed without updating this "
        f"guard"
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


def test_verify_is_not_a_sixth_mirror() -> None:
    """`verify/` does NOT implement the commitment digest, and no doc may imply it does.

    The published verifier checks the event chain and erasure certificates. Describing it as a sixth
    implementation of the commitment digest would overstate what an auditor running it has actually
    verified — the precise class of overclaim this workstream is meant to remove, not add.
    """

    # Look for the domain tag as CODE, not as prose. `verify/src/lib.rs` names the string in its
    # module docs precisely to say it does NOT implement this digest, and a guard that fired on that
    # would punish the documentation for being explicit — the opposite of what it is for.
    def implements_it(path: pathlib.Path) -> bool:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.lstrip()
            if stripped.startswith(("//", "#", "*", "/*")):
                continue
            if "seam-commitment-digest" in line:
                return True
        return False

    hits = [
        p.relative_to(REPO)
        for p in (REPO / "verify").rglob("*")
        if p.is_file()
        and p.suffix in {".rs", ".toml"}
        and "target" not in p.parts
        and implements_it(p)
    ]
    assert not hits, (
        f"`seam-commitment-digest` now appears under verify/ ({hits}). If the verifier genuinely "
        f"implements the commitment digest, that is a real change: add it to SHIMS above, give it "
        f"the rationale comment, and update COMPATIBILITY.md — which currently states the published "
        f"verifier does NOT cover commitment digests."
    )
