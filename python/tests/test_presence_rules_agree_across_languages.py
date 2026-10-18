"""The `policy_enforcement` / `collective_outcome` presence rules are hand-written, in two languages.

Nothing regenerates these. They are prose in `python/seam_sdk/_policy.py`,
`python/seam_sdk/_collective.py`, `ts/src/client.ts` and the two `errors` modules, describing a
runtime this repository cannot read: `PROGRESS.md`'s clean-room constraint forbids `seam-runtime`'s
Rust sources, and CI does not check that repository out at all. So a codegen refresh will not fix
them, and no gate here can check them against the runtime.

What CAN be checked is the failure mode that actually happened. seam-sdk#107 found FOUR stale sites
— two claims, each written twice, once per language — and they went stale *together* because they
were written together and then the runtime moved under both. The TS block says so in as many words:
"deliberately the same content in two places, so neither language is the authoritative copy of it."
Two copies with no tie between them is one claim that can be half-corrected, and a half-corrected
claim is worse than an uncorrected one: it looks maintained.

So this file pins the two directions that are checkable without leaving the repo:

  * a claim the runtime retracted must not survive anywhere, in either language;
  * a claim that replaced it must appear in BOTH languages, never one.

It cannot tell you the current text is TRUE. It can tell you the two copies have not drifted apart,
and that a specific wrong sentence has not come back.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]

PY_POLICY = REPO / "python" / "seam_sdk" / "_policy.py"
PY_COLLECTIVE = REPO / "python" / "seam_sdk" / "_collective.py"
PY_ERRORS = REPO / "python" / "seam_sdk" / "errors.py"
TS_CLIENT = REPO / "ts" / "src" / "client.ts"
TS_ERRORS = REPO / "ts" / "src" / "errors.ts"

#: Sentences the runtime retracted, and where each was written. A retracted claim that reappears is
#: not a style regression — each of these was *acted on* by a consumer before it was corrected.
RETRACTED = [
    (
        "exactly three steps",
        (PY_POLICY, TS_CLIENT),
        "seam-runtime#561 narrowed all three sites: each reports only when the decision_id being "
        "returned was sealed by that runtime process AND by a commit. 'Exactly three steps' is "
        "wrong in the FAIL-OPEN direction — a caller told absence is impossible on a "
        "commit-terminal step reads absence as 'unenforced' rather than 'no evidence', which is "
        "the opposite conclusion.",
    ),
    (
        "applied the commit envelope and sealed the session",
        (PY_COLLECTIVE, TS_CLIENT),
        "Missing 'freshly'. The two readings used to differ on the store fast path, which could "
        "return a verdict folded from a different round than the decision_id beside it named; "
        "seam-runtime#561 closed that toward absence, making the unqualified sentence wrong.",
    ),
]

#: Claims that must be present in BOTH languages. The pairing is the point — a claim in one
#: language is a claim half the SDK's consumers cannot read.
BOTH_LANGUAGES = [
    (
        "freshly sealed",
        PY_COLLECTIVE,
        TS_CLIENT,
        "the collective_outcome freshness qualifier",
    ),
    (
        "this runtime process",
        PY_POLICY,
        TS_CLIENT,
        "#561's sealed-by-this-process clause",
    ),
    (
        "no enforcement evidence for this call",
        PY_POLICY,
        TS_CLIENT,
        "the reading rule for an absent/false policy_enforcement — the fail-open direction",
    ),
    (
        "three distinct meanings",
        PY_POLICY,
        TS_CLIENT,
        "enforced=False is not one condition; under the third the natural reading is backwards",
    ),
    (
        "not a contract",
        PY_ERRORS,
        TS_ERRORS,
        "FAILED_PRECONDITION's two causes differ only in message text (seam-runtime#565), and the "
        "message must not be parsed",
    ),
]


def _text(path: pathlib.Path) -> str:
    """Lower-cased, comment continuation markers dropped, whitespace collapsed to single spaces.

    All three normalisations are load-bearing, and each was added after a mutation showed the guard
    blind or wrong without it:

    * **casing** — ``THREE distinct meanings`` is prose emphasis, not part of the claim;
    * **whitespace** — these blocks are hard-wrapped at ~100 columns, so a phrase can straddle a
      line break. A plain substring test would report a required claim absent purely because of
      where the wrap fell: a false red, and the fastest way to teach someone to delete a guard;
    * **continuation markers** — and collapsing whitespace is not enough on its own. A wrapped
      TypeScript block comment carries a leading ``*`` on every line, so joining the lines leaves
      ``this runtime * process`` where the source reads ``this runtime process``. That mutation was
      run and this guard FAILED it; this line is what makes it pass. Python docstrings carry no
      such marker, which is exactly why proving the guard against the Python side alone would have
      missed it.

    Nothing here strips ``**`` emphasis: that sits around a phrase rather than inside one, so it
    never splits a needle. A needle that spanned an emphasis boundary would need this revisited.
    """
    body = path.read_text(encoding="utf-8")
    assert body.strip(), f"{path} is empty, so every assertion over it would be vacuous"
    lines = [re.sub(r"^\s*(?:\*|//|#)\s?", "", ln) for ln in body.splitlines()]
    return " ".join(" ".join(lines).split()).lower()


def test_every_file_this_guard_reads_exists() -> None:
    """Anti-vacuity. A renamed module would make every `not in` assertion below pass trivially.

    This is the failure this repo keeps finding: a check that passes because it did not run. A
    substring test is the easiest possible instance of it — `needle not in ""` is `True`.
    """
    for path in (PY_POLICY, PY_COLLECTIVE, PY_ERRORS, TS_CLIENT, TS_ERRORS):
        assert path.is_file(), f"{path} does not exist; this guard is checking nothing"
        assert _text(path), f"{path} normalised to nothing"


@pytest.mark.parametrize(
    ("phrase", "paths", "why"), RETRACTED, ids=[r[0][:34] for r in RETRACTED]
)
def test_a_retracted_presence_rule_does_not_come_back(
    phrase: str, paths: tuple[pathlib.Path, ...], why: str
) -> None:
    for path in paths:
        assert phrase not in _text(path), (
            f"{path.relative_to(REPO)} states a rule seam-runtime retracted: {phrase!r}.\n\n{why}"
        )


@pytest.mark.parametrize(
    ("phrase", "py", "ts", "what"),
    BOTH_LANGUAGES,
    ids=[b[3][:36] for b in BOTH_LANGUAGES],
)
def test_a_corrected_claim_reaches_both_languages(
    phrase: str, py: pathlib.Path, ts: pathlib.Path, what: str
) -> None:
    """Half a correction looks maintained, which is worse than none — a reader trusts it."""
    in_py = phrase in _text(py)
    in_ts = phrase in _text(ts)
    assert in_py and in_ts, (
        f"{what} — {phrase!r} is in "
        f"{'Python only' if in_py else 'TypeScript only' if in_ts else 'NEITHER language'}. "
        f"Python: {py.relative_to(REPO)}, TypeScript: {ts.relative_to(REPO)}. These two carry the "
        f"same claim on purpose; correcting one and not the other leaves half this SDK's consumers "
        f"reading a rule the runtime no longer implements."
    )
