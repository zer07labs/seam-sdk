"""Every `file:line` citation in `COMPATIBILITY.md`, `DECISIONS.md` and `PROGRESS.md` must resolve.

`COMPATIBILITY.md` closes by stating its own rule:

    Every row must cite a `file:line` that resolves. If a claim cannot be verified, **delete it** — a
    compatibility matrix with aspirational rows is worse than a short one, because a reader cannot
    tell which rows were checked.

That rule is self-defeating without enforcement, and not hypothetically: **six citations were stale
the day the document was written**, because the same PR that wrote them also inserted lines into
`publish.yml`, `release-on-runtime.yml` and `CHANGELOG.md` and shifted the targets underneath. A
citation that points at the wrong line is worse than no citation — it looks checked.

Three levels of check, because line numbers rot in three different ways:

1. **Structural** — the file exists and the cited line is in range. Catches a deleted file or a
   citation past EOF.
2. **Anchored** — for the load-bearing claims, the cited line must still contain the thing it is
   cited *for*. This is what catches the failure that actually happened: the line existing, but now
   holding something else entirely.
3. **Quoted** — for claims resting on a file this repo vendors verbatim, there is no line number at
   all: the document quotes the sentence, and the check confirms the file still says it. Levels 1
   and 2 both presume a line number worth keeping true; against a file replaced whole-file on every
   upstream refresh, that presumption is false, and the `VENDORED` rule below now rejects the
   attempt outright (issue #73).

`DECISIONS.md` was brought under the same checks later, and the argument for it is the argument
against ever scoping a check to the tidiest document. It is a live record a reader trusts exactly as
much as COMPATIBILITY.md, and it had rotted the same way in three distinct ways at once:

* **A drifted line.** It cited `.github/workflows/ci.yml:289-297` for the zero-Seam-crates gate.
  COMPATIBILITY.md cited *the same claim in the same file*, and that copy was repaired — by this
  test — while this one stayed stale, because nothing was reading this document. Both are now
  anchored, and `cited` is scoped per document precisely so one cannot cover for the other.
* **Bare paths.** Five citations named sibling-repo files with no repo prefix
  (`scripts/sdk-digest-parity.sh`, `crates/seam-store/src/lib.rs`, three adapter `pyproject.toml`s).
  Those are not merely untidy — `scripts/sdk-digest-parity.sh` reads as a local file, this repo has
  its own `scripts/` directory, and nothing mechanical can tell the two apart. Unresolvable
  citations are why the rot was invisible.
* **A citation repointed by hand five times**, as the vendored spec it pointed into was refreshed
  and its header rewritten. That is the same signal that made the anchored check find its needle
  rather than pin a line; it just took a second document to notice it applied here too. (It read
  "three times in one session" until the drift was measured rather than remembered — see `VENDORED`
  below for the actual history. Understating your own evidence is its own small version of this
  file's subject.)

`PROGRESS.md` was brought under the same checks later still, for a reason distinct from either
document above: it is not a reader-facing record, it is what `/implement` reads *instead of
re-scanning the repo* on a resumed run, so a wrong anchor there misdirects the next run's actions
rather than merely a reader's understanding. Two citations had drifted 16 and 22 lines
(`ts/src/client.ts` for `collectiveOutcomeOf`/`submitCommit`), resolving fine under the structural
check the whole time — the same "resolves but does not say what it claims" failure `DECISIONS.md`
demonstrated above, now against the document a resumed run trusts most. A third citation
line-anchored into `ts/gen/seam/api/v1/seam_pb.ts`, a **gitignored, regenerated file**: worse than a
`VENDORED` anchor, since `VENDORED` at least survives until upstream's next refresh, while a
generated stub is invalidated by the citing contributor's own next `make generate` and cannot be
checked at all on a checkout that has never run codegen. The `GENERATED` rule below is `VENDORED`'s
shape applied to that case.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).parents[2]

#: Every document whose `file:line` citations are checked, and the minimum each must carry.
#:
#: `DECISIONS.md` was added after a citation in it had to be hand-repointed five times — the same
#: signal that motivated rewriting the anchored check below to find its needle instead of pinning a
#: line. It is a live document that a reader trusts exactly as much as
#: COMPATIBILITY.md, and it had drifted the same way: one citation pointed at a line that had moved
#: 26 lines, and five more were **bare paths with no repo prefix** (`scripts/sdk-digest-parity.sh`,
#: which reads as a local file and is seam-runtime's) — unresolvable by anything mechanical, which
#: is why nothing had noticed.
#:
#: The floor per document is a guard-the-guard: a gutted document, or a regex that stopped matching
#: its format, would otherwise make every check below pass vacuously.
#:
#: `PROGRESS.md` was added after Phase 6 of the gate-blindness-hardening plan measured it as the
#: single most-cited unguarded document in the repo — the previous plan's own Phase 6 divergence
#: note had flagged the case as "evidence, not tidiness" and left it undone. `PROGRESS.md` is not a
#: narrative like `COMPATIBILITY.md`/`DECISIONS.md`: it is what `/implement` reads *instead of
#: re-scanning the repo* on a resumed run, so a wrong anchor there misdirects the next run's
#: actions, not merely a reader's understanding. Measured rot at the time it was added: two citations
#: drifted 16 and 22 lines (`ts/src/client.ts` for `collectiveOutcomeOf`/`submitCommit`), and one
#: line-anchored into a **gitignored, regenerated file** (`ts/gen/...`) — worse than a `VENDORED`
#: anchor, since it cannot be verified at all on a fresh clone before its first `make generate`. The
#: floor is 30 against a measured 81 resolved citations at the commit that added it — comfortably
#: below the true count (the same ~1/3 margin `COMPATIBILITY.md`'s 10-of-27 floor uses), high enough
#: that gutting the document or breaking `CITATION`'s match shape cannot pass unnoticed.
DOCS = {
    "COMPATIBILITY.md": 10,
    "DECISIONS.md": 10,
    "PROGRESS.md": 30,
}

#: `path/to/file.ext:12` or `path/to/file.ext:12-34`, inside backticks.
#: The extension must START WITH A LETTER. `\w+` also matches a purely numeric extension, which
#: makes `127.0.0.1:8099` parse as a citation to a file named `127.0.0.1` at line 8099 — an IP and
#: port, matched by accident. That failure is loud rather than silent, so it never hid anything, but
#: it fails for a reason unrelated to citations and the only remedy was to reword the prose around
#: it. Requiring a leading letter drops exactly that class: measured across COMPATIBILITY.md,
#: DECISIONS.md, PROGRESS.md and CHANGELOG.md, it removes zero real citations (27/57/81/3, unchanged
#: in every file). No source file in this repo has a digit-initial extension.
CITATION = re.compile(r"`([\w./-]+\.[A-Za-z]\w*):(\d+)(?:-(\d+))?`")

#: Paths that live in sibling repos — real citations, but not resolvable from this checkout.
#: Named explicitly rather than pattern-skipped, so a typo'd local path cannot hide among them.
#:
#: This list is also why a citation must carry its repo prefix. An unprefixed sibling path is not
#: merely untidy: `scripts/sdk-digest-parity.sh` and `crates/seam-store/src/lib.rs` both look local,
#: so they would be asserted against THIS repo and fail — or worse, collide with a real local file
#: of the same name and be checked against the wrong one entirely.
#:
#: `seam/` (the shared cross-repo context repo) joined this tuple for the same reason: Phase 6 added
#: `PROGRESS.md` citations into its docs. Each entry ends in `/`, so `startswith` cannot confuse
#: `seam/` with `seam-runtime/`, `seam-adapters/` or `seam-aegis/` — the character right after
#: `seam` differs (`/` vs `-`) — and this repo has no top-level directory literally named `seam`
#: (`test_no_local_directory_shadows_a_sibling_prefix` below fails loudly, not silently, if one is
#: ever added).
SIBLING_PREFIXES = ("seam-adapters/", "seam-aegis/", "seam-runtime/", "seam/")


def _sibling_relative_path(path: str) -> str:
    """Strip a single leading `../`, so a citation written relative to the repo root
    (`../seam-runtime/foo`) is recognised the same as one written bare (`seam-runtime/foo`).

    Phase 6 wrote `PROGRESS.md`'s new sibling citations in the `../`-relative form — it reads
    naturally next to the other `../seam-runtime/...` prose in that document — and
    `SIBLING_PREFIXES` was never taught to strip it before matching. Six citations therefore fell
    through to the local-file branch below and were asserted against `REPO / "../seam-runtime/..."`,
    which resolves (by plain filesystem `..` traversal, not by this test's own logic) to the sibling
    checkout *only when one happens to sit next to this repo* — true on a workspace checkout, false
    on an isolated clone, where the same expression is simply absent and the assertion is a hard
    failure instead of a skip. `removeprefix` rather than `lstrip("./")`: it strips exactly one
    `../`, never accidentally eating a `..` that is actually part of a real (if odd) path.
    """
    return path.removeprefix("../")


#: Paths vendored into this repo **byte-verbatim from upstream** — refreshed whole-file, by policy,
#: whenever upstream moves. A line number into one of these is not a citation, it is a countdown.
#:
#: Named file by file, NOT as the `verify/docs/` directory prefix, which would be wrong in the one
#: way that matters: that directory also holds `audit-anchor.md` and `erasure-certificate.v1.md`,
#: which `scripts/check_vendored_spec.py` deliberately excludes because they were **authored here**
#: and have no upstream. A prefix rule would forbid line-anchoring into two files this repo edits
#: itself — exactly the case the decision below argues should stay line-anchored, since there a
#: drifting line number is a real signal about our own layout rather than upstream noise.
#:
#: This is issue #73. `verify/docs/seam-event.v1.md` is a verbatim copy of seam-runtime's
#: `docs/specs/seam-event.v1.md`; refreshing it replaces the whole body, so every line below an
#: upstream insertion shifts. One `DECISIONS.md` citation into it was **repointed five times in six
#: days** — measured against git, not recalled, and re-measured after the first table here was wrong:
#:
#:     PR #58  2026-08-24  :271-272  introduced, correct (needle at 271)
#:     PR #63  2026-08-25  :271-272  refresh moved the needle to 276 — MERGED STALE, not repointed
#:     PR #66  2026-08-25  :295-296  repoint 1 (silently absorbs #63's drift)
#:     PR #71  2026-08-26  :332-333  repoint 2
#:     PR #72  2026-08-27  :338-339  repoint 3
#:     PR #74  2026-08-27  :381-382  repoint 4
#:     PR #80  2026-08-31  :388-389  repoint 5
#:
#: Six refreshes, five repoints — NOT one repair per refresh. #63 shipped the citation five lines
#: wrong and nothing objected, because `DECISIONS.md` did not come under this test until #67. That
#: is the sharpest fact in the table and the one nobody had: not the churn, but a citation sitting
#: on `main` pointing at a plausible wrong line, looking exactly as checked as a correct one.
#:
#: Issue #73 recorded two of these and this file's own comments long said "three, in one session".
#: Every repoint carried zero information, and each was an opportunity to "fix" the citation by
#: pointing it at another plausible wrong line.
#: Widening `CITATION_SLACK` was considered and ruled out in #73: slack that survives a whole-file
#: refresh is slack that no longer checks anything.
#:
#: The rule, enforced below: **no line-anchored citation into a vendored path, from any checked
#: document.** Two sanctioned alternatives, neither of which rots:
#:
#: * Cite the *upstream* file with its `seam-runtime/` prefix. It is the real source, and
#:   `SIBLING_PREFIXES` already skips it when the sibling repo is not checked out.
#: * Quote the sentence and let `QUOTED` (bottom of this file) check it by content. A trade rather
#:   than an upgrade — see that table's own note — but the half it keeps is the half that survives a
#:   refresh: the document and the file must still say the same words.
VENDORED = ("verify/docs/seam-event.v1.md",)


def _line_anchors_into_vendored(text: str) -> list[str]:
    """Every line-anchored citation in `text` that names a vendored path. Empty is the good case."""
    return [
        m.group(0) for m in CITATION.finditer(text) if m.group(1).startswith(VENDORED)
    ]


#: Directory prefixes that are NEVER committed — regenerated by `make generate`/`make generate-local`
#: from the contract, gitignored (see `.gitignore` and `Makefile`'s `clean:` target), and simply
#: absent on a fresh clone until a `buf registry login` runs codegen for the first time. A line
#: number into one of these is worse than a `VENDORED` line number: `VENDORED` at least survives
#: until *upstream's* next refresh, a cadence this repo can observe; a generated stub is invalidated
#: by the citing CONTRIBUTOR'S OWN next `make generate`, and cannot be checked at all on a checkout
#: that has never run codegen — which is every fresh clone before its first BSR login. This is not
#: hypothetical: `PROGRESS.md` cited `ts/gen/seam/api/v1/seam_pb.ts:942` for a branded `SessionStep`
#: type that was correct only until ACDP's receipt-slot fields landed above it in the same file.
#:
#: The rule, enforced below, is the same shape as `VENDORED`: no line-anchored citation into a
#: generated path, from any checked document. There is only one sanctioned alternative, and it is
#: narrower than `VENDORED`'s two: cite the symbol by name. `QUOTED`-style content-matching has
#: nothing to quote — the generated file does not exist at all until codegen runs, so even a content
#: check would have no durable source to check against on a checkout that has never generated.
#:
#: Kept in sync with `Makefile`'s `clean:` target below — the other place "these are the generated
#: stub trees" is asserted. `ts/dist` is excluded there on purpose: it is a TS *build* artifact
#: `make clean` also removes, not a generated-stub tree, and no citation is ever pointed into it.
GENERATED = ("ts/gen/", "python/seam_sdk/_gen/", "gen/")


def _line_anchors_into_generated(text: str) -> list[str]:
    """Every line-anchored citation in `text` that names a generated path. Empty is the good case."""
    return [
        m.group(0) for m in CITATION.finditer(text) if m.group(1).startswith(GENERATED)
    ]


def _citations(doc: str) -> list[tuple[str, str, int, int]]:
    out = []
    for m in CITATION.finditer((REPO / doc).read_text(encoding="utf-8")):
        path, start, end = m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))
        out.append((doc, path, start, end))
    return out


def _all_citations() -> list[tuple[str, str, int, int]]:
    return [c for doc in DOCS for c in _citations(doc)]


@pytest.mark.parametrize(("doc", "floor"), DOCS.items())
def test_the_document_actually_cites_things(doc: str, floor: int) -> None:
    """Guard the guard — an empty citation list would make every test below pass vacuously."""
    assert len(_citations(doc)) >= floor, (
        f"{doc} carries almost no file:line citations. Either the document was gutted or the "
        f"citation regex no longer matches its format; both need looking at."
    )


@pytest.mark.parametrize("doc", DOCS)
def test_no_document_line_anchors_into_a_vendored_file(doc: str) -> None:
    """Issue #73's rule. A line number into a whole-file-refreshed copy has a shelf life."""
    offenders = _line_anchors_into_vendored((REPO / doc).read_text(encoding="utf-8"))
    assert not offenders, (
        f"{doc} line-anchors into a vendored file: {', '.join(offenders)}. Those files are "
        f"refreshed whole and verbatim from upstream, so the line number is guaranteed to rot at "
        f"the next refresh — one such citation was repointed five times in six days for zero "
        f"information, once per upstream refresh. Cite "
        f"the upstream file instead (`seam-runtime/docs/specs/...:N`), or quote the sentence and "
        f"add it to QUOTED at the bottom of this file, which checks it by content and never drifts."
    )


def test_this_files_vendored_set_matches_the_real_vendored_registry() -> None:
    """Two lists of "what is vendored" now exist. They are not allowed to disagree.

    `scripts/check_vendored_spec.py` holds the authoritative registry — it is what actually fetches
    upstream and asserts byte-identity, so a file is vendored if and only if it is in there. This
    file needs the same set for a different purpose, and its own comment states the repo's rule for
    exactly this shape: "a value stored twice can disagree with itself, and the disagreement is the
    signal that someone repointed one of them alone."

    Importing the registry outright was the alternative and was rejected: this test file deliberately
    imports nothing but `pathlib`, `re` and `pytest`, and a doc-checking test that fails because a
    network-fetching script failed to import is a worse trade than one assertion.
    """
    src = (REPO / "scripts" / "check_vendored_spec.py").read_text(encoding="utf-8")
    registry = set(re.findall(r'^\s*local="([^"]+)"', src, re.MULTILINE))
    assert registry, (
        "Could not read the vendored registry out of scripts/check_vendored_spec.py — its "
        "`Vendored(local=...)` shape changed. Re-derive this check rather than deleting it; a "
        "silently-empty registry makes the comparison below pass vacuously."
    )
    assert set(VENDORED) == registry, (
        f"VENDORED here is {sorted(VENDORED)} but scripts/check_vendored_spec.py vendors "
        f"{sorted(registry)}. The registry is authoritative — it is what fetches upstream and "
        f"proves byte-identity. If a copy was added there, add it here; if one was retired, drop "
        f"it here. Divergence means this rule is either policing a file nobody vendors or missing "
        f"one that is refreshed whole-file underneath its citations."
    )


def test_the_vendored_rule_fires_on_a_line_anchor_and_leaves_the_alternatives_alone() -> (
    None
):
    """Red-first: prove the guard above catches the thing it exists for, and nothing else.

    Without this, the guard passing on today's documents is indistinguishable from a `VENDORED`
    prefix that matches no path at all — the vacuous-pass failure this file already guards against
    twice elsewhere. The negative controls matter just as much: a rule that also rejected the two
    sanctioned alternatives would leave a citation into vendored content with nowhere legal to go,
    and the way that gets resolved under deadline is by deleting the check.
    """
    vendored = VENDORED[0]

    assert _line_anchors_into_vendored(f"verbatim at `{vendored}:388-389`:") == [
        f"`{vendored}:388-389`"
    ]
    assert _line_anchors_into_vendored(f"see `{vendored}:388`") == [f"`{vendored}:388`"]

    # The two sanctioned forms, and an unrelated local citation, must all pass clean.
    assert _line_anchors_into_vendored(f"quoted verbatim from `{vendored}`") == []
    assert (
        _line_anchors_into_vendored(
            "`seam-runtime/docs/specs/seam-event.v1.md:388-389`"
        )
        == []
    )
    assert _line_anchors_into_vendored("`python/seam_sdk/crypto.py:378-408`") == []


@pytest.mark.parametrize("doc", DOCS)
def test_no_document_line_anchors_into_a_generated_tree(doc: str) -> None:
    """`GENERATED`'s rule: a line number into a gitignored, regenerated tree is a countdown, and an
    unverifiable one on a checkout that has never run codegen.
    """
    offenders = _line_anchors_into_generated((REPO / doc).read_text(encoding="utf-8"))
    assert not offenders, (
        f"{doc} line-anchors into a generated tree: {', '.join(offenders)}. These paths are "
        f"regenerated by `make generate`/`make generate-local`, gitignored, and absent entirely on "
        f"a fresh clone before its first BSR login — a line number into one is stale by the "
        f"contributor's own next `make generate` and cannot be checked at all before that first "
        f"codegen run. Cite the symbol by name instead of a line."
    )


def test_this_files_generated_set_matches_the_makefiles_clean_target() -> None:
    """Two lists of "what is a generated stub tree" now exist. They are not allowed to disagree,
    for the same reason `VENDORED`'s registry check exists: a value stored twice can disagree with
    itself, and the disagreement is the signal that someone updated one copy and not the other.

    `Makefile`'s `clean:` target is the authoritative list of directories nothing here should ever
    depend on surviving — it is what actually deletes them. `ts/dist` is excluded from the
    comparison by name, not silently: it is a TS build artifact `clean` also removes, not a
    generated-stub tree, and this file never expects a citation pointed into it.
    """
    src = (REPO / "Makefile").read_text(encoding="utf-8")
    m = re.search(r"^clean:\n\trm -rf (.+)$", src, re.MULTILINE)
    assert m, (
        "Could not find Makefile's `clean:` target in the expected `rm -rf <paths>` shape. "
        "Re-derive this check rather than deleting it; a silently-unmatched registry makes the "
        "comparison below pass vacuously."
    )
    cleaned = m.group(1).split()
    assert cleaned, (
        "Makefile's `clean:` target rm -rf's nothing — re-derive this check rather than deleting it."
    )
    stub_trees = {p + "/" for p in cleaned if p != "ts/dist"}
    assert set(GENERATED) == stub_trees, (
        f"GENERATED here is {sorted(GENERATED)} but Makefile's `clean:` target removes "
        f"{sorted(stub_trees)} (plus `ts/dist`, a build artifact, excluded on purpose). If a tree "
        f"was added to one, add it to the other; divergence means this rule is either policing a "
        f"directory `make clean` no longer touches or missing one that clean now removes."
    )


def test_the_generated_rule_fires_on_a_line_anchor_and_leaves_symbol_references_alone() -> (
    None
):
    """Red-first, mirroring the `VENDORED` proof above: prove `GENERATED` catches exactly the case
    it exists for, and nothing else — including the one sanctioned alternative (a bare symbol
    reference, no line number) and an unrelated local citation.
    """
    generated = GENERATED[0]  # "ts/gen/"
    path = f"{generated}seam/api/v1/seam_pb.ts"

    assert _line_anchors_into_generated(f"see `{path}:942`") == [f"`{path}:942`"]
    assert _line_anchors_into_generated(f"see `{path}:942-971`") == [
        f"`{path}:942-971`"
    ]

    # The sanctioned form (symbol only, no line number) and an unrelated local citation must both
    # pass clean.
    assert _line_anchors_into_generated(f"the branded type in `{path}`") == []
    assert _line_anchors_into_generated("`python/seam_sdk/crypto.py:378-408`") == []


def test_an_ip_and_port_is_not_mistaken_for_a_citation() -> None:
    """`127.0.0.1:8099` is an address, not a file at a line.

    `\\w+` as the extension matched it: "file `127.0.0.1`, line 8099". The guard then failed
    because no such file exists — loud, so nothing was ever hidden, but failing for a reason that
    has nothing to do with citations, and the only fix available to a writer was to reword the
    sentence. A guard that makes people edit around it teaches them to edit around it.

    Pinned here because the remedy narrows the pattern, and narrowing a pattern is exactly how a
    guard goes blind. What must stay true is that it narrows by this class ONLY.
    """
    assert not CITATION.findall("a server at `127.0.0.1:8099` was used")
    assert not CITATION.findall("`192.168.1.10:8080`")
    # ...and every real extension shape in this repo still parses.
    for real in (
        "`python/seam_sdk/client.py:541`",
        "`ts/src/client.ts:218`",
        "`.github/workflows/ci.yml:19`",
        "`verify/src/verify.rs:636-645`",
        "`contract/field-manifest.txt:76`",
        "`go/seam/client.go:88`",
        "`PROGRESS.md:59`",
    ):
        assert CITATION.findall(real), (
            f"tightening the pattern dropped a real citation: {real}"
        )


def _resolve_citation_target(
    doc: str, path: str, start: int, *, repo: pathlib.Path
) -> pathlib.Path | None:
    """Resolve one citation's `path` to a concrete file under `repo`, or return `None` if it
    names a sibling repo that is not checked out next to `repo` — the case the real test turns
    into `pytest.skip`.

    Factored out of `test_each_citation_resolves` so a regression test can drive the exact same
    resolution logic against a `repo` with no sibling checkouts beside it, independent of whatever
    happens to be checked out in the environment the suite is actually running in. That is the
    difference between "this passed" and "this passed because a sibling repo happened to be
    sitting there" — the failure mode this function exists to make impossible to reintroduce.

    Raises `AssertionError` (not a return value) when the citation cannot be resolved at all,
    matching what `test_each_citation_resolves` asserts today.
    """
    sibling_path = _sibling_relative_path(path)
    if sibling_path.startswith(SIBLING_PREFIXES):
        sibling = repo.parent / sibling_path
        if not sibling.exists():
            return None
        return sibling

    target = repo / path
    assert target.exists(), (
        f"{doc} cites `{path}:{start}`, but that file does not exist. Fix or delete the "
        f"claim — COMPATIBILITY.md's rule, which this applies to every checked document, is "
        f"that an unverifiable claim gets deleted. If the file lives in a sibling repo, the "
        f"citation must carry its repo prefix ({'/, '.join(SIBLING_PREFIXES)}) or nothing can "
        f"tell it apart from a broken local path."
    )
    return target


@pytest.mark.parametrize(
    "citation", _all_citations(), ids=lambda c: f"{c[0]}~{c[1]}:{c[2]}"
)
def test_each_citation_resolves(citation: tuple[str, str, int, int]) -> None:
    doc, path, start, end = citation

    target = _resolve_citation_target(doc, path, start, repo=REPO)
    if target is None:
        pytest.skip(f"{path} is in a sibling repo not checked out here")

    line_count = len(target.read_text(encoding="utf-8", errors="ignore").splitlines())
    assert end <= line_count, (
        f"{doc} cites `{path}:{start}-{end}`, but {path} has only {line_count} lines. "
        f"The citation is stale."
    )


def test_no_local_directory_shadows_a_sibling_prefix() -> None:
    """Guard the ambiguity `SIBLING_PREFIXES` cannot itself detect.

    Every entry is matched with plain `str.startswith`, which is unambiguous only as long as this
    repo never grows a top-level directory whose name collides with one of those prefixes (e.g. a
    real local `seam/`). If that ever happens, citations into it would be silently routed to the
    sibling-skip branch instead of being checked against the real local file — exactly the
    collision `SIBLING_PREFIXES`'s own comment warns a *pattern*-based rule would risk, reintroduced
    by hand. This test makes that collision loud instead of silent.
    """
    shadowing = [
        prefix for prefix in SIBLING_PREFIXES if (REPO / prefix.rstrip("/")).is_dir()
    ]
    assert not shadowing, (
        f"local director{'y' if len(shadowing) == 1 else 'ies'} {shadowing} now share a name with "
        f"a SIBLING_PREFIXES entry — citations into {'it' if len(shadowing) == 1 else 'them'} would "
        f"be silently treated as sibling-repo citations (skip-if-absent) instead of local ones "
        f"(must-exist). Rename the directory, or rename the prefix and every citation that uses it."
    )


def test_sibling_citations_skip_cleanly_with_no_sibling_repos_checked_out(
    tmp_path: pathlib.Path,
) -> None:
    """Reproduces the actual CI failure: on a checkout with no sibling repos above it, a
    sibling-repo citation must SKIP, never hard-fail — regardless of whether it names its prefix
    bare (`seam-runtime/...`) or `../`-relative (`../seam-runtime/...`, the form Phase 6 used).

    This is the regression test for the bug itself, not for `SIBLING_PREFIXES`'s contents: it
    drives `_resolve_citation_target` — the real resolution function `test_each_citation_resolves`
    uses — against a `repo` whose parent directory is guaranteed to hold no sibling checkouts,
    which is exactly the shape of a fresh CI clone and exactly the shape this repo's own dev
    workspace is NOT. Before the fix, the `../`-relative forms fell to the local-file branch and
    raised `AssertionError` here instead of skipping.
    """
    repo = tmp_path / "only-repo"
    repo.mkdir()
    assert list(tmp_path.iterdir()) == [repo], (
        "sanity: tmp_path must hold only `repo` itself"
    )
    for prefix in SIBLING_PREFIXES:
        assert not (tmp_path / prefix.rstrip("/")).exists(), (
            f"test fixture is broken: {prefix} unexpectedly exists next to the fake repo"
        )

    # Real citation shapes pulled from PROGRESS.md itself (see the six paths Finding 1 reported),
    # covering both siblings in the tuple and both the bare and `../`-relative forms.
    for path in (
        "../seam-runtime/.github/workflows/ci.yml",
        "../seam-runtime/plans/acdp-p1a-receipt-slots.md",
        "../seam/docs/OPEN-TASKS.md",
        "../seam/docs/sdk/01-base-concepts-and-quickstart.md",
        "seam-runtime/.github/workflows/ci.yml",
        "seam-adapters/pyproject.toml",
        "seam-aegis/pyproject.toml",
        "seam/docs/OPEN-TASKS.md",
    ):
        assert _resolve_citation_target("PROGRESS.md", path, 1, repo=repo) is None, (
            f"`{path}` must resolve to None (skip) when no sibling repo is checked out next to "
            f"the repo — anything else means this citation would hard-fail CI on a fresh clone, "
            f"which is the exact bug this test exists to catch."
        )


#: The claims whose citations MUST still point at the right content — eight, of which six are the
#: original COMPATIBILITY.md set that went stale the day it was written.
#:
#: Each entry is (cited path, a needle that must be UNIQUE in that file). **There is deliberately no
#: line number here.** An earlier version of this table pinned one, and it had to be repointed five
#: times over six days — every repoint an opportunity to "fix" the test by pointing it
#: at the wrong line, which is precisely the failure it exists to catch. The line number was also pure
#: duplication: it is derivable from the needle, and a fact stored in two places is a fact that can
#: disagree with itself.
#:
#: What the check does instead: find the needle's line in the target file, then assert COMPATIBILITY.md
#: cites *that* line. So the document is checked against the code rather than against a copy of the
#: line number kept here — which is the direction that catches a stale citation, and the direction that
#: needs no maintenance when unrelated edits shift a file.
ANCHORED = [
    ("COMPATIBILITY.md", "CHANGELOG.md", "No yank"),
    (
        "COMPATIBILITY.md",
        ".github/workflows/publish.yml",
        'registry-url: "https://npm.cloudsmith.io',
    ),
    (
        "COMPATIBILITY.md",
        ".github/workflows/publish.yml",
        'TWINE_REPOSITORY_URL: "https://python.cloudsmith.io',
    ),
    (
        "COMPATIBILITY.md",
        ".github/workflows/release-on-runtime.yml",
        'git tag -a "go/v$VER"',
    ),
    ("COMPATIBILITY.md", "README.md", "crypto shims + conformance tests only"),
    ("COMPATIBILITY.md", ".github/workflows/ci.yml", "must link NOTHING"),
    # DECISIONS.md's own load-bearing three. The zero-Seam-crates gate is cited from BOTH
    # documents and drifted in both — it was repaired in COMPATIBILITY.md and left stale here,
    # which is exactly the argument for checking every document rather than the tidiest one.
    ("DECISIONS.md", ".github/workflows/ci.yml", "must link NOTHING"),
    # The sentence the whole v1-skip decision rests on used to be pinned here, and was repointed
    # five times as the vendored spec was refreshed. It moved to QUOTED (bottom of this file)
    # under issue #73 — same needle, same uniqueness assertion, no line number to rot.
    ("DECISIONS.md", "CHANGELOG.md", "this SDK cannot express its own"),
    # "No yank" is cited from BOTH documents. It was anchored in COMPATIBILITY.md only — so when
    # Phase 9's own CHANGELOG entry moved it, COMPATIBILITY.md's copy went red and was repaired
    # while DECISIONS.md's sat 87 lines stale, passing the in-range check. That is verbatim the
    # `ci.yml` failure recorded above, repeating because the lesson was written down and not wired.
    ("DECISIONS.md", "CHANGELOG.md", "No yank"),
    # The four references in the v1-skip entry. They were written as bare `:N` shorthand continuing
    # an earlier path, which `CITATION` cannot match — so nothing resolved them and nothing checked
    # them, and all three of the bare ones had rotted by 5 to 66 lines before Phase 8 repointed
    # them. Repointing alone would have fixed the instance and left the class: a full path earns
    # them the range check, and these entries earn them the content check that would have caught
    # the rot in the first place.
    (
        "DECISIONS.md",
        "verify/tests/authenticity.rs",
        "fn a_v1_record_is_link_verified_but_not_recomputed",
    ),
    (
        "DECISIONS.md",
        "verify/tests/authenticity.rs",
        "the v1 record is skipped, not recomputed",
    ),
    (
        "DECISIONS.md",
        "verify/tests/authenticity.rs",
        "Each column is tested ALONE, with the other three removed",
    ),
    (
        "DECISIONS.md",
        "verify/tests/authenticity.rs",
        "fn a_genuine_v1_record_is_still_skipped_not_refused",
    ),
    # PROGRESS.md's own two rotted anchors, Phase 6 of gate-blindness-hardening (measured at HEAD
    # before the fix): `collectiveOutcomeOf` had drifted 16 lines (cited `:202`, actually `:218`)
    # and `submitCommit` had drifted 22 (cited `:654`, which is a `submitObjection` doc comment;
    # actually `:676`). Both resolved fine under the structural check the whole time — this is the
    # concrete case for anchoring PROGRESS.md's load-bearing citations rather than only counting
    # them: "resolves" and "says what it claims" are different properties.
    ("PROGRESS.md", "ts/src/client.ts", "export function collectiveOutcomeOf"),
    ("PROGRESS.md", "ts/src/client.ts", "  submitCommit("),
]

#: How far a citation may sit from the needle's true line and still count. A citation naming a block
#: usually points at its heading or its first line, not at the exact line carrying the string.
CITATION_SLACK = 3


@pytest.mark.parametrize(("doc", "path", "needle"), ANCHORED, ids=lambda v: str(v))
def test_the_load_bearing_citations_still_point_at_the_right_thing(
    doc: str, path: str, needle: str
) -> None:
    """A line that exists but no longer says what it was cited for is the failure that happened.

    **Known limit, accepted deliberately:** within a document, citations are matched to a claim by
    PATH only, so if a document cites one file more than once, any of those citations landing within
    `CITATION_SLACK` of the needle satisfies the check — a drifted citation could in principle be
    masked by an unrelated one. Binding each claim to its own citation would mean parsing the
    document's prose structure, which is materially more machinery than the risk earns. Documents do
    NOT mask each other: `cited` is scoped to `doc`, so `ci.yml` being correctly cited in
    COMPATIBILITY.md cannot cover for its being stale in DECISIONS.md — which is not hypothetical,
    it is exactly the state this entry was added in. The duplicated paths within a single document
    are `CHANGELOG.md` and `publish.yml` in COMPATIBILITY.md, and now `verify/tests/authenticity.rs`
    in DECISIONS.md — cited four times (`:238`, `:254-257`, `:906-909`, `:944`) with four anchored
    needles, one per citation. The closest needle-to-foreign-citation distance there is 16 lines
    (needle at 256, citation at 238), which is the tightest margin in this table: still clear of
    `CITATION_SLACK` 3, but it is now the case to check first when adding anything nearby. Each
    needle is satisfied only by its own citation — verified by hand, because that is the property
    the path-only matching cannot enforce. That margin has NARROWED:
    COMPATIBILITY.md now cites `publish.yml` four times (`:199`, `:340`, `:367`, `:413`), and the
    closest pair is 27 lines apart, not the 125+ this note originally recorded. 27 is still well
    clear of `CITATION_SLACK` 3, so every anchored entry is still satisfied by exactly its own
    citation — but the headroom is a fifth of what it was. What would actually close it is a fifth
    citation landing WITHIN 3 lines of an anchored one, not merely one landing somewhere in the
    span between them; the span is wide, the danger zone is six lines wide. Revisit before adding
    a citation near `:199`, `:340`, `:367` or `:413`, not after.

    `PROGRESS.md` duplicates a path too, and these numbers are taken from `_citations()` — the same
    function the assertion below uses — rather than read off the document by hand. `ts/src/client.ts`
    is cited **eight** times at **five** distinct lines: `:218` x3 and `:326` x2, plus `:746`, `:777`,
    `:914`. Two are anchored here, and the closest needle-to-foreign-citation distances are **108**
    (needle `collectiveOutcomeOf` at 218, nearest foreign citation `policyEnforcementOf` at 326) and
    **31** (needle `  submitCommit(` at 777, nearest foreign the confidence mapping at 746). Both are
    clear of `CITATION_SLACK` 3, so each needle is satisfied by exactly its own citation.

    **This paragraph previously recorded 53, and getting the correction right took two attempts.** It
    was written before Phase 4 inserted `policyEnforcementOf`, and Open Question 6 of that phase's
    plan predicted the insertion would shrink the margin. It did — 53 to 31 — but the first
    correction claimed 53 had been *wrong all along*, on the grounds that the foreign citation `:623`
    named the confidence mapping while the mapping really sat at 645. That misidentifies the metric.
    The distance that governs foreign-citation masking, and the only one the assertion consults, is
    from the needle to a citation **as written**, never to the true location of what it names — so 53
    was correct for the state it described. The margin moved because the citation was *corrected*
    (623 to 746, +123: +101 for the insertion and +22 for the correction) while the needle moved only
    +101; the insertion by itself would have preserved 53 exactly. A hand-maintained margin measured
    against an unverified citation is a real hazard, but it is not what happened here, and the two
    are worth keeping apart. 31 is the second-tightest margin in this table after `publish.yml`'s 27,
    and it narrows for real whenever something lands between the confidence mapping and
    `submitCommit`.
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

    cited = [(start, end) for _d, p, start, end in _citations(doc) if p == path]
    assert cited, (
        f"ANCHORED pins {needle!r} in {path}, but {doc} no longer cites {path} at all. Either the "
        f"claim was dropped (then drop this entry too) or the citation format changed."
    )
    assert any(
        start - CITATION_SLACK <= true_line <= end + CITATION_SLACK
        for start, end in cited
    ), (
        f"{needle!r} is at {path}:{true_line}, but {doc} cites {path} only at "
        f"{[str(a) if a == b else f'{a}-{b}' for a, b in cited]}. The citation has drifted — update "
        f"{doc} to {path}:{true_line}."
    )


#: Claims a document supports by **quoting** a file rather than by pointing at a line in it.
#:
#: Each entry is (document, cited path, the quoted needle). There is no line number in this table,
#: and there deliberately never will be: these are the claims whose target is a `VENDORED` file, so
#: a line number is exactly the thing that cannot be kept true.
#:
#: This is a TRADE, not a superset — worth stating precisely, because "strictly stronger" is the
#: comfortable way to describe it and it is not true. What is **dropped** is the line-position claim:
#: nothing here asserts the document points at any particular line. What is **gained** is that the
#: document must quote the sentence verbatim, so a refresh that silently reworded it fails here while
#: satisfying a dutifully repointed line anchor — and `ANCHORED` never checked the document's own
#: text at all, only where it pointed. The trade is worth taking only because the dropped half is
#: precisely the half that cannot be kept true against a whole-file refresh. Against a file this repo
#: edits itself, the line position is a real signal and `ANCHORED` remains the right mechanism.
#:
#: Uniqueness in the target file is asserted for the same reason `ANCHORED` asserts it, and the same
#: guidance holds: if a needle stops being unique, LENGTHEN it, do not relax the assertion.
QUOTED = [
    # The sentence the whole v1-skip decision rests on. Held in ANCHORED until issue #73; moved here
    # after its line anchor into the vendored spec had to be repointed five times in six days.
    (
        "DECISIONS.md",
        "verify/docs/seam-event.v1.md",
        "is absent (no wire bytes) only on",
    ),
]


def test_the_quoted_table_is_not_empty() -> None:
    """Guard the guard, same as the citation floor — an empty table parametrizes to no tests."""
    assert QUOTED, (
        "QUOTED is empty, so nothing below runs. If the last entry was genuinely retired, delete "
        "this test and the mechanism with it rather than leaving a check that asserts nothing."
    )


@pytest.mark.parametrize(("doc", "path", "needle"), QUOTED, ids=lambda v: str(v))
def test_the_quoted_claims_still_match_their_source_word_for_word(
    doc: str, path: str, needle: str
) -> None:
    """The document quotes it, the file still says it, and no line number is involved either way."""
    target = REPO / path
    assert target.exists(), (
        f"{doc} quotes {path}, but that file does not exist. Re-source the claim or delete it, "
        f"per COMPATIBILITY.md's own rule."
    )

    hits = [
        i + 1
        for i, line in enumerate(
            target.read_text(encoding="utf-8", errors="ignore").splitlines()
        )
        if needle in line
    ]
    assert len(hits) == 1, (
        f"{needle!r} occurs {len(hits)} times in {path} (lines {hits or 'none'}); this check needs "
        f"exactly one. If it is 0, the refresh changed or dropped the sentence {doc} quotes — the "
        f"claim is now unsupported, so re-quote it or delete it. If it is >1, the needle is too "
        f"weak to identify the sentence: lengthen it here until it is unique, do NOT relax this."
    )

    doc_lines = (REPO / doc).read_text(encoding="utf-8").splitlines()
    quoted_at = [i for i, line in enumerate(doc_lines) if needle in line]
    assert quoted_at, (
        f"{doc} no longer quotes {needle!r}, so there is nothing here to check it against. Either "
        f"the claim was dropped (then drop this entry too) or the quote was paraphrased — and a "
        f"paraphrase is the failure this table exists to catch, not a cosmetic edit."
    )

    # The attribution must sit NEXT TO the quote, not merely somewhere in the document. A
    # document-global search was the first shape of this assertion and it was already too weak to
    # mean what it said: the commit that introduced this check also added a second backticked
    # mention of the same path in its own decision record, so deleting the real attribution line
    # left the test green with an orphaned quote. An assertion that a later edit can satisfy by
    # accident is the "looks checked" failure this whole file exists to prevent.
    window = 2
    attributed = any(
        f"`{path}`" in line
        for q in quoted_at
        for line in doc_lines[max(0, q - window) : q + window + 1]
    )
    assert attributed, (
        f"{doc} quotes {needle!r} (line {quoted_at[0] + 1}) but does not attribute it to `{path}` "
        f"within {window} lines of the quote. An unattributed quote cannot be re-verified by a "
        f"reader, which is the whole point of citing anything. Note this deliberately does NOT "
        f"accept a mention elsewhere in the document: the quote and its source must travel together."
    )
