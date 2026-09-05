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


#: `` `path/to/generated.pyi:106,163` `` — a comma-list. It line-anchors into a generated tree just as
#: hard as an ordinary citation, and `CITATION` matches it not at all (the regex needs the closing
#: backtick straight after the number). Three such citations sat in `PROGRESS.md` while the rule
#: forbidding them was stated in the table one row above; the ban was enforced only against the
#: spelling that happened to be checkable. Scanned separately rather than by widening `CITATION`,
#: which would change what every other test in this file counts.
COMMA_LIST_CITATION = re.compile(
    r"`([\w./-]+\.[A-Za-z]\w*):(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)+)`"
)


def _line_anchors_into_generated(text: str) -> list[str]:
    """Every line-anchored citation in `text` that names a generated path. Empty is the good case.

    Both spellings, because the rule is about line-anchoring into a tree that regenerates, and a
    comma separating two line numbers does not make them less line numbers.
    """
    return [
        m.group(0)
        for pattern in (CITATION, COMMA_LIST_CITATION)
        for m in pattern.finditer(text)
        if m.group(1).startswith(GENERATED)
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
    # ── §10 / the 2026-09-04 DECISIONS entries ───────────────────────────────────────────────────
    # Both of these were written WRONG on the first pass and the guard did not notice, because a bare
    # line number resolves whatever it lands on: `ts/src/crypto.ts:270` pointed into an error
    # message's hint table and `go/crypto/crypto.go:193-198` straddled the wrong end of the rule.
    # That is the entire argument for anchoring rather than trusting a number, made twice in one
    # change, so these are anchored to the declarations themselves.
    (
        "COMPATIBILITY.md",
        "ts/src/crypto.ts",
        "function isPlainObject(v: object): boolean {",
    ),
    ("DECISIONS.md", "go/crypto/crypto.go", 'exp, ok := payload["exp"].(float64)'),
    # `authorize()` is where the aliased digest was actually SIGNED, so this is the citation that
    # carries §10's weight — the exported helper is only how a caller reaches the same code on purpose.
    (
        "COMPATIBILITY.md",
        "ts/src/client.ts",
        "return jcsCanonicalize(toolInput ?? {});",
    ),
    # The `canonical=` keyword-only parameter, in both clients. Both citations had drifted into the
    # `subjects` docstring PROSE — `client.py:291` and `aio.py:221` — while the parameter they name
    # sits at `:257` / `:195`. The line resolved, the file was right, and the citation pointed at an
    # unrelated paragraph: precisely the class `test_each_citation_resolves` cannot see. This is a
    # contractual claim ("additive and keyword-only") about a security-relevant parameter, so it is
    # anchored to the declaration itself rather than to a line number that has already moved once.
    (
        "COMPATIBILITY.md",
        "python/seam_sdk/client.py",
        "canonical: Optional[bytes] = None,",
    ),
    (
        "COMPATIBILITY.md",
        "python/seam_sdk/aio.py",
        "canonical: Optional[bytes] = None,",
    ),
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
    # Phase 2's integer-slot guards. These are anchored because their citations have now drifted
    # TWICE inside one workstream: `ts/src/crypto.ts` grew 31 lines mid-phase and stranded two
    # citations, one of which had additionally been pointing at the *string* slot validator for a
    # claim about a coerced integer since before the phase began. Both repairs were then unguarded —
    # a verification round reverted one to its stale value and the whole suite stayed green. A
    # citation that has drifted twice and is defended by nothing will drift a third time.
    (
        "COMPATIBILITY.md",
        "ts/src/crypto.ts",
        "function uintSlot(name: string, value: number | bigint, bits: 32 | 64): bigint {",
    ),
    (
        "COMPATIBILITY.md",
        "ts/src/crypto.ts",
        "function u64le(name: string, n: number | bigint)",
    ),
    (
        "COMPATIBILITY.md",
        "ts/src/crypto.ts",
        "const digest = chainHeadAttestationDigest({ ...a, attestedHead, issuerAid });",
    ),
    (
        "COMPATIBILITY.md",
        "python/seam_sdk/crypto.py",
        "def _uint_slot(name: str, value: int, bits: int) -> int:",
    ),
    ("COMPATIBILITY.md", "python/seam_sdk/crypto.py", "_uint_slot(name, value, bits)"),
    ("DECISIONS.md", "ts/src/crypto.ts", "must be a number or bigint, not "),
    ("PROGRESS.md", "ts/src/crypto.ts", "export function recordDigestV3(d: {"),
    # `record_digest_v3` and `_opt_bytes`, cited from PROGRESS.md and DECISIONS.md respectively.
    # A verification round mutated `PROGRESS.md`'s `python/seam_sdk/crypto.py` citation to line 1 and
    # the whole suite stayed green — while the TS twin in the *same sentence* was anchored and did go
    # red. That asymmetry is why these are here: the file had drifted 25 lines and only the guarded
    # half of the claim noticed.
    ("PROGRESS.md", "python/seam_sdk/crypto.py", "def record_digest_v3("),
    (
        "DECISIONS.md",
        "python/seam_sdk/crypto.py",
        "def _opt_bytes(b: bytes | None) -> bytes:",
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
    # Added in Phase 4 of consumer-decoders-and-event-surface, because this pair had by then been
    # wrong TWICE — once before that phase (cited `:601,637` while sitting at 623/659) and once
    # inside the very commit whose message claimed it had shifted every citation below `:239`.
    # Both times it was written as a comma-list, `` `ts/src/client.ts:723,759` ``, which matches
    # CITATION *not at all* (the regex needs the closing backtick straight after the number), so it
    # was invisible to every check here. It is now two ordinary citations, and anchoring them is what
    # makes them checkable rather than merely countable: a citation that resolves but cannot be wrong
    # is the vacuity this file exists against. See the margin note below — this narrowed the tightest
    # margin in this table, deliberately, and that trade is recorded rather than absorbed.
    ("PROGRESS.md", "ts/src/client.ts", "  submitEvaluation("),
    ("PROGRESS.md", "ts/src/client.ts", "  submitObjection("),
    # Added in the round-5 fixes of consumer-decoders-and-event-surface, for the same reason the
    # four above were: the commit that CLOSED a stale-citation finding broke five of its own. It
    # added 5 lines of comment to check-contract.sh and 22 to test_field_manifest_gate.py above
    # these five constructs and repointed only one row, so `:226` landed on a comment, `:266` landed
    # inside `fields_ts`'s awk body, and `:69` landed on a blank line — all three still "resolved".
    # These are files this repo edits constantly, which is exactly the case the QUOTED trade-off note
    # says line anchors are the right mechanism for; what was missing was the anchoring, not the
    # citation.
    ("PROGRESS.md", "scripts/check-contract.sh", "fields_python() {"),
    ("PROGRESS.md", "scripts/check-contract.sh", "fields_ts() {"),
    ("PROGRESS.md", "scripts/check-contract.sh", "manifest_fields() {"),
    (
        "PROGRESS.md",
        "scripts/check-contract.sh",
        "# Scoped to seam.api.v1 — and seam.event.v1 is now manifested too",
    ),
    ("PROGRESS.md", "python/tests/test_field_manifest_gate.py", "def _run("),
    # Added in round 7, and the reason is the round-6 fix repeating itself one document over: the
    # commit that repointed and anchored the five citations above shifted `DECISIONS.md` by +8 lines
    # and repointed none of the citations INTO it. `PROGRESS.md:87` landed on the yank/no-yank
    # decision instead of the buf-plugin one, and `:158` on a line of prose instead of the section
    # heading it calls a "lookup key". Both still resolved. `DECISIONS.md` is a file this repo edits
    # constantly and every reconcile pass prepends to it, which makes it the highest-drift citation
    # target in the repo and the one that had no anchors at all.
    (
        "PROGRESS.md",
        "DECISIONS.md",
        "### Why a floor-pinned install, rather than pinning the buf plugins",
    ),
    (
        "PROGRESS.md",
        "DECISIONS.md",
        "## 2026-08-24 — reconcile `plans/record-digest-v3.md`'s ASSUMPTIONS.md (4 entries)",
    ),
    # `DECISIONS.md` -> `scripts/check-contract.sh`, the five citations in the field-manifest
    # decision record. Found by sweeping every citation into a file the round-7 commit changed and
    # diffing the cited line's content across it. All five were ALREADY stale at `origin/main` —
    # `:383` was `awk '`, `:262` was `expected_local_lag_age_days() {` — so nothing on this branch
    # broke them; they had simply never been checked beyond "the line exists". The script has roughly
    # doubled in length since they were written, which is what makes an unanchored line number into
    # this file a claim with a shelf life rather than a citation.
    (
        "DECISIONS.md",
        "scripts/check-contract.sh",
        '_fwant="$(manifest_fields)"',
    ),
    ("DECISIONS.md", "scripts/check-contract.sh", "  exit 6"),
    (
        "DECISIONS.md",
        "scripts/check-contract.sh",
        'fields_python "$PY_GEN" >> "$ftmp"',
    ),
    (
        "DECISIONS.md",
        "scripts/check-contract.sh",
        "# against TS is deliberate and is the reason the Python extractor must not read",
    ),
    (
        "DECISIONS.md",
        "scripts/check-contract.sh",
        'err "the moment someone DECIDES whether this SDK carries it. Decide first — wire it into the"',
    ),
]

#: How far a citation may sit from the needle's true line and still count. A citation naming a block
#: usually points at its heading or its first line, not at the exact line carrying the string.
CITATION_SLACK = 3


#: For an anchored needle whose document cites its path more than once, a substring identifying the
#: DOCUMENT line that carries the claim. Without it, "its own citation" has no definition and the
#: check below can only ask "is SOME citation of this path near the needle" — which masking satisfies,
#: because masking leaves exactly one citation in range, just the wrong one.
#:
#: Two needles may share a claim line (`submit_evaluation` / `submit_objection` are one table row),
#: and that is fine: the candidate set is then both of that row's citations, which is still far
#: narrower than every citation of the path in the document.
CLAIM_LINES = {
    (
        "COMPATIBILITY.md",
        "ts/src/client.ts",
        "return jcsCanonicalize(toolInput ?? {});",
    ): "calls",
    (
        "COMPATIBILITY.md",
        "ts/src/crypto.ts",
        "function isPlainObject(v: object): boolean {",
    ): "An enumeration of",
    (
        "DECISIONS.md",
        "go/crypto/crypto.go",
        'exp, ok := payload["exp"].(float64)',
    ): "It is the only one with a written rationale",
    ("PROGRESS.md", "python/seam_sdk/crypto.py", "def record_digest_v3("): (
        "`verify/src/verify.rs:448`; the 6a/6b"
    ),
    (
        "DECISIONS.md",
        "python/seam_sdk/crypto.py",
        "def _opt_bytes(b: bytes | None) -> bytes:",
    ): "past-EOF",
    # COMPATIBILITY.md
    # Phase 2's integer-slot guards. COMPATIBILITY.md cites `ts/src/crypto.ts` four times and
    # `python/seam_sdk/crypto.py` three times, so without these the anchors could be satisfied by a
    # sibling citation — the needle would be "found" against a line the claim never named.
    (
        "COMPATIBILITY.md",
        "ts/src/crypto.ts",
        "function uintSlot(name: string, value: number | bigint, bits: 32 | 64): bigint {",
    ): "The guard is `uintSlot`",
    (
        "COMPATIBILITY.md",
        "ts/src/crypto.ts",
        "function u64le(name: string, n: number | bigint)",
    ): "now route through it",
    (
        "COMPATIBILITY.md",
        "ts/src/crypto.ts",
        "const digest = chainHeadAttestationDigest({ ...a, attestedHead, issuerAid });",
        # Was "blanket `catch { return false }`" until §10 stopped that being true: the type checks
        # now run before the `try`. Re-anchored to the corrected sentence rather than to the code,
        # because what this pins is WHICH CLAIM carries the citation, and the claim is now historical.
    ): "wrapped its whole body in a catch that returned",
    (
        "COMPATIBILITY.md",
        "python/seam_sdk/crypto.py",
        "def _uint_slot(name: str, value: int, bits: int) -> int:",
    ): "was `_v3_uint`, and `record_digest_v2` now shares it",
    (
        "COMPATIBILITY.md",
        "python/seam_sdk/crypto.py",
        "_uint_slot(name, value, bits)",
    ): "now returns `False`",
    ("COMPATIBILITY.md", "CHANGELOG.md", "No yank"): "is not being re-litigated",
    (
        "COMPATIBILITY.md",
        "python/seam_sdk/client.py",
        "canonical: Optional[bytes] = None,",
    ): "`authorize(canonical=…)`",
    (
        "COMPATIBILITY.md",
        "python/seam_sdk/aio.py",
        "canonical: Optional[bytes] = None,",
    ): "`authorize(canonical=…)`",
    (
        "COMPATIBILITY.md",
        ".github/workflows/publish.yml",
        'registry-url: "https://npm.cloudsmith.io',
    ): "**TypeScript** (`@zer07labs/seam-sdk`)",
    (
        "COMPATIBILITY.md",
        ".github/workflows/publish.yml",
        'TWINE_REPOSITORY_URL: "https://python.cloudsmith.io',
    ): "**Python** (`seam-sdk`)",
    # DECISIONS.md
    (
        "DECISIONS.md",
        ".github/workflows/ci.yml",
        "must link NOTHING",
    ): "runs `scripts/check-independence.sh`",
    (
        "DECISIONS.md",
        "CHANGELOG.md",
        "this SDK cannot express its own",
    ): "whatever number the runtime's history computes",
    ("DECISIONS.md", "CHANGELOG.md", "No yank"): "The precedent already covers worse",
    (
        "DECISIONS.md",
        "verify/tests/authenticity.rs",
        "fn a_v1_record_is_link_verified_but_not_recomputed",
    ): "through to `continue` and is tested twice",
    (
        "DECISIONS.md",
        "verify/tests/authenticity.rs",
        "the v1 record is skipped, not recomputed",
    ): "whose skipped-not-recomputed assertion is at",
    (
        "DECISIONS.md",
        "verify/tests/authenticity.rs",
        "fn a_genuine_v1_record_is_still_skipped_not_refused",
    ): "(`a_genuine_v1_record_is_still_skipped_not_refused`)",
    (
        "DECISIONS.md",
        "verify/tests/authenticity.rs",
        "Each column is tested ALONE, with the other three removed",
    ): "exercises each column with the other three removed",
    # PROGRESS.md — the four Phase 4 anchors.
    (
        "PROGRESS.md",
        "ts/src/client.ts",
        "export function collectiveOutcomeOf",
    ): "the TS twin",
    (
        "PROGRESS.md",
        "ts/src/client.ts",
        "  submitCommit(",
    ): "`submit_commit` / `submitCommit`",
    (
        "PROGRESS.md",
        "ts/src/client.ts",
        "  submitEvaluation(",
    ): "`submit_evaluation` / `submit_objection`",
    (
        "PROGRESS.md",
        "ts/src/client.ts",
        "  submitObjection(",
    ): "`submit_evaluation` / `submit_objection`",
    # PROGRESS.md — the five round-5 anchors. Both paths are cited more than once in the document,
    # so `test_the_claim_line_map_covers_every_needle_that_needs_it` requires every one of them here.
    # `fields_python` and `fields_ts` share a claim line on purpose: one repo-map row makes one claim
    # about both extractors, and it now carries a full citation for each rather than a bare `:248`.
    (
        "PROGRESS.md",
        "scripts/check-contract.sh",
        "fields_python() {",
    ): "**Phase 5 parameterises both on stub path + package**",
    (
        "PROGRESS.md",
        "scripts/check-contract.sh",
        "fields_ts() {",
    ): "**Phase 5 parameterises both on stub path + package**",
    (
        "PROGRESS.md",
        "scripts/check-contract.sh",
        "manifest_fields() {",
    ): "its stripper claims every",
    (
        "PROGRESS.md",
        "scripts/check-contract.sh",
        "# Scoped to seam.api.v1 — and seam.event.v1 is now manifested too",
    ): "The comment #88 was filed from",
    (
        "PROGRESS.md",
        "python/tests/test_field_manifest_gate.py",
        "def _run(",
    ): "the scratch-copy-plus-env-override pattern",
    # Round 7's two, into the document every reconcile pass prepends to.
    (
        "PROGRESS.md",
        "DECISIONS.md",
        "### Why a floor-pinned install, rather than pinning the buf plugins",
    ): "Unpinned remote plugins",
    (
        "PROGRESS.md",
        "DECISIONS.md",
        "## 2026-08-24 — reconcile `plans/record-digest-v3.md`'s ASSUMPTIONS.md (4 entries)",
    ): "which are lookup keys that must match",
    # DECISIONS.md -> check-contract.sh. Three claim lines carry two citations each; the binding
    # still narrows, because `allc` is every check-contract.sh citation in the document.
    (
        "DECISIONS.md",
        "scripts/check-contract.sh",
        '_fwant="$(manifest_fields)"',
    ): "set-compared per language in both directions",
    (
        "DECISIONS.md",
        "scripts/check-contract.sh",
        "  exit 6",
    ): "set-compared per language in both directions",
    (
        "DECISIONS.md",
        "scripts/check-contract.sh",
        'fields_python "$PY_GEN" >> "$ftmp"',
    ): "with TypeScript as the cross-check",
    (
        "DECISIONS.md",
        "scripts/check-contract.sh",
        "# against TS is deliberate and is the reason the Python extractor must not read",
    ): "with TypeScript as the cross-check",
    (
        "DECISIONS.md",
        "scripts/check-contract.sh",
        'err "the moment someone DECIDES whether this SDK carries it. Decide first — wire it into the"',
    ): "puts the escape second",
}


def _citations_on_claim_line(doc: str, path: str, claim: str) -> list[tuple[int, int]]:
    """Citations of `path` written on the document line that carries `claim`.

    **A table row is a self-contained claim; wrapped prose is not.** A markdown row holds its claim
    and its citations on one physical line, and the row above it is a *different* claim — so for rows
    the scope is exactly that line, which is what makes this able to catch a citation drifting into a
    neighbouring row's territory. Prose wraps, and a claim's citation routinely lands on the next
    physical line, so for non-row lines the scope extends one line either side. Widening prose to a
    whole paragraph was rejected: `DECISIONS.md`'s `authenticity.rs` paragraph carries all four of
    that file's citations, so paragraph scope would narrow nothing there and would silently merge
    adjacent table rows elsewhere.
    """
    lines = (REPO / doc).read_text(encoding="utf-8").splitlines()
    scope: set[int] = set()
    for i, line in enumerate(lines):
        if claim not in line:
            continue
        scope.add(i)
        if not line.lstrip().startswith("|"):
            scope.update({i - 1, i + 1})

    out = []
    for i in sorted(scope):
        if 0 <= i < len(lines):
            for m in CITATION.finditer(lines[i]):
                if m.group(1) == path:
                    out.append((int(m.group(2)), int(m.group(3) or m.group(2))))
    return out


def test_every_claim_binding_actually_narrows_the_candidate_set() -> None:
    """A claim whose scope catches every citation of its path binds nothing.

    The point of `CLAIM_LINES` is that the needle is measured against ITS citation rather than any of
    them; an entry that admits the full set would pass while checking exactly what the path-only
    assertion already checks. `authenticity.rs` is the one place this cannot be fully achieved — the
    paragraph genuinely carries two citations on one line — so it is allowed to narrow to two of
    four rather than to one, and that ceiling is asserted rather than assumed.
    """
    weak = []
    for (doc, path, needle), claim in CLAIM_LINES.items():
        allc = {(s, e) for _d, p, s, e in _citations(doc) if p == path}
        own = set(_citations_on_claim_line(doc, path, claim))
        if len(allc) > 1 and not own < allc:
            weak.append(
                f"{doc} -> {path} {needle!r}: scope {sorted(own)} is not narrower than "
                f"{sorted(allc)}"
            )
    assert not weak, "these claim bindings do not narrow anything:\n  " + "\n  ".join(
        weak
    )


@pytest.mark.parametrize(
    ("key", "claim"), sorted(CLAIM_LINES.items()), ids=lambda v: str(v)[:60]
)
def test_an_anchored_needle_is_satisfied_by_its_own_citation(
    key: tuple[str, str, str], claim: str
) -> None:
    """The property the path-only matching above cannot enforce: the RIGHT citation is the near one.

    This replaces a check that asserted "more than one citation of this path satisfies the needle",
    which sounds like the masking condition and is not: masking leaves exactly one citation in range.
    The scenario the record itself describes — delete fourteen lines between `submitEvaluation` and
    `submitObjection`, so `submitObjection` lands on the confidence mapping's citation and
    `submitCommit` lands on `submitObjection`'s — passed that check with the whole suite green.
    It fails this one, because each needle is now measured only against the citations written on the
    document line that makes the claim about it.
    """
    doc, path, needle = key
    lines = (REPO / path).read_text(encoding="utf-8", errors="ignore").splitlines()
    hits = [i + 1 for i, line in enumerate(lines) if needle in line]
    assert len(hits) == 1, (
        f"{needle!r} occurs {len(hits)} times in {path}; see the test above"
    )
    true_line = hits[0]

    own = _citations_on_claim_line(doc, path, claim)
    assert own, (
        f"no citation of {path} appears on any {doc} line containing {claim!r}. Either the claim "
        f"line was reworded (update CLAIM_LINES) or its citation was dropped."
    )
    assert any(a - CITATION_SLACK <= true_line <= b + CITATION_SLACK for a, b in own), (
        f"{needle!r} is at {path}:{true_line}, but the {doc} line that claims it cites {path} only "
        f"at {[str(a) if a == b else f'{a}-{b}' for a, b in own]}. The citation on the claim's own "
        f"line has drifted — another citation elsewhere in {doc} may still be covering for it, "
        f"which is exactly why this check exists alongside the path-only one."
    )


def test_the_claim_line_map_covers_every_needle_that_needs_it() -> None:
    """`CLAIM_LINES` is opt-in, so a new anchored needle into an already-multiply-cited path would
    silently get only the weaker path-only check. Anything whose document cites its path more than
    once must be listed."""
    missing = []
    for doc, path, needle in ANCHORED:
        distinct = {(s, e) for _d, p, s, e in _citations(doc) if p == path}
        if len(distinct) > 1 and (doc, path, needle) not in CLAIM_LINES:
            missing.append(
                f"{doc} -> {path} {needle!r} ({len(distinct)} distinct citations)"
            )
    assert not missing, (
        "these anchored needles point at a path their document cites more than once, so a foreign "
        "citation can satisfy them, and they are not in CLAIM_LINES:\n  "
        + "\n  ".join(missing)
    )


def test_the_anchored_table_is_not_empty() -> None:
    """A floor with a real margin: 17 entries at the time of writing. The check this replaced
    asserted only `report` was non-empty, a floor of one against seventeen — the weakest calibration
    in a file whose stated discipline is a third."""
    assert len(ANCHORED) >= 12, (
        f"ANCHORED has shrunk to {len(ANCHORED)}; entries are being deleted"
    )


@pytest.mark.parametrize(("doc", "path", "needle"), ANCHORED, ids=lambda v: str(v))
def test_the_load_bearing_citations_still_point_at_the_right_thing(
    doc: str, path: str, needle: str
) -> None:
    """A line that exists but no longer says what it was cited for is the failure that happened.

    **Known limit, and where it is now closed:** *this* check matches citations to a claim by PATH
    only, so if a document cites one file more than once, any of those citations landing within
    `CITATION_SLACK` of the needle satisfies it — a drifted citation can be masked by an unrelated
    one. That is not merely theoretical; it is how three of these entries went stale unnoticed. It is
    closed one level up, by `test_an_anchored_needle_is_satisfied_by_its_own_citation`, which binds
    each needle in `CLAIM_LINES` to the citations on *the line making the claim* — the single line
    for a `|`-prefixed table row, ±1 for wrapped prose. Both checks run: path-only catches a citation
    that has no correct twin anywhere, claim-bound catches the one that does.

    Documents do NOT mask each other either: `cited` is scoped to `doc`, so `ci.yml` being correctly
    cited in COMPATIBILITY.md cannot cover for its being stale in DECISIONS.md — which is not
    hypothetical, it is exactly the state this entry was added in.

    **No margin numbers here, on purpose.** This paragraph used to carry them by hand and every one
    rotted — three wrong figures in the docstring attached to the assertion that could have computed
    them, one of which contradicted a sentence fifteen lines above it. The round-3 replacement
    computed margins but asserted the wrong property ("more than one citation satisfies", when
    masking leaves exactly one) and is gone. The qualitative point is the part worth keeping in
    prose: the danger zone is `2 * CITATION_SLACK + 1` lines wide, not the whole span between two
    citations, so what masks a needle is a *foreign* citation landing within three lines of it — and
    a claim-bound needle cannot be masked at all, since a citation elsewhere in the document is not
    on its claim line.
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
    # COMPATIBILITY.md §2's two sibling-repo rows. Both rotted while their citations stayed green,
    # which is the whole argument for this mechanism over `ANCHORED`:
    #
    #   * the `seam-aegis` row quoted `seam-agent-core[sdk]>=0.1,<0.2` against a line that had long
    #     since become `>=0.4,<0.5` — the LINE NUMBER never moved, so nothing could notice;
    #   * the editable-source caveat cited `seam-adapters/pyproject.toml:32`, which is a comment
    #     about the Makefile; the source it describes is at `:54`.
    #
    # A version constraint is exactly the wrong thing to line-anchor: it is a short string that
    # changes VALUE in place, on another repo's release cadence, without moving. Quoting it is the
    # only check that fails when it goes stale.
    (
        "COMPATIBILITY.md",
        "seam-aegis/pyproject.toml",
        "seam-agent-core[sdk]>=0.5,<0.6",
    ),
    (
        "COMPATIBILITY.md",
        "seam-adapters/core/pyproject.toml",
        "seam-sdk>=0.7.20,<0.8",
    ),
    (
        "COMPATIBILITY.md",
        "seam-adapters/pyproject.toml",
        '{ path = "../seam-sdk/python", editable = true }',
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
    # Sibling-aware, for the same reason `test_each_citation_resolves` is: a `QUOTED` entry whose
    # source lives in another repo is the case that needs this mechanism MOST — a line anchor into a
    # sibling cannot be re-checked from here at all, so the verbatim quote is the only handle there
    # is. Resolving it as `REPO / path` instead would look for `seam-sdk/seam-aegis/pyproject.toml`,
    # fail the `exists()` assertion, and make the entry unaddable — which is why the two stale
    # sibling constraints in COMPATIBILITY.md §2 went unguarded until now.
    sibling_path = _sibling_relative_path(path)
    if sibling_path.startswith(SIBLING_PREFIXES):
        target = REPO.parent / sibling_path
        if not target.exists():
            pytest.skip(f"{path} is in a sibling repo not checked out here")
    else:
        target = REPO / path
        assert target.exists(), (
            f"{doc} quotes {path}, but that file does not exist. Re-source the claim or delete "
            f"it, per COMPATIBILITY.md's own rule."
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
    # The attribution may carry a line suffix — `` `path:22` `` is how COMPATIBILITY.md's §2 table
    # writes it, and that is still an attribution. Matching only the bare `` `path` `` form rejected
    # all three §2 rows on their first run here, which would have been read as "these cannot be
    # guarded" rather than "the matcher is too narrow". The suffix must be delimited (`:` or the
    # closing backtick) so `a/b.py` cannot be satisfied by an unrelated `a/b.pyi`.
    window = 2
    attributed = any(
        f"`{path}`" in line or f"`{path}:" in line
        for q in quoted_at
        for line in doc_lines[max(0, q - window) : q + window + 1]
    )
    assert attributed, (
        f"{doc} quotes {needle!r} (line {quoted_at[0] + 1}) but does not attribute it to `{path}` "
        f"within {window} lines of the quote. An unattributed quote cannot be re-verified by a "
        f"reader, which is the whole point of citing anything. Note this deliberately does NOT "
        f"accept a mention elsewhere in the document: the quote and its source must travel together."
    )


# ---------------------------------------------------------------------------
# The bare `:NNN` companion form (issue #91, part 1)
# ---------------------------------------------------------------------------
#
# `CITATION` above requires a path, so a citation written as a bare line number — the companion
# form these documents use constantly, ``(`x.py:69`, `:93`, `:108`)`` — was invisible to every
# check in this file. Measured when this was written: 27 in DECISIONS.md, 155 in PROGRESS.md, 2 in
# CHANGELOG.md, 0 in COMPATIBILITY.md. None of them was checked by anything.
#
# The binding rule below is NOT the one the issue proposed ("the file named in the previous full
# citation"). That rule was measured against this corpus and it is wrong twice over:
#
#   * **In a table row, the row's SUBJECT wins, not the nearest citation.** PROGRESS.md's repo-map
#     row for `python/seam_sdk/crypto.py` names `python/seam_sdk/admin.py:141` mid-sentence and then
#     continues `:386` `_frame` · `:390` `_opt` · `:584` `_opt_bytes` — all four of which are
#     crypto.py. "Nearest preceding citation" binds them to admin.py, where `:584` is past EOF, and
#     reports a stale citation that is not stale. Verified by reading the file: crypto.py:584 is
#     `def _opt_bytes`, exactly what the row claims.
#   * **Inheritance must not cross lines.** PROGRESS.md writes `` `p1a:103-107`, `:290-291` `` where
#     `p1a` is a shorthand alias for a sibling-repo spec, not a path. A paragraph-scoped resolver
#     walks past it to the previous line and binds those refs to whatever unrelated file it finds
#     there — measured, it picked `COMPATIBILITY.md` and reported a false stale citation.
#
# So: same line only, and the row subject outranks an interior citation. A ref that binds to
# nothing is NOT quietly dropped — it is counted, and the count is a ratchet (see below).

#: `` `:12` `` or `` `:12-34` `` — a line reference with no path of its own.
BARE_CITATION = re.compile(r"`:(\d+)(?:-(\d+))?`")

#: A backticked path carrying a line suffix — the only prose antecedent accepted. Requiring the
#: suffix is what keeps `` `seam.api.v1` `` (a proto package, which matches the path shape exactly)
#: and `` `p1a` `` (an alias) from being mistaken for the subject of a following bare reference.
_FULL_TOKEN = re.compile(r"`(\.{0,2}/?[\w./-]+\.[A-Za-z]\w*):[\d,\-]+`")

#: A table row's subject: the first cell, containing ONLY a backticked path (bold markers and a
#: line suffix allowed). Deliberately a full match rather than a search — a cell naming two files
#: has no single subject, and guessing one is how a resolver starts reporting confident nonsense.
_SUBJECT_CELL = re.compile(
    r"^\s*\**\s*`(\.{0,2}/?[\w./-]+\.[A-Za-z]\w*)(?::[\d,\-]+)?`\s*\**\s*$"
)


def _bind_bare_citations_in(
    text: str, doc: str = "<text>"
) -> tuple[list[tuple[str, str, int, int, int]], int]:
    """Bind every bare `:NNN` in `text` to a file, same-line only.

    Pure — takes the document text rather than reading it — so the binding RULES can be driven
    directly by the tests below against hand-written two-line documents. Testing the rule through
    the real corpus only would mean the mutation tests could never construct the exact shapes the
    rule exists to get right.

    Returns `(bound, unbound_count)` where each bound entry is
    `(doc, path, start, end, doc_line)`.
    """
    bound: list[tuple[str, str, int, int, int]] = []
    unbound = 0
    for doc_line, line in enumerate(text.splitlines(), 1):
        subject = None
        if line.lstrip().startswith("|"):
            cells = line.split("|")
            if len(cells) > 2:
                cell = _SUBJECT_CELL.match(cells[1])
                if cell:
                    subject = cell.group(1)
        for bare in BARE_CITATION.finditer(line):
            path = subject
            if path is None:
                preceding = list(_FULL_TOKEN.finditer(line[: bare.start()]))
                path = preceding[-1].group(1) if preceding else None
            if path is None:
                unbound += 1
                continue
            start = int(bare.group(1))
            end = int(bare.group(2) or bare.group(1))
            bound.append((doc, path, start, end, doc_line))
    return bound, unbound


def _bind_bare_citations(doc: str) -> tuple[list[tuple[str, str, int, int, int]], int]:
    return _bind_bare_citations_in((REPO / doc).read_text(encoding="utf-8"), doc)


def _all_bare_citations() -> list[tuple[str, str, int, int, int]]:
    return [b for doc in DOCS for b in _bind_bare_citations(doc)[0]]


@pytest.mark.parametrize(
    "citation", _all_bare_citations(), ids=lambda c: f"{c[0]}~L{c[4]}~{c[1]}:{c[2]}"
)
def test_each_bound_bare_citation_resolves(
    citation: tuple[str, str, int, int, int],
) -> None:
    """A bare `:NNN` that binds to a file is held to exactly the standard a full citation is."""
    doc, path, start, end, doc_line = citation

    target = _resolve_citation_target(doc, path, start, repo=REPO)
    if target is None:
        pytest.skip(f"{path} is in a sibling repo not checked out here")

    line_count = len(target.read_text(encoding="utf-8", errors="ignore").splitlines())
    assert end <= line_count, (
        f"{doc}:{doc_line} carries the bare citation `:{start}-{end}`, which binds to `{path}` "
        f"({'the subject of its table row' if start else ''}), but {path} has only {line_count} "
        f"lines. The citation is stale. This is the class that was invisible until issue #91: the "
        f"line number is real, the file is real, and nothing pointed one at the other."
    )


#: Bare references that bind to nothing on their own line, per document. **A ratchet: it may be
#: lowered, never raised.** These are not a backlog of broken citations — they are overwhelmingly
#: two legitimate kinds that must NOT be checked against HEAD:
#:
#:   * **historical records.** DECISIONS.md's repoint table is literally a column of the values a
#:     citation held at each PR (`:271-272` → `:295-296` → `:332-333` → …). Asserting a record of
#:     where a line USED to be against where it is now is not a check, it is a contradiction.
#:   * **the notation quoted as data.** Both documents discuss this very failure — "it still said
#:     `:473` after the guard moved to `:571`" — and those are mentions, not claims.
#:
#: The ceiling exists so the unchecked population cannot grow silently, which is the actual issue
#: #91 complaint. If you add a bare reference and this fails, bind it: put a full `path:line`
#: citation earlier on the SAME line, or put the path in the table row's subject cell. Raising the
#: number instead is how 156 unchecked references accumulated in the first place.
UNBOUND_BARE_CEILING = {
    "COMPATIBILITY.md": 0,
    "DECISIONS.md": 26,
    "PROGRESS.md": 68,
}


@pytest.mark.parametrize(("doc", "ceiling"), UNBOUND_BARE_CEILING.items())
def test_unbound_bare_citations_do_not_grow(doc: str, ceiling: int) -> None:
    _, unbound = _bind_bare_citations(doc)
    assert unbound <= ceiling, (
        f"{doc} now has {unbound} bare `:NNN` references that bind to no file, up from {ceiling}. "
        f"Bind the new one instead of raising this number: name the file in a full `path:line` "
        f"citation earlier on the same line, or make it the subject cell of its table row."
    )


def test_the_ceiling_is_not_slack() -> None:
    """A ceiling far above the real count would pass while permitting silent growth."""
    for doc, ceiling in UNBOUND_BARE_CEILING.items():
        _, unbound = _bind_bare_citations(doc)
        assert unbound == ceiling, (
            f"{doc} has {unbound} unbound bare references but the ratchet says {ceiling}. If you "
            f"just BOUND some, lower the ceiling to {unbound} — that is the ratchet working. This "
            f"check exists because a ceiling with headroom is a ceiling that permits exactly the "
            f"drift it claims to stop."
        )


def test_the_corpus_actually_contains_bare_citations() -> None:
    """Guard the guard: if `BARE_CITATION` stopped matching, every check above passes vacuously."""
    total = sum(len(_bind_bare_citations(doc)[0]) for doc in DOCS)
    assert total >= 50, (
        f"only {total} bare citations bind across {list(DOCS)}. Either the documents were gutted "
        f"or `BARE_CITATION`/`_FULL_TOKEN`/`_SUBJECT_CELL` stopped matching the real format — and "
        f"in that case `test_each_bound_bare_citation_resolves` is parametrized to nothing and is "
        f"asserting nothing at all."
    )


def test_a_bound_bare_citation_past_eof_is_caught(tmp_path: pathlib.Path) -> None:
    """The mutation the whole mechanism exists to catch: a real file, a real-looking line number,
    and nothing previously connecting the two."""
    (tmp_path / "short.py").write_text("one\ntwo\nthree\n", encoding="utf-8")

    bound, unbound = _bind_bare_citations_in(
        "the helper at `short.py:2` and its partner at `:99`\n"
    )
    assert unbound == 0
    assert bound == [("<text>", "short.py", 99, 99, 1)], bound

    doc, path, start, end, _ = bound[0]
    target = _resolve_citation_target(doc, path, start, repo=tmp_path)
    assert target is not None
    line_count = len(target.read_text().splitlines())
    assert end > line_count, (
        "the past-EOF bare citation resolved as in-bounds, so the check this test guards would "
        "have passed on a stale citation"
    )


def test_a_table_rows_subject_outranks_an_interior_citation() -> None:
    """The measured failure of the rule issue #91 proposed. `:584` belongs to the row's subject
    (`crypto.py`), not to the `admin.py` citation that happens to sit closer to it."""
    row = (
        "| `python/seam_sdk/crypto.py:606-610` | context_digest appears only as an input "
        "(`python/seam_sdk/admin.py:141`), and `:584` is `_opt_bytes`. |\n"
    )
    bound, unbound = _bind_bare_citations_in(row)
    assert unbound == 0
    assert [b[1] for b in bound] == ["python/seam_sdk/crypto.py"], (
        f"bare `:584` bound to {[b[1] for b in bound]}. Binding it to the nearer `admin.py` "
        f"citation is the bug this rule exists to avoid: admin.py is 568 lines, so it would be "
        f"reported as a stale citation when the claim is true of crypto.py, which has 724."
    )


def test_binding_never_crosses_a_line() -> None:
    """The other measured failure: an alias with no extension (`p1a`) is not a path, so the refs
    after it bind to nothing rather than reaching back to an unrelated file on the line above."""
    text = (
        "re-verified against `COMPATIBILITY.md:12`:\n"
        "`p1a:103-107`, `:290-291`, `:439-441`\n"
    )
    bound, unbound = _bind_bare_citations_in(text)
    assert bound == [], (
        f"bare references on line 2 bound to {[b[1] for b in bound]} by reaching back to line 1. "
        f"Cross-line inheritance manufactures false antecedents — measured against the real "
        f"PROGRESS.md, it bound sibling-repo spec anchors to COMPATIBILITY.md and reported three "
        f"stale citations that were not stale."
    )
    # Two, not three: `` `p1a:103-107` `` is not a bare reference at all — its colon follows text
    # rather than a backtick — so only `:290-291` and `:439-441` are in play. Stated exactly
    # because getting this count wrong is how a test ends up asserting the wrong shape passes.
    assert unbound == 2


def test_a_subject_cell_naming_two_files_binds_nothing() -> None:
    """`_SUBJECT_CELL` is a full match on purpose: a cell with no single subject has no subject."""
    row = "| `a/one.py` and `a/two.py` | see `:42` |\n"
    bound, unbound = _bind_bare_citations_in(row)
    assert bound == [] and unbound == 1, (
        f"a two-file subject cell bound `:42` to {[b[1] for b in bound]}. Picking one of two "
        f"candidates is a guess, and a guess that resolves is indistinguishable from a check."
    )


@pytest.mark.parametrize("doc", DOCS)
def test_a_bare_citation_cannot_smuggle_a_line_anchor_into_a_protected_tree(
    doc: str,
) -> None:
    """`_line_anchors_into_vendored` and `_line_anchors_into_generated` both scan for `CITATION`,
    which needs a path — so binding the bare form (issue #91) opened a way around both of them.

    A table row whose subject cell is the vendored spec, carrying bare `:NNN` companions, is a line
    anchor into a whole-file-refreshed document by every argument issue #73 makes, while matching
    neither rule's regex. Nothing in the repo does this today; this closes it before something does,
    because the failure would look exactly like compliance.
    """
    protected = VENDORED + GENERATED
    offenders = [
        f"{doc}:{doc_line} binds `:{start}-{end}` to `{path}`"
        for (_, path, start, end, doc_line) in _bind_bare_citations(doc)[0]
        if path.startswith(protected)
    ]
    assert offenders == [], (
        f"bare line references bound to a vendored or generated path: {offenders}. Vendored files "
        f"are refreshed whole-file on another repo's cadence and generated trees do not exist in a "
        f"fresh clone, so a line number into either is unmaintainable — which is the whole of issue "
        f"#73. Quote the text instead (see QUOTED), or cite the file with no line number."
    )


def test_the_smuggling_check_would_actually_fire() -> None:
    """The check above passes today because nothing offends. Prove it is not passing vacuously."""
    row = f"| `{VENDORED[0]}` | the slots are filled at `:569-572`. |\n"
    bound, _ = _bind_bare_citations_in(row)
    assert [b[1] for b in bound] == [VENDORED[0]], (
        "the evasion shape does not even bind, so the check above is guarding nothing"
    )
    assert bound[0][1].startswith(VENDORED + GENERATED), (
        "the bound path is not recognised as protected, so the real check could not fire on it"
    )
