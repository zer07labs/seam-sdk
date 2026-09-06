"""`publish.yml`'s gates all worked; the refusals told nobody, which is why the registry lagged.

v0.7.69, v0.7.70 and v0.7.72 were each refused correctly by `ci-green`. Each refusal was found by
hand, days later — the registry sat five days behind a source tree, a tag and a runtime that all
said 0.7.72 existed. A failed workflow run is a red dot on a page nobody opens.

`release-outcome` exists to make that arrive somewhere. It is a REPORTER, not a gate, and the
properties worth pinning are the ones that make a reporter useless when they rot:

  * it runs when its dependencies FAILED (`if: always()`) — the default is "only if needs
    succeeded", which is silent in precisely the case it was written for;
  * it stays quiet on a real success, or it trains everyone to ignore it;
  * it treats `registry-smoke` — not npm/python — as the proof of a landed release, because
    "uploaded" and "installable" are different claims and this repo has already been bitten by
    the gap;
  * it does not open a second issue for a tag that already has one.

These execute the real step script out of the workflow against a stubbed `gh`, for the reason
`test_publish_gate.py` gives: a gate whose logic is only read and never run is how the ordering bug
in `release-on-runtime.yml` survived a day.

Run: `python -m pytest scripts/test_release_notice_gate.py -q`
"""

from __future__ import annotations

import re
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
PUBLISH = REPO / ".github" / "workflows" / "publish.yml"
JOB = "release-outcome"

#: Every job whose result the notice reads. Kept here so a job added to `needs:` without being
#: reported is a test failure rather than a silently missing row in the issue body.
REPORTED = ["ci-green", "version-check", "npm", "python", "registry-smoke"]


def _job() -> dict:
    return yaml.safe_load(PUBLISH.read_text())["jobs"][JOB]


def _script() -> str:
    return _job()["steps"][0]["run"]


def _run(
    tmp_path: Path,
    *,
    smoke: str = "success",
    ci_green: str = "success",
    version_check: str = "success",
    npm: str = "success",
    python: str = "success",
    open_issues: list[dict] | None = None,
) -> tuple[subprocess.CompletedProcess, list[list[str]]]:
    """Run the notice script with a stubbed `gh`; return the process and every `gh` argv it made."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "gh-calls"
    calls.write_text("")
    listing = tmp_path / "issues.tsv"
    listing.write_text(
        "".join(f"{i['number']}\t{i['title']}\n" for i in (open_issues or []))
    )

    # The stub answers `issue list` with a pre-rendered TSV — exactly the shape the script's
    # `--jq '.[] | "\(.number)\t\(.title)"'` produces — and records every invocation.
    (bin_dir / "gh").write_text(
        textwrap.dedent(f"""\
        #!/usr/bin/env bash
        printf '%s\\n' "$*" >> {calls}
        if [ "$1" = "issue" ] && [ "$2" = "list" ]; then
          cat {listing}
        fi
        exit 0
        """)
    )
    (bin_dir / "gh").chmod(0o755)

    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/local/bin",
        "GH_TOKEN": "stub",
        "CI_GREEN": ci_green,
        "VERSION_CHECK": version_check,
        "NPM": npm,
        "PYTHON": python,
        "SMOKE": smoke,
        "GITHUB_REF_NAME": "v0.7.72",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "zer07labs/seam-sdk",
        "GITHUB_RUN_ID": "12345",
    }
    proc = subprocess.run(
        ["bash", "-c", _script()],
        env=env,
        capture_output=True,
        text=True,
    )
    argv = [line.split() for line in calls.read_text().splitlines() if line.strip()]
    return proc, argv


def _verbs(argv: list[list[str]]) -> list[str]:
    return [" ".join(a[:2]) for a in argv]


# ── it reports when the release did not land ───────────────────────────────────────────────────


def test_a_refused_release_opens_an_issue(tmp_path: Path) -> None:
    proc, argv = _run(tmp_path, ci_green="failure", npm="skipped", python="skipped", smoke="skipped")
    assert proc.returncode == 0, proc.stderr
    assert "issue create" in _verbs(argv), f"nothing was filed; gh saw {_verbs(argv)}"


@pytest.mark.parametrize("failed", REPORTED)
def test_any_job_short_of_a_landed_release_reports(failed: str, tmp_path: Path) -> None:
    """Not just `ci-green`. A half-published release — npm up, python down — is still a failure.

    The three real incidents all failed at `ci-green`, so a guard written only against them would
    pass while staying blind to the partial-publish case, which is the worse one: the registry then
    holds an npm package with no matching wheel.
    """
    kwargs = {"ci_green": "success", "version_check": "success", "npm": "success", "python": "success", "smoke": "success"}
    kwargs["smoke" if failed == "registry-smoke" else failed.replace("-", "_")] = "failure"
    if failed != "registry-smoke":
        kwargs["smoke"] = "skipped"
    proc, argv = _run(tmp_path, **kwargs)
    assert proc.returncode == 0, proc.stderr
    assert "issue create" in _verbs(argv), f"{failed} failing filed nothing"


def test_the_issue_names_the_tag(tmp_path: Path) -> None:
    proc, argv = _run(tmp_path, ci_green="failure", smoke="skipped")
    create = next(a for a in argv if a[:2] == ["issue", "create"])
    assert "v0.7.72" in " ".join(create), (
        "the issue title does not carry the tag, so two failed releases collapse into one thread"
    )


# ── it stays quiet when the release actually landed ────────────────────────────────────────────


def test_a_landed_release_files_nothing(tmp_path: Path) -> None:
    proc, argv = _run(tmp_path, smoke="success")
    assert proc.returncode == 0, proc.stderr
    assert argv == [], f"a successful release still called gh: {_verbs(argv)}"


def test_npm_and_python_succeeding_is_not_enough(tmp_path: Path) -> None:
    """`registry-smoke` is the proof, not the upload jobs.

    npm and python report the PUSH succeeded. registry-smoke installs the artifact back out of
    Cloudsmith and runs the vectors against it. A release that uploads and never becomes
    installable passes the first two and fails the third — and that exact failure is why
    registry-smoke exists, so the notice must read it and not them.
    """
    proc, argv = _run(tmp_path, npm="success", python="success", smoke="failure")
    assert "issue create" in _verbs(argv), (
        "an uploaded-but-not-installable release reported nothing"
    )


# ── it does not spam ───────────────────────────────────────────────────────────────────────────


def test_a_tag_that_already_has_an_issue_gets_a_comment(tmp_path: Path) -> None:
    proc, argv = _run(
        tmp_path,
        ci_green="failure",
        smoke="skipped",
        open_issues=[{"number": 101, "title": "Release v0.7.72 did not publish"}],
    )
    assert proc.returncode == 0, proc.stderr
    verbs = _verbs(argv)
    assert "issue comment" in verbs, f"re-run did not comment; gh saw {verbs}"
    assert "issue create" not in verbs, "a second issue was opened for the same tag"


def test_an_unrelated_open_issue_does_not_suppress_the_report(tmp_path: Path) -> None:
    """Title matching must be exact.

    A substring match against a busy issue list is how a reporter goes quiet for reasons nobody
    can reconstruct later — the failure class this whole job was written against.
    """
    proc, argv = _run(
        tmp_path,
        ci_green="failure",
        smoke="skipped",
        open_issues=[
            {"number": 100, "title": "Three releases silently failed to publish"},
            {"number": 44, "title": "Reserve unregistered PyPI package names defensively"},
        ],
    )
    assert "issue create" in _verbs(argv), "an unrelated open issue swallowed the report"


# ── structure: the properties that make it a reporter rather than a gate ────────────────────────


def test_it_runs_even_when_its_dependencies_failed() -> None:
    cond = str(_job()["if"])
    assert "always()" in cond, (
        "release-outcome lost `always()`. Without it the job inherits 'run only if needs "
        "succeeded' and goes silent in exactly the case it exists to report."
    )


def test_it_watches_every_job_that_can_stop_a_release() -> None:
    needs = set(_job()["needs"])
    assert set(REPORTED) <= needs, (
        f"release-outcome does not depend on {set(REPORTED) - needs}, so it can be evaluated "
        "before those jobs finish and report a release that had not failed yet."
    )


def test_it_can_actually_file_an_issue() -> None:
    """A reporter without `issues: write` fails at the last step — visibly, but only in the run.

    publish.yml's top-level permissions are read-only, and job-level permissions REPLACE rather
    than extend them, so this has to be declared on the job itself.
    """
    perms = _job()["permissions"]
    assert perms.get("issues") == "write", f"release-outcome cannot open an issue: {perms}"


def test_it_cannot_turn_a_failed_release_green() -> None:
    """It reports; it must never be mistaken for a gate.

    A notifier that other jobs depend on, or that carries `continue-on-error`, starts having an
    opinion on the release's outcome. This one only ever reads results.
    """
    wf = yaml.safe_load(PUBLISH.read_text())
    dependents = [j for j, spec in wf["jobs"].items() if JOB in (spec.get("needs") or [])]
    assert dependents == [], f"{dependents} depend on the notifier, making a reporter into a gate"


# ── The blind-spot paragraph's pointer ───────────────────────────────────────────────────────
#
# This guard has been broken twice by reviewers, both times the same way: a decoy reference
# placed somewhere in the surrounding prose satisfied a pattern that was scoped too widely, and
# the real citation could then be deleted with the suite green. The scope has therefore been
# tightened twice — first from the whole 19-line comment block to the `NOTE …` paragraph, then
# from the paragraph to the SENTENCE that makes the promise. The current rule is the narrowest
# one that is still true: the pointer must sit on the line that says the gap is not solved here,
# or on the line immediately after it, because that is where a reader looks for it.

#: Opens the paragraph. Must occur exactly once — a second occurrence earlier in the block would
#: re-widen the scope to everything between the two, which is how defeat #2 worked.
_NOTE_MARKER = "NOTE the blind spot"

#: What the paragraph is ABOUT. A wholesale rewrite that drops this should fail rather than pass.
_BLIND_SPOT_SENTINEL = "never ran at all"

#: The promise itself. The pointer is required in ITS sentence, not merely somewhere nearby.
_PROMISE = "NOT solved here"

#: Repo-qualified: a bare `#\d+` is matched by a colour hex, a markdown heading, and by any PR
#: reference in neighbouring prose, and `grpc/grpc#100` points at a different project entirely.
_ISSUE_POINTER = re.compile(r"zer07labs/seam-sdk#100\b")

#: Phase 9 re-points this comment at the shipped workflow, so a path is acceptable — but not
#: `publish.yml` itself, which is a self-reference to the file the comment lives in. IGNORECASE
#: so `Publish.yml` is rejected too: macOS resolves it on a case-insensitive filesystem while
#: `ubuntu-latest` does not, and a guard whose verdict depends on the developer's filesystem is
#: worse than no guard. The captured name is resolved on disk — a regex cannot tell a live path
#: from a dead one.
_WORKFLOW_POINTER = re.compile(
    r"\.github/workflows/(?!publish\.)([\w.-]+\.ya?ml)", re.IGNORECASE
)

#: The literal paragraph this phase replaced, at its true length — byte-identical to the five
#: comment lines at `publish.yml:761-765` before the fix, plus two anchor lines. Held at full
#: length because a shorter excerpt cannot catch a loosening of `_WORKFLOW_POINTER` that drops
#: the directory prefix, which is exactly the edit Phase 9 invites.
_PRE_FIX_PARAGRAPH = textwrap.dedent(
    """\
      # NOTE the blind spot this job structurally cannot cover: it is a job INSIDE publish.yml, so it
      # reports a publish that ran and failed. A publish that never ran at all — no tag pushed, trigger
      # misconfigured, workflow file broken — fails silently exactly as before, because nothing
      # executes. That case needs a check that runs on its own schedule and compares the registry to
      # the source; it is deliberately NOT solved here (see the issue this job cites).
      release-outcome:
        name: report a release that did not publish
    """
)


def _comment_block_above(text: str, job_key: str) -> list[str]:
    """The contiguous `#`-prefixed lines immediately above `  <job_key>:` in raw YAML text."""
    lines = text.splitlines()
    anchor = next((i for i, ln in enumerate(lines) if ln.strip() == f"{job_key}:"), None)
    if anchor is None:
        return []
    block: list[str] = []
    for ln in reversed(lines[:anchor]):
        if not ln.strip().startswith("#"):
            break
        block.append(ln)
    return list(reversed(block))


def _blind_spot_paragraph(text: str, job_key: str) -> list[str]:
    """The `NOTE …` paragraph: from the marker to the first blank `#` line, or to the job key.

    Bounded at BOTH ends. Anchoring only at the top left the paragraph running all the way to the
    job key, so a maintainer adding any cross-reference below it — the most ordinary edit there
    is — silently supplied the pointer the promise sentence was missing.
    """
    block = _comment_block_above(text, job_key)
    start = next((i for i, ln in enumerate(block) if _NOTE_MARKER in ln), None)
    if start is None:
        return []
    para = [block[start]]
    for ln in block[start + 1 :]:
        if ln.strip() == "#":
            break
        para.append(ln)
    return para


def _pointer_window(para: list[str]) -> str | None:
    """The promise LINE. Nothing else.

    Three drafts of this guard tried to be generous about where the citation could sit — the
    whole comment block, then the paragraph, then the promise sentence with a one-line extension
    for wrapping. Each was defeated by a decoy placed just inside the generous boundary, and the
    third only narrowly: the extension fired when the promise line did not end in `.`, `!` or `?`,
    so a line ending `.)` or `."` or `…` was read as unfinished and absorbed the line below it.
    A guard whose verdict turns on the last character of a prose line is a guard nobody can
    reason about.

    So the boundary is now the line. It cannot be widened by an edit to the file it checks, needs
    no punctuation table, and behaves identically on every platform. The cost is that a citation
    which wraps onto a second line reads as absent — the suite goes red and says to join it onto
    the promise line. That is a real constraint on the prose, accepted deliberately: this comment
    is five lines long and the citation fits, and a rule that always means the same thing is
    worth more here than one that accommodates a wrap nobody has needed.

    `None` when the paragraph makes no promise at all, which is a distinct failure from making
    one and not keeping it.
    """
    idx = next((i for i, ln in enumerate(para) if _PROMISE in ln), None)
    return None if idx is None else para[idx]


def _blind_spot_failures(text: str, job_key: str, repo: Path) -> list[str]:
    """Every way the blind-spot paragraph currently fails its contract. Empty means it holds.

    Returns failures rather than asserting so the red-first tests can run **this same function**
    over the text this phase replaced, and over fixtures that gut each clause in turn. A
    red-first test that re-implements one clause proves that clause is breakable and leaves the
    rest never exercised in their failing direction — true of the first draft, caught by review.
    """
    block = _comment_block_above(text, job_key)
    if not block:
        return [f"no comment block above `{job_key}:` — the job was renamed or deleted"]
    if sum(_NOTE_MARKER in ln for ln in block) > 1:
        return [
            f"`{_NOTE_MARKER}` appears more than once above `{job_key}:`. The paragraph scope "
            "becomes ambiguous, and the wider of the two readings lets prose elsewhere in the "
            "block supply the citation this guard checks for."
        ]
    if sum(_PROMISE in ln for ln in block) > 1:
        return [
            f"{_PROMISE!r} appears more than once above `{job_key}:`. Only the first is checked, "
            "so a second promise carrying no citation would never be examined — the same "
            "asymmetry the marker-uniqueness check exists to remove."
        ]
    para = _blind_spot_paragraph(text, job_key)
    if not para:
        return [
            f"no `{_NOTE_MARKER}…` paragraph above `{job_key}:` — it was deleted or reworded, "
            "and every check below would pass by examining nothing"
        ]
    joined = "\n".join(para)
    failures: list[str] = []
    if _BLIND_SPOT_SENTINEL not in joined:
        failures.append(
            f"the paragraph no longer says what it is about (looked for "
            f"{_BLIND_SPOT_SENTINEL!r}). If the blind spot was genuinely closed, delete the "
            "paragraph and this guard together — do not leave prose describing a gap that is gone."
        )
    window = _pointer_window(para)
    if window is None:
        failures.append(
            f"the paragraph no longer contains the promise ({_PROMISE!r}) whose citation this "
            "guard exists to check. Either restore it or retire the guard deliberately."
        )
        return failures
    named = _WORKFLOW_POINTER.search(window)
    # Case-EXACT, by listing the directory rather than asking the filesystem to resolve a name.
    # `Path(".github/workflows/Ci.yml").is_file()` is True on macOS's case-insensitive APFS and
    # False on `ubuntu-latest`, where `ci.yml:660` actually runs this suite — so a name that only
    # differs in case would pass locally and fail in CI. The guard's own reasoning about
    # `Publish.yml` applies to both case-sensitive decisions, not just the regex.
    workflows = repo / ".github" / "workflows"
    on_disk = {q.name for q in workflows.iterdir()} if workflows.is_dir() else set()
    resolves = bool(_ISSUE_POINTER.search(window)) or bool(
        named and named.group(1) in on_disk
    )
    if not resolves:
        detail = (
            f" It names `{named.group(1)}`, which does not exist."
            if named
            else ""
        )
        failures.append(
            "the sentence saying this gap is 'deliberately NOT solved here' gives the reader "
            "nowhere to go." + detail + " Name the tracking issue (`zer07labs/seam-sdk#100`) or "
            "the workflow that closes it, in that sentence — a citation further down the block "
            "is not where anyone looks, and has twice been used to defeat this guard."
        )
    return failures


def _mutate(pointer: str, *, above: str = "", below: str = "") -> str:
    """The pre-fix paragraph with its citation replaced, plus optional decoy lines around it."""
    text = _PRE_FIX_PARAGRAPH.replace("(see the issue this job cites)", f"({pointer})")
    if above:
        text = text.replace("  # NOTE the blind spot", f"  # {above}\n  # NOTE the blind spot", 1)
    if below:
        text = text.replace("  release-outcome:", f"  #\n  # {below}\n  release-outcome:", 1)
    return text


def test_the_blind_spot_comment_points_at_a_real_issue() -> None:
    """The paragraph above `release-outcome` promised a citation it did not contain.

    It ended "it is deliberately NOT solved here (see the issue this job cites)" while the job
    body cited no issue number, no URL and no repo reference anywhere. A reader following that
    sentence had nowhere to go, and the scheduled check it describes had no tracking link.

    This is the one guard in this file that asserts on COMMENT text, inverting
    `test_yank_gate.py:51-62`'s rule that static assertions must strip comments first. That rule
    exists because a comment can accidentally satisfy a guard aimed at code. Here the comment IS
    the subject — it makes a promise to the reader — so reading raw text is correct rather than
    sloppy. Said here because the next reader will have the other rule in mind.
    """
    assert _blind_spot_failures(PUBLISH.read_text(), JOB, REPO) == []


def test_the_pointer_guard_fires_on_the_text_it_replaced() -> None:
    """Red-first: the guard, run over the literal text this phase replaced, must fail."""
    failures = _blind_spot_failures(_PRE_FIX_PARAGRAPH, JOB, REPO)
    assert any("nowhere to go" in f for f in failures), (
        f"the text this phase replaced no longer fails for the missing pointer — got {failures}. "
        "Either a pattern grew too loose or the fixture was edited."
    )


@pytest.mark.parametrize(
    ("text", "why"),
    [
        (_mutate("#100"), "a bare hash number is also a colour hex and a markdown heading"),
        (_mutate("#123456"), "a six-digit colour hex"),
        (_mutate("see grpc/grpc#100"), "an issue in a different project entirely"),
        (_mutate(".github/workflows/publish.yml"), "the file the comment is written in"),
        (_mutate(".github/workflows/Publish.yml"), "the same self-reference, differently cased"),
        (_mutate(".github/workflows/nope.yml"), "a workflow that was never merged"),
        (_mutate("see #69"), "a PR reference"),
        (
            _mutate("", above="v0.7.69 (see #69) was refused"),
            "a decoy ABOVE the paragraph — defeat #1 of this guard",
        ),
        (
            _mutate("", below="the same shape is used by .github/workflows/ci.yml"),
            "a decoy BELOW the paragraph — defeat #3, downward growth",
        ),
        (
            _mutate("", above="NOTE the blind spot notes below; see .github/workflows/ci.yml"),
            "a duplicate marker re-widening the scope — defeat #4",
        ),
    ],
    ids=[
        "bare-hash",
        "colour-hex",
        "foreign-repo",
        "self-reference",
        "self-reference-cased",
        "dead-path",
        "pr-ref",
        "decoy-above",
        "decoy-below",
        "duplicate-marker",
    ],
)
def test_the_guard_rejects_pointers_that_go_nowhere(text: str, why: str) -> None:
    """Every one of these defeated some draft of this guard. They are pinned as a set.

    Three came from the first review round (the pattern was unqualified), three more from the
    second (the paragraph was unbounded below, and the case-sensitive lookahead disagreed with
    macOS's filesystem). A guard broken twice by the same manoeuvre earns a regression set.
    """
    assert _blind_spot_failures(text, JOB, REPO), (
        f"the guard accepted this text, but {why}. A reader following it lands nowhere, which is "
        "the defect this guard exists to prevent."
    )


#: Fixtures in which exactly ONE clause of the guard is the reason for failure. A fixture that
#: fails for two reasons cannot prove either clause is load-bearing: delete one and the other
#: still reddens the test. Four clauses survived deletion against the first fixture set for
#: precisely that reason, so each of these gives its clause nothing to hide behind.
_GOOD = "it is deliberately NOT solved here — see zer07labs/seam-sdk#100."
_SUBJECT = "A publish that never ran at all is the gap."


def _block(*lines: str) -> str:
    """A synthetic comment block above the job key, from bare paragraph text."""
    body = "\n".join(f"  # {ln}" if ln else "  #" for ln in lines)
    return f"{body}\n  release-outcome:\n    name: report a release that did not publish\n"


@pytest.mark.parametrize(
    ("text", "clause"),
    [
        # No sentinel in the paragraph; pointer is valid. Only the sentinel clause can fail.
        (_block(f"NOTE the blind spot is real. {_GOOD}"), "sentinel"),
        # Sentinel present, but only BELOW the paragraph break — reachable if the paragraph is
        # not bounded downward, which is what the scope bound exists to prevent.
        (_block(f"NOTE the blind spot is real. {_GOOD}", "", _SUBJECT), "paragraph-scope"),
        # Promise sentence is COMPLETE and pointerless; the citation sits on the next line. Only
        # the sentence-window rule rejects this.
        (
            _block(
                f"NOTE the blind spot. {_SUBJECT} It is deliberately NOT solved here.",
                "the same shape is used by .github/workflows/ci.yml",
            ),
            "sentence-window",
        ),
        # A valid paragraph followed by a second marker. Only the uniqueness clause fires.
        (_block(f"NOTE the blind spot. {_SUBJECT} {_GOOD}", "", "NOTE the blind spot, later"),
         "marker-uniqueness"),
        # Two promises, only the first cited. `next()` never examines the second.
        (_block(f"NOTE the blind spot. {_SUBJECT} {_GOOD}", "", "Also NOT solved here."),
         "promise-uniqueness"),
        # An existing workflow named with the wrong case. APFS resolves it; ubuntu-latest, where
        # this suite is authoritative, does not.
        (_block(f"NOTE the blind spot. {_SUBJECT} It is NOT solved here — see "
                ".github/workflows/YANK.yml."), "case-exact-existence"),
        (_PRE_FIX_PARAGRAPH.replace("NOTE the blind spot", "A note on the gap"), "marker"),
        (_PRE_FIX_PARAGRAPH.replace("NOT solved here", "left for later"), "promise"),
        (_PRE_FIX_PARAGRAPH.replace("release-outcome:", "other-job:"), "anchor"),
    ],
    ids=[
        "sentinel",
        "paragraph-scope",
        "sentence-window",
        "marker-uniqueness",
        "promise-uniqueness",
        "case-exact-existence",
        "marker",
        "promise",
        "anchor",
    ],
)
def test_every_clause_of_the_guard_is_exercised_failing(text: str, clause: str) -> None:
    """Mutation coverage: each clause must be the sole reason some fixture fails.

    Without this, a clause can be deleted outright and the suite stays green — which was true of
    the sentinel and anti-vacuity clauses in the previous draft, because every fixture in the
    file happened to satisfy them. A clause no test can observe failing is decoration.
    """
    assert _blind_spot_failures(text, JOB, REPO), (
        f"gutting the {clause} left the guard green, so that clause could be deleted and nothing "
        "would notice. Add a fixture that isolates it."
    )


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        (_block(f"A note on the gap. {_SUBJECT} {_GOOD}"), _NOTE_MARKER),
        (_PRE_FIX_PARAGRAPH.replace("release-outcome:", "other-job:"), "renamed or deleted"),
    ],
    ids=["paragraph-absent", "job-absent"],
)
def test_the_vacuity_paths_report_their_own_cause(text: str, needle: str) -> None:
    """The two structural clauses fail SAFE, so they need their message pinned, not their verdict.

    Deleting `if not para` or `if not block` does not let a defect through — with the paragraph
    empty the sentinel clause fires anyway, so the guard still goes red. What is lost is the
    diagnosis: "the paragraph was deleted or reworded" degrades into "the paragraph no longer
    says what it is about", which sends the reader looking for the wrong thing.

    That makes these clauses diagnostics rather than gates, and a diagnostic is tested by its
    output. Distinguished here from the clauses above, whose deletion is fail-OPEN and which are
    therefore pinned by verdict.
    """
    failures = _blind_spot_failures(text, JOB, REPO)
    assert any(needle in f for f in failures), (
        f"expected a failure naming {needle!r}, got {failures}. The guard still fails closed, but "
        "it now misdiagnoses the cause."
    )


@pytest.mark.parametrize(
    "ending",
    [".", "!", "?", ".)", '."', "…", "。", "`", ")", "", " ", ".'", ".]", "?)", "!»", ".*"],
    ids=lambda e: f"ends-{e!r}",
)
def test_no_line_ending_lets_the_next_line_supply_the_citation(ending: str) -> None:
    """The defeat class that survived three review rounds, closed by construction.

    Drafts 1-3 each drew the boundary somewhere generous and were defeated by a decoy just inside
    it. Draft 3 extended the promise line onto the next one when it did not end in `.`, `!` or
    `?` — so `.)`, `."`, `…` and `。` were misread as unfinished sentences and absorbed whatever
    followed. The verdict on a deleted citation turned on one character of prose.

    The window is now the promise LINE, so no ending can widen it. This parametrization exists to
    keep it that way: it is not testing sixteen behaviours, it is testing that there are not
    sixteen behaviours.
    """
    text = _block(
        f"NOTE the blind spot. {_SUBJECT} It is deliberately NOT solved here{ending}",
        "the same shape is used by .github/workflows/ci.yml",
    )
    assert _blind_spot_failures(text, JOB, REPO), (
        f"a promise line ending {ending!r} absorbed the citation on the line below it. The "
        "window was widened, or a punctuation heuristic came back."
    )
