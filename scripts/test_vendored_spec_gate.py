"""`check_vendored_spec.py` is the only thing standing between a vendored copy and silent drift.

So it gets the same treatment the copy itself now gets: every guard is driven RED, not read. A
gate whose logic is only reviewed and never executed is how the ordering bug in
`release-on-runtime.yml` survived a day, and how the vendored spec went stale three times under a
header that asserted it was verbatim.

These build **real git repositories** in `tmp_path` rather than mocking `git`. Ancestry, merges,
deleted branches and force-pushes are the whole subject matter here, and a mock of them would only
ever assert my model of git — which is precisely the thing that could be wrong. The upstream repo
is cloned so `origin/<branch>` refs exist, because that is what the local backend reads.

The GitHub backend gets a stubbed `gh` instead (there is no real API to build in a tmpdir), narrow
by design: it pins the request shapes and the `--from gh` wiring, and leaves the semantics to the
git-backed cases above.

Run: `python -m pytest scripts/test_vendored_spec_gate.py -q`
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_vendored_spec.py"


def _load():
    """Load the checker by path — `scripts/` is not a package, so a plain import will not find it.

    Registering in `sys.modules` before executing is not optional: `@dataclass` resolves its field
    annotations through `sys.modules[cls.__module__]`, and an unregistered module makes that lookup
    return None.
    """
    spec = importlib.util.spec_from_file_location("check_vendored_spec", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mod = _load()

SPEC_V1 = "# spec\n\nbody, revision one.\n"
SPEC_V2 = "# spec\n\nbody, revision two — the runtime moved.\n"

HEADER = "<!-- Pinned copy of up/spec.md @ {sha}{tracking} (why this exists) -->"


# ── fixtures: a real upstream, and a real clone of it ──────────────────────────────────────────


def _git(where: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(where), *args], capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


class Upstream:
    """A throwaway `seam-runtime` stand-in, plus a clone to read it through."""

    def __init__(self, root: Path) -> None:
        self.origin = root / "origin"
        self.origin.mkdir()
        _git(self.origin, "init", "-q", "-b", "main")
        _git(self.origin, "config", "user.email", "t@t")
        _git(self.origin, "config", "user.name", "t")
        self.commit(SPEC_V1, "initial spec")
        self.clone = root / "clone"
        subprocess.run(
            ["git", "clone", "-q", str(self.origin), str(self.clone)],
            capture_output=True,
            check=True,
        )

    def commit(self, spec: str, message: str) -> str:
        (self.origin / "spec.md").write_text(spec)
        _git(self.origin, "add", "spec.md")
        _git(self.origin, "commit", "-q", "-m", message)
        return _git(self.origin, "rev-parse", "HEAD")

    def branch(self, name: str) -> None:
        _git(self.origin, "checkout", "-q", "-b", name)

    def checkout(self, name: str) -> None:
        _git(self.origin, "checkout", "-q", name)

    def merge(self, name: str) -> None:
        _git(self.origin, "merge", "-q", "--no-ff", "-m", f"merge {name}", name)

    def squash_merge(self, name: str) -> None:
        """How seam-runtime actually merges — and the case the ancestry arm cannot see."""
        _git(self.origin, "merge", "-q", "--squash", name)
        _git(self.origin, "commit", "-q", "-m", f"squash {name}")

    def delete_branch(self, name: str) -> None:
        _git(self.origin, "branch", "-q", "-D", name)

    def refresh(self) -> None:
        """What a developer's `git fetch` does — and what a stale checkout has NOT done."""
        subprocess.run(
            ["git", "-C", str(self.clone), "fetch", "-q", "--prune", "origin"],
            capture_output=True,
            check=True,
        )

    def head(self) -> str:
        return _git(self.origin, "rev-parse", "HEAD")


@pytest.fixture()
def world(tmp_path, monkeypatch):
    """A vendored copy in a fake repo root, an upstream, and the module pointed at both."""
    root = tmp_path / "sdk"
    root.mkdir()
    up = Upstream(tmp_path)
    up.refresh()

    monkeypatch.setattr(mod, "REPO", root)
    monkeypatch.setattr(
        mod,
        "VENDORED",
        (mod.Vendored(local="doc.md", repo="org/up", remote="spec.md"),),
    )
    return root, up


def write_copy(root: Path, sha: str, body: str, *, tracking: str = "", sep: str = "\n\n") -> None:
    head = HEADER.format(sha=sha[:7], tracking=f" tracking {tracking}" if tracking else "")
    (root / "doc.md").write_text(head + sep + body)


def run(up: Upstream, capsys) -> tuple[int, str]:
    code = mod.main(["--from", f"local:{up.clone}"])
    return code, capsys.readouterr().out


# ── the green case, so every red below means something ─────────────────────────────────────────


def test_a_verbatim_current_copy_passes(world, capsys) -> None:
    root, up = world
    write_copy(root, up.head(), SPEC_V1)
    code, out = run(up, capsys)
    assert code == 0, out
    assert "OK" in out
    assert "::error::" not in out


# ── CURRENCY ───────────────────────────────────────────────────────────────────────────────────


def test_a_stale_copy_is_red(world, capsys) -> None:
    """The failure that actually happened, three times, under a header claiming verbatim."""
    root, up = world
    pinned = up.head()
    write_copy(root, pinned, SPEC_V1)
    up.commit(SPEC_V2, "the runtime moves")
    up.refresh()

    code, out = run(up, capsys)
    assert code == 1
    assert "CURRENCY" in out and "STALE" in out
    # The message has to be actionable on its own — a red that does not say what to copy from
    # where is how a mechanical fix turns into an investigation.
    assert "re-copy" in out
    assert "revision two" in out, "the diff must show what changed, not just that something did"


def test_a_lagging_pin_with_identical_content_is_a_notice_not_a_failure(world, capsys) -> None:
    """The header's claim is still TRUE — the content matches. Failing here would train people to
    ignore this gate, which costs more than the cosmetic lag it would be reporting."""
    root, up = world
    pinned = up.head()
    write_copy(root, pinned, SPEC_V1)
    # Edited and reverted upstream: the newest commit touching the path is now well past the pin,
    # while the bytes at that commit are exactly the pinned bytes.
    up.commit(SPEC_V2, "a change")
    up.commit(SPEC_V1, "…and its revert")
    up.refresh()

    code, out = run(up, capsys)
    assert code == 0, out
    assert "::notice::" in out and "re-pin at your convenience" in out


# ── INTEGRITY ──────────────────────────────────────────────────────────────────────────────────


def test_a_copy_edited_in_place_is_red(world, capsys) -> None:
    """The header names a commit; the body is not that commit's bytes. The header is lying."""
    root, up = world
    write_copy(root, up.head(), SPEC_V1.replace("revision one", "revision one, but tweaked here"))
    code, out = run(up, capsys)
    assert code == 1
    assert "INTEGRITY" in out and "NOT verbatim" in out


def test_repinning_without_recopying_is_red(world, capsys) -> None:
    """The subtler half of the same guard: the sha is bumped, the body is not refreshed. This is
    the mistake a hurried 'fix the gate' produces, so it must not be the thing that satisfies it."""
    root, up = world
    up.commit(SPEC_V2, "the runtime moves")
    up.refresh()
    write_copy(root, up.head(), SPEC_V1)  # new sha, old body

    code, out = run(up, capsys)
    assert code == 1
    assert "INTEGRITY" in out


# ── REACHABILITY ───────────────────────────────────────────────────────────────────────────────


def test_a_stale_local_view_refuses_to_issue_a_verdict(world, capsys) -> None:
    """A checkout whose fetch predates the pin must NOT report the copy as stale.

    This is not hypothetical — it is what the local backend did the first time it was run against
    a real sibling checkout, and it produced a confident, actionable, wrong red. A verdict from a
    stale view is worse than no verdict.
    """
    root, up = world
    newer = up.commit(SPEC_V2, "a commit the clone has never fetched")
    write_copy(root, newer, SPEC_V2)  # the copy is CORRECT and current…

    code, out = run(up, capsys)  # …but the clone was never refreshed
    assert code == 1
    assert "not reachable" in out
    assert "git fetch" in out, "the message must name the actual remedy"
    assert "CURRENCY" not in out, "it must not accuse a current copy of being stale"


# ── the tracking exception, and its expiry ─────────────────────────────────────────────────────


def test_tracking_an_unmerged_branch_passes_with_a_notice(world, capsys) -> None:
    """Today's real state: the copy documents v3, whose spec text is on an unmerged runtime branch."""
    root, up = world
    up.branch("feat/x")
    sha = up.commit(SPEC_V2, "spec text that main does not have yet")
    up.checkout("main")
    up.refresh()
    write_copy(root, sha, SPEC_V2, tracking="feat/x")

    code, out = run(up, capsys)
    assert code == 0, out
    assert "::notice::" in out and "unmerged branch" in out


def test_an_undeclared_branch_pin_is_red(world, capsys) -> None:
    """Being ahead of the default branch is allowed. Being ahead of it *silently* is not — that is
    exactly the state this repo was in, with nothing recording it."""
    root, up = world
    up.branch("feat/x")
    sha = up.commit(SPEC_V2, "off-main spec text")
    up.checkout("main")
    up.refresh()
    write_copy(root, sha, SPEC_V2)  # no `tracking` in the header

    code, out = run(up, capsys)
    assert code == 1
    assert "not reachable" in out


def test_tracking_ends_itself_once_the_branch_lands(world, capsys) -> None:
    """The expiry that keeps the exception from outliving its reason.

    Without this the declaration is written once and never revisited: currency stays measured
    against a feature branch forever, and the copy drifts from the published contract with nothing
    objecting.
    """
    root, up = world
    up.branch("feat/x")
    sha = up.commit(SPEC_V2, "spec text")
    up.checkout("main")
    up.merge("feat/x")
    up.refresh()
    write_copy(root, sha, SPEC_V2, tracking="feat/x")

    code, out = run(up, capsys)
    assert code == 1
    assert "has landed on main" in out
    assert "delete `tracking" in out


def test_tracking_ends_itself_on_a_squash_merge_even_if_the_branch_survives(
    world, capsys
) -> None:
    """The arm that ancestry alone cannot provide — and the common case, not the exotic one.

    A squash merge never puts the pinned sha on the default branch, so `contains(default, pin)` is
    False forever. If the branch is not also deleted, the two other expiry arms both stay silent
    and the declaration tracks a zombie branch while the published contract moves — precisely the
    failure the declaration exists to prevent. seam-runtime squash merges; the first real expiry
    fired only because the branch happened to be auto-deleted as well.

    So the third arm keys on content, which no merge strategy can hide.
    """
    root, up = world
    up.branch("feat/x")
    sha = up.commit(SPEC_V2, "spec text")
    up.checkout("main")
    up.squash_merge("feat/x")  # branch deliberately NOT deleted
    up.refresh()
    write_copy(root, sha, SPEC_V2, tracking="feat/x")

    code, out = run(up, capsys)
    assert code == 1
    assert "byte-identical" in out
    assert "squash" in out
    # The two older arms must genuinely be silent here, or this test proves nothing about the new
    # one: the branch still exists, and the pinned sha is still not an ancestor of main.
    assert "no such branch" not in out
    assert "has landed on" not in out


def test_tracking_a_branch_that_no_longer_exists_is_red(world, capsys) -> None:
    """Merged-and-deleted, force-pushed away, or renamed — the header now names nothing."""
    root, up = world
    up.branch("feat/x")
    sha = up.commit(SPEC_V2, "spec text")
    up.checkout("main")
    up.refresh()
    up.delete_branch("feat/x")
    up.refresh()
    write_copy(root, sha, SPEC_V2, tracking="feat/x")

    code, out = run(up, capsys)
    assert code == 1
    assert "no such branch" in out


# ── the header itself ──────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("first_line", "expect"),
    [
        ("# spec\n", "does not start with a pin header"),
        ("<!-- Pinned copy of up/spec.md @ nothexsha (x) -->", "cannot read a pin"),
        ("<!-- Pinned copy of up/spec.md (x) -->", "cannot read a pin"),
        ("<!-- Pinned copy of up/spec.md @ abc (x) -->", "cannot read a pin"),  # too short
        ("<!-- Pinned copy of up/spec.md @ 1234567 (x)", "never closed"),
        ("<!-- Pinned copy of OTHER/spec.md @ 1234567 (x) -->", "says it copies"),
    ],
    ids=["no-header", "non-hex", "no-sha", "sha-too-short", "unclosed", "wrong-path"],
)
def test_a_header_that_cannot_be_trusted_is_red(world, capsys, first_line, expect) -> None:
    """Every one of these would otherwise turn the gate into a green no-op — the same defect as
    the stale copy it exists to catch, just quieter. So none of them may be a skip."""
    root, up = world
    (root / "doc.md").write_text(first_line + "\n\n" + SPEC_V1)
    code, out = run(up, capsys)
    assert code == 1
    assert expect in out


def test_a_missing_blank_line_after_the_header_is_red(world, capsys) -> None:
    """The body is compared byte-for-byte, so the separator is structure, not whitespace taste."""
    root, up = world
    write_copy(root, up.head(), SPEC_V1, sep="\n")
    code, out = run(up, capsys)
    assert code == 1
    assert "exactly one blank line" in out


def test_an_extra_blank_line_is_caught_as_a_body_difference(world, capsys) -> None:
    """It is red, but as INTEGRITY rather than as a separator complaint — and that is the honest
    verdict, not a shortcoming.

    `-->\n\n\n# spec` is genuinely ambiguous: nothing distinguishes "the separator is two blank
    lines" from "the upstream file begins with a blank line". Rather than guess, the parser takes
    the first `\n\n` as the separator and lets everything after it be the body — so an extra blank
    line becomes a leading blank line in the body, and the byte comparison against upstream catches
    it with a diff that shows exactly the stray line. Guessing would mean normalising, and a
    normalising comparison is one that can be argued with.
    """
    root, up = world
    write_copy(root, up.head(), SPEC_V1, sep="\n\n\n")
    code, out = run(up, capsys)
    assert code == 1
    assert "INTEGRITY" in out


def test_a_missing_registered_copy_is_red(world, capsys) -> None:
    root, _up = world
    code, out = run(_up, capsys)
    assert code == 1
    assert "does not exist" in out


# ── guard the guard ────────────────────────────────────────────────────────────────────────────


def test_an_empty_registry_is_red(world, capsys, monkeypatch) -> None:
    """An empty `VENDORED` would exit 0 having checked nothing — green, and meaningless."""
    _root, up = world
    monkeypatch.setattr(mod, "VENDORED", ())
    code, out = run(up, capsys)
    assert code == 1
    assert "checking nothing" in out


def test_an_empty_upstream_file_is_refused_rather_than_compared(world, capsys) -> None:
    """Comparing against nothing would be a verdict about the fetch, not about the copy."""
    root, up = world
    sha = up.commit("", "truncate the spec upstream")
    up.refresh()
    write_copy(root, sha, "")
    code, out = run(up, capsys)
    assert code == 1
    assert "came back empty" in out


def test_an_unknown_backend_is_red(capsys) -> None:
    assert mod.main(["--from", "carrier-pigeon"]) == 1
    assert "unknown --from" in capsys.readouterr().out


# ── the GitHub backend, and the wiring that runs it ────────────────────────────────────────────


def _stub_gh(tmp_path: Path, spec_body: str, *, default: str = "main") -> Path:
    """A `gh` that answers the calls the GitHub backend makes, keyed by URL shape.

    Narrow, and worth being explicit about what it does and does not prove. It asserts the one URL
    detail that would silently corrupt a verdict — a `contents` request with no `?ref=` reads the
    default branch whatever commit you meant, so INTEGRITY would compare the pin against the wrong
    file and could pass. Beyond that it is a wildcard: it does not pin exact paths or query
    ordering, so it would not catch a merely misspelled endpoint. Those semantics are covered by
    the git-backed cases above, against a real git.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "gh").write_text(
        textwrap.dedent(f"""\
        #!/usr/bin/env bash
        # `gh api <url> …` — the URL is the second word, not the third.
        url="$2"
        case "$url" in
          */compare/*)   echo "behind" ;;
          */contents/*\\?ref=*)  cat {tmp_path / "payload.md"} ;;
          */contents/*)  echo "stub: contents request with no ?ref= — that silently reads the default branch" >&2; exit 3 ;;
          */branches/*)  echo "{default}" ;;
          */commits\\?*)  echo "1234567890abcdef1234567890abcdef12345678" ;;
          *)             echo "{default}" ;;
        esac
        """)
    )
    (bin_dir / "gh").chmod(0o755)
    (tmp_path / "payload.md").write_text(spec_body)
    return bin_dir


def test_the_github_backend_reads_a_matching_copy_as_green(tmp_path, monkeypatch, capsys) -> None:
    root = tmp_path / "sdk"
    root.mkdir()
    bin_dir = _stub_gh(tmp_path, SPEC_V1)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    monkeypatch.setattr(mod, "REPO", root)
    monkeypatch.setattr(
        mod, "VENDORED", (mod.Vendored(local="doc.md", repo="org/up", remote="spec.md"),)
    )
    write_copy(root, "1234567", SPEC_V1)

    assert mod.main(["--from", "gh"]) == 0
    out = capsys.readouterr().out
    assert "github api" in out


def test_the_github_backend_reddens_on_drift(tmp_path, monkeypatch, capsys) -> None:
    root = tmp_path / "sdk"
    root.mkdir()
    bin_dir = _stub_gh(tmp_path, SPEC_V2)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    monkeypatch.setattr(mod, "REPO", root)
    monkeypatch.setattr(
        mod, "VENDORED", (mod.Vendored(local="doc.md", repo="org/up", remote="spec.md"),)
    )
    write_copy(root, "1234567", SPEC_V1)

    assert mod.main(["--from", "gh"]) == 1
    assert "INTEGRITY" in capsys.readouterr().out


# ── the gate has to actually be wired into CI ──────────────────────────────────────────────────


def test_ci_runs_this_gate_against_the_real_api() -> None:
    """A checker nothing invokes is a file, not a gate.

    Pinned deliberately to `--from gh`: the local backend is only as current as someone's last
    `git fetch`, so a CI job quietly switched to it would keep reporting green against a view that
    had stopped moving — passing vacuously, which is the same defect as no gate at all.
    """
    workflow = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    jobs = workflow["jobs"]
    assert "spec-pin" in jobs, (
        "the `spec-pin` job is gone or renamed. It is the only place anything proves the vendored "
        "spec matches seam-runtime — nothing in this repo can prove it, because the proof lives "
        "in another repository."
    )
    body = yaml.safe_dump(jobs["spec-pin"])
    assert "check_vendored_spec.py" in body
    assert "--from gh" in body, (
        "spec-pin must use the GitHub API. `--from local:` depends on a fetch CI never performs."
    )
    # seam-runtime is private, so github.token cannot read it. The App token must be minted AND
    # scoped: an unscoped App token would reach every repo the App is installed on, for a job that
    # reads one file.
    assert "create-github-app-token" in body, (
        "spec-pin no longer mints an App token. seam-runtime is private and github.token is scoped "
        "to this repo, so the job would 404 and go red for a reason unrelated to the spec."
    )
    assert "SEAM_BOT_APP_ID" in body and "SEAM_BOT_PRIVATE_KEY" in body
    assert "repositories: seam-runtime" in body, (
        "the App token must be scoped to seam-runtime alone — this job reads one file"
    )
    assert "spec-pin" in yaml.safe_dump(jobs["ci-ok"]["needs"]), (
        "spec-pin is not in ci-ok's needs, so it can fail while the required check reports success"
    )


def test_the_vendored_copy_this_repo_actually_ships_parses() -> None:
    """The real file, through the real parser — no fixtures.

    Every case above runs against synthetic copies, so all of them could pass while the one file
    that ships is unparseable. This is cheap and needs no network: it proves the header shipped in
    this repo is one the gate can read, leaving only the comparison itself to CI.
    """
    for v in mod.VENDORED:
        head = mod.split_header(REPO / v.local)
        assert head.declared == v.declared
        assert len(head.sha) >= 7
        assert head.body, f"{v.local} has a header but no body"
