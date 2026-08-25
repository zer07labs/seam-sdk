#!/usr/bin/env python3
"""A vendored spec copy claims to be verbatim. This is what makes that claim checkable.

`verify/docs/seam-event.v1.md` opens by declaring itself a pinned copy of the runtime's
`docs/specs/seam-event.v1.md` at a named commit. Until this script existed, nothing checked it —
and it had gone stale three separate times:

  1. it omitted the `AUTHORIZE_EVALUATED` advisory kind, which shipped a real verifier bug;
  2. it carried no `§Record digest (v3)` while `src/verify.rs` implemented v3;
  3. it carried no `§"Presence on the wire"` while every new code comment cited that section as
     its authority.

Every one of those was found by a person or a review gate. None was found by a test, because
**no test could be**: nothing inside this repository can prove a file here matches a file in
another repository. The proof needs the other repository, and this is the only place in CI that
goes and gets it.

That matters more than tidiness. This copy is what a third party builds a verifier from when they
have no `seam-runtime` checkout — which is the entire independence claim. A stale copy hands them
a spec that does not describe the verifier they are running.

## What is checked

**INTEGRITY** — the body is byte-identical to the upstream file *at the commit the header names*.
If this fails the header is lying: the copy was edited in place, or re-pinned without being
re-copied. That is a defect in this repository, always.

**REACHABILITY** — the pinned commit is actually reachable from the ref the header says it tracks.
Without this, a stale local `git fetch` resolves the tracked branch to something *older* than the
pin, and the currency check below then fires confidently in the wrong direction — accusing a
current copy of being stale against an ancestor of itself. A verdict computed from a stale view is
worse than no verdict, because it is actionable and wrong.

**CURRENCY** — the body is byte-identical to the upstream file at the tip of the tracked ref. If
this fails the copy is stale. That is not a defect in whichever pull request happens to be in
flight; it is a task. It fails anyway, by owner decision, because the alternative is a warning
that scrolls past — and a warning nobody acts on is how all three stalenesses above survived. The
remedy is mechanical and the error message spells it out.

A pin whose sha lags while the *content* still matches is none of the above: the header's claim is
still true. That gets a notice, not a failure.

## Tracking an unmerged runtime branch

A copy may deliberately sit ahead of the runtime's default branch. That is the real state today:
`seam-sdk/verify` implements the v3 record digest, and the spec text defining v3 lives on an
unmerged `seam-runtime` branch. Pinning to the default branch instead would produce a copy that
does not document the verifier this repo actually ships — which is worse than being ahead.

So it is allowed, and it must be **declared** in the header:

    <!-- Pinned copy of seam-runtime/docs/specs/seam-event.v1.md @ dde87c8 tracking feat/b3-phase3 …

An undeclared branch pin is refused. A declared one is checked for currency against that branch's
tip like any other, and the exception is made **self-terminating** by three independent arms, because
no one of them covers every way a branch stops mattering:

  * the branch stops existing (merged-and-deleted, force-pushed away, renamed);
  * the pinned commit becomes reachable from the default branch (a merge-commit merge);
  * the file becomes byte-identical on both refs — which is what catches a **squash or rebase
    merge**, where the pinned sha never appears on the default branch at all and the ancestry arm
    alone would let the declaration outlive its branch indefinitely.

Without all three, a tracking note written once quietly outlives the branch it names, and the copy
drifts from the published contract with nothing objecting.

## Backends

  * `--from gh` — the GitHub API, authenticated by `GH_TOKEN`. THE authoritative backend, and the
    one CI uses; `seam-runtime` is private, so this needs a token that can read it — in CI, a
    short-lived seam-deps-bot App token scoped to that repo.
  * `--from local:<dir>` — a sibling checkout, via `git show`. A convenience for running this
    before pushing. It is only as current as the last `git fetch`, which is why CI does not use
    it, and why REACHABILITY exists.

Exit status is the gate: 0 clean, 1 on any failure. Run:

    python scripts/check_vendored_spec.py                 # auto-detect a backend
    python scripts/check_vendored_spec.py --from gh
    python scripts/check_vendored_spec.py --from local:../seam-runtime
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

#: The first line of a vendored copy, and the only place its provenance is recorded.
#:
#: Strict on purpose. A header that stops matching this is a hard failure rather than a skip: a
#: loose parse that silently matched nothing would turn this whole script into a green no-op,
#: which is the same defect as the stale copy it exists to catch, just quieter.
PIN = re.compile(
    rb"^<!-- Pinned copy of (?P<path>[\w./-]+) @ (?P<sha>[0-9a-f]{7,40})"
    rb"(?: tracking (?P<branch>[\w./-]+))?(?![\w./-])",
)


@dataclass(frozen=True)
class Vendored:
    """One vendored copy: where it lives here, and what it claims to be a copy of."""

    #: Path in THIS repo, relative to the repo root.
    local: str
    #: `owner/repo` the original lives in.
    repo: str
    #: Path to the original within that repo.
    remote: str

    @property
    def declared(self) -> str:
        """What the header must say it copies — `<repo-name>/<remote path>`.

        Held here as well as in the file's own header so the two must agree. The duplication is
        the point: a value stored twice can disagree with itself, and the disagreement is the
        signal that someone repointed one of them alone.
        """
        return f"{self.repo.split('/')[1]}/{self.remote}"


#: Every vendored copy in this repository. `verify/docs/` also holds `audit-anchor.md` and
#: `erasure-certificate.v1.md` — those are NOT here, deliberately: they were authored in this repo
#: and carry no pin header, so there is no upstream to compare them against.
VENDORED = (
    Vendored(
        local="verify/docs/seam-event.v1.md",
        repo="zer07labs/seam-runtime",
        remote="docs/specs/seam-event.v1.md",
    ),
)


class Failure(Exception):
    """A check that failed. The message is written for whoever has to fix it."""


# ── reading the vendored copy ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Header:
    declared: str
    sha: str
    branch: str | None
    body: bytes


def split_header(path: Path) -> Header:
    """Parse a vendored copy into its pin header and its body bytes.

    The structure asserted here is `<!-- … -->\\n\\n<upstream bytes>`: a leading HTML comment, one
    blank line, then the original file unmodified to the last byte. The separator is required, not
    merely tolerated — that is what makes "the body IS the upstream file" a statement about bytes
    rather than about intent.

    Where it deliberately does not guess: `-->\\n\\n\\n# spec` is ambiguous, because nothing
    distinguishes "the separator is two blank lines" from "the upstream file begins with a blank
    line". The first `\\n\\n` is taken as the separator and everything after it is body, so a stray
    blank line lands in the body and INTEGRITY catches it with a diff pointing straight at it.
    Resolving the ambiguity by stripping would mean normalising, and a normalising comparison is
    one that can be argued with.
    """
    rel = path.relative_to(REPO)
    data = path.read_bytes()

    if not data.startswith(b"<!--"):
        raise Failure(
            f"{rel} does not start with a pin header. Every vendored copy must open with "
            f"`<!-- Pinned copy of <repo>/<path> @ <sha> … -->` — that header is the only record "
            f"of what it is a copy of, and without it nothing here can be checked."
        )

    close = data.find(b"-->")
    if close < 0:
        raise Failure(
            f"{rel} opens a `<!--` comment that is never closed. The header must end with `-->`, "
            f"followed by one blank line, then the upstream file verbatim."
        )

    m = PIN.match(data)
    if not m:
        first = data.split(b"\n", 1)[0].decode("utf-8", "replace")
        raise Failure(
            f"{rel}: cannot read a pin out of the first line.\n"
            f"  got:    {first}\n"
            f"  wanted: <!-- Pinned copy of <repo>/<path> @ <sha> [tracking <branch>] …\n"
            f"The sha must be 7-40 lowercase hex. This is a hard failure and not a skip on "
            f"purpose: a header this cannot parse is a copy that nothing can verify."
        )

    rest = data[close + len(b"-->") :]
    if not rest.startswith(b"\n\n"):
        raise Failure(
            f"{rel}: the pin header must be followed by exactly one blank line and then the "
            f"upstream file. Got {rest[:20]!r} instead. The body is compared byte-for-byte, so "
            f"the separator has to be fixed rather than tolerated."
        )

    branch = m.group("branch")
    return Header(
        declared=m.group("path").decode(),
        sha=m.group("sha").decode(),
        branch=branch.decode() if branch else None,
        body=rest[2:],
    )


# ── reaching the upstream repository ───────────────────────────────────────────────────────────


def _run(cmd: list[str]) -> bytes:
    proc = subprocess.run(cmd, capture_output=True, check=False)
    if proc.returncode != 0:
        raise Failure(
            f"`{' '.join(cmd[:4])} …` failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return proc.stdout


class Source:
    """Where upstream bytes come from.

    Branch names crossing this interface are always *logical* (`main`, `feat/x`) — each backend
    maps them to whatever it needs locally. A green result is only as good as its source, so every
    backend is named and the name is printed with the verdict.
    """

    name = "?"

    def default_branch(self, repo: str) -> str: ...
    def branch_exists(self, repo: str, branch: str) -> bool: ...
    def fetch(self, repo: str, path: str, ref: str) -> bytes: ...
    def last_commit(self, repo: str, path: str, ref: str) -> str | None: ...
    def contains(self, repo: str, branch: str, sha: str) -> bool: ...


class GitHub(Source):
    """The GitHub API. Authoritative: it reads the branch as it actually is, right now."""

    name = "github api"

    def default_branch(self, repo: str) -> str:
        return _run(["gh", "api", f"repos/{repo}", "--jq", ".default_branch"]).decode().strip()

    def branch_exists(self, repo: str, branch: str) -> bool:
        try:
            _run(["gh", "api", f"repos/{repo}/branches/{branch}", "--jq", ".name"])
        except Failure:
            return False
        return True

    def fetch(self, repo: str, path: str, ref: str) -> bytes:
        return _run(
            [
                "gh",
                "api",
                f"repos/{repo}/contents/{path}?ref={ref}",
                "-H",
                "Accept: application/vnd.github.raw",
            ]
        )

    def last_commit(self, repo: str, path: str, ref: str) -> str | None:
        out = _run(
            [
                "gh",
                "api",
                f"repos/{repo}/commits?path={path}&sha={ref}&per_page=1",
                "--jq",
                ".[0].sha",
            ]
        )
        return out.decode().strip() or None

    def contains(self, repo: str, branch: str, sha: str) -> bool:
        # `identical` or `behind` both mean sha is reachable from branch; `ahead`/`diverged` mean
        # branch has never held that commit.
        status = (
            _run(["gh", "api", f"repos/{repo}/compare/{branch}...{sha}", "--jq", ".status"])
            .decode()
            .strip()
        )
        return status in {"identical", "behind"}


class LocalCheckout(Source):
    """A sibling clone, read through `git show`.

    Only as current as the last `git fetch`, so it is a pre-push convenience and never the gate.
    It reads `origin/<branch>` rather than the working tree on purpose: an uncommitted local edit
    to the runtime's spec is not something this repository should be validated against.
    """

    name = "local checkout"

    def __init__(self, directory: str) -> None:
        self.dir = Path(directory).expanduser().resolve()
        if not (self.dir / ".git").exists():
            raise Failure(f"{self.dir} is not a git checkout")

    def _git(self, *args: str) -> bytes:
        return _run(["git", "-C", str(self.dir), *args])

    def _remote(self, branch: str) -> str:
        return f"origin/{branch}"

    def default_branch(self, repo: str) -> str:
        try:
            head = self._git("symbolic-ref", "--short", "refs/remotes/origin/HEAD").decode()
            return head.strip().removeprefix("origin/")
        except Failure:
            pass
        # No `origin/HEAD` — a common state for a clone that was never `git remote set-head`-ed.
        for candidate in ("main", "master"):
            if self.branch_exists(repo, candidate):
                return candidate
        raise Failure(
            f"{self.dir}: cannot resolve a default branch. Run `git -C {self.dir} fetch origin`, "
            f"or use `--from gh`, which does not depend on a local fetch."
        )

    def branch_exists(self, repo: str, branch: str) -> bool:
        try:
            self._git("rev-parse", "--verify", "--quiet", f"{self._remote(branch)}^{{commit}}")
        except Failure:
            return False
        return True

    def _rev(self, ref: str) -> str:
        """Resolve a logical ref to something `git` can read here.

        Branch names go through `origin/`, never the local branch of the same name — a local
        `main` can sit at an entirely different commit from `origin/main`, and validating this
        repository against someone's unpushed work is exactly the wrong answer. Commit shas are
        used as-is. Resolved by asking git rather than by pattern-matching the string, because a
        branch can be legitimately named `deadbeef`.
        """
        return self._remote(ref) if self.branch_exists("", ref) else ref

    def fetch(self, repo: str, path: str, ref: str) -> bytes:
        return self._git("show", f"{self._rev(ref)}:{path}")

    def last_commit(self, repo: str, path: str, ref: str) -> str | None:
        out = self._git("log", "-1", "--format=%H", self._rev(ref), "--", path)
        return out.decode().strip() or None

    def contains(self, repo: str, branch: str, sha: str) -> bool:
        try:
            self._git("merge-base", "--is-ancestor", sha, self._remote(branch))
        except Failure:
            return False
        return True


def pick_source(spec: str | None) -> Source:
    if spec == "gh":
        return GitHub()
    if spec and spec.startswith("local:"):
        return LocalCheckout(spec.split(":", 1)[1])
    if spec:
        raise Failure(f"unknown --from {spec!r}; expected `gh` or `local:<dir>`")

    # Auto. A checkout is preferred only because it is faster and needs no token; CI passes
    # `--from gh` explicitly, so this branch never decides anything the gate depends on.
    for candidate in (os.environ.get("SEAM_RUNTIME_DIR"), str(REPO.parent / "seam-runtime")):
        if candidate and (Path(candidate).expanduser() / ".git").exists():
            return LocalCheckout(candidate)
    return GitHub()


# ── the checks ─────────────────────────────────────────────────────────────────────────────────


def _diff(want: bytes, got: bytes, want_label: str, got_label: str, limit: int = 40) -> str:
    lines = list(
        difflib.unified_diff(
            want.decode("utf-8", "replace").splitlines(),
            got.decode("utf-8", "replace").splitlines(),
            fromfile=want_label,
            tofile=got_label,
            lineterm="",
            n=1,
        )
    )
    shown = lines[:limit]
    if len(lines) > limit:
        shown.append(f"… and {len(lines) - limit} more diff lines")
    return "\n".join("    " + line for line in shown)


def _nonempty(blob: bytes, what: str, source: Source) -> bytes:
    """Guard the guard: an empty fetch would make every byte comparison a verdict about the network."""
    if not blob.strip():
        raise Failure(
            f"{what} came back empty via {source.name}. Refusing to compare against nothing — "
            f"that would be a verdict about the network, not about the copy."
        )
    return blob


def check(v: Vendored, source: Source) -> list[str]:
    """Check one vendored copy. Returns notices; raises `Failure` on anything that must go red."""
    path = REPO / v.local
    if not path.exists():
        raise Failure(f"{v.local} is registered as a vendored copy but does not exist")

    head = split_header(path)
    notices: list[str] = []

    if head.declared != v.declared:
        raise Failure(
            f"{v.local} says it copies {head.declared!r}, but this script has it registered "
            f"against {v.declared!r}. One of the two is wrong — fix whichever, in the same "
            f"change. They are kept in both places precisely so a silent repoint cannot happen."
        )

    default = source.default_branch(v.repo)
    tracked = head.branch or default

    # ── the tracking exception, and its expiry ──
    if head.branch:
        if not source.branch_exists(v.repo, head.branch):
            raise Failure(
                f"{v.local} declares `tracking {head.branch}`, but {v.repo} has no such branch "
                f"(via {source.name}). It was merged and deleted, force-pushed away, or renamed. "
                f"A tracking declaration that outlives its branch pins this copy to a commit "
                f"nobody can find from a branch name.\n"
                f"  Fix: re-copy from {v.repo}@{default} and drop `tracking {head.branch}` from "
                f"the header — or name the branch it actually moved to."
            )
        if source.contains(v.repo, default, head.sha):
            raise Failure(
                f"{v.local} declares `tracking {head.branch}`, but its pin {head.sha} has landed "
                f"on {default}. The exception has served its purpose and must now end: while it "
                f"stands, currency is measured against a feature branch instead of the published "
                f"contract, and the copy can drift from {default} with nothing objecting.\n"
                f"  Fix: re-copy from {v.repo}@{default} and delete `tracking {head.branch}` from "
                f"the header."
            )
        # The ancestry arm above is NOT sufficient, and assuming it was would have left the
        # "self-terminating" claim false in the common case. A squash or rebase merge never puts
        # the pinned sha on the default branch, so a squash-merged branch that is not also DELETED
        # slips past both arms above and tracks a zombie branch forever while the published
        # contract moves — the exact failure the declaration exists to prevent. seam-runtime squash
        # merges; the first live expiry fired only because the branch was auto-deleted too.
        #
        # So the third arm keys on CONTENT, which no merge strategy can hide: if the tracked
        # branch's copy of the file is byte-identical to the default branch's, there is nothing
        # left to be ahead about, and pinning to the default branch is strictly better because it
        # is the ref that cannot be rewritten under us.
        if source.fetch(v.repo, v.remote, head.branch) == source.fetch(v.repo, v.remote, default):
            raise Failure(
                f"{v.local} declares `tracking {head.branch}`, but {v.remote} is now byte-identical "
                f"on {head.branch} and on {default}. Whether that is a squash merge, a rebase "
                f"merge, or a branch that never diverged here, the declaration is buying nothing "
                f"and is measuring currency against a rewritable ref.\n"
                f"  Fix: re-pin to {v.repo}@{default} and delete `tracking {head.branch}` from the "
                f"header. The body does not change — only the header does."
            )
        notices.append(
            f"{v.local} tracks the unmerged branch {head.branch!r}, so it documents runtime "
            f"behaviour that is NOT yet on {default}. Deliberate — the verifier in this repo "
            f"implements it — but re-pin to {default} as soon as that branch lands; this gate "
            f"goes red when it does."
        )

    # ── REACHABILITY ──
    # BEFORE integrity, deliberately. Fetching the file at an unreachable pin fails inside git or
    # the API with its own message — `fatal: invalid object name '2648ca9'` — which says nothing
    # about what to do. Establishing that the pin is real, and reachable from the ref the header
    # names, is what turns that into an actionable red.
    if not source.contains(v.repo, tracked, head.sha):
        raise Failure(
            f"{v.local} pins {head.sha}, which is not reachable from {v.repo}@{tracked} (via "
            f"{source.name}). Two possible causes, and this refuses to guess between them:\n"
            f"  * the view is stale — a local checkout whose {tracked} predates the pin. Run "
            f"`git fetch origin` in it, or use `--from gh`, which cannot be behind.\n"
            f"  * the pin is genuinely not on that ref — it names a commit from a branch that was "
            f"never merged, or one that a force-push removed. Then the header cites a commit "
            f"nobody else can resolve, and the copy needs re-pinning to a real one.\n"
            f"No currency verdict is issued either way: comparing against a ref that does not "
            f"contain the pin would produce a confident answer to the wrong question."
        )

    # ── INTEGRITY ──
    at_pin = _nonempty(
        source.fetch(v.repo, v.remote, head.sha), f"{v.repo}@{head.sha}:{v.remote}", source
    )
    if head.body != at_pin:
        raise Failure(
            f"INTEGRITY: {v.local} is NOT verbatim at the commit it names.\n"
            f"  Its header claims {v.repo}@{head.sha}, but the body differs from that file. So "
            f"either the copy was edited in place, or it was re-pinned without being re-copied. "
            f"Either way the header is currently a false statement.\n"
            f"  Fix: re-copy the whole file, do not patch the difference —\n"
            f"    git -C <seam-runtime> show {head.sha}:{v.remote} > /tmp/spec.md\n"
            f"    # then rebuild {v.local} as: header, one blank line, /tmp/spec.md\n"
            f"{_diff(at_pin, head.body, f'{v.repo}@{head.sha}', v.local)}"
        )

    # ── CURRENCY ──
    at_head = _nonempty(
        source.fetch(v.repo, v.remote, tracked), f"{v.repo}@{tracked}:{v.remote}", source
    )
    newest = source.last_commit(v.repo, v.remote, tracked)

    if head.body != at_head:
        raise Failure(
            f"CURRENCY: {v.local} is STALE. The runtime spec has moved and this copy has not.\n"
            f"  pinned at: {head.sha}\n"
            f"  now at:    {(newest or tracked)[:7]} (on {tracked})\n"
            f"  This copy is what a third party builds a verifier from when they have no "
            f"seam-runtime checkout, so a stale copy ships them a spec that does not describe the "
            f"verifier they are running. It has gone stale three times; that is why this is red "
            f"rather than a warning.\n"
            f"  Fix (whole-file, never cherry-picked — verbatim is the property being claimed):\n"
            f"    1. re-copy {v.remote} from {v.repo}@{(newest or tracked)[:7]}\n"
            f"    2. keep the `<!-- Pinned copy … -->` header, one blank line, then the new body\n"
            f"    3. update the sha in that header to {(newest or tracked)[:7]}\n"
            f"    4. read the diff below — if it changes normative behaviour, the verifier and "
            f"its tests need the same change, not just this file\n"
            f"{_diff(at_head, head.body, f'{v.repo}@{tracked}', v.local)}"
        )

    if newest and not newest.startswith(head.sha):
        notices.append(
            f"{v.local} pins {head.sha} but {newest[:7]} is the newest commit touching "
            f"{v.remote} on {tracked}. The content is identical, so the header's claim is still "
            f"true and this is not a failure — re-pin at your convenience."
        )

    return notices


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--from",
        dest="source",
        default=None,
        help="`gh` (the API, needs GH_TOKEN) or `local:<dir>` (a sibling checkout)",
    )
    args = ap.parse_args(argv)

    # Guard the guard, again: an empty registry would make this exit 0 having checked nothing.
    if not VENDORED:
        print("::error::no vendored copies are registered — this gate is checking nothing")
        return 1

    try:
        source = pick_source(args.source)
    except Failure as exc:
        print(f"::error::{exc}")
        return 1

    failed = False
    for v in VENDORED:
        try:
            notices = check(v, source)
        except Failure as exc:
            print(f"::error::{exc}")
            failed = True
        else:
            print(f"OK  {v.local} is verbatim and current ({v.repo}, via {source.name})")
            for notice in notices:
                print(f"::notice::{notice}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
