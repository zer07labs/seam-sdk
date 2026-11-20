"""A refused proto-train release writes nothing, is recorded, and re-fires exactly what was asked.

0.88.0 and 0.90.0 were tagged and never published. release-on-runtime.yml's main-is-green gate read
a green computed against the OLD contract: the runtime pushes to the BSR at merge but dispatches at
its release tag, and this repo's catch-up had not merged in between. The fix has three parts, and
each is pinned here:

  * release-on-runtime.yml re-runs the contract gate and the vendored-spec gate FRESH, before
    anything is written. A red there must leave no commit and no tag. That is proven by EXECUTING
    the job's real steps, in order and with GitHub's `if:` semantics, against a throwaway origin
    (`test_a_red_fresh_gate_leaves_no_commit_and_no_tag`). The green twin of that test proves the
    harness is not vacuous: it really tags.
  * The refusal is recorded in one `release-pending` issue (scripts/release_pending.py).
  * release-refire.yml re-dispatches exactly the recorded version and framing, only from a push run
    of ci.yml on this repo's main, with least privilege, and refuses when a newer release exists.

Run: `python -m pytest scripts/test_release_refire_gate.py -q`
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
RELEASE = REPO / ".github" / "workflows" / "release-on-runtime.yml"
REFIRE = REPO / ".github" / "workflows" / "release-refire.yml"
_spec = importlib.util.spec_from_file_location(
    "release_pending", REPO / "scripts" / "release_pending.py"
)
rp = importlib.util.module_from_spec(_spec)
sys.modules["release_pending"] = rp
_spec.loader.exec_module(rp)

SHA = "a" * 40
SHA2 = "b" * 40


def _issue(
    n: int,
    ver: str,
    wf: str = "3",
    comments: list[str] | None = None,
    title: str | None = None,
):
    return {
        "number": n,
        "title": title if title is not None else rp.title(ver),
        "body": rp.body(
            ver, wf, "https://example.invalid/run", "fresh contract gate: failure"
        ),
        "comments": comments or [],
    }


# ── decide: the re-fire rules ──────────────────────────────────────────────────────────────────


def test_fires_exactly_the_recorded_version_and_framing() -> None:
    [d] = rp.decide(
        [_issue(7, "0.91.0", "3")], ["seamd-v0.91.0", "seamd-v0.90.0"], ["v0.90.1"], SHA
    )
    assert (d.action, d.issue, d.version, d.wire_framing_version) == (
        "fire",
        7,
        "0.91.0",
        "3",
    )


def test_a_newer_runtime_release_supersedes_the_pending_one() -> None:
    [d] = rp.decide([_issue(7, "0.91.0")], ["seamd-v0.91.0", "seamd-v0.92.0"], [], SHA)
    assert d.action == "refuse" and "0.92.0" in d.reason


def test_a_manual_runtime_tag_counts_as_a_release_too() -> None:
    [d] = rp.decide([_issue(7, "0.91.0")], ["v0.91.1"], [], SHA)
    assert d.action == "refuse"


def test_a_runtime_prerelease_or_crate_tag_is_not_a_newer_release() -> None:
    [d] = rp.decide(
        [_issue(7, "0.91.0")], ["v0.92.0-rc.1", "seam-types-v0.99.0"], [], SHA
    )
    assert d.action == "fire"


def test_a_newer_sdk_tag_refuses() -> None:
    [d] = rp.decide([_issue(7, "0.91.0")], ["seamd-v0.91.0"], ["v0.91.1"], SHA)
    assert d.action == "refuse" and "v0.91.1" in d.reason


def test_an_already_tagged_version_closes_the_issue() -> None:
    [d] = rp.decide([_issue(7, "0.91.0")], ["seamd-v0.91.0"], ["v0.91.0"], SHA)
    assert d.action == "close"


def test_re_fires_at_most_once_per_main_commit() -> None:
    done = _issue(7, "0.91.0", comments=[rp.refired_marker(SHA) + "\nRe-dispatched"])
    assert rp.decide([done], [], [], SHA)[0].action == "skip"
    assert rp.decide([done], [], [], SHA2)[0].action == "fire"


def test_a_refusal_is_stated_once() -> None:
    [first] = rp.decide([_issue(7, "0.91.0")], ["seamd-v0.92.0"], [], SHA)
    said = _issue(
        7,
        "0.91.0",
        comments=[rp.refusal_comment(first.reason) + " A human decides now."],
    )
    assert rp.decide([said], ["seamd-v0.92.0"], [], SHA2)[0].action == "skip"


@pytest.mark.parametrize(
    "body",
    [
        "",
        "no marker here",
        "<!-- release-pending version=latest wire_framing_version=3 -->",
        "<!-- release-pending version=0.91.0 wire_framing_version=0 -->",
        "<!-- release-pending version=0.91.0 wire_framing_version=3 -->\n"
        "<!-- release-pending version=0.92.0 wire_framing_version=3 -->",
    ],
)
def test_a_body_that_does_not_parse_exactly_is_refused(body: str) -> None:
    issue = {"number": 7, "title": rp.title("0.91.0"), "body": body, "comments": []}
    assert rp.decide([issue], [], [], SHA)[0].action == "refuse"


def test_a_title_that_disagrees_with_its_marker_is_refused() -> None:
    [d] = rp.decide(
        [_issue(7, "0.91.0", title="release pending: v0.92.0")], [], [], SHA
    )
    assert d.action == "refuse"


def test_two_refirable_pendings_refuse_rather_than_pick() -> None:
    out = rp.decide([_issue(7, "0.91.0"), _issue(8, "0.91.0")], [], [], SHA)
    assert [d.action for d in out] == ["refuse", "refuse"]


@pytest.mark.parametrize("bad", ["latest", "0.91", "v0.91.0", "0.91.0-rc.1", ""])
def test_the_ledger_refuses_to_record_anything_but_a_release_version(bad: str) -> None:
    with pytest.raises(ValueError):
        rp.body(bad, "3", "u", "r")


# ── release-refire.yml: scope and privilege ───────────────────────────────────────────────────


def _refire() -> dict:
    return yaml.safe_load(REFIRE.read_text())


def test_refire_listens_only_to_ci_completing_on_main() -> None:
    on = _refire()[True]  # PyYAML reads the bare key `on` as True
    assert set(on) == {"workflow_run"}
    assert on["workflow_run"] == {
        "workflows": ["ci"],
        "types": ["completed"],
        "branches": ["main"],
    }


def test_refire_acts_only_on_a_green_push_run_of_this_repos_main() -> None:
    cond = " ".join(_refire()["jobs"]["refire"]["if"].split())
    for clause in (
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'main'",
        "github.event.workflow_run.head_repository.full_name == github.repository",
    ):
        assert clause in cond, clause
    assert "||" not in cond, (
        "every clause must hold; an `||` would let a PR or fork run through"
    )


def test_refire_runs_with_least_privilege() -> None:
    wf = _refire()
    assert wf["permissions"] == {}
    assert wf["jobs"]["refire"]["permissions"] == {
        "contents": "read",
        "issues": "write",
        "actions": "write",
    }


def test_refire_dispatches_only_the_decided_version_and_framing() -> None:
    run = next(s["run"] for s in _refire()["jobs"]["refire"]["steps"] if "run" in s)
    dispatch = re.findall(r"gh workflow run[^\n]*\n[^\n]*", run)
    assert len(dispatch) == 1
    assert '-f version="$VER" -f wire_framing_version="$WF"' in dispatch[0]
    assert "--ref main" in dispatch[0]
    assert 'VER="$(jq -r .version <<<"$line")"' in run
    assert "latest" not in run.lower()
    assert 'if [ "$MAIN_SHA" != "$RUN_SHA" ]' in run, (
        "a stale run must not act on a moved main"
    )


# ── release-on-runtime.yml: where the fresh gate sits ─────────────────────────────────────────


def _steps() -> list[dict]:
    return yaml.safe_load(RELEASE.read_text())["jobs"]["release"]["steps"]


def _at(step_id: str | None = None, name: str | None = None) -> int:
    for i, s in enumerate(_steps()):
        if (step_id and s.get("id") == step_id) or (name and s.get("name") == name):
            return i
    raise AssertionError(
        f"{step_id or name} is gone from release-on-runtime.yml; this guard is stale"
    )


WRITES = (
    "Bump both packages to the runtime version",
    "Retitle CHANGELOG.md's Unreleased heading to this version",
    "Commit the release to its branch (no tag yet)",
    "Advance main and tag (triggers publish.yml)",
)


def test_the_fresh_gates_run_after_main_is_green_and_before_anything_is_written() -> (
    None
):
    green, fresh, spec = _at("green"), _at("fresh"), _at("specpin")
    first_write = min(_at(name=n) for n in WRITES)
    assert green < fresh < first_write and green < spec < first_write


def test_the_fresh_gate_calls_the_script_not_make() -> None:
    run = _steps()[_at("fresh")]["run"]
    assert "make generate" in run
    assert "STREAM=1 EVENTS=1 ./scripts/check-contract.sh" in run
    assert "make check-contract" not in run, (
        "make rewrites the exit code into 2, a different verdict"
    )


def test_no_write_step_can_run_after_a_failure() -> None:
    for n in WRITES:
        assert "if" not in _steps()[_at(name=n)], (
            f"{n!r} must keep the default success() condition"
        )


def test_the_ledger_step_records_only_pre_write_refusals_and_writes_no_git() -> None:
    step = next(
        s
        for s in _steps()
        if s.get("name") == "Record the refused version for release-refire"
    )
    cond = " ".join(step["if"].split())
    assert cond.startswith("failure() && (")
    assert set(re.findall(r"steps\.(\w+)\.outcome", cond)) == {
        "green",
        "fresh",
        "specpin",
        "relci",
        "advance",
    }
    assert not re.search(r"\bgit\b", step["run"])


# ── the executed dry run ──────────────────────────────────────────────────────────────────────


def _expr(expr: str, ctx: dict) -> str:
    e = expr.strip()
    if (
        e.startswith("secrets.")
        or e == "github.token"
        or re.fullmatch(r"steps\.\w+\.outputs\.token", e)
    ):
        return "dummy"
    if e in (
        "steps.v.outputs.version",
        "github.event.client_payload.version || github.event.inputs.version",
    ):
        return ctx["version"]
    if (
        e
        == "github.event.client_payload.wire_framing_version || github.event.inputs.wire_framing_version"
    ):
        return "3"
    if e == "github.repository":
        return "zer07labs/seam-sdk"
    if e == "github.event_name":
        return "repository_dispatch"
    if m := re.fullmatch(r"steps\.(\w+)\.outcome", e):
        return ctx["outcomes"].get(m.group(1), "")
    if m := re.fullmatch(r"steps\.(\w+)\.outputs\.(\w+)", e):
        return ctx["outputs"].get(m.group(1), {}).get(m.group(2), "")
    raise AssertionError(
        f"the dry run does not know the expression `{e}`; teach it, do not skip it"
    )


def _sub(text: str, ctx: dict) -> str:
    return re.sub(r"\$\{\{(.*?)\}\}", lambda m: _expr(m.group(1), ctx), text)


def _cond(cond: str | None, ctx: dict) -> bool:
    if cond is None or cond.strip() == "success()":
        return not ctx["failed"]
    c = " ".join(cond.split())
    c = re.sub(
        r"steps\.(\w+)\.outcome", lambda m: repr(ctx["outcomes"].get(m.group(1), "")), c
    )
    c = re.sub(
        r"steps\.(\w+)\.outputs\.(\w+)",
        lambda m: repr(ctx["outputs"].get(m.group(1), {}).get(m.group(2), "")),
        c,
    )
    c = c.replace("failure()", str(ctx["failed"])).replace(
        "success()", str(not ctx["failed"])
    )
    c = c.replace("always()", "True")
    c = c.replace("&&", " and ").replace("||", " or ")
    return bool(eval(c, {"__builtins__": {}}, {}))  # noqa: S307 -- our own workflow's literal condition


_GH = r"""#!/bin/bash
echo "$*" >> "$LOG/gh.log"
case "$1 $2" in
  "api --paginate")
    # main's own ci-ok is green; any other commit (the release commit) answers $RELEASE_CI.
    if [[ "$*" == *"$BASE_SHA"* ]]; then echo success; else echo "${RELEASE_CI:-success}"; fi ;;
  "issue list") : ;;
  "issue create")
    while [ $# -gt 0 ]; do [ "$1" = --body-file ] && cat "$2" >> "$LOG/issue-body"; shift; done ;;
esac
exit 0
"""


# The dry run's version must never be the in-tree one. 0.91.0 was burned by exactly that: on the
# release commit the tree already says 0.91.0, so the job takes its "already at — tagging only" path,
# pushes no commit, and the green twin's `origin_head != base` failed on the very commit publish.yml
# gates on. A version no release will ever carry keeps this test independent of where main is.
DRY_RUN_VERSION = "999.0.0"


def _dry_run(
    tmp: Path,
    contract_exit: int,
    version: str = DRY_RUN_VERSION,
    release_ci: str = "success",
    move_main_before: str | None = None,
) -> dict:
    """Execute release-on-runtime's job, step by step with GitHub's `if:` semantics.

    `release_ci` is the ci-ok verdict the release commit gets on its branch; main's own is green.
    `move_main_before` names a step before which another commit lands on origin's main.
    """
    origin, wc, bin_dir, log = tmp / "origin.git", tmp / "wc", tmp / "bin", tmp / "log"
    for d in (bin_dir, log):
        d.mkdir()

    def git(*a: str, cwd: Path = wc) -> str:
        return subprocess.run(
            ["git", *a], cwd=cwd, check=True, capture_output=True, text=True
        ).stdout

    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True
    )
    wc.mkdir()
    git("init", "-q", "-b", "main")
    for rel in (
        "contract/wire-framing.json",
        "scripts/release_pending.py",
        "scripts/set_version.sh",
        "scripts/retitle_changelog.sh",
        "scripts/shift_changelog_citations.py",
        "COMPATIBILITY.md",
        "DECISIONS.md",
        "PROGRESS.md",
        "ts/package.json",
        "python/pyproject.toml",
        "CHANGELOG.md",
    ):
        (wc / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, wc / rel)
    (wc / "scripts/check-contract.sh").write_text(
        f"#!/bin/bash\necho stubbed gate\nexit {contract_exit}\n"
    )
    (wc / "scripts/check-contract.sh").chmod(0o755)
    (wc / "scripts/check_vendored_spec.py").write_text("print('stubbed spec pin')\n")
    shutil.copy2(REPO / "scripts/wait_ci_ok.sh", wc / "scripts/wait_ci_ok.sh")
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base")
    git("remote", "add", "origin", str(origin))
    git("push", "-q", "origin", "main")
    base = git("rev-parse", "HEAD").strip()

    (bin_dir / "gh").write_text(_GH)
    # The `buf` stub must DRAIN stdin, as the real `buf registry login --token-stdin` does. The fresh
    # step runs `printf ... | buf registry login --token-stdin` under `pipefail`; a stub that exits
    # without reading races printf, and when the stub wins printf takes SIGPIPE (141) and the fresh
    # gate reads as RED. On a loaded Linux runner that is ~1 in 1000, and it is #391: a dry run
    # that meant to exercise the release commit's CI refused at the fresh gate instead.
    (bin_dir / "buf").write_text(
        '#!/bin/bash\n[[ " $* " == *" --token-stdin "* ]] && cat >/dev/null\nexit 0\n'
    )
    (bin_dir / "make").write_text("#!/bin/bash\nexit 0\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)

    ctx = {"version": version, "failed": False, "outcomes": {}, "outputs": {}}
    ran: list[str] = []
    errors: dict[str, str] = {}
    for i, step in enumerate(_steps()):
        if "run" not in step:  # `uses:` steps: checkout, setup actions, token mints
            continue
        if step.get("name") == move_main_before:
            other = tmp / "other"
            subprocess.run(["git", "clone", "-q", str(origin), str(other)], check=True)
            (other / "MOVED").write_text("someone else merged\n")
            for a in (
                ["add", "MOVED"],
                ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "moved"],
                ["push", "-q", "origin", "main"],
            ):
                subprocess.run(["git", *a], cwd=other, check=True, capture_output=True)
        if not _cond(step.get("if"), ctx):
            continue
        out = tmp / f"out{i}"
        out.touch()
        env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "HOME": str(tmp),
            "LOG": str(log),
            "GITHUB_OUTPUT": str(out),
            "GITHUB_REPOSITORY": "zer07labs/seam-sdk",
            "GITHUB_SERVER_URL": "https://example.invalid",
            "GITHUB_RUN_ID": "1",
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
            "BASE_SHA": base,
            "RELEASE_CI": release_ci,
            "CI_WAIT_ATTEMPTS": "3",
            "CI_WAIT_INTERVAL": "0",
        }
        env.update({k: _sub(str(v), ctx) for k, v in (step.get("env") or {}).items()})
        r = subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-eo",
                "pipefail",
                "-c",
                _sub(step["run"], ctx),
            ],
            cwd=wc,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
        ran.append(step.get("name", step.get("id", "?")))
        if step.get("id"):
            ctx["outcomes"][step["id"]] = "success" if r.returncode == 0 else "failure"
            ctx["outputs"][step["id"]] = dict(
                ln.split("=", 1) for ln in out.read_text().splitlines() if "=" in ln
            )
        if r.returncode != 0:
            ctx["failed"] = True
            errors[ran[-1]] = (r.stdout + r.stderr)[-2000:]
    return {
        "ran": ran,
        "errors": errors,
        "failed": ctx["failed"],
        "base": base,
        "origin_head": git("rev-parse", "refs/heads/main", cwd=origin).strip(),
        "origin_tags": git("tag", "-l", cwd=origin).split(),
        "origin_branches": git(
            "branch", "--format=%(refname:short)", cwd=origin
        ).split(),
        "tagged": git("rev-list", "-n1", f"v{version}", cwd=origin).strip()
        if f"v{version}" in git("tag", "-l", cwd=origin).split()
        else "",
        "gh": (log / "gh.log").read_text() if (log / "gh.log").exists() else "",
        "issue_body": (log / "issue-body").read_text()
        if (log / "issue-body").exists()
        else "",
    }


def _why(r: dict) -> str:
    """The whole dry run, untruncated: pytest elides the middle of a long `in` operand, which is
    exactly where the refusal reason sits (#391)."""
    errors = "\n".join(f"--- {k} ---\n{v}" for k, v in r["errors"].items())
    return (
        f"\n=== issue body ===\n{r['issue_body']}\n=== steps run ===\n"
        + "\n".join(r["ran"])
        + f"\n=== failed steps' output ===\n{errors}"
    )


def test_the_dry_run_version_is_never_the_in_tree_version() -> None:
    tree = json.loads((REPO / "ts" / "package.json").read_text())["version"]
    assert DRY_RUN_VERSION != tree


def test_a_red_fresh_gate_leaves_no_commit_and_no_tag(tmp_path: Path) -> None:
    r = _dry_run(tmp_path, contract_exit=6)
    assert r["failed"]
    assert r["origin_head"] == r["base"], "a refused release pushed a commit"
    assert r["origin_tags"] == [], "a refused release pushed a tag"
    assert not any(n in r["ran"] for n in WRITES)
    assert "Record the refused version for release-refire" in r["ran"]
    assert "issue create" in r["gh"] and "--label release-pending" in r["gh"]
    assert (
        f"<!-- release-pending version={DRY_RUN_VERSION} wire_framing_version=3 -->"
        in r["issue_body"]
    )
    assert "fresh contract gate: failure" in r["issue_body"], _why(r)


def test_a_green_fresh_gate_really_tags(tmp_path: Path) -> None:
    """The twin that keeps the red test honest: the same harness, a green gate, a real release."""
    r = _dry_run(tmp_path, contract_exit=0)
    assert not r["failed"], r["errors"]
    assert r["origin_head"] != r["base"]
    assert sorted(r["origin_tags"]) == [f"go/v{DRY_RUN_VERSION}", f"v{DRY_RUN_VERSION}"]
    assert r["tagged"] == r["origin_head"], (
        "the tag must be exactly the CI'd commit main now holds"
    )
    assert r["origin_branches"] == ["main"], "the release branch must be cleaned up"
    assert "Record the refused version for release-refire" not in r["ran"]
    assert "Close this version's pending issue, if any" in r["ran"]
    assert "issue create" not in r["gh"]


def test_the_recorded_issue_is_what_refire_will_fire(tmp_path: Path) -> None:
    body = _dry_run(tmp_path, contract_exit=6)["issue_body"]
    issue = {
        "number": 1,
        "title": rp.title(DRY_RUN_VERSION),
        "body": body,
        "comments": [],
    }
    [d] = rp.decide([issue], [f"seamd-v{DRY_RUN_VERSION}"], ["v0.90.1"], SHA)
    assert (d.action, d.version, d.wire_framing_version) == (
        "fire",
        DRY_RUN_VERSION,
        "3",
    )


def test_the_ledger_cli_round_trips() -> None:
    out = subprocess.run(
        [sys.executable, str(REPO / "scripts/release_pending.py"), "decide"],
        input=json.dumps(
            {
                "issues": [_issue(3, "0.91.0")],
                "runtime_tags": [],
                "sdk_tags": [],
                "main_sha": SHA,
            }
        ),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert json.loads(out)["action"] == "fire"


# ── #375: the release commit's own CI gates the tag ───────────────────────────────────────────


def test_a_red_release_commit_ci_leaves_main_untouched_and_no_tag(
    tmp_path: Path,
) -> None:
    """0.91.0's failure mode: every gate before the stamp green, the release commit's CI red."""
    r = _dry_run(tmp_path, contract_exit=0, release_ci="failure")
    assert r["failed"]
    assert r["origin_head"] == r["base"], "main moved to a commit whose CI is red"
    assert r["origin_tags"] == [], "a tag exists for a commit whose CI is red"
    assert "Advance main and tag (triggers publish.yml)" not in r["ran"]
    assert r["origin_branches"] == ["main"], (
        "the refused release branch was left behind"
    )
    assert "release commit ci-ok: failure" in r["issue_body"], _why(r)


def test_a_release_commit_ci_that_never_settles_is_a_refusal(tmp_path: Path) -> None:
    r = _dry_run(tmp_path, contract_exit=0, release_ci="pending")
    assert r["failed"] and r["origin_tags"] == [] and r["origin_head"] == r["base"]


def test_main_moving_during_release_ci_refuses_the_tag(tmp_path: Path) -> None:
    r = _dry_run(
        tmp_path,
        contract_exit=0,
        move_main_before="Advance main and tag (triggers publish.yml)",
    )
    assert r["failed"]
    assert r["origin_tags"] == []
    assert r["origin_head"] != r["base"], (
        "the other commit must survive (no force push)"
    )
    assert "advance main and tag: failure" in r["issue_body"], _why(r)


def test_the_release_commit_ci_runs_on_the_release_branch() -> None:
    ci = yaml.safe_load((REPO / ".github/workflows/ci.yml").read_text())
    assert "release/**" in ci[True]["push"]["branches"]


def test_refire_still_ignores_release_branch_ci() -> None:
    assert _refire()[True]["workflow_run"]["branches"] == ["main"]
