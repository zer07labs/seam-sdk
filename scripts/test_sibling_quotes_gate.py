"""`check_sibling_quotes.py` is the only CI check on the sibling half of `QUOTED` (seam-sdk#103).

That table catches a claim whose source **changes value in place** — a version constraint on another
repo's release cadence, which never moves a line and so cannot be line-anchored. Three of its four
entries name sibling repos, and the pytest that owns it skips those: `../seam-adapters` is not
checked out in CI and never will be. So the only mechanism that can catch this class of drift ran on
a workstation that happened to have the siblings cloned.

These run the real script against a **stubbed `gh`**, for the reason `test_release_notice_gate.py`
gives: a gate whose logic is only read and never run is how a real bug survives review. The stub also
means this file needs no credential, so it runs in `workflow-guards` and a fork PR still proves the
logic even though it cannot run the job itself. That property is why `sibling-quotes` is tolerable in
`ALLOWED_ADVISORY` at all.

The properties worth pinning are the ones that make this check useless when they rot:

  * it FIRES on a quote whose source changed — the whole point;
  * it cannot be satisfied by a broken query. An API failure is exit 2, never exit 0 and never a
    verdict about the claim;
  * **an empty scan is exit 2, not exit 0.** A check reporting "all clear" because it found nothing
    to check is this repo's named failure class, and rebuilding it inside the fix for it would be
    the same-shape regression;
  * a crash is exit 2, not exit 1 — 1 is the drift verdict here, and Python spends 1 on an uncaught
    exception (the seam-sdk#110 hole);
  * the repos the script will reach match the repos the workflow mints a token for.

Run: `python -m pytest scripts/test_sibling_quotes_gate.py -q`
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_sibling_quotes.py"
CI = REPO / ".github" / "workflows" / "ci.yml"
JOB = "sibling-quotes"

#: A table shaped exactly like the real one: one local row (ignored) and two sibling rows.
TABLE = '''\
CITATION = None

QUOTED = [
    ("DECISIONS.md", "verify/docs/seam-event.v1.md", "a local claim, not a sibling one"),
    ("COMPATIBILITY.md", "seam-aegis/pyproject.toml", "seam-agent-core[sdk]>=0.6,<0.7"),
    ("COMPATIBILITY.md", "../seam-adapters/core/pyproject.toml", "seam-sdk>=0.7.20,<0.8"),
]
'''

#: What the stubbed `gh` serves per (repo, path), keyed by the tail of the request.
SOURCES = {
    "seam-aegis": 'dependencies = ["seam-agent-core[sdk]>=0.6,<0.7"]\n',
    "seam-adapters": 'dependencies = ["seam-sdk>=0.7.20,<0.8"]\n',
}


def _tree(tmp_path: Path, *, table: str = TABLE, doc: str | None = None) -> Path:
    """A scratch repo root holding the table module and the document that quotes it."""
    (tmp_path / "python" / "tests").mkdir(parents=True)
    (tmp_path / "python" / "tests" / "test_compatibility_citations_resolve.py").write_text(
        table, encoding="utf-8"
    )
    body = (
        doc
        if doc is not None
        else (
            "# Compatibility\n\n"
            "seam-aegis pins `seam-agent-core[sdk]>=0.6,<0.7` today.\n"
            "seam-adapters pins `seam-sdk>=0.7.20,<0.8` today.\n"
        )
    )
    (tmp_path / "COMPATIBILITY.md").write_text(body, encoding="utf-8")
    (tmp_path / "DECISIONS.md").write_text("# Decisions\n", encoding="utf-8")
    return tmp_path


def _run(
    tree: Path,
    tmp_path: Path,
    *,
    sources: dict[str, str] | None = None,
    gh_exit: int = 0,
    gh_present: bool = True,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    if gh_present:
        # Serves the file body for whichever sibling repo the request names, so a per-entry
        # response is possible; `gh_exit` forces the API-failure path instead.
        # Each body is written to a real file and `cat`ed, rather than embedded in the stub as a
        # quoted literal. Two harness bugs came out of the shorter forms and both made the stub
        # UNFAITHFUL rather than broken, which is the dangerous kind:
        #
        #   * `textwrap.dedent` on an f-string carrying an interpolated block computes its common
        #     prefix from that block's own indentation and leaves the shebang indented, so the stub
        #     does not exec at all;
        #   * `printf %s 'a\nb'` does NOT interpret the escape — `%s` never does, only `%b` — so a
        #     two-line body arrived as ONE line with a literal backslash-n in it. Every assertion
        #     still passed, because a needle present once in one line is present once. The
        #     duplicate-needle test was the only one that could tell, and it silently tested
        #     nothing until this changed.
        cases = []
        for repo, body in (sources if sources is not None else SOURCES).items():
            f = tmp_path / f"body-{repo}.txt"
            f.write_text(body, encoding="utf-8")
            cases.append(f'  *"/{repo}/"*) cat {f} ;;')
        (bin_dir / "gh").write_text(
            "\n".join(
                [
                    "#!/usr/bin/env bash",
                    f'if [ "{gh_exit}" != "0" ]; then',
                    '  echo "gh: HTTP 404: Not Found" >&2',
                    f"  exit {gh_exit}",
                    "fi",
                    'case " $* " in',
                    *cases,
                    '  *) echo "gh: unexpected request: $*" >&2; exit 1 ;;',
                    "esac",
                    "exit 0",
                    "",
                ]
            )
        )
        (bin_dir / "gh").chmod(0o755)

    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--table",
            str(tree / "python" / "tests" / "test_compatibility_citations_resolve.py"),
            "--repo",
            str(tree),
        ],
        capture_output=True,
        text=True,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "GH_TOKEN": "stub"},
    )


# ── the clean case, which everything below is a departure from ────────────────────────────────


def test_matching_quotes_pass(tmp_path: Path) -> None:
    proc = _run(_tree(tmp_path), tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "checking 2 sibling quote(s)" in proc.stdout, (
        "the local row was counted as a sibling, or a sibling row was dropped: " + proc.stdout
    )


def test_the_local_row_is_not_fetched(tmp_path: Path) -> None:
    """`verify/docs/...` is in `QUOTED` but is not a sibling; the pytest already covers it.

    If it were fetched, the stub would exit 1 on an unexpected request — so the clean pass above
    already implies this. Asserted separately because that implication is invisible.
    """
    proc = _run(_tree(tmp_path), tmp_path)
    assert "verify/docs" not in proc.stdout, proc.stdout


# ── it fires ──────────────────────────────────────────────────────────────────────────────────


def test_a_changed_constraint_is_drift(tmp_path: Path) -> None:
    """The case that actually happened: seam-aegis bumped 0.5 -> 0.6 and CI stayed green."""
    moved = dict(SOURCES, **{"seam-aegis": 'dependencies = ["seam-agent-core[sdk]>=0.7,<0.8"]\n'})
    proc = _run(_tree(tmp_path), tmp_path, sources=moved)
    assert proc.returncode == 1, f"exit {proc.returncode}: {proc.stdout}{proc.stderr}"
    assert "seam-agent-core[sdk]>=0.6,<0.7" in proc.stdout
    assert "0 time(s)" in proc.stdout, proc.stdout


def test_a_needle_that_stopped_being_unique_is_drift(tmp_path: Path) -> None:
    """>1 hit means the needle no longer identifies one sentence — lengthen it, never relax."""
    dupe = dict(SOURCES)
    dupe["seam-adapters"] = dupe["seam-adapters"] * 2
    proc = _run(_tree(tmp_path), tmp_path, sources=dupe)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "2 time(s)" in proc.stdout, proc.stdout
    assert "LENGTHEN" in proc.stdout


def test_a_document_that_stopped_quoting_is_drift(tmp_path: Path) -> None:
    """The entry outliving the claim. Checking a sentence the document no longer makes is noise."""
    tree = _tree(tmp_path, doc="# Compatibility\n\nnothing is quoted here any more\n")
    proc = _run(tree, tmp_path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "no longer quotes" in proc.stdout


# ── it cannot be satisfied by not running ─────────────────────────────────────────────────────


def test_an_api_failure_is_infrastructure_not_a_verdict(tmp_path: Path) -> None:
    """A 404 is ambiguous — renamed file, or a token that cannot reach the repo.

    Reported as infrastructure on purpose. Calling a permissions problem a stale claim sends
    someone to edit a document that is fine.
    """
    proc = _run(_tree(tmp_path), tmp_path, gh_exit=1)
    assert proc.returncode == 2, f"exit {proc.returncode} — an API failure read as a verdict"
    assert "gh api failed" in proc.stdout


def test_a_missing_gh_is_infrastructure(tmp_path: Path) -> None:
    proc = _run(_tree(tmp_path), tmp_path, gh_present=False)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "gh" in proc.stdout


@pytest.mark.parametrize(
    ("table", "why"),
    [
        ("QUOTED = []\n", "empty table"),
        (
            'QUOTED = [("DECISIONS.md", "verify/docs/x.md", "local only")]\n',
            "rows, but none reachable",
        ),
        ("NOT_QUOTED = []\n", "table renamed away"),
        ("QUOTED = [SOMETHING]\n", "table stopped being a literal"),
    ],
    ids=["empty", "no-sibling-rows", "renamed", "not-a-literal"],
)
def test_nothing_to_check_is_infrastructure_never_a_clean_pass(
    table: str, why: str, tmp_path: Path
) -> None:
    """**Exit 0 here would rebuild the bug inside the fix for it.**

    Every one of these leaves the script with nothing to verify. Reporting that as "all sibling
    quotes still match" is precisely the shape seam-sdk#103 describes: a check whose result is
    decided by something other than the property it names.
    """
    proc = _run(_tree(tmp_path, table=table), tmp_path)
    assert proc.returncode == 2, (
        f"{why}: exit {proc.returncode} — nothing was checked and that was not reported as "
        f"infrastructure.\n{proc.stdout}{proc.stderr}"
    )


def test_a_crash_exits_two_not_one(tmp_path: Path) -> None:
    """1 is the DRIFT verdict and Python also spends 1 on an uncaught exception (seam-sdk#110).

    Injected by making `--repo` a path whose `COMPATIBILITY.md` is a directory, so the local read
    raises `IsADirectoryError` — an `OSError`, deliberately not an `InfraError`.
    """
    tree = _tree(tmp_path)
    (tree / "COMPATIBILITY.md").unlink()
    (tree / "COMPATIBILITY.md").mkdir()
    proc = _run(tree, tmp_path)
    assert proc.returncode == 2, f"exit {proc.returncode} — a crash was reported as drift"
    assert "crashed" in proc.stderr, proc.stderr
    assert "Traceback" in proc.stderr


# ── the job and the script must agree about what they reach ───────────────────────────────────


def _job() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"][JOB]


def _script_repos() -> tuple[str, ...]:
    import ast

    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "SIBLING_REPOS" for t in node.targets
        ):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError("SIBLING_REPOS is gone from check_sibling_quotes.py")


def test_the_token_scope_matches_what_the_script_will_reach() -> None:
    """Widening one side only is silent: the script skips a repo, or the token is over-scoped.

    Skipping a repo is the dangerous half — a `QUOTED` entry naming an unreachable repo is filtered
    out by `sibling_entries` and simply not checked, with no error, which is the exact silence this
    job exists to end.
    """
    step = next(s for s in _job()["steps"] if "create-github-app-token" in str(s.get("uses", "")))
    minted = tuple(r.strip() for r in step["with"]["repositories"].split(",") if r.strip())
    assert sorted(minted) == sorted(_script_repos()), (
        f"the job mints a token for {sorted(minted)} but the script will reach "
        f"{sorted(_script_repos())}. Change both together."
    )


def test_the_job_actually_runs_the_checker() -> None:
    """Anti-vacuity for the whole mechanism: a job that no longer runs this proves nothing."""
    runs = " ".join(str(s.get("run", "")) for s in _job()["steps"])
    assert "scripts/check_sibling_quotes.py" in runs, (
        f"{JOB} no longer runs the checker, so the sibling half of QUOTED is unverified in CI "
        f"again — which is the whole of seam-sdk#103."
    )


def test_the_job_skips_rather_than_fails_without_the_app() -> None:
    """A fork PR cannot mint the token. Without the guard the job fails and blocks every fork PR."""
    assert "have_bot_app" in str(_job().get("if", "")), (
        f"{JOB} has no bot-app guard, so a secretless fork PR runs it and fails on token minting"
    )
