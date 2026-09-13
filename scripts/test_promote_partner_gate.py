"""The partner-promotion allowlist, executed rather than read.

`zer07labs/internal` holds the private runtime crates, and a Cargo crate ships source. So the
allowlist that decides what reaches `zer07labs/partner` is the boundary between "a design partner
can install the SDK" and "a design partner has the closed half of the product". It is worth more
than a code review.

Three things this exercises that reading the script cannot:

  * `cloudsmith copy` is NOT idempotent. Copying a package already in the destination exits 0 and
    creates a SECOND copy under a fresh slug — measured against the real API, not assumed. So
    idempotency here is a destination check BEFORE the copy, and a test that only asserted "the
    re-run exits 0" would pass against a script that silently duplicates every version.

  * A name on the allowlist that matches nothing must REFUSE, not skip. An earlier draft got this
    wrong in a way no review would have caught: the helper printed one blank line for an empty
    result, the caller counted it as a row, and the missing package was reported as
    "already present". The refusal message was correct and the reason was fiction.

  * One python version is TWO packages (sdist + wheel) with two slugs. Resolving "the slug" for a
    version promotes the wheel and leaves the sdist behind.

The stub speaks the CLI's actual shapes — `list packages OWNER/REPO -q '...' -F json` and
`copy OWNER/REPO/SLUG DEST` — against an in-memory registry, so the script under test is the real
one, unmodified.

Run: `python -m pytest scripts/test_promote_partner_gate.py -q`
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "promote-to-partner.sh"
PUBLISH = REPO / ".github" / "workflows" / "publish.yml"
BACKFILL = REPO / ".github" / "workflows" / "promote-partner-backfill.yml"


def _major(path: str) -> int:
    try:
        out = subprocess.run(
            [path, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True
        ).stdout.strip()
        return int(out or 0)
    except (OSError, ValueError):
        return 0


def _capable_bash() -> tuple[str, int]:
    """`mapfile` is bash 4+, and macOS still ships 3.2 as /bin/bash — so `which bash` finds the one
    shell that cannot run this script. Prefer a real one if the machine has it (Homebrew installs
    bash 5 outside PATH precedence) before giving up and skipping."""
    seen = []
    for cand in (
        shutil.which("bash"),
        "/opt/homebrew/bin/bash",
        "/usr/local/bin/bash",
        "/bin/bash",
    ):
        if cand and cand not in seen:
            seen.append(cand)
            if _major(cand) >= 4:
                return cand, _major(cand)
    return (seen[0] if seen else "/bin/bash"), 0


BASH, _BASH_MAJOR = _capable_bash()

# Skipping locally is honest rather than a gap — ubuntu-latest has bash 5, so CI runs all of these.
pytestmark = pytest.mark.skipif(
    _BASH_MAJOR < 4,
    reason="no bash >= 4 found (tried PATH and the usual Homebrew locations)",
)


# ── a fake Cloudsmith ────────────────────────────────────────────────────────────────────────────
STUB = r"""#!/usr/bin/env python3
import json, os, re, sys

WORLD = os.environ["STUB_WORLD"]
LOG = os.environ["STUB_LOG"]

def load(): return json.load(open(WORLD))
def save(w): json.dump(w, open(WORLD, "w"))

argv = sys.argv[1:]
if argv[0] == "list" and argv[1] == "packages":
    repo = argv[2].split("/", 1)[1]
    q = argv[argv.index("-q") + 1]
    name = re.search(r"name:\^(.*?)\$", q).group(1)
    fmt = re.search(r"format:(\S+)", q).group(1)
    ver = re.search(r"version:\^(.*?)\$", q)
    rows = [
        r for r in load().get(repo, [])
        if r["name"] == name and r["format"] == fmt
        and (ver is None or r["version"] == ver.group(1))
    ]
    print(json.dumps({"data": rows}))
    sys.exit(0)

if argv[0] == "copy":
    src_owner, src_repo, slug = argv[1].split("/")
    dest = argv[2]
    w = load()
    pkg = next((r for r in w.get(src_repo, []) if r["slug"] == slug), None)
    if pkg is None:
        print(f"no such package {slug}", file=sys.stderr); sys.exit(1)
    with open(LOG, "a") as fh:
        fh.write(f"{src_repo}/{slug} -> {dest}\n")
    # THE REAL BEHAVIOUR: append unconditionally, new slug, exit 0. Copying something already
    # there duplicates it rather than failing.
    w.setdefault(dest, []).append({**pkg, "slug": pkg["slug"] + "-dup"})
    save(w)
    print(f"Copying {slug} package from {src_repo} to {dest} ... OK")
    sys.exit(0)

print(f"stub: unhandled {argv}", file=sys.stderr)
sys.exit(2)
"""


def _pkg(name, version, fmt, filename, slug=None):
    return {
        "name": name,
        "version": version,
        "format": fmt,
        "filename": filename,
        "slug": slug or re.sub(r"[^a-z0-9]", "", filename.lower())[:20],
    }


def _world(internal=None, partner=None):
    """internal holds the SDK at 0.14.3 plus things that must never be promoted."""
    if internal is None:
        internal = [
            _pkg("@zer07labs/seam-sdk", "0.14.3", "npm", "seam-sdk-0.14.3.tgz"),
            _pkg("seam-sdk", "0.14.3", "python", "seam_sdk-0.14.3.tar.gz"),
            _pkg("seam-sdk", "0.14.3", "python", "seam_sdk-0.14.3-py3-none-any.whl"),
            # The closed half of the product. None of these may ever appear in partner.
            _pkg("seam-verify", "0.1.0", "cargo", "seam-verify-0.1.0.crate"),
            _pkg("seam-kernel", "0.14.3", "cargo", "seam-kernel-0.14.3.crate"),
            _pkg("seamd", "0.14.3", "cargo", "seamd-0.14.3.crate"),
            _pkg(
                "seam-learning-keys", "0.3.0", "cargo", "seam-learning-keys-0.3.0.crate"
            ),
        ]
    return {"internal": internal, "partner": partner or []}


def _run(tmp_path: Path, *args, script: Path | None = None, world=None, key="raw-key"):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "cloudsmith"
    stub.write_text(STUB)
    stub.chmod(0o755)

    wf = tmp_path / "world.json"
    wf.write_text(json.dumps(world if world is not None else _world()))
    log = tmp_path / "copies.log"
    log.write_text("")

    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "STUB_WORLD": str(wf),
        "STUB_LOG": str(log),
        "CLOUDSMITH_PARTNER_API_KEY": key,
    }
    proc = subprocess.run(
        [BASH, str(script or SCRIPT), *args], capture_output=True, text=True, env=env
    )
    return proc, json.loads(wf.read_text()), log.read_text().splitlines()


def _variant(tmp_path: Path, old: str, new: str) -> Path:
    src = SCRIPT.read_text()
    assert old in src, f"anchor not found: {old!r}"
    p = tmp_path / "variant.sh"
    p.write_text(src.replace(old, new))
    return p


# ── the allowlist is a literal list ──────────────────────────────────────────────────────────────
def _allowlist() -> list[str]:
    body = re.search(r"PARTNER_ALLOWLIST=\((.*?)\n\)", SCRIPT.read_text(), re.S).group(
        1
    )
    return re.findall(r'"([^"]+)"', body)


def test_the_allowlist_is_exactly_the_two_sdk_packages() -> None:
    assert _allowlist() == ["@zer07labs/seam-sdk|npm", "seam-sdk|python"]


def test_the_allowlist_carries_no_wildcard_of_any_kind() -> None:
    # A glob here would grow new matches on its own, in the one repo where that is indefensible.
    for entry in _allowlist():
        assert not set(entry) & set("*?["), entry
        assert "~" not in entry


def test_every_allowlist_entry_pins_a_format() -> None:
    # Name alone is not enough: a cargo crate named `seam-sdk` would otherwise match and put Rust
    # source into the partner repo.
    for entry in _allowlist():
        name, _, fmt = entry.partition("|")
        assert name and fmt in {"npm", "python"}, entry


# ── the verb ─────────────────────────────────────────────────────────────────────────────────────
def test_the_script_copies_and_never_moves() -> None:
    """`promote` is cloudsmith-cli's alias for MOVE. Using the word in the ticket as the verb in
    the script would delete the version out of `internal`, which every internal consumer resolves."""
    body = "\n".join(
        ln for ln in SCRIPT.read_text().splitlines() if not ln.lstrip().startswith("#")
    )
    assert re.search(r'"\$\{CS\[@\]\}" copy ', body)
    for forbidden in (" move ", " mv ", " promote "):
        assert forbidden not in body, (
            f"{forbidden!r} would move the artifact, not copy it"
        )


# ── fail closed ──────────────────────────────────────────────────────────────────────────────────
def test_an_empty_allowlist_refuses_rather_than_reporting_success(
    tmp_path: Path,
) -> None:
    v = _variant(tmp_path, '"@zer07labs/seam-sdk|npm"\n  "seam-sdk|python"\n', "")
    proc, world, copies = _run(tmp_path, "0.14.3", script=v)
    assert proc.returncode == 1
    assert "allowlist is EMPTY" in proc.stderr
    assert copies == [] and world["partner"] == []


def test_an_allowlisted_name_with_no_match_refuses(tmp_path: Path) -> None:
    """Not a skip. If internal does not have the version, the release did not land the way the
    caller believes, and promoting the rest of the list while staying green hides it."""
    internal = [r for r in _world()["internal"] if r["name"] != "seam-sdk"]
    proc, world, _ = _run(tmp_path, "0.14.3", world=_world(internal=internal))
    assert proc.returncode == 1
    assert "has NO version 0.14.3" in proc.stderr
    assert "seam-sdk" in proc.stderr


def test_a_version_that_was_never_published_refuses(tmp_path: Path) -> None:
    proc, _, copies = _run(tmp_path, "9.9.9")
    assert proc.returncode == 1 and copies == []


def test_a_malformed_allowlist_entry_refuses(tmp_path: Path) -> None:
    v = _variant(tmp_path, '"seam-sdk|python"', '"seam-sdk-no-pipe"')
    proc, _, _ = _run(tmp_path, "0.14.3", script=v)
    assert proc.returncode == 1
    assert "malformed allowlist entry" in proc.stderr


def test_a_tag_is_refused_rather_than_queried(tmp_path: Path) -> None:
    proc, _, copies = _run(tmp_path, "v0.14.3")
    assert proc.returncode == 1
    assert "not a version" in proc.stderr and copies == []


def test_a_bearer_prefixed_key_is_refused(tmp_path: Path) -> None:
    """The org's Cargo token is stored WITH that prefix; reusing it here 401s in a way that reads
    like a permissions problem."""
    proc, _, _ = _run(tmp_path, "0.14.3", key="Bearer abc123")
    assert proc.returncode == 1
    assert "RAW key" in proc.stderr


def test_a_missing_key_refuses(tmp_path: Path) -> None:
    proc, _, _ = _run(tmp_path, "0.14.3", key="")
    assert proc.returncode == 1
    assert "CLOUDSMITH_PARTNER_API_KEY is not set" in proc.stderr


# ── what actually lands ──────────────────────────────────────────────────────────────────────────
def test_exactly_the_allowlisted_packages_are_copied(tmp_path: Path) -> None:
    proc, world, copies = _run(tmp_path, "0.14.3")
    assert proc.returncode == 0, proc.stderr
    assert sorted(r["filename"] for r in world["partner"]) == [
        "seam-sdk-0.14.3.tgz",
        "seam_sdk-0.14.3-py3-none-any.whl",
        "seam_sdk-0.14.3.tar.gz",
    ]
    assert len(copies) == 3


def test_no_cargo_crate_ever_reaches_partner(tmp_path: Path) -> None:
    """The whole reason the second repo exists."""
    _, world, _ = _run(tmp_path, "0.14.3")
    assert [r for r in world["partner"] if r["format"] == "cargo"] == []
    for closed in ("seam-verify", "seam-kernel", "seamd", "seam-learning-keys"):
        assert not any(r["name"] == closed for r in world["partner"]), closed


def test_both_python_artifacts_are_copied_not_just_the_wheel(tmp_path: Path) -> None:
    """One version is two packages with two slugs; matching on version alone drops the sdist."""
    _, world, _ = _run(tmp_path, "0.14.3")
    py = sorted(r["filename"] for r in world["partner"] if r["format"] == "python")
    assert py == ["seam_sdk-0.14.3-py3-none-any.whl", "seam_sdk-0.14.3.tar.gz"]


# ── idempotency ──────────────────────────────────────────────────────────────────────────────────
def test_a_rerun_copies_nothing_and_creates_no_duplicate(tmp_path: Path) -> None:
    """The stub duplicates on copy exactly as the real API does, so this fails loudly if the
    destination check is ever removed."""
    first, world, copies = _run(tmp_path, "0.14.3")
    assert first.returncode == 0 and len(copies) == 3

    # Re-run against the world the first run produced.
    second, world2, copies2 = _run(tmp_path, "0.14.3", world=world)
    assert second.returncode == 0, second.stderr
    assert copies2 == [], "a re-run copied again — partner will accumulate duplicates"
    assert "0 copied, 3 already present" in second.stdout
    assert len(world2["partner"]) == 3


def test_a_half_promoted_version_is_completed_not_skipped(tmp_path: Path) -> None:
    """If only the wheel made it last time, the re-run must copy the sdist and nothing else."""
    partner = [_pkg("seam-sdk", "0.14.3", "python", "seam_sdk-0.14.3-py3-none-any.whl")]
    proc, world, copies = _run(tmp_path, "0.14.3", world=_world(partner=partner))
    assert proc.returncode == 0, proc.stderr
    assert len(copies) == 2
    assert sorted(r["filename"] for r in world["partner"]) == [
        "seam-sdk-0.14.3.tgz",
        "seam_sdk-0.14.3-py3-none-any.whl",
        "seam_sdk-0.14.3.tar.gz",
    ]


# ── --since ──────────────────────────────────────────────────────────────────────────────────────
def _multiversion_world():
    rows = []
    for v in ("0.7.46", "0.7.47", "0.7.75", "0.10.0", "0.14.3"):
        rows.append(_pkg("@zer07labs/seam-sdk", v, "npm", f"seam-sdk-{v}.tgz"))
        rows.append(_pkg("seam-sdk", v, "python", f"seam_sdk-{v}.tar.gz"))
        rows.append(_pkg("seam-sdk", v, "python", f"seam_sdk-{v}-py3-none-any.whl"))
    return _world(internal=rows)


def test_since_orders_versions_numerically_not_lexically(tmp_path: Path) -> None:
    """A lexical sort puts 0.14.3 below 0.7.47 and would drop most of a backfill."""
    proc, world, _ = _run(tmp_path, "--since", "0.7.47", world=_multiversion_world())
    assert proc.returncode == 0, proc.stderr
    got = sorted({r["version"] for r in world["partner"]})
    assert got == ["0.10.0", "0.14.3", "0.7.47", "0.7.75"]
    assert "0.7.46" not in got


def test_since_excludes_everything_below_the_floor(tmp_path: Path) -> None:
    _, world, _ = _run(tmp_path, "--since", "0.7.47", world=_multiversion_world())
    assert not any(r["version"] == "0.7.46" for r in world["partner"])


def test_since_with_no_matching_version_refuses(tmp_path: Path) -> None:
    proc, _, copies = _run(tmp_path, "--since", "99.0.0", world=_multiversion_world())
    assert proc.returncode == 1 and copies == []


def test_an_unknown_option_refuses(tmp_path: Path) -> None:
    proc, _, _ = _run(tmp_path, "--bogus")
    assert proc.returncode == 1 and "unknown option" in proc.stderr


# ── the workflow wiring ──────────────────────────────────────────────────────────────────────────
def _publish_jobs() -> dict:
    return yaml.safe_load(PUBLISH.read_text())["jobs"]


def test_promotion_is_gated_on_the_job_that_proves_the_release_landed() -> None:
    """`registry-smoke` installs the published artifact back out of Cloudsmith. Gating on
    npm+python alone would forward a version that uploaded and never became installable."""
    assert "registry-smoke" in _publish_jobs()["promote-partner"]["needs"]


def test_promotion_cannot_run_before_the_publish_jobs() -> None:
    needs = _publish_jobs()["promote-partner"]["needs"]
    assert {"npm", "python"} <= set(needs)


def test_promotion_does_not_run_by_default_on_a_failed_publish() -> None:
    # No `if: always()`: the default `needs` semantics are what make this dependent.
    job = _publish_jobs()["promote-partner"]
    assert "always()" not in str(job.get("if", ""))


def test_promotion_uses_its_own_credential_not_the_publishing_one() -> None:
    job = str(_publish_jobs()["promote-partner"])
    assert "CLOUDSMITH_PARTNER_API_KEY" in job
    assert "secrets.CLOUDSMITH_API_KEY" not in job
    assert "CARGO_REGISTRIES_ZER07LABS_TOKEN" not in job


def test_the_publish_jobs_still_target_internal() -> None:
    """Promotion must not have repointed anything — internal consumers depend on it."""
    jobs = _publish_jobs()
    assert "npm.cloudsmith.io/zer07labs/internal/" in str(jobs["npm"])
    assert "python.cloudsmith.io/zer07labs/internal/" in str(jobs["python"])


def test_release_outcome_does_not_report_a_promotion_failure_as_a_failed_release() -> (
    None
):
    """A promotion failure leaves internal published and correct; filing "did not publish" for it
    would be false."""
    assert "promote-partner" not in _publish_jobs()["release-outcome"]["needs"]


def test_the_cli_is_pinned_in_both_workflows() -> None:
    """`copy` and `promote` are different operations in this CLI; an unpinned upgrade that
    reshuffled them would turn a mirror into a migration."""
    for wf in (PUBLISH, BACKFILL):
        assert "cloudsmith-cli==1.11.1" in wf.read_text(), wf.name


def test_the_backfill_is_a_separate_workflow_from_publish() -> None:
    """publish.yml's `publish-verify` fires on ANY workflow_dispatch, so a backfill input there
    would also release the seam-verify crate."""
    assert BACKFILL.exists()
    verify = _publish_jobs()["publish-verify"]
    assert verify["if"] == "github.event_name == 'workflow_dispatch'"
    assert "backfill" not in str(_publish_jobs().keys())


def test_the_backfill_refuses_both_inputs_at_once() -> None:
    run = str(
        yaml.safe_load(BACKFILL.read_text())["jobs"]["backfill"]["steps"][-1]["run"]
    )
    assert "not both" in run
