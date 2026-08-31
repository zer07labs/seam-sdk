"""Executed guards for `.github/workflows/yank.yml` — the one workflow that DELETES artifacts.

This file exists because `yank.yml` is a tool nobody runs until an incident, which is the worst
moment to discover it does not work. It sat with a token bug that made every invocation — dry run
included — fail with a Cloudsmith 401 unless a dedicated secret happened to be set. That failure
is *closed* (no wrong deletion is possible) and therefore invisible: nothing was broken enough to
notice, so nothing did.

The token step is EXECUTED here rather than read, for the same reason the publish guards are: the
first draft of that fix used `publish.yml`'s `&&` one-liner, which behaves differently under this
workflow's `set -euo pipefail`. Reading it would not have shown that.

The destructive scoping is guarded statically. Those three filters — exact version equality, the
python+npm format allowlist, and the exact-name match that keeps the org's Cargo crates
unreachable — are what stand between a typo and deleting the wrong package, and they are asserted
here so that widening one is a deliberate, visible act.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
YANK = REPO / ".github" / "workflows" / "yank.yml"


def _step() -> dict:
    job = yaml.safe_load(YANK.read_text(encoding="utf-8"))["jobs"]["yank"]
    return next(s for s in job["steps"] if "delete" in str(s.get("name", "")))


def _token_script() -> str:
    """The workflow's own shell, truncated at the first network call.

    Truncating rather than stubbing `curl` keeps the test honest about what it covers: the
    credential resolution and the refusal, not the query or the deletion.
    """
    run = _step()["run"]
    marker = 'echo "querying'
    assert marker in run, (
        "yank.yml no longer contains the query announcement this harness truncates at. The step "
        "was restructured; re-point the marker rather than deleting the guard."
    )
    return run[: run.index(marker)] + 'echo "TOKEN=[$TOKEN]"\n'


def _run(dedicated: str | None, cargo: str | None) -> subprocess.CompletedProcess:
    """Run the real extracted shell with the two secrets set as GitHub would set them.

    `None` means the variable is absent entirely (an unset secret), which is distinct from empty
    and is the case that breaks under `set -u`.
    """
    # VERSION is supplied because the extracted region includes the workflow's own version
    # validation, which runs under `set -u`. A valid value keeps this test about credentials;
    # the version filter has its own guard below.
    env = {"PATH": "/usr/bin:/bin", "VERSION": "0.7.43"}
    if dedicated is not None:
        env["CLOUDSMITH_API_KEY"] = dedicated
    if cargo is not None:
        env["CARGO_REGISTRIES_ZER07LABS_TOKEN"] = cargo
    # Plain `bash -c`, NOT `bash -e`: the workflow sets its own `set -euo pipefail`, and running it
    # under an externally-imposed -e would hide the removal of that line.
    return subprocess.run(
        ["bash", "-c", _token_script()],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


# ── the credential resolution, executed ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("dedicated", "cargo", "expected"),
    [
        ("cs-key", "", "cs-key"),
        ("", "Bearer cargo-tok", "cargo-tok"),
        ("", "cargo-tok", "cargo-tok"),
        ("Bearer cs-key", "", "cs-key"),
        ("cs-key", "Bearer cargo-tok", "cs-key"),
    ],
    ids=["dedicated-only", "cargo-with-bearer", "cargo-without-bearer", "dedicated-with-bearer", "both-set"],
)
def test_the_bearer_prefix_is_stripped_from_whichever_source_is_used(
    dedicated: str, cargo: str, expected: str
) -> None:
    """A `Bearer ` prefix reaches Cloudsmith as `X-Api-Key: Bearer …` and 401s.

    `cargo-with-bearer` is the case that was broken: the org Cargo token carries the prefix, and
    `publish.yml:369-371` strips it while this workflow did not.
    """
    p = _run(dedicated, cargo)
    assert p.returncode == 0, f"the step refused a usable credential: {p.stdout}{p.stderr}"
    assert f"TOKEN=[{expected}]" in p.stdout, (
        f"resolved token is not {expected!r} — got {p.stdout.strip()!r}. A token that still "
        f"carries 'Bearer ' authenticates as nothing and every call 401s."
    )


@pytest.mark.parametrize(
    ("dedicated", "cargo"),
    [("", ""), (None, None), ("", "Bearer "), ("Bearer ", "")],
    ids=["both-empty", "both-unset", "cargo-is-only-the-prefix", "dedicated-is-only-the-prefix"],
)
def test_an_unusable_credential_refuses_rather_than_proceeding(
    dedicated: str | None, cargo: str | None
) -> None:
    """Fail-closed must survive the strip.

    `cargo-is-only-the-prefix` is the case the fix could plausibly have broken: stripping turns
    `"Bearer "` into `""`, and an empty token must be refused rather than sent. `both-unset` covers
    `set -u`, under which a bare `${VAR#Bearer }` on an absent variable aborts.
    """
    p = _run(dedicated, cargo)
    assert p.returncode != 0, (
        f"the step accepted an unusable credential and would have proceeded to the query and "
        f"then the DELETE loop: {p.stdout.strip()!r}"
    )
    assert "No Cloudsmith credential" in p.stdout + p.stderr, (
        "the step failed, but not with its own refusal — so it failed for some other reason and "
        f"this test is not proving what it claims: {p.stdout}{p.stderr}"
    )


def test_the_token_resolution_does_not_rely_on_an_and_list() -> None:
    """`publish.yml` resolves with `[ -z … ] && TOKEN=…`; that step has no `set -e`, this one does.

    The AND-list happens to be safe here (a failing non-final command in an AND-OR list does not
    trip `-e`), but it is safe by a rule most readers do not hold, and it becomes the step's exit
    status if it is ever moved last. The explicit `if` is immune to both.
    """
    run = _step()["run"]
    code = [ln for ln in run.splitlines() if not ln.strip().startswith("#")]
    offenders = [ln for ln in code if "&&" in ln and "TOKEN=" in ln]
    assert not offenders, (
        f"the token resolution uses an AND-list under `set -euo pipefail`: {offenders}. Use the "
        f"explicit `if`, which does not depend on the AND-OR exit-status rule."
    )
    assert "set -euo pipefail" in run, (
        "yank.yml's step lost `set -euo pipefail`. Every guard in this file assumes it, and "
        "without it a failed curl no longer aborts before the DELETE loop."
    )


# ── the destructive scoping, which must not widen by accident ─────────────────────────────────


def test_the_delete_scope_stays_exactly_as_narrow_as_it_was() -> None:
    """Three filters stand between a mistyped input and deleting the wrong artifact.

    Asserted individually so a failure names which one moved. `0.7.4` must not match `0.7.43`,
    the format allowlist must stay python+npm, and the name must match exactly `seam-sdk` after
    stripping an npm scope — the org's Cargo crates live in the same Cloudsmith repository and
    must remain unreachable from this workflow.
    """
    run = _step()["run"]
    for needle, why in (
        ('select(.version == env.VERSION)', "exact version equality — a prefix match would take 0.7.43 when asked for 0.7.4"),
        ('select(.format == "python" or .format == "npm")', "the format allowlist that keeps Cargo crates out of reach"),
        ('sub("^@[^/]+/"; "")) == "seam-sdk"', "exact name match after stripping the npm scope"),
    ):
        assert needle in run, f"yank.yml no longer applies: {why}"


def test_nothing_automatic_can_ever_trigger_a_yank() -> None:
    """`workflow_dispatch` only, and dry-run is the default.

    A yank is irreversible on a registry. The dry-run default is what makes the first invocation
    during an incident a listing rather than a deletion.
    """
    wf = yaml.safe_load(YANK.read_text(encoding="utf-8"))
    triggers = wf[True] if True in wf else wf["on"]
    assert set(triggers) == {"workflow_dispatch"}, (
        f"yank.yml is reachable by {sorted(triggers)} — it must be workflow_dispatch only, or a "
        f"push or schedule could delete published artifacts."
    )
    assert triggers["workflow_dispatch"]["inputs"]["dry_run"]["default"] == "true", (
        "dry_run no longer defaults to true, so a dispatch that omits it would DELETE."
    )
