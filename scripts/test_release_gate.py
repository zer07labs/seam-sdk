"""The framing gate can only gate a release if it runs where the repo exists.

`release-on-runtime.yml` refuses to tag when the runtime's wire framing is not one this SDK
implements — it is the one gate that PREVENTS a 0.7.17 rather than reporting one afterwards. It
does that by reading `contract/wire-framing.json` out of the checkout.

It was originally placed before the token mint, on the correct instinct that a refusal should
leave no commit, no tag, and nothing published. But `actions/checkout` has to follow the mint (it
needs the app token), so "before the mint" also meant "before the repo exists". The gate read a
file into an empty working directory, `set -euo pipefail` killed the job, and every release from
2026-08-24 onward failed — four in a row — without the comparison ever running once.

It failed CLOSED, so nothing wrong was published. That is exactly what made it survive: a gate
that always refuses looks, from the outside, like a gate that is working.

These assertions pin the two constraints that were in tension, so the next reorder cannot satisfy
one by breaking the other:

  * the gate runs AFTER checkout   — otherwise it cannot read its own contract file
  * the gate runs BEFORE the stamp — otherwise a refusal arrives after the damage

Run: `python -m pytest scripts/test_release_gate.py -q`
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
RELEASE = REPO / ".github" / "workflows" / "release-on-runtime.yml"

GATE = "The runtime's wire framing must be one this SDK implements"
CHECKOUT = "actions/checkout"
STAMP = "Bump both packages to the runtime version"
TAG = "Commit + tag (triggers publish.yml)"


def _steps() -> list[dict]:
    return yaml.safe_load(RELEASE.read_text())["jobs"]["release"]["steps"]


def _index(predicate, what: str) -> int:
    for i, step in enumerate(_steps()):
        if predicate(step):
            return i
    raise AssertionError(
        f"{what} is no longer in release-on-runtime.yml — this guard is stale"
    )


def _gate_index() -> int:
    return _index(lambda s: s.get("name") == GATE, f"the framing gate ({GATE!r})")


def _checkout_index() -> int:
    return _index(lambda s: CHECKOUT in str(s.get("uses", "")), "actions/checkout")


def test_the_framing_gate_runs_after_checkout() -> None:
    """The regression itself: a gate reading a repo file before the repo is cloned."""
    gate, checkout = _gate_index(), _checkout_index()
    assert gate > checkout, (
        f"the framing gate is step {gate}, checkout is step {checkout} — the gate reads "
        "contract/wire-framing.json out of the checkout, so running first means it crashes on a "
        "missing file and fails every release closed, which is what happened on 2026-08-24"
    )


def test_the_framing_gate_runs_before_anything_is_stamped_or_tagged() -> None:
    """The invariant the original ordering was protecting — a refusal must leave nothing behind."""
    gate = _gate_index()
    for name in (STAMP, TAG):
        step = _index(lambda s, n=name: s.get("name") == n, f"the {name!r} step")
        assert gate < step, (
            f"the framing gate is step {gate} but {name!r} is step {step} — a refusal that arrives "
            "after the version is stamped or the tag is pushed is not a gate, it is a report"
        )


def test_the_gate_still_reads_a_file_out_of_the_repo() -> None:
    """Guards the guard: the ordering constraint above only matters while this is true.

    If the gate is ever rewritten to take its inputs entirely from the dispatch payload, the
    after-checkout assertion becomes vacuous rather than false — it would keep passing while
    protecting nothing. Failing here forces that rewrite to revisit this file deliberately.
    """
    script = next(s for s in _steps() if s.get("name") == GATE)["run"]
    assert "contract/wire-framing.json" in script, (
        "the framing gate no longer reads contract/wire-framing.json — if that is intentional, "
        "test_the_framing_gate_runs_after_checkout is now asserting nothing and should be revisited"
    )


def test_every_repo_file_the_gate_reads_actually_exists() -> None:
    """The direct form of the failure: FileNotFoundError, from a path nothing checks."""
    script = next(s for s in _steps() if s.get("name") == GATE)["run"]
    paths = set(re.findall(r"open\('([^']+)'\)", script))
    assert paths, (
        "no open('...') call found in the gate — this guard can no longer see its inputs"
    )
    for rel in sorted(paths):
        assert (REPO / rel).is_file(), (
            f"the framing gate reads {rel!r}, which does not exist in the repo — that is the exact "
            "shape of the 2026-08-24 failure, just from a missing file instead of a missing checkout"
        )


# ─── The stale-latch branch, and the manual-release path it must not kill ──────────────────────
#
# `runtime_emits_version` is an adoption latch: while it is false, a dispatch carrying NO
# wire_framing_version is downgraded to a warning and the release tags anyway. Correct ONLY while
# the runtime genuinely does not emit the field.
#
# seam-runtime#418 landed the field on 2026-08-26 and the latch sat false until 2026-09-03 — a week
# in which the one gate that PREVENTS a 0.7.17 could not refuse anything. Nothing watched it.
#
# The check that closes this is NOT a comparison between two fields of wire-framing.json. That was
# the first design and it is circular: the latch and any recorded tracking-issue state go stale
# together, so it would have been green through the entire week. The dispatch is the only witness —
# a payload that CARRIES the field proves the runtime emits it, so a latch reading false at that
# moment is provably stale.
#
# Flipping the latch also has a non-obvious cost, which is why the manual path is pinned here too:
# `workflow_dispatch` has no client_payload, so with the latch true an absent framing version would
# hit the "a field that stopped being emitted is a REGRESSION" branch and refuse EVERY manual run —
# killing the recovery path exactly when it is reached, after the automatic dispatch already failed.
#
# These tests run the gate's REAL script against a synthetic contract file, so they assert
# behaviour (exit codes) rather than the presence of some text in the YAML.


def _gate_script() -> str:
    return next(s for s in _steps() if s.get("name") == GATE)["run"]


def _run_gate(
    *,
    dispatched: str,
    latched: bool,
    supported: int = 2,
    event: str = "repository_dispatch",
    write_contract: bool = True,
) -> subprocess.CompletedProcess:
    """Execute the gate exactly as the workflow does, in a scratch tree we control.

    `write_contract=False` reproduces the 2026-08-24 failure — the gate running where its own
    contract file does not exist — which is the condition it must fail CLOSED on.
    """
    with tempfile.TemporaryDirectory() as tmp:
        contract = Path(tmp) / "contract"
        contract.mkdir()
        if write_contract:
            (contract / "wire-framing.json").write_text(
                json.dumps(
                    {
                        "supported": supported,
                        "runtime_emits_version": latched,
                        "runtime_adoption_issue": "test fixture",
                    }
                )
            )
        return subprocess.run(
            ["bash", "-c", _gate_script()],
            cwd=tmp,
            env={"PATH": os.environ["PATH"], "DISPATCHED": dispatched, "EVENT": event},
            capture_output=True,
            text=True,
        )


def test_a_dispatch_that_carries_the_field_refuses_a_false_latch() -> None:
    """The week-long staleness, caught from the only data that cannot itself go stale."""
    r = _run_gate(dispatched="2", latched=False)
    assert r.returncode == 1, (
        "the dispatch carried wire_framing_version=2 — proof the runtime emits it — while the "
        f"latch read false, and the gate exited {r.returncode} instead of refusing. That is the "
        "2026-08-26..09-03 state, in which an absent field would have been warned past and tagged"
    )
    assert "STALE" in r.stdout, (
        f"the refusal does not say the latch is stale:\n{r.stdout}"
    )


def test_a_manual_run_without_the_input_asks_for_it_instead_of_blaming_the_runtime() -> (
    None
):
    """The regression the latch flip would otherwise have introduced.

    `workflow_dispatch` has no `client_payload`, so DISPATCHED is empty on every manual run. With
    the latch true and no special case, that lands on the "a field that stopped being emitted is a
    REGRESSION" branch — so the documented manual fallback refuses unconditionally, and the operator
    is sent to investigate the runtime when the actual fix is to fill in one input.
    """
    r = _run_gate(dispatched="", latched=True, event="workflow_dispatch")
    assert r.returncode == 1, (
        "a manual run with no framing version must not tag blindly"
    )
    assert "MANUAL release run" in r.stdout, (
        "a manual run with no wire_framing_version got the wrong diagnosis — it should ask for the "
        f"input, not report a runtime regression:\n{r.stdout}"
    )
    assert "REGRESSION" not in r.stdout


def test_a_manual_run_that_supplies_the_input_releases_normally() -> None:
    """The recovery path stays usable — that is the point of the special case above."""
    r = _run_gate(dispatched="2", latched=True, supported=2, event="workflow_dispatch")
    assert r.returncode == 0, (
        f"a manual run supplying the correct framing version exited {r.returncode}; the fallback "
        f"is now unusable, which is worse than the hole it was closing:\n{r.stdout}"
    )


def test_a_manual_run_still_catches_a_framing_mismatch() -> None:
    """The manual path must not become a way around the gate."""
    r = _run_gate(dispatched="3", latched=True, supported=2, event="workflow_dispatch")
    assert r.returncode == 1, (
        "a manual run with the wrong framing version must still refuse"
    )
    assert "WIRE FRAMING MISMATCH" in r.stdout


def test_the_staged_adoption_window_still_works_on_both_paths() -> None:
    """The latch's legitimate use must survive: no field emitted yet, so nothing to be stale about."""
    for event in ("repository_dispatch", "workflow_dispatch"):
        r = _run_gate(dispatched="", latched=False, event=event)
        assert r.returncode == 0, (
            f"a {event} with no wire_framing_version and latch=false exited {r.returncode}; the "
            "staged-adoption window is why the latch exists and must keep warning, not refusing"
        )
        assert "warning" in r.stdout.lower()


def test_a_field_that_stopped_being_emitted_is_still_a_regression() -> None:
    """The branch that already existed, re-pinned now that the latch is actually true."""
    r = _run_gate(dispatched="", latched=True)
    assert r.returncode == 1, (
        "the runtime is known to emit wire_framing_version and the automatic dispatch carried none "
        f"— that is a handshake regression, but the gate exited {r.returncode}"
    )
    assert "REGRESSION" in r.stdout


def test_the_agreeing_case_still_tags() -> None:
    r = _run_gate(dispatched="2", latched=True, supported=2)
    assert r.returncode == 0, (
        f"framing agrees but the gate exited {r.returncode}:\n{r.stdout}"
    )


def test_a_framing_mismatch_still_refuses() -> None:
    r = _run_gate(dispatched="3", latched=True, supported=2)
    assert r.returncode == 1, (
        f"the runtime carries framing v3 and this SDK implements v2; the gate exited {r.returncode}"
    )


def test_a_stale_latch_is_diagnosed_before_a_framing_mismatch() -> None:
    """Both refuse, so this is about the message, not the verdict.

    With latch=false AND a version mismatch, the stale-latch branch fires first and the MISMATCH
    diagnostic never prints. That is deliberate — the latch is the thing that must be fixed before
    the comparison means anything — but it is a two-step diagnosis, so pin it rather than leaving
    the ordering to be rediscovered by whoever hits it during a release.
    """
    r = _run_gate(dispatched="3", latched=False, supported=2)
    assert r.returncode == 1
    assert "STALE" in r.stdout and "WIRE FRAMING MISMATCH" not in r.stdout, (
        "the precedence between the stale-latch and mismatch refusals changed; both still refuse, "
        f"but the operator now sees a different first message:\n{r.stdout}"
    )


def test_a_manual_run_during_staged_adoption_does_not_claim_the_latch_is_stale() -> (
    None
):
    """The stale-latch claim is "the payload proves the RUNTIME emits the field" — false on a manual run.

    `$DISPATCHED` has two sources since the manual fallback gained an input. Only one of them is
    evidence about the runtime. Firing the stale-latch refusal on the other tells an operator to flip
    the latch on no evidence, and every automatic dispatch for the rest of a legitimate staged-adoption
    window then hits the REGRESSION branch — the gate arming itself on a false premise.
    """
    r = _run_gate(dispatched="2", latched=False, supported=2, event="workflow_dispatch")
    assert "STALE" not in r.stdout, (
        "a manual run supplied the framing version by hand and the gate called the latch stale; "
        f"that value is an operator assertion, not proof the runtime emits anything:\n{r.stdout}"
    )
    assert r.returncode == 0, (
        f"a manual release during staged adoption, with a framing version that matches, exited "
        f"{r.returncode}; it should fall through to the comparison:\n{r.stdout}"
    )


def test_a_manual_run_during_staged_adoption_still_catches_a_mismatch() -> None:
    """Falling through must mean comparing, not waving through."""
    r = _run_gate(dispatched="3", latched=False, supported=2, event="workflow_dispatch")
    assert r.returncode == 1 and "WIRE FRAMING MISMATCH" in r.stdout, (
        f"exit={r.returncode}; the manual staged-adoption path must still refuse a mismatch:\n{r.stdout}"
    )


# ─── The YAML plumbing the env-injected tests above cannot see ────────────────────────────────
#
# `_run_gate` injects DISPATCHED and EVENT directly, which is what makes the branch tests fast and
# hermetic — but it means NOTHING above exercises the `${{ ... }}` expressions that populate them.
# Both mutations below were demonstrated to leave all the branch tests green while reintroducing the
# exact defect they exist to prevent:
#
#   * deleting the `wire_framing_version` input declaration
#   * deleting `|| github.event.inputs.wire_framing_version` from the env expression
#
# The second is worse than having no fix at all: DISPATCHED can then never be non-empty on a manual
# run, so the gate tells the operator to set an input it is ignoring, and they loop.


def _gate_step() -> dict:
    return next(s for s in _steps() if s.get("name") == GATE)


def test_the_manual_fallback_declares_a_wire_framing_version_input() -> None:
    wf = yaml.safe_load(RELEASE.read_text())
    # PyYAML is YAML 1.1, so the `on:` key parses as the boolean True. Same defensive form as
    # scripts/test_yank_gate.py, so a YAML-1.2 parser does not turn this into a KeyError.
    on = wf[True] if True in wf else wf["on"]
    inputs = on["workflow_dispatch"]["inputs"]
    assert "wire_framing_version" in inputs, (
        "workflow_dispatch no longer declares wire_framing_version. With runtime_emits_version true "
        "the framing gate refuses a manual run that supplies no framing version, so removing the "
        "input makes the documented manual fallback permanently unusable"
    )


def test_the_gate_reads_the_manual_input_as_well_as_the_dispatch_payload() -> None:
    dispatched = _gate_step()["env"]["DISPATCHED"]
    assert "client_payload.wire_framing_version" in dispatched, (
        f"the gate stopped reading the repository-dispatch payload: {dispatched!r}"
    )
    assert "inputs.wire_framing_version" in dispatched, (
        f"the gate's DISPATCHED expression ({dispatched!r}) no longer falls back to the manual "
        "input, so DISPATCHED can never be non-empty on a workflow_dispatch run — the gate would "
        "ask the operator for an input it then ignores, and refuse on every attempt"
    )


def test_the_gate_can_tell_the_two_trigger_types_apart() -> None:
    """Two branches key on EVENT — the MANUAL diagnosis and the stale-latch scoping.

    Losing it merges the manual and automatic paths: the manual run would be told the runtime
    regressed, and an operator-typed framing version would be read as proof about the runtime.
    """
    assert "github.event_name" in _gate_step()["env"].get("EVENT", ""), (
        "the gate no longer receives github.event_name, so it cannot distinguish an operator-typed "
        "framing version from one the runtime sent — the distinction two of its branches rest on"
    )


def test_the_automatic_release_trigger_is_still_declared() -> None:
    """The stale-latch branch is scoped to `repository_dispatch`, so its reachability now depends on
    this trigger existing. Deleting the trigger would make that branch dead code silently — the same
    shape as the plumbing gaps above, one cell over. (It would also stop all automatic releases, so
    the practical risk is low; this pins the coupling rather than the release path.)
    """
    wf = yaml.safe_load(RELEASE.read_text())
    on = wf[True] if True in wf else wf["on"]
    assert "repository_dispatch" in on, (
        "release-on-runtime.yml no longer declares a repository_dispatch trigger, so the gate's "
        "stale-latch branch — which fires only on that event — can never run"
    )


def test_an_unreadable_contract_file_fails_closed() -> None:
    """The gate must refuse when it cannot read the thing it is comparing against.

    This is the 2026-08-24 failure's condition, and until 2026-09-03 it did not matter much: with
    the latch false, that cell warned and tagged anyway, so `set -e` was not load-bearing. Arming
    the latch changed that. The refusal now rests entirely on `set -e` aborting the `python3`
    substitution — drop the `-e` and `LATCHED` becomes the empty string, which is not "true", so
    the gate takes the staged-adoption branch and **tags a release having read nothing at all**.

    That is the fail-open shape this whole phase exists to close, one cell over from the four
    plumbing cells above, so it is asserted by behaviour rather than by grepping for `set -e`:
    what matters is that the gate refuses, not which shell option makes it.
    """
    for event in ("repository_dispatch", "workflow_dispatch"):
        for dispatched in ("", "2"):
            r = _run_gate(
                dispatched=dispatched, latched=True, event=event, write_contract=False
            )
            assert r.returncode != 0, (
                f"the gate exited 0 with no contract/wire-framing.json to read "
                f"(event={event}, dispatched={dispatched!r}) — it cannot have compared anything, "
                f"so tagging here publishes on an unverified framing:\n{r.stdout}{r.stderr}"
            )
