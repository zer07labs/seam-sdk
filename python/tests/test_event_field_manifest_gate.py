"""The `seam.event.v1` field-surface gate — issue #88.

`contract/field-manifest.txt` declares the `seam.api.v1` field surface. `seam.event.v1` — the outbox
stream `seam-connectors` consume and `verify/` reads — had no equivalent: four named presence probes
out of ninety fields, and nothing at all on an addition, a removal or a rename anywhere else. A field
could land on the outbox contract and reach every consumer through this SDK with every gate green.
`contract/event-field-manifest.txt` closes that, and this file is what proves it closed.

Mirrors `test_field_manifest_gate.py` down to the `_run`/manifests fixture shape, and for the same
non-negotiable reason: **every case drives the REAL script against SCRATCH COPIES of the stubs.**
`python/seam_sdk/_gen` and `ts/gen` are gitignored, so a test that corrupted them could not restore
them with git and recovery would need `make generate` plus a BSR login. `SEAM_PY_EV`, `SEAM_TS_EV`
and `SEAM_EVENT_FIELD_MANIFEST` exist for that, and nothing in CI sets them.

The second discipline is that no case asserts against the ambient checkout. Every manifest is written
from the scratch copies the case itself constructed, so a baseline is what this test built, never what
the machine happened to have — the environment-dependence failure `plans/gate-blindness-hardening.md`
records (passed locally, failed in CI).
"""

from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).parents[2]
SCRIPT = REPO / "scripts" / "check-contract.sh"
PY_EV = (
    REPO
    / "python"
    / "seam_sdk"
    / "_gen"
    / "seam"
    / "event"
    / "v1"
    / "seam_event_pb2.pyi"
)
TS_EV = REPO / "ts" / "gen" / "seam" / "event" / "v1" / "seam_event_pb.ts"
PY_API = REPO / "python" / "seam_sdk" / "_gen" / "seam" / "api" / "v1" / "seam_pb2.pyi"
TS_API = REPO / "ts" / "gen" / "seam" / "api" / "v1" / "seam_pb.ts"
COMMITTED = REPO / "contract" / "event-field-manifest.txt"

#: Exit codes this file asserts on. Named rather than inlined, because the whole argument for 8 is
#: that it is NOT 6 — a bare integer literal in an assertion does not carry that.
OK = 0
EVENT_SURFACE_DISAGREES = 8
PRECONDITION_FAILED = 7


def _require_stubs() -> None:
    for f in (PY_EV, TS_EV, PY_API, TS_API):
        if not f.exists():
            pytest.skip(f"generated stubs absent ({f}); run 'make generate' first")


def _run(
    scratch: dict[str, pathlib.Path], *args: str, stream: str = "1"
) -> subprocess.CompletedProcess:
    """Run the real script with every file it reads or writes redirected into a scratch directory.

    `stream="0"` drops the four presence probes back to report-only. Exactly one case needs it, and
    needs it to separate two things every other run decides together — see
    `test_the_presence_probes_still_refuse_what_the_manifest_gate_accepts`.
    """
    env = {
        **os.environ,
        "STREAM": stream,
        "EVENTS": "1",
        "SEAM_PY_EV": str(scratch["py_ev"]),
        "SEAM_TS_EV": str(scratch["ts_ev"]),
        "SEAM_PY_GEN": str(scratch["py_api"]),
        "SEAM_TS_GEN": str(scratch["ts_api"]),
        "SEAM_EVENT_FIELD_MANIFEST": str(scratch["event_manifest"]),
        "SEAM_FIELD_MANIFEST": str(scratch["field_manifest"]),
        "SEAM_RPC_MANIFEST": str(scratch["rpc_manifest"]),
        # Always a scratch path: `--write-manifest` DELETES this file, and the committed one records
        # the real pre-ACDP api lag. It is never created here, so the api side simply has no recorded
        # lag to downgrade against — which is correct, since these manifests are written from the
        # same stubs they are then compared to.
        "SEAM_EXPECTED_LOCAL_LAG": str(scratch["lag"]),
    }
    return subprocess.run(
        ["bash", str(SCRIPT), *args], cwd=REPO, env=env, capture_output=True, text=True
    )


@pytest.fixture
def scratch(tmp_path: pathlib.Path):
    """Copies of all four stub files plus three scratch manifests written FROM those copies.

    Writing the manifests from the copies rather than using the committed ones is what makes a
    mutation the only difference between the baseline and the assertion. Using the committed api
    manifest here would drag in the recorded five-field ACDP lag and make every case exit 6 for a
    reason none of them are about.
    """
    _require_stubs()
    s = {
        "py_ev": tmp_path / "seam_event_pb2.pyi",
        "ts_ev": tmp_path / "seam_event_pb.ts",
        "py_api": tmp_path / "seam_pb2.pyi",
        "ts_api": tmp_path / "seam_pb.ts",
        "event_manifest": tmp_path / "event-field-manifest.txt",
        "field_manifest": tmp_path / "field-manifest.txt",
        "rpc_manifest": tmp_path / "rpc-manifest.txt",
        "lag": tmp_path / "expected-local-lag.txt",
    }
    for key, src in (
        ("py_ev", PY_EV),
        ("ts_ev", TS_EV),
        ("py_api", PY_API),
        ("ts_api", TS_API),
    ):
        s[key].write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    r = _run(s, "--write-manifest")
    assert r.returncode == OK, r.stderr
    assert s["event_manifest"].exists()
    return s


def _event_fields(manifest: pathlib.Path) -> list[str]:
    return sorted(
        line.strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


# A real ChainHeadAttestation field in both event stub trees, used as a known-good anchor to append
# after or delete outright. Lifted verbatim from the generated files rather than hand-typed, so a
# mutation that stops matching means the stubs changed shape — which is itself worth knowing.
#
# `digest_schema` and not `signature`, which reads more naturally as "the tail": `signature` also
# appears on `DecisionSealed`, so `SIGNATURE_FIELD_NUMBER` occurs twice in the .pyi and the
# uniqueness assertion below catches it. Every mutation here needs a line it can identify, not one it
# can merely find.
PY_ANCHOR = "    DIGEST_SCHEMA_FIELD_NUMBER: _ClassVar[int]\n"
TS_ANCHOR = "   * @generated from field: uint32 digest_schema = 5;\n"


def _append_field_both(
    s: dict[str, pathlib.Path], name: str = "notary_receipt"
) -> None:
    py = s["py_ev"].read_text(encoding="utf-8")
    assert py.count(PY_ANCHOR) == 1, (
        "the python event stub no longer has the expected anchor"
    )
    s["py_ev"].write_text(
        py.replace(
            PY_ANCHOR, PY_ANCHOR + f"    {name.upper()}_FIELD_NUMBER: _ClassVar[int]\n"
        ),
        encoding="utf-8",
    )
    ts = s["ts_ev"].read_text(encoding="utf-8")
    assert ts.count(TS_ANCHOR) == 1, (
        "the ts event stub no longer has the expected anchor"
    )
    s["ts_ev"].write_text(
        ts.replace(
            TS_ANCHOR, TS_ANCHOR + f"   * @generated from field: bytes {name} = 99;\n"
        ),
        encoding="utf-8",
    )


def test_a_field_added_to_both_event_trees_is_refused_with_exit_8(scratch) -> None:
    """The headline: an ADDITIVE field on the outbox contract is now a refusal, not a silent pass.

    Additive is the case that matters most and the one nothing caught before. `buf breaking` passes
    it upstream by design, the four presence probes never mention it, and `check_vendored_spec.py`
    only sees it if the runtime also edited the markdown spec doc.
    """
    _append_field_both(scratch)
    r = _run(scratch)

    assert r.returncode == EVENT_SURFACE_DISAGREES, (
        f"expected exit {EVENT_SURFACE_DISAGREES}, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    out = r.stdout + r.stderr
    assert "ChainHeadAttestation/notary_receipt" in out, out
    # BOTH languages must name it: the whole design reads the two trees independently, and a report
    # that named one would mean the other's extractor went blind while the gate still went red.
    assert out.count("ChainHeadAttestation/notary_receipt") >= 2, out
    assert "NOT IN THE MANIFEST" in out, out


def test_a_field_deleted_from_both_event_trees_is_reported_missing_with_exit_8(
    scratch,
) -> None:
    """The other direction. A REMOVED field breaks every consumer holding it, so it must never be
    quietly rewritten away by the escape hatch."""
    for key, anchor in (("py_ev", PY_ANCHOR), ("ts_ev", TS_ANCHOR)):
        text = scratch[key].read_text(encoding="utf-8")
        scratch[key].write_text(text.replace(anchor, ""), encoding="utf-8")
    r = _run(scratch)

    assert r.returncode == EVENT_SURFACE_DISAGREES, (
        f"{r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    out = r.stdout + r.stderr
    assert "ChainHeadAttestation/digest_schema" in out, out
    assert "MISSING from the" in out, out


def test_a_field_added_to_one_event_tree_only_is_named_as_generation_skew(
    scratch,
) -> None:
    """python and ts disagreeing with EACH OTHER is a different failure from either disagreeing with
    the manifest, and must not be reported as if it were one: `--write-manifest` writes from Python
    only, so applying the escape to a skew canonicalises whichever tree happens to be ahead."""
    py = scratch["py_ev"].read_text(encoding="utf-8")
    scratch["py_ev"].write_text(
        py.replace(PY_ANCHOR, PY_ANCHOR + "    SKEWED_FIELD_NUMBER: _ClassVar[int]\n"),
        encoding="utf-8",
    )
    r = _run(scratch)

    assert r.returncode == EVENT_SURFACE_DISAGREES, (
        f"{r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    out = r.stdout + r.stderr
    assert "GENERATION SKEW" in out, out
    assert "python has it, ts does not: ChainHeadAttestation/skewed" in out, out


@pytest.mark.parametrize(
    ("key", "anchor", "addition", "what"),
    [
        pytest.param(
            "py_ev",
            "class ChainHeadAttestation(_message.Message):\n",
            "    class Nested(_message.Message):\n        __slots__ = ()\n"
            "        INNER_FIELD_NUMBER: _ClassVar[int]\n",
            "NESTED MESSAGE in python",
            id="python-nested-message",
        ),
        pytest.param(
            "py_ev",
            "class ChainHeadAttestation(_message.Message):\n",
            "class Verdict(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):\n"
            "    __slots__ = ()\nUNKNOWN: Verdict\n",
            "ENUM in python",
            id="python-enum",
        ),
        pytest.param(
            "ts_ev",
            'export type ChainHeadAttestation = Message<"seam.event.v1.ChainHeadAttestation"> & {\n',
            'export type Outer_Inner = Message<"seam.event.v1.Outer.Inner"> & {\n};\n',
            "NESTED MESSAGE in ts",
            id="ts-nested-message",
        ),
        pytest.param(
            "ts_ev",
            'export type ChainHeadAttestation = Message<"seam.event.v1.ChainHeadAttestation"> & {\n',
            "/**\n * @generated from enum seam.event.v1.Verdict\n */\nexport enum Verdict {\n}\n",
            "ENUM in ts",
            id="ts-enum",
        ),
    ],
)
def test_an_event_enum_or_nested_message_fails_the_precondition_with_exit_7(
    scratch, key, anchor, addition, what
) -> None:
    """Zero enums and zero nested messages are ASSERTED, never assumed.

    Both would fail silently AND symmetrically if they were only assumed: a nested message's fields
    are dropped from Python and TypeScript at once by the shared extractors, and an enum value has
    nothing on either side to be compared against. An empty event-enum partition compared in both
    directions would pass — for the wrong reason, and would go on passing after the contract grew an
    enum. That is the exact vacuity `plans/gate-blindness-hardening.md` is written against.
    """
    text = scratch[key].read_text(encoding="utf-8")
    assert text.count(anchor) == 1, "the event stub no longer has the expected anchor"
    scratch[key].write_text(text.replace(anchor, addition + anchor), encoding="utf-8")
    r = _run(scratch)

    assert r.returncode == PRECONDITION_FAILED, (
        f"{r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    out = r.stdout + r.stderr
    assert "structural precondition of the EVENT field gate failed" in out, out
    assert what in out, out


def test_both_surfaces_disagreeing_at_once_reports_both_and_exits_8(scratch) -> None:
    """This is what pins the PLACEMENT decision — together with the three single-surface cases above,
    not alone.

    There are two wrong placements and they are caught by different tests, which is worth stating
    since a reader looking for one decisive case will not find it:

      * **Exiting 8 at the event probe, before the api report** — caught HERE, and only here. The api
        report never prints, so `AuditEntry/bogus_api` is absent from the output. Measured against a
        variant of the script built to do exactly that.
      * **Reporting the event surface only after the api `exit 6`** — caught by the three cases above,
        which exit 0 instead of 8 because the event report never reaches a decision. Measured the
        same way. This case still passes under that variant, since the api failure carries the block.

    The exit code itself is the third claim: 8, not 6, even though the api surface is also broken
    here. 6 is what CI and CLAUDE.md's Gotchas both say to read past, so an event regression exiting
    6 arrives wearing the code that means "ignore this".
    """
    _append_field_both(scratch)
    api = scratch["py_api"].read_text(encoding="utf-8")
    anchor = "class AuditEntry(_message.Message):\n"
    assert api.count(anchor) == 1
    scratch["py_api"].write_text(
        api.replace(anchor, anchor + "    BOGUS_API_FIELD_NUMBER: _ClassVar[int]\n"),
        encoding="utf-8",
    )
    r = _run(scratch)

    out = r.stdout + r.stderr
    assert "AuditEntry/bogus_api" in out, f"the api report is missing:\n{out}"
    assert "ChainHeadAttestation/notary_receipt" in out, (
        f"the event report is missing:\n{out}"
    )
    assert r.returncode == EVENT_SURFACE_DISAGREES, (
        f"exit {r.returncode}: an event disagreement must win over the api one, or a real event "
        f"regression arrives wearing the exit code that means 'the known local lag'.\n{out}"
    )


def test_the_clean_path_says_so_out_loud(scratch) -> None:
    """ "Checked and clean" must be distinguishable from "never ran".

    This is the failure mode the placement decision is guarding against, so silence is not an
    acceptable success signal: a probe that never executed also produces no complaint.
    """
    r = _run(scratch)
    assert r.returncode == OK, f"{r.returncode}\n{r.stdout}\n{r.stderr}"
    assert "the event field surface matches" in r.stdout, r.stdout
    # Counted from the manifest this case itself wrote, not hard-coded. 90 is an ambient number — it
    # is what this checkout happens to carry — so pinning it here would redden this case on a
    # legitimate contract growth for a reason it is not about. What it asserts is that the positive
    # line names the size of the surface actually compared.
    n = len(_event_fields(scratch["event_manifest"]))
    assert n > 0, "the scratch manifest is empty; this case would be asserting nothing"
    for lang in ("python", "ts"):
        assert f"PRESENT all {n} declared seam.event.v1 fields [{lang}]" in r.stdout, (
            r.stdout
        )


def test_the_committed_manifest_is_not_empty_and_names_every_message() -> None:
    """The anti-vacuity floor. Every comparison in this file is a SET comparison, and a manifest
    emptied by a bad write would make all of them pass — the gate would be green precisely because it
    declares nothing. Asserted against the committed file, not a scratch copy, because it is the
    committed file that CI compares against.

    Deliberately NOT guarded by `_require_stubs()`: it reads only the committed manifest, so a tree
    without generated stubs can still check it. Skipping here would let the one test that guarantees
    the manifest is non-empty go quiet on exactly the checkout least able to notice.
    """
    fields = _event_fields(COMMITTED)
    assert len(fields) == 90, f"expected 90 declared event fields, found {len(fields)}"
    messages = {line.split("/")[0] for line in fields}
    assert messages == {
        "AuditEntryEvent",
        "AuthorizeEvaluated",
        "BudgetBreach",
        "ChainHeadAttestation",
        "DecisionSealed",
        "ErasureCertificate",
        "LearningDecision",
        "LearningOutcome",
        "PolicyKey",
        "SeamEvent",
        "SessionLifecycle",
    }, sorted(messages)
    assert not any("#" in line for line in fields), (
        "a field line carrying '#' would be read as an enum line by the api manifest's stripper if "
        "these files were ever merged — see the manifest header's reason 1"
    )


def test_the_presence_probes_still_refuse_what_the_manifest_gate_accepts(
    scratch,
) -> None:
    """The manifest does not replace the four presence probes — proven by a case only they catch.

    Grepping the script's source for the four field names cannot make this claim, and used to be
    what this test did. Those names also appear in the header comment describing probe 2 and in the
    comment above the field gate saying the probes must not be deleted, so the grep passed with the
    entire probe loop removed: a guard that could not fire.

    The mutation instead RENAMES `SeamEvent.session_lifecycle` in both event trees and then records
    the rename with `--write-manifest`. The manifest gate is left with nothing to say — trees and
    manifest agree exactly, and the second run below asserts it says so out loud. The probe is the
    only thing that can still notice the field a `StreamEvents` consumer decodes is gone.
    """
    for key, pairs in (
        (
            "py_ev",
            (
                ("session_lifecycle", "renamed_lifecycle"),
                ("SESSION_LIFECYCLE", "RENAMED_LIFECYCLE"),
            ),
        ),
        (
            "ts_ev",
            (
                ("session_lifecycle", "renamed_lifecycle"),
                ("sessionLifecycle", "renamedLifecycle"),
            ),
        ),
    ):
        text = scratch[key].read_text(encoding="utf-8")
        for before, after in pairs:
            assert before in text, f"{key} no longer carries {before}"
            text = text.replace(before, after)
        scratch[key].write_text(text, encoding="utf-8")
    assert _run(scratch, "--write-manifest").returncode == OK

    hard = _run(scratch)
    assert hard.returncode == 2, (
        f"expected exit 2 — STREAM=1 hard-gates the presence probes. Got {hard.returncode}; if "
        f"that is 0, the probes no longer refuse a field only they can see.\n"
        f"{hard.stdout}\n{hard.stderr}"
    )
    out = hard.stdout + hard.stderr
    for lang in ("python", "ts"):
        assert f"ABSENT  SeamEvent.session_lifecycle (tag 21) [{lang}]" in out, out

    # The other half, and what makes the first half mean anything: with the probes back to
    # report-only the run is CLEAN. The manifest gate accepts this mutation.
    soft = _run(scratch, stream="0")
    assert soft.returncode == OK, f"{soft.returncode}\n{soft.stdout}\n{soft.stderr}"
    assert "the event field surface matches" in soft.stdout, (
        "the manifest gate was supposed to accept this rename; if it did not, the case above no "
        "longer isolates the probes\n" + soft.stdout
    )


def test_the_comment_that_stops_the_probes_being_deleted_is_still_there() -> None:
    """A source-level guard that is honest about being one.

    It asserts on the EXPLANATION, never on the field names — those appear in three comments, so
    grepping for them proves nothing about the probes. The behavioural claim belongs to the test
    above; this only keeps the reasoning that stops the next reader deleting them as duplication.
    """
    src = SCRIPT.read_text(encoding="utf-8")
    assert "must not be deleted as" in src, (
        "the comment explaining why the probes survive the manifest is gone; without it the next "
        "reader deletes them as duplication"
    )


def test_the_recorded_api_lag_note_does_not_claim_exit_6_when_the_event_surface_fired(
    scratch,
) -> None:
    """The most likely real exit-8 scenario, and the one that most needs the prose to be right.

    Every local checkout matches the recorded api lag, so this NOTE prints on essentially every real
    run. It used to end "so this STILL exits 6 below" unconditionally — false exactly when the event
    surface also disagrees, and it told that reader the run ended in the code CLAUDE.md's Gotchas
    say to read past. That is the confusion exit 8 exists to prevent, printed by the gate itself.

    Constructing `lag_match == 1` needs two fields the manifest declares and neither tree carries —
    an identical MISSING set in both languages, no extras, enums clean — plus a lag file naming
    exactly those two. No other case in either gate file builds a matched lag together with an event
    disagreement, which is why the false sentence survived.
    """
    scratch["field_manifest"].write_text(
        scratch["field_manifest"].read_text(encoding="utf-8")
        + "ContextBinding/pretend_lag_one\nContextBinding/pretend_lag_two\n",
        encoding="utf-8",
    )
    scratch["lag"].write_text(
        "# EXPECTED-FROM: 2026-08-31 (synthetic; written by this test, never the committed file)\n"
        "ContextBinding/pretend_lag_one\n"
        "ContextBinding/pretend_lag_two\n",
        encoding="utf-8",
    )
    _append_field_both(scratch)
    r = _run(scratch)
    out = r.stdout + r.stderr

    assert "NOTE — the FIELD surface disagrees" in out, (
        f"the lag was not matched, so this case is not exercising what it claims\n{out}"
    )
    assert r.returncode == EVENT_SURFACE_DISAGREES, f"{r.returncode}\n{out}"
    assert "STILL exits 6" not in out, (
        "the NOTE claims this run exits 6 while it exits 8 — the reader is being pointed past a "
        f"real event regression by the gate's own output\n{out}"
    )
    assert "does NOT exit 6" in out, out
    assert "ChainHeadAttestation/notary_receipt" in out, out
