"""The `seam.event.v1` field-surface gate — issue #88.

`contract/field-manifest.txt` declares the `seam.api.v1` field surface. `seam.event.v1` — the outbox
stream `seam-connectors` consume and `verify/` reads — had no equivalent: four named presence probes
out of ninety fields, and nothing at all on an addition, a removal or a rename anywhere else. A field
could land on the outbox contract and reach every consumer through this SDK with every gate green.
`contract/event-field-manifest.txt` closes that, and this file is what proves it closed.

Mirrors `test_field_manifest_gate.py` down to the `_run`/manifests fixture shape, and for the same
non-negotiable reason: **every case drives the REAL script against SCRATCH COPIES of the stubs.**
`python/seam_sdk/_gen` and `ts/gen` are gitignored, so a test that corrupted them could not restore
them with git and recovery would need `make generate` plus a BSR login. `SEAM_PY_EV`,
`SEAM_PY_EV_GRPC`, `SEAM_TS_EV` and `SEAM_EVENT_FIELD_MANIFEST` exist for that, and nothing in CI
sets them. `_run` redirects every `SEAM_*` the script reads — all nine — so no case can reach a
real tree even by omission.

The second discipline is that no case asserts against the ambient checkout. Every manifest is written
from the scratch copies the case itself constructed, so a baseline is what this test built, never what
the machine happened to have — the environment-dependence failure `plans/gate-blindness-hardening.md`
records (passed locally, failed in CI).
"""

from __future__ import annotations

import os
import pathlib
import re
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
#: The event package's grpc stub — where RPCs live. A `.pyi` message stub carries fields and no
#: verbs at all, so no override of PY_EV could ever reach a service; the verb probe needs its own.
PY_EV_GRPC = (
    REPO
    / "python"
    / "seam_sdk"
    / "_gen"
    / "seam"
    / "event"
    / "v1"
    / "seam_event_pb2_grpc.py"
)
PY_API = REPO / "python" / "seam_sdk" / "_gen" / "seam" / "api" / "v1" / "seam_pb2.pyi"
TS_API = REPO / "ts" / "gen" / "seam" / "api" / "v1" / "seam_pb.ts"
COMMITTED = REPO / "contract" / "event-field-manifest.txt"
CLAUDE_MD = REPO / "CLAUDE.md"

#: Exit codes this file asserts on. Named rather than inlined, because the whole argument for 8 is
#: that it is NOT 6 — a bare integer literal in an assertion does not carry that.
OK = 0
EVENT_SURFACE_DISAGREES = 8
PRECONDITION_FAILED = 7


def _require_stubs() -> None:
    for f in (PY_EV, PY_EV_GRPC, TS_EV, PY_API, TS_API):
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
        "SEAM_PY_EV_GRPC": str(scratch["py_ev_grpc"]),
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
        # The two globbed paths get their OWN directories, mirroring the real gen tree
        # (`python/seam_sdk/_gen/seam/event/v1/`, `ts/gen/seam/event/v1/`). The probe globs the
        # package directory rather than one filename — a package is not a file — so a flat scratch
        # dir would put the API stubs inside the event package's glob and make the fixture describe
        # a layout that does not exist.
        "py_ev_grpc": tmp_path / "pyevent" / "seam_event_pb2_grpc.py",
        "ts_ev": tmp_path / "tsevent" / "seam_event_pb.ts",
        "py_api": tmp_path / "seam_pb2.pyi",
        "ts_api": tmp_path / "seam_pb.ts",
        "event_manifest": tmp_path / "event-field-manifest.txt",
        "field_manifest": tmp_path / "field-manifest.txt",
        "rpc_manifest": tmp_path / "rpc-manifest.txt",
        "lag": tmp_path / "expected-local-lag.txt",
    }
    for key, src in (
        ("py_ev", PY_EV),
        ("py_ev_grpc", PY_EV_GRPC),
        ("ts_ev", TS_EV),
        ("py_api", PY_API),
        ("ts_api", TS_API),
    ):
        s[key].parent.mkdir(parents=True, exist_ok=True)
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


#: The four STREAM presence probes, each with a DECLARATION-ONLY rename of the field it names and a
#: string that must SURVIVE that rename. The residual is the anti-vacuity half: it proves the probe
#: fired because its anchor moved, not because the field name vanished from the file. `actor` is the
#: case that forced this shape — `ts/gen`'s comment for it ("Mirrors `AuditEntryPb.actor` (tag 4).")
#: carries the word verbatim from the proto, so the old `\bactor\b` pattern reported PRESENT against
#: a stub whose declaration had been renamed to `principal`. The other three had the same hole one
#: step further away, in `__slots__` and the `__init__` signature.
PROBES = [
    pytest.param(
        "SeamEvent.session_lifecycle (tag 21)",
        ("SESSION_LIFECYCLE_FIELD_NUMBER", "RENAMEDLC_FIELD_NUMBER"),
        ("session_lifecycle = 21;", "renamedlc = 21;"),
        "session_lifecycle",
        "sessionLifecycle?",
        id="session_lifecycle",
    ),
    pytest.param(
        "SeamEvent.chain_head_attestation (tag 22)",
        ("CHAIN_HEAD_ATTESTATION_FIELD_NUMBER", "RENAMEDCHA_FIELD_NUMBER"),
        ("chain_head_attestation = 22;", "renamedcha = 22;"),
        "chain_head_attestation",
        "chainHeadAttestation?",
        id="chain_head_attestation",
    ),
    pytest.param(
        "DecisionSealed.ciphertext_digest (tag 10)",
        ("CIPHERTEXT_DIGEST_FIELD_NUMBER", "RENAMEDCD_FIELD_NUMBER"),
        ("ciphertext_digest = 10;", "renamedcd = 10;"),
        "ciphertext_digest",
        "ciphertextDigest",
        id="ciphertext_digest",
    ),
    pytest.param(
        "AuditEntryEvent.actor (tag 4)",
        ("ACTOR_FIELD_NUMBER", "RENAMEDACTOR_FIELD_NUMBER"),
        ("actor = 4;", "renamedactor = 4;"),
        "actor: str",
        "AuditEntryPb.actor",
        id="actor",
    ),
]


@pytest.mark.parametrize(
    ("label", "py_sub", "ts_sub", "residual_py", "residual_ts"), PROBES
)
def test_the_presence_probes_still_refuse_what_the_manifest_gate_accepts(
    scratch, label, py_sub, ts_sub, residual_py, residual_ts
) -> None:
    """The manifest does not replace the four presence probes — proven per probe, by a case only that
    probe catches.

    Grepping the script's source for the four field names cannot make this claim, and used to be what
    this test did. Those names also appear in the header comment describing probe 2 and in the comment
    above the field gate saying the probes must not be deleted, so the grep passed with the entire
    probe loop removed: a guard that could not fire.

    Each case instead renames ONE field's DECLARATION in both event trees and then records the rename
    with `--write-manifest`. The manifest gate is left with nothing to say — trees and manifest agree
    exactly, and the second run below asserts it says so out loud — so the probe is the only thing
    that can still notice a field a `StreamEvents` consumer decodes is gone.

    Parametrized over all four rather than run once on `session_lifecycle`: a single case leaves the
    other three probes deletable with this file still green, which is the same "one test stands for
    four" gap the version it replaced had.

    `residual_py`/`residual_ts` are asserted to SURVIVE the rename. Without them a case would pass
    just as well against a probe keyed on the bare field name, and would not distinguish "the anchor
    moved" from "the word is gone from the file" — the distinction `actor` exists to make.
    """
    for key, sub, residual in (
        ("py_ev", py_sub, residual_py),
        ("ts_ev", ts_sub, residual_ts),
    ):
        text = scratch[key].read_text(encoding="utf-8")
        before, after = sub
        assert text.count(before) == 1, f"{key}: {before!r} is not a unique anchor"
        text = text.replace(before, after)
        assert residual in text, (
            f"{key}: {residual!r} did not survive the rename, so this case cannot tell an anchored "
            f"probe from one satisfied by any mention of the field"
        )
        scratch[key].write_text(text, encoding="utf-8")
    assert _run(scratch, "--write-manifest").returncode == OK

    hard = _run(scratch)
    assert hard.returncode == 2, (
        f"expected exit 2 — STREAM=1 hard-gates the presence probes. Got {hard.returncode}; if "
        f"that is 0, the {label} probe no longer refuses a field only it can see.\n"
        f"{hard.stdout}\n{hard.stderr}"
    )
    out = hard.stdout + hard.stderr
    for lang in ("python", "ts"):
        assert f"ABSENT  {label} [{lang}]" in out, out

    # The other half, and what makes the first half mean anything: with the probes back to
    # report-only the run is CLEAN. The manifest gate accepts this mutation.
    soft = _run(scratch, stream="0")
    assert soft.returncode == OK, f"{soft.returncode}\n{soft.stdout}\n{soft.stderr}"
    assert "the event field surface matches" in soft.stdout, (
        "the manifest gate was supposed to accept this rename; if it did not, the case above no "
        "longer isolates the probes\n" + soft.stdout
    )


def test_a_field_moved_to_another_message_still_fires_its_probe(scratch) -> None:
    """The probes are MESSAGE-scoped, which a grep of the stub file cannot be.

    Anchoring the patterns to declarations closed the "a comment about the field satisfies the probe"
    hole and left a larger one open: a file-wide grep does not know which message declares what.
    Measured against the anchored-but-unscoped version — moving `actor` from `AuditEntryEvent` to
    `ChainHeadAttestation` in both trees and re-recording the manifest left the whole gate green at
    exit 0, printing `PRESENT AuditEntryEvent.actor (tag 4)` against an `AuditEntryEvent` that no
    longer declares it. The label named a message; nothing checked the message.

    This is the strongest form of the manifest-cannot-see-it case in this file: the manifest is
    perfectly happy — the field exists, on some message, in both languages — and only a probe that
    knows where it belongs can refuse.
    """
    py = scratch["py_ev"].read_text(encoding="utf-8")
    py_line = "    ACTOR_FIELD_NUMBER: _ClassVar[int]\n"
    assert py.count(py_line) == 1
    py = py.replace(py_line, "")
    assert py.count(PY_ANCHOR) == 1
    scratch["py_ev"].write_text(
        py.replace(PY_ANCHOR, PY_ANCHOR + py_line), encoding="utf-8"
    )

    ts = scratch["ts_ev"].read_text(encoding="utf-8")
    ts_line = "   * @generated from field: optional string actor = 4;\n"
    assert ts.count(ts_line) == 1
    ts = ts.replace(ts_line, "")
    assert ts.count(TS_ANCHOR) == 1
    scratch["ts_ev"].write_text(
        ts.replace(TS_ANCHOR, TS_ANCHOR + ts_line), encoding="utf-8"
    )

    assert _run(scratch, "--write-manifest").returncode == OK
    # The manifest now says ChainHeadAttestation/actor, in both languages, and agrees with itself.
    assert "ChainHeadAttestation/actor" in scratch["event_manifest"].read_text(
        encoding="utf-8"
    )

    r = _run(scratch)
    out = r.stdout + r.stderr
    assert r.returncode == 2, (
        f"expected exit 2; got {r.returncode}. If this is 0 the probe is matching the field "
        f"anywhere in the file rather than on the message its own label names.\n{out}"
    )
    for lang in ("python", "ts"):
        assert f"ABSENT  AuditEntryEvent.actor (tag 4) [{lang}]" in out, out


def test_claude_mds_gotcha_names_the_exit_codes_this_gate_actually_produces(
    scratch,
) -> None:
    """`CLAUDE.md`'s Gotchas paragraph is prose about exit codes, and prose about exit codes has now
    been wrong twice in a row.

    It said "it still exits 6" unconditionally while the event surface could make the same run exit
    8. That was corrected to name 8 — and the correction was wrong too, because a regression in one
    of the four streamed-payload mirror fields is refused earlier, at exit 2, with no NOTE printed.
    Nothing guarded the paragraph either time; the script's own NOTE ends "See CLAUDE.md's Gotchas",
    so a reader was being sent from corrected output to an uncorrected claim.

    So all four codes are measured here and required to appear in that paragraph. This is not a
    grep for plausible-looking numbers: each is produced by a run this test constructs, and the
    paragraph must name every one of them.
    """
    gotcha = CLAUDE_MD.read_text(encoding="utf-8")
    # Located by the command, not by any exit code in the prose — the needle must not be a thing
    # this test is about to assert, or a paragraph that dropped a code would simply stop being found.
    # Anchored on the script spelling, not the `make` one: Phase 7 changed the documented command
    # because `make` collapses every exit code to its own 2 (see the sibling test below).
    start = gotcha.index("`STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits")
    para = gotcha[start : gotcha.index("\n\n", start)]

    # 8 — a matched api lag with the event surface also disagreeing.
    scratch["field_manifest"].write_text(
        scratch["field_manifest"].read_text(encoding="utf-8")
        + "ContextBinding/pretend_lag_one\n",
        encoding="utf-8",
    )
    scratch["lag"].write_text(
        "# EXPECTED-FROM: 2026-08-31 (synthetic; this test only)\nContextBinding/pretend_lag_one\n",
        encoding="utf-8",
    )
    _append_field_both(scratch)
    eight = _run(scratch)
    assert eight.returncode == EVENT_SURFACE_DISAGREES, (
        f"{eight.returncode}\n{eight.stdout}\n{eight.stderr}"
    )

    # 6 — the same matched lag with the event surface clean.
    for key, anchor in (("py_ev", PY_ANCHOR), ("ts_ev", TS_ANCHOR)):
        text = scratch[key].read_text(encoding="utf-8")
        scratch[key].write_text(
            text.replace(
                anchor + "    NOTARY_RECEIPT_FIELD_NUMBER: _ClassVar[int]\n", anchor
            ).replace(
                anchor + "   * @generated from field: bytes notary_receipt = 99;\n",
                anchor,
            ),
            encoding="utf-8",
        )
    six = _run(scratch)
    assert six.returncode == 6, f"{six.returncode}\n{six.stdout}\n{six.stderr}"
    assert "STILL exits 6" in six.stdout, six.stdout

    # 2 — a mirror field, refused before either of the above can be reached.
    py = scratch["py_ev"].read_text(encoding="utf-8")
    scratch["py_ev"].write_text(
        py.replace("SESSION_LIFECYCLE_FIELD_NUMBER", "RENAMEDLC_FIELD_NUMBER"),
        encoding="utf-8",
    )
    ts = scratch["ts_ev"].read_text(encoding="utf-8")
    scratch["ts_ev"].write_text(
        ts.replace("session_lifecycle = 21;", "renamedlc = 21;"), encoding="utf-8"
    )
    two = _run(scratch)
    assert two.returncode == 2, f"{two.returncode}\n{two.stdout}\n{two.stderr}"
    assert "NOTE" not in two.stdout, (
        "exit 2 preempts the field-report block entirely, so no NOTE is printed — if one appears "
        "here the ordering changed and CLAUDE.md's paragraph needs rewriting again\n"
        + two.stdout
    )

    # 7 — a structural precondition, which preempts even the exit-2 mirror check above. Measured
    # rather than assumed: the same run that produced 2 a moment ago produces 7 once a verb is
    # grafted in, because a precondition failure means the surface is not one the gate can read.
    scratch["py_ev_grpc"].write_text(
        scratch["py_ev_grpc"].read_text(encoding="utf-8") + _PY_RPC_GRAFT,
        encoding="utf-8",
    )
    seven = _run(scratch)
    assert seven.returncode == PRECONDITION_FAILED, (
        "a service in seam.event.v1 must outrank the mirror-field refusal still in place from the "
        f"exit-2 case above:\n{seven.returncode}\n{seven.stdout}\n{seven.stderr}"
    )

    for code in ("6", "8", "2", "7"):
        assert f"**{code}**" in para, (
            f"CLAUDE.md's Gotchas paragraph does not name exit {code}, which this test just "
            f"measured the documented command producing:\n{para}"
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


# ── The VERB surface, one level up from the fields ───────────────────────────────────────────────
# `scripts/check-contract.sh` says the rpc manifest declares "the whole verb surface" (the phrase
# is the script's, at its own line 44 — the manifest's header scopes itself to `seam.api.v1`). Both extractors were pinned
# to `seam.api.v1` and read only the api stubs, so an RPC landing in `seam.event.v1` was invisible in
# BOTH languages at once — no probe named it, no manifest covered it, and every gate stayed green.
# That is the same shape as the field-level gap #88 closed, one level up.
#
# The gate now refuses a non-empty event verb surface with exit 7 (structural precondition). These
# tests drive the REAL script against scratch copies, never the gitignored originals.

#: A python RPC as the generated grpc stub actually spells it — the registered-method call carrying
#: the fully-qualified path. This is the string the extractor greps for, not an approximation of it.
_PY_RPC_GRAFT = (
    "\n    self.Foo = channel.unary_unary('/seam.event.v1.SeamEvents/Foo')\n"
)

#: The TS equivalent: connect-es annotates each verb with its fully-qualified name in a comment.
_TS_RPC_GRAFT = "\n// @generated from rpc seam.event.v1.SeamEvents.Foo\n"


def test_an_rpc_grafted_into_the_python_event_stub_fails_the_precondition(
    scratch,
) -> None:
    """One language alone must be enough. A probe that needed BOTH is the blindness, not the fix."""
    scratch["py_ev_grpc"].write_text(
        scratch["py_ev_grpc"].read_text(encoding="utf-8") + _PY_RPC_GRAFT,
        encoding="utf-8",
    )
    r = _run(scratch)
    assert r.returncode == PRECONDITION_FAILED, (
        f"expected exit {PRECONDITION_FAILED} for a service in seam.event.v1, got "
        f"{r.returncode}\n{r.stderr}"
    )
    assert "SeamEvents/Foo" in r.stderr, (
        f"the refusal must NAME the verb it found, or it cannot be acted on:\n{r.stderr}"
    )
    assert "python" in r.stderr, (
        f"the refusal must say which language carried it:\n{r.stderr}"
    )


def test_an_rpc_grafted_into_the_ts_event_stub_fails_the_precondition(scratch) -> None:
    """Independently of Python — the TS half needs no new override, `SEAM_TS_EV` already reaches it."""
    scratch["ts_ev"].write_text(
        scratch["ts_ev"].read_text(encoding="utf-8") + _TS_RPC_GRAFT, encoding="utf-8"
    )
    r = _run(scratch)
    assert r.returncode == PRECONDITION_FAILED, (
        f"expected exit {PRECONDITION_FAILED}, got {r.returncode}\n{r.stderr}"
    )
    assert "SeamEvents/Foo" in r.stderr, r.stderr
    assert " ts " in r.stderr or "(ts" in r.stderr or "in ts" in r.stderr, (
        f"the refusal must say which language carried it:\n{r.stderr}"
    )


def test_the_unmodified_event_surface_declares_no_verbs(scratch) -> None:
    """The negative control. Without it, "always exit 7" would satisfy both tests above.

    This is also the live assertion that the invariant the tripwire defends is TRUE today: the
    committed event grpc stub is a scaffold with no service in it.
    """
    r = _run(scratch)
    assert r.returncode == OK, (
        "the unmodified event surface must be clean — if this fails, seam.event.v1 has grown a "
        f"service and the tripwire is reporting a real change:\n{r.stderr}"
    )
    assert "ZERO services" not in r.stderr, r.stderr


def test_the_real_generated_stub_has_no_service_in_it() -> None:
    """The invariant, asserted against the REAL tree rather than a copy.

    "Generated", not "committed": `python/seam_sdk/_gen/` is gitignored (`.gitignore:18`). Calling it
    committed would contradict this repo's first Gotcha in a test whose whole job is to be precise
    about what the tree actually contains.

    The scratch fixture copies the stub, so every test above would still pass if the committed file
    grew a service — they would just be testing a faithful copy of a broken invariant.
    """
    _require_stubs()
    text = PY_EV_GRPC.read_text(encoding="utf-8")
    assert "seam.event.v1." not in text, (
        "the generated seam.event.v1 grpc stub declares a service. That is not a test failure — it "
        "is the contract change this tripwire exists to announce. See the gate's own message."
    )


def test_the_verb_probe_uses_the_same_extractor_as_the_api_surface() -> None:
    """STRUCTURAL only: the verb rule is defined once and called twice, not copied.

    Read what this does and does not do. It inspects the SHELL SOURCE, so it is green on a gate that
    detects nothing and would go red on a purely cosmetic reformat. It is therefore **not** a guard
    on the probe's behaviour, and must never be counted as one — the graft tests above are what
    prove the gate works. The verification round caught exactly that overclaim here: this test
    passed while the probe was mutated to `if false; then`.

    It is still worth keeping, because "the rule lives in one place" is a property no behavioural
    test can observe — two copies that agree today behave identically until one is edited. Matched
    with whitespace-tolerant patterns so a reformat does not fail it; only re-inlining a
    package-specific grep does.
    """
    script = (REPO / "scripts" / "check-contract.sh").read_text(encoding="utf-8")
    for label, pattern in (
        (
            "the event probe calls the shared python extractor",
            r"rpcs_python_in\s+'seam\.event\.v1'",
        ),
        (
            "the event probe calls the shared ts extractor",
            r"rpcs_ts_in\s+'seam\.event\.v1'",
        ),
        (
            "the api python extractor is a wrapper over the shared rule",
            r"rpcs_python\(\)\s*\{\s*rpcs_python_in\s+'seam\.api\.v1'",
        ),
        (
            "the api ts extractor is a wrapper over the shared rule",
            r"rpcs_ts\(\)\s*\{\s*rpcs_ts_in\s+'seam\.api\.v1'",
        ),
    ):
        assert re.search(pattern, script), (
            f"{label}: no longer true. The verb-extraction rule has been copied rather than "
            "called, which is the defect this repo keeps finding — two copies agree until one is "
            "edited, and then only one of them is fixed."
        )


#: A service registration as grpc-python actually emits it: the name quoted and UNSLASHED, distinct
#: from the RPC form `'/pkg.Svc/Method'`. A service with zero methods emits this and no RPC literal.
_PY_SERVICE_GRAFT = (
    "\n    generic_handler = grpc.method_handlers_generic_handler(\n"
    "            'seam.event.v1.SeamEventRelay', {})\n"
)

#: The protobuf-es equivalent.
_TS_SERVICE_GRAFT = (
    "\n/**\n * @generated from service seam.event.v1.SeamEventRelay\n */\n"
)


def test_a_verb_in_a_second_file_of_the_same_package_is_caught(scratch) -> None:
    """A package is not a file, and the first version of this probe assumed it was.

    buf's ordinary layout puts a service in its own `.proto` — `seam/event/v1/seam_event_service.proto`
    — and codegen emits `seam_event_service_pb2_grpc.py` beside the message stub. Probing two
    hardcoded filenames therefore missed the most likely way a verb would actually arrive. Measured
    before the fix: exit 0, every gate green. Found by the verification round, not by the plan.
    """
    (scratch["py_ev_grpc"].parent / "seam_event_service_pb2_grpc.py").write_text(
        _PY_RPC_GRAFT, encoding="utf-8"
    )
    r = _run(scratch)
    assert r.returncode == PRECONDITION_FAILED, (
        f"a verb in a second file of seam.event.v1 must still be refused, got {r.returncode}\n"
        f"{r.stderr}"
    )
    assert "SeamEvents/Foo" in r.stderr, r.stderr


def test_a_verb_in_a_second_ts_file_of_the_same_package_is_caught(scratch) -> None:
    """The TS half of the same gap, independently."""
    (scratch["ts_ev"].parent / "seam_event_service_pb.ts").write_text(
        _TS_RPC_GRAFT, encoding="utf-8"
    )
    r = _run(scratch)
    assert r.returncode == PRECONDITION_FAILED, (
        f"expected {PRECONDITION_FAILED}, got {r.returncode}\n{r.stderr}"
    )
    assert "SeamEvents/Foo" in r.stderr, r.stderr


@pytest.mark.parametrize(
    "key,graft,language",
    [
        ("py_ev_grpc", _PY_SERVICE_GRAFT, "python"),
        ("ts_ev", _TS_SERVICE_GRAFT, "ts"),
    ],
    ids=["python", "ts"],
)
def test_a_service_with_no_methods_is_caught(
    scratch, key: str, graft: str, language: str
) -> None:
    """The refusal says "ZERO services"; it must therefore measure services, not only verbs.

    A service declaring no methods emits no `'/pkg.Svc/Method'` literal in either language, so the
    RPC-only probe let one through while its own message claimed otherwise — a check named for
    something other than what it measured, which is this repo's whole subject. Both generators do
    emit the service NAME, and that is what is matched now.
    """
    scratch[key].write_text(
        scratch[key].read_text(encoding="utf-8") + graft, encoding="utf-8"
    )
    r = _run(scratch)
    assert r.returncode == PRECONDITION_FAILED, (
        f"a zero-method service in seam.event.v1 must be refused, got {r.returncode}\n{r.stderr}"
    )
    assert "SeamEventRelay" in r.stderr, (
        f"the refusal must name the service it found:\n{r.stderr}"
    )
    assert f"a SERVICE in {language}" in r.stderr, (
        f"the refusal must say it found a SERVICE (not an RPC) and in which language:\n{r.stderr}"
    )


def test_claude_md_prescribes_the_script_not_make_for_the_contract_gate() -> None:
    """The four codes above are only readable if the documented command actually returns them.

    `make check-contract` runs this same script, but GNU make replaces a failed recipe's status
    with its own **2** — and 2 is a real, differently-meaning code in this gate's vocabulary (the
    `STREAM=1` streamed-payload mirror-field refusal). So the `make` form reports every distinct
    outcome — 6, 7, 8, 5, 3, 1 — as the one code that means "a mirror field disagrees".

    CLAUDE.md's Gotchas paragraph spends most of its length telling a reader to distinguish those
    codes, and for two years' worth of sessions its Commands section prescribed the one invocation
    that cannot express them. Measured, not reasoned: `make` returned 2 where the script returned 6
    on the same tree. This pins the fix so the convenient spelling does not drift back in.
    """
    claude_md = (REPO / "CLAUDE.md").read_text(encoding="utf-8")
    command_line = next(
        (
            ln
            for ln in claude_md.splitlines()
            if ln.startswith("- Contract surface gate:")
        ),
        None,
    )
    assert command_line is not None, (
        "CLAUDE.md no longer has a `- Contract surface gate:` line in its Commands section. That "
        "line is what tells a reader how to run the gate; if it moved, re-point this test at it."
    )
    assert "./scripts/check-contract.sh" in command_line, (
        "CLAUDE.md's contract-gate command no longer invokes the script directly: "
        f"{command_line!r}. The exit code IS the result for this gate, and `make` collapses every "
        "one of them to its own 2 — which this gate already uses to mean something else."
    )
    assert "make check-contract" not in command_line.split("**call the script")[0], (
        "CLAUDE.md's contract-gate command prescribes `make check-contract` again. It returns 2 "
        "for every failure mode, including the six the Gotchas paragraph asks the reader to tell "
        "apart. Mentioning `make` in the surrounding caveat is fine; prescribing it is not."
    )
