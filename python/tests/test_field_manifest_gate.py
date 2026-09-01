"""The field manifest is only worth committing if the gate it feeds actually refuses.

`contract/field-manifest.txt` declares every `seam.api.v1` message field the SDK expects, and
`scripts/check-contract.sh` set-compares it against the generated stubs per language, in both
directions. A manifest gate that cannot be driven red is a list, not a gate — so every assertion here
executes the REAL script (the pattern `scripts/test_ci_gate.py` uses) rather than reimplementing its
comparison in Python, which would only prove that two copies of the same logic agree.

**Nothing here touches the real manifests, the real stub trees, or the real recorded local lag.** The
script reads five paths from the environment (`SEAM_PY_GEN`, `SEAM_TS_GEN`, `SEAM_FIELD_MANIFEST`,
`SEAM_RPC_MANIFEST`, `SEAM_EXPECTED_LOCAL_LAG`), defaulting to the real ones, and `_run()` below
redirects the manifests into `tmp_path` and the expected-local-lag file to a scratch path colocated
with them by default — so `--write-manifest`'s delete-on-write step for that file can never touch
`contract/expected-local-lag.txt` as a side effect of an unrelated test. That is not fastidiousness:
`python/seam_sdk/_gen` and `ts/gen` are **gitignored**, so a test that corrupted them could not restore
them with git, and recovery would need a `make generate` and a BSR login. Exactly one test passes
`lag_file=False` to exercise the real committed file end-to-end, on purpose, read-only.

The baseline manifest each test starts from is written by the script itself from the stubs actually
present, so these tests do not depend on the checked-in manifest being in sync with a given
developer's stub tree — which it deliberately is not: the committed manifest declares the contract's
current surface, and a stub tree generated before ACDP P1a/P2 landed is legitimately five fields
behind it.
"""

from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).parents[2]
SCRIPT = REPO / "scripts" / "check-contract.sh"
PY_STUB = REPO / "python" / "seam_sdk" / "_gen" / "seam" / "api" / "v1" / "seam_pb2.pyi"
TS_STUB = REPO / "ts" / "gen" / "seam" / "api" / "v1" / "seam_pb.ts"
LAG_FILE = REPO / "contract" / "expected-local-lag.txt"


# NOT a file-level `pytestmark`: a whole-file skip makes an absent stub tree read as a green run, which
# is the same "skip == pass" shape this repo has already had to fix once. Only the tests that execute
# the script against stubs are skippable; the ones that read the COMMITTED manifest need no stubs and
# must run everywhere, so a header regression cannot hide behind a missing `make generate`.
def _require_stubs() -> None:
    if not (PY_STUB.exists() and TS_STUB.exists()):
        pytest.skip(
            "generated stubs absent — run `make generate` "
            "(this gate inspects stubs, it cannot invent them)"
        )


def _run(
    field_manifest: pathlib.Path,
    rpc_manifest: pathlib.Path,
    *args: str,
    py_gen: pathlib.Path | None = None,
    ts_gen: pathlib.Path | None = None,
    lag_file: pathlib.Path | None | bool = None,
):
    env = {
        **os.environ,
        "SEAM_FIELD_MANIFEST": str(field_manifest),
        "SEAM_RPC_MANIFEST": str(rpc_manifest),
        "STREAM": "1",
        "EVENTS": "1",
    }
    # Only the enum-mutation tests need these — they drive the real script against SCRATCH COPIES of
    # the stub trees (never the real gitignored ones; see the module docstring) so an enum value can
    # be appended or deleted without touching anything `make generate` would be needed to restore.
    if py_gen is not None:
        env["SEAM_PY_GEN"] = str(py_gen)
    if ts_gen is not None:
        env["SEAM_TS_GEN"] = str(ts_gen)
    # `lag_file=False` is the one deliberate escape: it leaves SEAM_EXPECTED_LOCAL_LAG unset, so the
    # script falls back to the REAL committed `contract/expected-local-lag.txt` — used by exactly one
    # test, which verifies the real command against the real files end-to-end. Every other call
    # defaults to a scratch path colocated with `field_manifest` (never created unless a test writes
    # to it), so `--write-manifest`'s delete-on-write step can never touch the committed file as a
    # side effect of an unrelated test.
    if lag_file is not False:
        env["SEAM_EXPECTED_LOCAL_LAG"] = str(
            lag_file
            if lag_file is not None
            else field_manifest.parent / "expected-local-lag.txt"
        )
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def manifests(tmp_path: pathlib.Path):
    """A field manifest written from the stubs actually present, plus a scratch RPC manifest.

    `--write-manifest` writes both, so the RPC one is redirected too — otherwise running this suite
    would rewrite the repo's real `contract/rpc-manifest.txt` as a side effect of testing fields.
    """
    _require_stubs()
    fm, rm = tmp_path / "field-manifest.txt", tmp_path / "rpc-manifest.txt"
    r = _run(fm, rm, "--write-manifest")
    assert r.returncode == 0, r.stderr
    assert fm.exists() and rm.exists()
    return fm, rm


@pytest.fixture
def scratch_stubs(tmp_path: pathlib.Path):
    """The real stub trees, COPIED into tmp_path so an enum value can be appended to or deleted from
    them. `python/seam_sdk/_gen` and `ts/gen` are gitignored — mutating the originals could not be
    undone with git, and recovery would need `make generate` and a BSR login this suite must never
    depend on. Only the two files the enum extractors read are copied; nothing else is touched."""
    _require_stubs()
    py = tmp_path / "seam_pb2.pyi"
    ts = tmp_path / "seam_pb.ts"
    py.write_text(PY_STUB.read_text())
    ts.write_text(TS_STUB.read_text())
    return py, ts


@pytest.fixture
def enum_manifests(scratch_stubs, tmp_path: pathlib.Path):
    """Field+RPC manifest written FROM THE SCRATCH STUB COPIES (not the committed manifest), so the
    baseline the enum-mutation tests start from matches exactly what those copies currently declare —
    mutating a copy and comparing it against a manifest derived from a DIFFERENT source would just be
    testing the pre-existing five-field ACDP lag, not the mutation."""
    py, ts = scratch_stubs
    fm, rm = tmp_path / "field-manifest.txt", tmp_path / "rpc-manifest.txt"
    r = _run(fm, rm, "--write-manifest", py_gen=py, ts_gen=ts)
    assert r.returncode == 0, r.stderr
    return fm, rm, py, ts


# The real BallotChoice tail, in both stub trees, used as a known-good anchor to append after or
# delete outright — lifted verbatim from the generated files rather than hand-typed, so a mutation
# test can never pass because the fixture text quietly drifted from what the generator actually emits.
_PY_ABSTAIN_LINE = "    BALLOT_CHOICE_ABSTAIN: _ClassVar[BallotChoice]\n"
_TS_ABSTAIN_BLOCK = (
    "  /**\n"
    "   * @generated from enum value: BALLOT_CHOICE_ABSTAIN = 3;\n"
    "   */\n"
    "  ABSTAIN = 3,\n"
)


def _py_add_enum_value(stub: pathlib.Path, enum: str, value: str) -> None:
    text = stub.read_text()
    assert _PY_ABSTAIN_LINE in text, (
        "known anchor not found — the real .pyi shape changed"
    )
    stub.write_text(
        text.replace(
            _PY_ABSTAIN_LINE,
            _PY_ABSTAIN_LINE + f"    {value}: _ClassVar[{enum}]\n",
            1,
        )
    )


def _py_delete_enum_value(stub: pathlib.Path) -> None:
    text = stub.read_text()
    assert _PY_ABSTAIN_LINE in text, (
        "known anchor not found — the real .pyi shape changed"
    )
    stub.write_text(text.replace(_PY_ABSTAIN_LINE, "", 1))


def _ts_add_enum_value(stub: pathlib.Path, value: str, ident: str, tag: int) -> None:
    text = stub.read_text()
    assert _TS_ABSTAIN_BLOCK in text, (
        "known anchor not found — the real .ts shape changed"
    )
    new_block = (
        "\n  /**\n"
        f"   * @generated from enum value: {value} = {tag};\n"
        "   */\n"
        f"  {ident} = {tag},\n"
    )
    stub.write_text(text.replace(_TS_ABSTAIN_BLOCK, _TS_ABSTAIN_BLOCK + new_block, 1))


def _ts_delete_enum_value(stub: pathlib.Path) -> None:
    text = stub.read_text()
    assert _TS_ABSTAIN_BLOCK in text, (
        "known anchor not found — the real .ts shape changed"
    )
    stub.write_text(text.replace(_TS_ABSTAIN_BLOCK, "", 1))


def _entries(p: pathlib.Path) -> list[str]:
    return [
        ln.strip()
        for ln in p.read_text().splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]


# ── the gate agrees with itself ────────────────────────────────────────────────────────────────────


def test_a_manifest_written_from_the_stubs_passes(manifests) -> None:
    """The baseline. If this ever fails, the two extractors disagree with each other and every
    negative case below is testing noise."""
    fm, rm = manifests
    r = _run(fm, rm)
    assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    assert "the field surface matches" in r.stdout


def test_write_manifest_is_idempotent(manifests) -> None:
    """The documented escape must not churn: a gate whose fix produces a different file every run
    gets worked around rather than used."""
    fm, rm = manifests
    first = fm.read_text()
    assert _run(fm, rm, "--write-manifest").returncode == 0
    assert fm.read_text() == first


# ── anti-vacuity: the manifest is not empty, and it covers real, load-bearing fields ───────────────


def test_the_manifest_is_not_vacuous(manifests) -> None:
    """A zero-entry manifest would make every comparison below trivially true."""
    fm, _ = manifests
    entries = _entries(fm)
    assert len(entries) > 200, (
        f"only {len(entries)} fields — the extractor is broken, not the proto"
    )
    # The file now also carries the ENUM section (`<Enum>#<VALUE>`, no "/") — restrict this check to
    # the FIELD lines specifically. `test_field_and_enum_lines_partition_cleanly` covers the split.
    fields = [e for e in entries if "#" not in e]
    assert all("/" in e for e in fields), "every FIELD entry is <Message>/<field>"


@pytest.mark.parametrize(
    "field",
    [
        # The two the `__slots__` extractor silently drops: `raise` is a Python keyword, so the .pyi
        # generator cannot emit it as an attribute — only as RAISE_FIELD_NUMBER.
        "ResumeRequest/raise",
        "AdminResumeRequest/raise",
        # AuditEntry is a REAL top-level message. An `*Entry` name filter would drop it from BOTH
        # sides — symmetric, so the gate would stay green while going blind to a real message.
        "AuditEntry/seq",
        "AuditEntry/decision_id",
        # An ordinary field, so the list above cannot pass by being all special cases.
        "AuthorizeRequest/call_sig",
    ],
)
def test_the_extractor_sees_the_fields_a_naive_one_would_miss(
    manifests, field: str
) -> None:
    fm, _ = manifests
    assert field in _entries(fm)


def test_synthetic_map_entry_messages_are_excluded(manifests) -> None:
    """Python emits `AuthorizeRequest.FeaturesEntry`/`RunDecisionRequest.FeaturesEntry`; protobuf-es
    emits no type for either. Carried naively they are fields TypeScript can never produce, so the
    gate would be permanently red. The `map` field itself stays, as one entry on its owner."""
    fm, _ = manifests
    entries = _entries(fm)
    assert not [e for e in entries if e.startswith("FeaturesEntry/")]
    assert not [e for e in entries if "Entry/key" in e or "Entry/value" in e]
    assert "AuthorizeRequest/features" in entries


# ── the falsifiable negatives: both directions, driven red ────────────────────────────────────────


def test_a_field_deleted_from_the_manifest_reddens_the_gate_and_names_it(
    manifests,
) -> None:
    """Direction 1 — the stubs carry a field the manifest does not declare. This is the refusal that
    forces a human to decide whether the SDK carries a newly-landed field."""
    fm, rm = manifests
    entries = _entries(fm)
    victim = "AuthorizeRequest/call_sig"
    assert victim in entries
    header = [
        ln for ln in fm.read_text().splitlines(True) if ln.lstrip().startswith("#")
    ]
    fm.write_text("".join(header) + "\n".join(e for e in entries if e != victim) + "\n")

    r = _run(fm, rm)
    assert r.returncode == 6, (
        f"expected exit 6, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert victim in combined, "the gate must NAME the field, not just fail"
    assert "NOT IN THE MANIFEST" in combined
    # Named independently for each language — a stale ts/gen beside a fresh python/_gen must show.
    assert combined.count(victim) >= 2


def test_a_phantom_field_in_the_manifest_reddens_the_gate_and_names_it(
    manifests,
) -> None:
    """Direction 2 — the manifest declares a field the stubs do not have. That is either a stale
    generation or a field REMOVED from the contract, which is a breaking change."""
    fm, rm = manifests
    phantom = "AuthorizeRequest/a_field_that_does_not_exist"
    fm.write_text(fm.read_text() + phantom + "\n")

    r = _run(fm, rm)
    assert r.returncode == 6, (
        f"expected exit 6, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert phantom in combined
    assert "MISSING from the" in combined


def test_an_absent_manifest_refuses_rather_than_passing_vacuously(tmp_path) -> None:
    """No manifest must never mean 'nothing to check'. That is the shape of failure this whole file
    exists to rule out."""
    _require_stubs()
    fm, rm = tmp_path / "field-manifest.txt", tmp_path / "rpc-manifest.txt"
    assert _run(fm, rm, "--write-manifest").returncode == 0
    fm.unlink()

    r = _run(fm, rm)
    assert r.returncode != 0
    assert "has no declared expectation" in (r.stdout + r.stderr)


def test_the_refusal_tells_the_reader_to_decide_before_running_the_escape(
    manifests,
) -> None:
    """The escape has to be documented in the failure, or it gets rediscovered as a workaround — but
    it must not read as the FIRST step, or the gate degrades back into the silent pass it replaced."""
    fm, rm = manifests
    entries = _entries(fm)
    header = [
        ln for ln in fm.read_text().splitlines(True) if ln.lstrip().startswith("#")
    ]
    # Drop the LAST FIELD entry specifically (not just the last line in the file) — the file now ends
    # with the ENUM section, and this test's scenario is the field one; dropping whatever happens to
    # be last would silently start testing the enum refusal text instead.
    fields = [e for e in entries if "#" not in e]
    survivors = [e for e in entries if e != fields[-1]]
    fm.write_text("".join(header) + "\n".join(survivors) + "\n")

    r = _run(fm, rm)
    combined = r.stdout + r.stderr
    assert "--write-manifest" in combined
    assert "Decide first" in combined
    assert "Running the escape first" in combined


# ── the committed manifest, as shipped ────────────────────────────────────────────────────────────


def test_the_committed_manifest_declares_the_acdp_slots_it_deliberately_does_not_interpret() -> (
    None
):
    """These five landed on the contract and are declared WITHOUT being interpreted — the gate refused
    them first and this is the decision that refusal forced. Phase 9 settled it rather than
    reversing it: the fields are carried and never wired, because `verify/` does not compute
    `context_digest`.

    The header must carry the reasoning, because a future reader finding five undeclared-looking lines
    needs the decision without archaeology — and must not 'helpfully' normalise either status
    vocabulary, which would silently break third-party digest recomputation."""
    committed = REPO / "contract" / "field-manifest.txt"
    entries = _entries(committed)
    for f in (
        "ContextBinding/content_hash",
        "ContextBinding/receipt_hash",
        "ContextBinding/key_status",
        "ContextBinding/resolved_status",
        "ContextBinding/retraction",
    ):
        assert f in entries, f

    header = committed.read_text()
    assert "DELIBERATELY NOT" in header
    assert "key_status" in header and "resolved_status" in header
    assert "Phase 9" in header


def test_the_committed_manifest_header_carries_every_rule_the_gate_depends_on() -> None:
    """`--write-manifest` preserves the header by grepping the file it is about to overwrite, so a
    DELETED manifest regenerates headerless and every rule below would vanish silently. These are not
    prose: each one is a rule someone re-deriving this extractor has to know, and getting any of them
    wrong produces a gate that is either permanently red or silently blind.

    Runs without stubs on purpose — a header regression must not be able to hide behind an absent
    `make generate`."""
    header = "\n".join(
        ln
        for ln in (REPO / "contract" / "field-manifest.txt").read_text().splitlines()
        if ln.lstrip().startswith("#")
    )
    for needle, why in [
        ("<Message>/<field_name>", "the spelling rule"),
        ("--write-manifest` WRITES FROM", "which side the escape writes from"),
        ("**Python**", "the authoritative side, named"),
        ("`*_FIELD_NUMBER`", "what the Python extractor reads"),
        ("__slots__", "and what it must NOT read"),
        ("raise", "the field that proves why"),
        ("NESTING", "how map entries are excluded"),
        ("AuditEntry", "the real message a name filter would drop"),
        ("Names only", "that tags and types are NOT checked"),
        ("buf breaking", "what does cover them"),
    ]:
        assert needle in header, (
            f"the manifest header no longer states {why} ({needle!r})"
        )


def test_the_ts_extractor_excludes_nested_types_rather_than_misattributing_them(
    tmp_path,
) -> None:
    """protobuf-es names a nested type `seam.api.v1.Outer.Inner`. The top-level pattern cannot match
    it (the dot), so without an explicit nested arm `cls` retains the PREVIOUS top-level message and
    the nested fields are attributed to it — Python drops them, TypeScript invents them on the wrong
    owner, and the Python-authoritative escape can never clear the disagreement.

    Latent today only because protobuf-es emits no type for map entries. That is not an exclusion, so
    this pins the real one."""
    stub = tmp_path / "seam_pb.ts"
    stub.write_text(
        'export type Outer = Message<"seam.api.v1.Outer"> & {\n'
        "  /**\n   * @generated from field: string alpha = 1;\n   */\n  alpha: string;\n};\n"
        'export type Outer_Inner = Message<"seam.api.v1.Outer.Inner"> & {\n'
        "  /**\n   * @generated from field: string beta = 1;\n   */\n  beta: string;\n};\n"
        'export type Later = Message<"seam.api.v1.Later"> & {\n'
        "  /**\n   * @generated from field: string delta = 1;\n   */\n  delta: string;\n};\n"
    )
    extracted = subprocess.run(
        ["bash", "-c", f'{_ts_extractor_src()}\nTS_GEN="{stub}"\nfields_ts'],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    got = extracted.stdout.split()
    assert got == ["Later/delta", "Outer/alpha"], got
    assert "Outer/beta" not in got, (
        "nested field misattributed to the enclosing message"
    )


def _ts_extractor_src() -> str:
    """The real `fields_ts` function, lifted out of the shipped script rather than retyped — a copy
    would only prove that two copies agree."""
    src = (REPO / "scripts" / "check-contract.sh").read_text().splitlines(True)
    start = next(i for i, ln in enumerate(src) if ln.startswith("fields_ts() {"))
    end = next(i for i in range(start, len(src)) if src[i].rstrip() == "}")
    return "".join(src[start : end + 1])


# ── the enum-value surface, one level below FIELD ──────────────────────────────────────────────────
#
# `AuthorizeVerdict`/`CollectiveVerdict`/`BallotChoice` are exactly as blind a spot as a new FIELD:
# `buf breaking` upstream passes an additive enum value by design, and `python/seam_sdk/_collective.py`
# / `errors.py` are deliberately fail-closed and raise on any value they don't recognise. These tests
# drive the REAL script, same as every field test above — a Python reimplementation of the comparison
# would only prove two copies of the same logic agree with each other.


def _enum_entries(p: pathlib.Path) -> list[str]:
    return [e for e in _entries(p) if "#" in e]


def test_enum_manifest_written_from_scratch_stubs_passes(enum_manifests) -> None:
    """The baseline. If this fails, the Python and TS enum extractors disagree with each other and
    every negative case below is testing noise."""
    fm, rm, py, ts = enum_manifests
    r = _run(fm, rm, py_gen=py, ts_gen=ts)
    assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    assert "the enum-value surface matches" in r.stdout


def test_field_and_enum_lines_partition_cleanly(manifests) -> None:
    """The manifest is one flat file for both surfaces (`#` cannot occur in a message/field name, and
    an enum line never begins with `#` so it survives the comment filter). Every line must land in
    exactly one bucket."""
    fm, _ = manifests
    entries = _entries(fm)
    fields = [e for e in entries if "#" not in e]
    enums = [e for e in entries if "#" in e]
    assert len(fields) + len(enums) == len(entries)
    assert all("/" in e for e in fields)
    assert all(e.count("#") == 1 for e in enums)


def test_appending_an_enum_value_to_both_languages_reddens_the_gate_and_names_it(
    enum_manifests,
) -> None:
    """Acceptance criterion 2: appending one enum value to BOTH scratch stub trees makes the gate
    exit 6 and name `<Enum>#<VALUE>` for both languages."""
    fm, rm, py, ts = enum_manifests
    _py_add_enum_value(py, "BallotChoice", "BALLOT_CHOICE_VETOED")
    _ts_add_enum_value(ts, "BALLOT_CHOICE_VETOED", "VETOED", 4)

    r = _run(fm, rm, py_gen=py, ts_gen=ts)
    assert r.returncode == 6, (
        f"expected exit 6, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "BallotChoice#BALLOT_CHOICE_VETOED" in combined
    assert "NOT IN THE MANIFEST" in combined
    assert combined.count("BallotChoice#BALLOT_CHOICE_VETOED") >= 2, (
        "named independently for each language — a stale ts/gen beside a fresh python/_gen must show"
    )
    assert "GENERATION SKEW" not in combined, (
        "both languages agree with each other here — this is manifest drift, not generation skew"
    )


def test_deleting_an_enum_value_from_both_languages_reddens_the_gate_as_missing(
    enum_manifests,
) -> None:
    """Acceptance criterion 3: deleting one enum value from both scratch trees makes the gate exit 6,
    reporting it MISSING."""
    fm, rm, py, ts = enum_manifests
    _py_delete_enum_value(py)
    _ts_delete_enum_value(ts)

    r = _run(fm, rm, py_gen=py, ts_gen=ts)
    assert r.returncode == 6, (
        f"expected exit 6, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "BallotChoice#BALLOT_CHOICE_ABSTAIN" in combined
    assert "MISSING from the" in combined
    assert combined.count("BallotChoice#BALLOT_CHOICE_ABSTAIN") >= 2
    assert "GENERATION SKEW" not in combined, (
        "both languages still agree with each other — the value is just gone from both"
    )


def test_an_enum_value_added_to_only_one_language_is_reported_as_generation_skew(
    enum_manifests,
) -> None:
    """Acceptance criterion 4: a value added to only ONE language's stubs is neither ordinary
    'missing' nor ordinary 'not in the manifest' — python and ts disagree with EACH OTHER, which is a
    stale/partial regeneration in one tree, never a manifest decision, and must be reported as its own
    class of failure."""
    fm, rm, py, ts = enum_manifests
    _py_add_enum_value(py, "BallotChoice", "BALLOT_CHOICE_VETOED")
    # ts is deliberately left untouched.

    r = _run(fm, rm, py_gen=py, ts_gen=ts)
    assert r.returncode == 6, (
        f"expected exit 6, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "GENERATION SKEW" in combined
    assert "BallotChoice#BALLOT_CHOICE_VETOED" in combined
    assert "python has it, ts does not" in combined
    assert "A GENERATION SKEW is neither of the above" in combined, (
        "the explanation must distinguish this from an ordinary manifest-drift refusal"
    )


def test_nested_enum_in_python_stub_trips_the_guard(scratch_stubs, tmp_path) -> None:
    """No enum is nested inside a message today. enums_python assumes that structurally (a column-0
    class header); a nested one would otherwise vanish silently instead of being compared. This must
    fail loud, not pass quietly, the moment the assumption stops holding."""
    py, ts = scratch_stubs
    py.write_text(
        py.read_text()
        + "\n    class NestedEnum(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):\n"
    )
    r = _run(
        tmp_path / "field-manifest.txt",
        tmp_path / "rpc-manifest.txt",
        py_gen=py,
        ts_gen=ts,
    )
    assert r.returncode == 7, (
        f"expected exit 7, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    assert "NESTED enum" in (r.stdout + r.stderr)


def test_nested_enum_in_ts_stub_trips_the_guard(scratch_stubs, tmp_path) -> None:
    """Same guard, TS side: protobuf-es would name a nested enum `seam.api.v1.Outer.Inner` (the dot),
    which enums_ts's top-level anchor cannot match — so, like the Python side, it would silently
    vanish rather than fail."""
    py, ts = scratch_stubs
    ts.write_text(
        ts.read_text() + "\n * @generated from enum seam.api.v1.Outer.Inner\n"
    )
    r = _run(
        tmp_path / "field-manifest.txt",
        tmp_path / "rpc-manifest.txt",
        py_gen=py,
        ts_gen=ts,
    )
    assert r.returncode == 7, (
        f"expected exit 7, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    assert "NESTED enum" in (r.stdout + r.stderr)


# ── the committed manifest's enum section, as shipped ──────────────────────────────────────────────


def test_the_committed_manifest_enum_section_is_not_vacuous_and_covers_all_three_enums() -> (
    None
):
    """The anti-vacuity floor: a future refactor that silently empties the enum section (or narrows it
    to fewer than all three enums) must fail here, not slip through as a passing gate. Runs without
    stubs on purpose, same as the field header test — a regression here must not be able to hide
    behind an absent `make generate`."""
    committed = REPO / "contract" / "field-manifest.txt"
    entries = _enum_entries(committed)
    assert len(entries) >= 15, (
        f"only {len(entries)} enum values declared — the section emptied, or the extractor broke"
    )
    names = {e.split("#", 1)[0] for e in entries}
    assert names == {"AuthorizeVerdict", "CollectiveVerdict", "BallotChoice"}, names
    # UNSPECIFIED zero values are DECLARED, never filtered — removing the fail-safe default every
    # OTHER value's fail-closed behaviour depends on is exactly as real a breaking change as removing
    # any other value.
    for zero in (
        "AuthorizeVerdict#AUTHORIZE_VERDICT_UNSPECIFIED",
        "BallotChoice#BALLOT_CHOICE_UNSPECIFIED",
        "CollectiveVerdict#COLLECTIVE_VERDICT_UNSPECIFIED",
    ):
        assert zero in entries, zero


# ── the nested-message tripwire ────────────────────────────────────────────────────────────────────
#
# fields_python/fields_ts exclude a nested message BY NESTING (see the manifest header's own
# "SYNTHETIC MAP-ENTRY MESSAGES..." section) — correct for the two known FeaturesEntry map-entry
# synthetics, but that exclusion is SYMMETRIC across both languages, so a genuine nested message is
# invisible to BOTH extractors at once: the manifest header's own stated failure mode, "the gate stays
# green while going blind," reproduced by the fix for the *other* case of it.
#
# The contract has zero real nested messages today, so `assert_known_nested_messages_only` in
# `scripts/check-contract.sh` is a tripwire, not a speculative extractor: it asserts the only nested
# message types are the two known synthetics, with an EXACT allowlist — removing a known synthetic
# must trip it exactly as loudly as an unknown one appearing.

# The real AuthorizeRequest.FeaturesEntry block, lifted verbatim from the generated .pyi (it also
# appears once more, verbatim, as RunDecisionRequest.FeaturesEntry) — hand-typing it risks silently
# drifting from what the generator actually emits and passing for the wrong reason.
_PY_FEATURES_ENTRY_BLOCK = (
    "    class FeaturesEntry(_message.Message):\n"
    '        __slots__ = ("key", "value")\n'
    "        KEY_FIELD_NUMBER: _ClassVar[int]\n"
    "        VALUE_FIELD_NUMBER: _ClassVar[int]\n"
    "        key: str\n"
    "        value: str\n"
    "        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...\n"
)

_PY_NESTED_MESSAGE_MUTATION = (
    "\nclass EscrowDirective(_message.Message):\n"
    '    __slots__ = ("amount_cents",)\n'
    "    class Hold(_message.Message):\n"
    '        __slots__ = ("amount_cents", "release_after_ms")\n'
    "        AMOUNT_CENTS_FIELD_NUMBER: _ClassVar[int]\n"
    "        RELEASE_AFTER_MS_FIELD_NUMBER: _ClassVar[int]\n"
    "        amount_cents: int\n"
    "        release_after_ms: int\n"
    "        def __init__(self, amount_cents: _Optional[int] = ..., "
    "release_after_ms: _Optional[int] = ...) -> None: ...\n"
    "    AMOUNT_CENTS_FIELD_NUMBER: _ClassVar[int]\n"
    "    amount_cents: int\n"
    "    def __init__(self, amount_cents: _Optional[int] = ...) -> None: ...\n"
)

_TS_NESTED_MESSAGE_MUTATION = (
    '\nexport type EscrowDirective_Hold = Message<"seam.api.v1.EscrowDirective.Hold"> & {\n'
    "  /**\n   * @generated from field: int64 amount_cents = 1;\n   */\n"
    "  amountCents: bigint;\n"
    "};\n"
)


def test_nested_message_added_to_python_stub_trips_the_guard(
    scratch_stubs, tmp_path
) -> None:
    """Acceptance criterion 1 (python side). Proven by mutation against a scratch copy — never the
    real gitignored stub tree — that `EscrowDirective.Hold{amount_cents, release_after_ms}` is
    invisible to fields_python (only the top-level sibling `EscrowDirective/amount_cents` would show)
    unless the nested-message tripwire fires first."""
    py, ts = scratch_stubs
    py.write_text(py.read_text() + _PY_NESTED_MESSAGE_MUTATION)
    r = _run(
        tmp_path / "field-manifest.txt",
        tmp_path / "rpc-manifest.txt",
        py_gen=py,
        ts_gen=ts,
    )
    assert r.returncode == 7, (
        f"expected exit 7, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "nested-message allowlist" in combined
    assert "EscrowDirective.Hold" in combined
    assert "UNKNOWN nested message" in combined


def test_nested_message_added_to_ts_stub_trips_the_guard(
    scratch_stubs, tmp_path
) -> None:
    """Acceptance criterion 1 (ts side). protobuf-es would spell a real nested message
    `Message<"seam.api.v1.EscrowDirective.Hold">` — the same dotted shape fields_ts already matches to
    SKIP a nested type, so without the tripwire it vanishes from the TS side exactly as silently as it
    does on the Python side."""
    py, ts = scratch_stubs
    ts.write_text(ts.read_text() + _TS_NESTED_MESSAGE_MUTATION)
    r = _run(
        tmp_path / "field-manifest.txt",
        tmp_path / "rpc-manifest.txt",
        py_gen=py,
        ts_gen=ts,
    )
    assert r.returncode == 7, (
        f"expected exit 7, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "nested-message allowlist" in combined
    assert "EscrowDirective.Hold" in combined
    assert "ts (" in combined and "allowlist does not expect" in combined


def test_removing_a_known_synthetic_also_trips_the_guard(
    scratch_stubs, tmp_path
) -> None:
    """Acceptance criterion 2: the allowlist is EXACT, not a floor. Deleting one of the two known
    FeaturesEntry synthetics must trip the wire exactly as loudly as an unknown one appearing — a
    one-directional check (only 'unknown extra' fails) would let the allowlist quietly decay to fewer
    entries than the stubs actually declare without anyone noticing."""
    py, ts = scratch_stubs
    text = py.read_text()
    assert text.count(_PY_FEATURES_ENTRY_BLOCK) == 2, (
        "known anchor not found twice — the real .pyi shape changed"
    )
    py.write_text(text.replace(_PY_FEATURES_ENTRY_BLOCK, "", 1))

    r = _run(
        tmp_path / "field-manifest.txt",
        tmp_path / "rpc-manifest.txt",
        py_gen=py,
        ts_gen=ts,
    )
    assert r.returncode == 7, (
        f"expected exit 7, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "MISSING a known synthetic" in combined
    assert "AuthorizeRequest.FeaturesEntry" in combined


def test_the_real_tree_passes_the_nested_message_tripwire(manifests) -> None:
    """Acceptance criterion 4: on the real generated stubs, the only nested message types are the two
    known FeaturesEntry map-entry synthetics. The `manifests` fixture already proves this indirectly
    (--write-manifest calls assert_known_nested_messages_only before writing), but this drives the
    probing path too and asserts the failure mode by name, not just by side effect."""
    fm, rm = manifests
    r = _run(fm, rm)
    combined = r.stdout + r.stderr
    assert r.returncode != 7, (
        f"the real tree tripped the nested-message tripwire unexpectedly\n{r.stdout}\n{r.stderr}"
    )
    assert "nested-message allowlist disagrees" not in combined


def test_nested_messages_python_extractor_sees_exactly_the_two_known_synthetics() -> (
    None
):
    """A direct check on the extractor itself (lifted from the shipped script, same technique as
    `_ts_extractor_src`), independent of the hardcoded allowlist in
    `assert_known_nested_messages_only` — so a future edit that changes BOTH the extractor and the
    allowlist together in a way that still agrees with each other, but no longer matches what the real
    stubs carry, cannot hide behind the tripwire alone."""
    _require_stubs()
    src = _nested_messages_python_extractor_src()
    extracted = subprocess.run(
        ["bash", "-c", f'{src}\nPY_GEN="{PY_STUB}"\nnested_messages_python'],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    got = extracted.stdout.split()
    assert got == [
        "AuthorizeRequest.FeaturesEntry",
        "RunDecisionRequest.FeaturesEntry",
    ], got


def _nested_messages_python_extractor_src() -> str:
    """The real `nested_messages_python` function, lifted out of the shipped script rather than
    retyped — a copy would only prove that two copies agree."""
    src = (REPO / "scripts" / "check-contract.sh").read_text().splitlines(True)
    start = next(
        i for i, ln in enumerate(src) if ln.startswith("nested_messages_python() {")
    )
    end = next(i for i in range(start, len(src)) if src[i].rstrip() == "}")
    return "".join(src[start : end + 1])


# ── the expected local lag — distinguishing the known gap from real drift ─────────────────────────
#
# `STREAM=1 EVENTS=1 make check-contract` exits 6 on every pre-ACDP local checkout: the committed
# `contract/field-manifest.txt` already declares five `ContextBinding` fields the local stubs do not
# carry until a regeneration pulls a BSR module that republishes them. The refusal text is the exact
# wording, exit code, and direction a REAL removal produces, which trains a reader to stop looking —
# `contract/expected-local-lag.txt` exists so the SDK can tell "the known five" from "the known five
# plus one" by machine. The gate STILL exits 6 on an exact match (CI is the authority); only the
# OUTPUT changes.

_KNOWN_LAG_FIELDS = [
    "ContextBinding/content_hash",
    "ContextBinding/key_status",
    "ContextBinding/receipt_hash",
    "ContextBinding/resolved_status",
    "ContextBinding/retraction",
]


def test_the_committed_lag_file_declares_exactly_the_five_known_fields() -> None:
    """Anti-vacuity floor for the file itself, no stubs required — a regression here (an emptied or
    narrowed file) would make every downgrade test below pass vacuously."""
    assert LAG_FILE.exists(), f"{LAG_FILE} is missing"
    entries = _entries(LAG_FILE)
    assert entries == sorted(_KNOWN_LAG_FIELDS), entries
    header = LAG_FILE.read_text()
    assert "EXPECTED-FROM:" in header
    assert "--write-manifest" in header and "DELETES" in header


def test_the_real_pre_acdp_tree_downgrades_to_a_note_naming_the_lag_file() -> None:
    """Acceptance criterion 1: on the real tree, with NO overrides at all (the exact command
    CLAUDE.md's Gotchas now documents), the gate exits 6 and its output unmistakably identifies the
    five ACDP fields as the recorded expected lag, naming `contract/expected-local-lag.txt` by path."""
    _require_stubs()
    if not LAG_FILE.exists():
        pytest.skip("contract/expected-local-lag.txt is absent on this checkout")
    r = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO,
        env={**os.environ, "STREAM": "1", "EVENTS": "1"},
        capture_output=True,
        text=True,
    )
    assert r.returncode == 6, (
        f"expected exit 6, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "NOTE" in combined
    assert "contract/expected-local-lag.txt" in combined
    assert "STILL exits 6" in combined
    for field in _KNOWN_LAG_FIELDS:
        assert field in combined, field
    # The full, un-downgraded refusal text must NOT also appear — the whole point is that the reader
    # sees ONE unmistakable story, not both.
    assert "the generated FIELD surface disagrees with" not in combined


def test_a_superset_of_the_known_lag_stays_a_full_undowngraded_error(
    manifests,
) -> None:
    """Acceptance criterion 2: a scratch manifest that expects the known five PLUS one more field the
    stubs also lack is a SUPERSET of the recorded lag — not a match — and must produce the full,
    un-downgraded exit 6, not the NOTE.

    Built from the REAL committed manifest (not the `manifests` fixture's stub-derived one) so the
    baseline actually reproduces the real five-field gap; `manifests` here only supplies a scratch RPC
    manifest so `--write-manifest` never touches the committed one.
    """
    _, rm = manifests
    real_manifest_text = (REPO / "contract" / "field-manifest.txt").read_text()
    fm = rm.parent / "superset-field-manifest.txt"
    fm.write_text(real_manifest_text + "ContextBinding/a_field_that_does_not_exist\n")

    r = _run(fm, rm)
    assert r.returncode == 6, (
        f"expected exit 6, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "the generated FIELD surface disagrees with" in combined
    assert "ContextBinding/a_field_that_does_not_exist" in combined
    for field in _KNOWN_LAG_FIELDS:
        assert field in combined, field


def test_a_subset_of_the_known_lag_stays_a_full_undowngraded_error(manifests) -> None:
    """Acceptance criterion 3: a scratch manifest missing only FOUR of the five recorded fields is
    also not a match (subset != match) and must produce the full, un-downgraded exit 6."""
    _, rm = manifests
    real_manifest_text = (REPO / "contract" / "field-manifest.txt").read_text()
    fm = rm.parent / "subset-field-manifest.txt"
    fm.write_text(
        "\n".join(
            ln
            for ln in real_manifest_text.splitlines()
            if ln.strip() != "ContextBinding/retraction"
        )
        + "\n"
    )

    r = _run(fm, rm)
    assert r.returncode == 6, (
        f"expected exit 6, got {r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    combined = r.stdout + r.stderr
    assert "the generated FIELD surface disagrees with" in combined
    for field in _KNOWN_LAG_FIELDS[:-1]:
        assert field in combined, field


def test_write_manifest_deletes_the_scratch_lag_file(manifests) -> None:
    """Acceptance criterion 4, tested via `SEAM_FIELD_MANIFEST`/a scratch lag file ONLY — never the
    real committed manifest or the real committed `contract/expected-local-lag.txt`. After a
    `--write-manifest` rewrite the recorded lag is meaningless (the manifest's forward set moved), so
    the file must be removed, not left to silently downgrade a future, unrelated gap."""
    fm, rm = manifests
    lag = fm.parent / "expected-local-lag.txt"
    lag.write_text("\n".join(_KNOWN_LAG_FIELDS) + "\n")
    assert lag.exists()

    r = _run(fm, rm, "--write-manifest", lag_file=lag)
    assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    assert not lag.exists(), "the scratch lag file must be deleted by --write-manifest"
    assert "removed" in (r.stdout + r.stderr)
    assert str(lag) in (r.stdout + r.stderr)


def test_write_manifest_is_a_noop_when_no_lag_file_is_present(manifests) -> None:
    """The delete step must not fail (or fabricate output) when there is nothing to delete — the
    common case for every OTHER test in this file, which never creates a scratch lag file at all."""
    fm, rm = manifests
    lag = fm.parent / "expected-local-lag.txt"
    assert not lag.exists()

    r = _run(fm, rm, "--write-manifest", lag_file=lag)
    assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    assert not lag.exists()
