"""The field manifest is only worth committing if the gate it feeds actually refuses.

`contract/field-manifest.txt` declares every `seam.api.v1` message field the SDK expects, and
`scripts/check-contract.sh` set-compares it against the generated stubs per language, in both
directions. A manifest gate that cannot be driven red is a list, not a gate — so every assertion here
executes the REAL script (the pattern `scripts/test_ci_gate.py` uses) rather than reimplementing its
comparison in Python, which would only prove that two copies of the same logic agree.

**Nothing here touches the real manifests or the real stub trees.** The script reads four paths from
the environment (`SEAM_PY_GEN`, `SEAM_TS_GEN`, `SEAM_FIELD_MANIFEST`, `SEAM_RPC_MANIFEST`), defaulting
to the real ones, and every test below redirects the two manifests into `tmp_path`. That is not
fastidiousness: `python/seam_sdk/_gen` and `ts/gen` are **gitignored**, so a test that corrupted them
could not restore them with git, and recovery would need a `make generate` and a BSR login.

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

pytestmark = pytest.mark.skipif(
    not (PY_STUB.exists() and TS_STUB.exists()),
    reason="generated stubs absent — run `make generate` (this gate inspects stubs, it cannot invent them)",
)


def _run(field_manifest: pathlib.Path, rpc_manifest: pathlib.Path, *args: str):
    env = {
        **os.environ,
        "SEAM_FIELD_MANIFEST": str(field_manifest),
        "SEAM_RPC_MANIFEST": str(rpc_manifest),
        "STREAM": "1",
        "EVENTS": "1",
    }
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
    fm, rm = tmp_path / "field-manifest.txt", tmp_path / "rpc-manifest.txt"
    r = _run(fm, rm, "--write-manifest")
    assert r.returncode == 0, r.stderr
    assert fm.exists() and rm.exists()
    return fm, rm


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
    assert all("/" in e for e in entries), "every entry is <Message>/<field>"


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
    fm.write_text("".join(header) + "\n".join(entries[:-1]) + "\n")

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
    them first and this is the decision that refusal forced. Wiring them is Phase 9.

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
