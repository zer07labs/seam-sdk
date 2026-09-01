"""`publish.yml`'s CI gate races the CI it is checking, so patience is part of its correctness.

The release step pushes the commit and the tag seconds apart. The commit push starts `ci.yml`; the
tag push starts `publish.yml`. So when the gate asks "is `ci-ok` green for this commit?", the honest
answer is often "no check run exists yet" — not because CI failed, but because it has not registered.

Read once and that reads as absent, which the gate refuses. It is refusing the right way for the
wrong reason. v0.7.47 hit exactly this: publish fired at 03:24:39Z, `ci-ok` appeared at 03:25:26Z,
and the release lost by 47 seconds and needed a hand re-run.

The fix is a bounded wait, and the thing worth testing is that waiting did not soften anything:

  * absent / pending / API failure  → transient, keep waiting
  * settled non-success            → refuse IMMEDIATELY, do not wait out the ceiling
  * ceiling exhausted              → refuse; a timeout is not a pass

These run the real script out of the workflow against a stubbed `gh`, because a gate whose logic is
only read and never executed is how the ordering bug in `release-on-runtime.yml` survived a day.

Run: `python -m pytest scripts/test_publish_gate.py -q`
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
PUBLISH = REPO / ".github" / "workflows" / "publish.yml"
SHA = "860db039ae97d4e52cef956a4959c349b444e468"


def _gate_script() -> str:
    job = yaml.safe_load(PUBLISH.read_text())["jobs"]["ci-green"]
    step = next(s for s in job["steps"] if "resolve ci-ok" in str(s.get("name", "")))
    return step["run"]


def _run(responses: list[str | None], tmp_path: Path) -> subprocess.CompletedProcess:
    """Execute the gate with `gh` returning `responses[i]` on call i (None == API failure).

    The final response repeats forever, so a test can say "absent, then green" or "absent always"
    without enumerating forty entries. `sleep` is stubbed to a no-op so the ceiling is exercised in
    milliseconds rather than twenty minutes.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    calls = tmp_path / "calls"
    calls.write_text("0")

    payloads = tmp_path / "payloads"
    payloads.mkdir()
    for i, r in enumerate(responses):
        (payloads / str(i)).write_text("" if r is None else r)
        (payloads / f"{i}.fail").write_text("1" if r is None else "0")

    (bin_dir / "gh").write_text(
        textwrap.dedent(f"""\
        #!/usr/bin/env bash
        n=$(cat {calls})
        echo $((n + 1)) > {calls}
        last={len(responses) - 1}
        [ "$n" -gt "$last" ] && n=$last
        if [ "$(cat {payloads}/$n.fail)" = "1" ]; then exit 1; fi
        cat {payloads}/$n
        """)
    )
    (bin_dir / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n")
    for f in ("gh", "sleep"):
        (bin_dir / f).chmod(0o755)

    proc = subprocess.run(
        ["bash", "-c", _gate_script()],
        env={
            "GH_TOKEN": "stub",
            "REPO": "zer07labs/seam-sdk",
            "SHA": SHA,
            "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        },
        capture_output=True,
        text=True,
        check=False,  # a non-zero exit IS the thing under test
    )
    proc.gh_calls = int(calls.read_text())  # type: ignore[attr-defined]
    return proc


def test_green_on_the_first_look_publishes(tmp_path: Path) -> None:
    p = _run(["success"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "CI is green" in p.stdout


def test_two_ci_ok_runs_both_green_publishes(tmp_path: Path) -> None:
    """A commit that was also a PR head carries one ci-ok per check suite; all must pass."""
    p = _run(["success\nsuccess"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "2 ci-ok run(s)" in p.stdout


def test_absent_then_green_publishes(tmp_path: Path) -> None:
    """The v0.7.47 regression: CI had not registered yet, and the gate refused for it."""
    p = _run(["", "", "success"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "not registered yet" in p.stdout, "should have reported why it was waiting"


def test_pending_then_green_publishes(tmp_path: Path) -> None:
    p = _run(["pending", "success"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "still running" in p.stdout


def test_api_failure_then_green_publishes(tmp_path: Path) -> None:
    """A transient outage must not read as a verdict in either direction."""
    p = _run([None, "success"], tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "API call failed" in p.stdout


@pytest.mark.parametrize("verdict", ["failure", "cancelled", "timed_out", "neutral"])
def test_a_settled_non_success_refuses_immediately(verdict: str, tmp_path: Path) -> None:
    """Waiting cannot turn a red run green — refusing late would only delay the same answer."""
    p = _run([verdict], tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "not success" in (p.stdout + p.stderr)
    assert p.gh_calls == 1, (  # type: ignore[attr-defined]
        f"refused after {p.gh_calls} API calls — a settled verdict must not burn the ceiling"  # type: ignore[attr-defined]
    )


def test_one_green_does_not_mask_one_red(tmp_path: Path) -> None:
    p = _run(["success\nfailure"], tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "does not cancel a red one" in (p.stdout + p.stderr)


def test_never_registering_times_out_into_a_refusal(tmp_path: Path) -> None:
    """Fail-closed is the property the wait must not have softened."""
    p = _run([""], tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "Timed out" in (p.stdout + p.stderr)
    assert "not a pass" in (p.stdout + p.stderr)


def test_forever_pending_times_out_into_a_refusal(tmp_path: Path) -> None:
    p = _run(["pending"], tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "Timed out" in (p.stdout + p.stderr)


def test_the_gate_actually_waits_rather_than_asking_once(tmp_path: Path) -> None:
    """Guards the guard: if the loop is ever removed, every test above still passes on its first
    look. Only the call count distinguishes 'patient' from 'lucky'."""
    p = _run([""], tmp_path)
    assert p.gh_calls > 1, (  # type: ignore[attr-defined]
        f"the gate asked {p.gh_calls} time(s) before giving up — it is not waiting at all, which "  # type: ignore[attr-defined]
        "is the v0.7.47 failure"
    )


# ══════════════════════════════════════════════════════════════════════════════════════════
# The publish-time floor guard, and the tag-ancestry guard.
#
# v0.7.43 declared `protobuf>=7.35.1,<8` over 7.36.0 gencode and shipped it. Its CI was RED
# on that exact test (all three runs at ff0139a), and `ci-green` closes the path it took.
# What these guards close is the OTHER path: `ci.yml` runs the floor tests against the stubs
# generated in ITS run, so a genuinely green CI proves nothing about the shipped wheel.
# `publish.yml` regenerates from scratch against buf's unpinned REMOTE plugins, so the
# gencode it bundles can differ from the gencode CI measured — and nothing re-checked the
# floor afterwards. Both smoke tests then install protobuf unconstrained, which by
# construction satisfies any gencode, so the skew was invisible end to end.
#
# These execute the new steps rather than reading them, for the same reason the block above
# does. That is not theoretical here: a read-only pass over this very workflow missed
# `git fetch --depth=0`, which git refuses outright ("depth 0 is not a positive number"),
# and which would have failed every publish.
# ══════════════════════════════════════════════════════════════════════════════════════════

PY_TESTS = REPO / "python" / "tests"


def _steps(job: str) -> list[dict]:
    return yaml.safe_load(PUBLISH.read_text())["jobs"][job]["steps"]


def _step(job: str, needle: str) -> dict:
    return next(s for s in _steps(job) if needle in str(s.get("name", "")))


def _step_names(job: str) -> list[str]:
    return [str(s.get("name", s.get("uses", ""))) for s in _steps(job)]


# ── the floor re-derivation step ──────────────────────────────────────────────────────────

_GENCODE_STUB = """\
from google.protobuf import runtime_version as _runtime_version

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, {major}, {minor}, {patch}, '', 'seam/api/v1/seam.proto'
)
"""

# Both calling-convention markers the grpcio guard knows about, so the stub tree exercises
# the same derivation the real stubs do rather than a degenerate one.
_GRPC_STUB = """\
channel.unary_unary('/seam.api.v1.Seam/Authorize', _registered_method=True)
server.add_registered_method_handlers('seam.api.v1.Seam', rpc_method_handlers)
"""

# A convention in NEITHER `_MARKERS` entry — the shape a future grpc plugin roll takes, per
# `test_grpcio_floor.py`'s own docstring: "the plugin's output convention changed once already".
# Deliberately shares no substring with either known marker, so `_markers_present()` returns `[]`.
_UNKNOWN_MARKER_GRPC_STUB = """\
channel.unary_unary('/seam.api.v1.Seam/Authorize', _new_calling_convention_v9=True)
"""

_PYPROJECT_STUB = """\
[project]
name = "seam-sdk"
version = "0.0.0"
dependencies = [
  "protobuf>={floor},<{cap}",
  "grpcio>={grpcio}",
]
"""


def _stub_repo(
    tmp_path: Path,
    *,
    floor: str,
    gencode: str,
    grpcio: str = "1.64",
    generated: bool = True,
    grpc_stub: str = _GRPC_STUB,
) -> Path:
    """A miniature repo with the SAME layout the floor guards resolve against.

    `generated=False` omits the `_gen` TREE, not merely the files in it. That distinction is the
    whole test: an empty `_gen/` makes `test_grpcio_floor.py`'s `assert sources` hard-fail, so the
    step exits non-zero for a reason that has nothing to do with the guard under test — which is
    how the first version of this passed with the guard deleted.

    They locate the tree from their own `__file__` (`parents[2]`), so copying the real test
    files into a stub tree makes them measure the stub's pyproject and stub's gencode. The
    logic under test is therefore the shipped logic, not a re-description of it.
    """
    root = tmp_path / "stubrepo"
    gen = root / "python" / "seam_sdk" / "_gen" / "seam" / "api" / "v1"
    if generated:
        gen.mkdir(parents=True)
    tests = root / "python" / "tests"
    tests.mkdir(parents=True)
    for name in ("test_protobuf_floor.py", "test_grpcio_floor.py"):
        shutil.copy(PY_TESTS / name, tests / name)

    major, minor, patch = (int(p) for p in gencode.split("."))
    if generated:
        (gen / "seam_pb2.py").write_text(
            _GENCODE_STUB.format(major=major, minor=minor, patch=patch)
        )
        (gen / "seam_pb2_grpc.py").write_text(grpc_stub)
    (root / "python" / "pyproject.toml").write_text(
        _PYPROJECT_STUB.format(floor=floor, cap=major + 1, grpcio=grpcio)
    )
    return root


def _inner_python() -> str:
    """An interpreter that can actually run the two floor guards.

    The step's first line installs `pytest grpcio`; the harness neuters that rather than
    reaching PyPI, so something on this machine has to already have them. CI's
    `workflow-guards` job installs exactly that list, so `sys.executable` qualifies there.
    Locally the outer suite may run on an interpreter without grpcio, so the repo venv is
    tried as well — `test_grpcio_floor.py` imports grpc at module scope and would otherwise
    error out for a reason that has nothing to do with the floor.
    """
    candidates = [sys.executable, str(REPO / "python" / ".venv" / "bin" / "python")]
    for exe in candidates:
        probe = subprocess.run(
            [exe, "-c", "import pytest, grpc"], capture_output=True, check=False
        )
        if probe.returncode == 0:
            return exe
    pytest.skip(f"no interpreter with both pytest and grpcio among {candidates}")


def _run_floor_step(root: Path) -> subprocess.CompletedProcess:
    """Run the workflow's floor step verbatim against `root`, with `pip install` neutered."""
    exe = _inner_python()
    bin_dir = root.parent / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "python").write_text(
        textwrap.dedent(f"""\
        #!/usr/bin/env bash
        if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then exit 0; fi
        exec {exe} "$@"
        """)
    )
    (bin_dir / "python").chmod(0o755)

    return subprocess.run(
        ["bash", "-c", _step("python", "re-derive the dependency floors")["run"]],
        cwd=root,
        env={
            "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
            "HOME": str(root.parent),
        },
        capture_output=True,
        text=True,
        check=False,  # a non-zero exit IS the thing under test
    )


def test_the_floors_are_re_derived_after_generation_and_before_the_wheel_is_built() -> None:
    """Order is the whole mechanism. Re-deriving before `make generate` would measure the
    gencode of a previous run, which is exactly the stale answer `ci.yml` already gives."""
    names = _step_names("python")
    gen = next(i for i, n in enumerate(names) if "generate the transport stubs" in n)
    derive = next(i for i, n in enumerate(names) if "re-derive the dependency floors" in n)
    build = next(i for i, n in enumerate(names) if n.startswith("build ("))
    assert gen < derive < build, (
        f"floor re-derivation must sit between generation and build; got "
        f"generate={gen}, re-derive={derive}, build={build} in {names}"
    )


def test_a_floor_that_trails_the_gencode_fails_the_publish_step(tmp_path: Path) -> None:
    """v0.7.43, reconstructed: floor 7.35.1 declared over 7.36.0 gencode. This is the case
    that shipped, and the publish path must now refuse it."""
    root = _stub_repo(tmp_path, floor="7.35.1", gencode="7.36.0")
    p = _run_floor_step(root)
    assert p.returncode != 0, (
        "the publish step accepted a floor BELOW its own bundled gencode — this is the "
        f"0.7.43 defect and it must not pass:\n{p.stdout}{p.stderr}"
    )
    assert "Raise the floor to >=7.36.0" in p.stdout + p.stderr, (
        f"it failed, but not for the floor reason — check the harness:\n{p.stdout}{p.stderr}"
    )


def test_a_floor_that_matches_the_gencode_passes_the_publish_step(tmp_path: Path) -> None:
    """Guards the guard above: proves the red case is red for the floor, not because the
    harness cannot run the tests at all (a `-k` that matches nothing exits 5, not 0)."""
    root = _stub_repo(tmp_path, floor="7.36.0", gencode="7.36.0")
    p = _run_floor_step(root)
    assert p.returncode == 0, (
        f"a correctly-derived floor must publish:\n{p.stdout}{p.stderr}"
    )


def test_a_grpcio_floor_below_the_emitted_convention_fails_the_publish_step(
    tmp_path: Path,
) -> None:
    """The same skew in the other dependency: the stubs call
    `add_registered_method_handlers` (grpcio 1.64) while pyproject claims 1.63."""
    root = _stub_repo(tmp_path, floor="7.36.0", gencode="7.36.0", grpcio="1.63")
    p = _run_floor_step(root)
    assert p.returncode != 0, (
        f"a grpcio floor the emitted stubs outrun must not publish:\n{p.stdout}{p.stderr}"
    )
    assert "add_registered_method_handlers" in p.stdout + p.stderr, (
        f"failed for some other reason than the grpcio floor:\n{p.stdout}{p.stderr}"
    )


def test_an_unrecognised_grpc_convention_fails_the_publish_step(tmp_path: Path) -> None:
    """The hole `covers_every_convention` alone cannot see: a plugin roll that emits a THIRD
    calling-convention marker, in neither `_MARKERS` entry, leaves `_markers_present()` empty.
    `max()` over an empty sequence still raises — so this stub already made the OLD `-k` non-zero,
    just via an uncaught `ValueError` inside the wrong test, not via a refusal that names the
    problem. The second assertion below is what tells the two apart: it only holds once the `-k`
    selects `test_the_emitted_stubs_use_a_convention_this_guard_recognises`, the test whose whole
    job is to fire — with a message that says what happened — when no known marker matches."""
    root = _stub_repo(
        tmp_path,
        floor="7.36.0",
        gencode="7.36.0",
        grpc_stub=_UNKNOWN_MARKER_GRPC_STUB,
    )
    p = _run_floor_step(root)
    assert p.returncode != 0, (
        f"an unrecognised grpc calling-convention marker must not publish:\n{p.stdout}{p.stderr}"
    )
    assert "none of the known calling-convention markers" in p.stdout + p.stderr, (
        "failed, but not via the recognizer test's own message — the derivation's bare `max()` "
        f"crash is not the same guard as a named refusal:\n{p.stdout}{p.stderr}"
    )


def test_stubs_in_the_wrong_place_fail_rather_than_skip_the_guard(tmp_path: Path) -> None:
    """The guard's own blind spot, asserted shut.

    `test_protobuf_floor.py` calls `pytest.skip()` when `seam_pb2.py` is absent, and pytest exits
    **0** when every selected test skips — only *zero collected* is exit 5. So a `make generate`
    that succeeds while writing the tree somewhere else would leave the step green having checked
    nothing. Writing `_gen` in a place the package cannot import from is precisely the defect this
    job shipped once already, so "it was just generated, it must be there" is an assumption, not an
    assertion.
    """
    root = _stub_repo(tmp_path, floor="7.36.0", gencode="7.36.0", generated=False)
    p = _run_floor_step(root)
    assert p.returncode != 0, (
        "the floor guard passed with NO generated stubs to measure — it skipped, exited 0, and "
        f"would have published unchecked:\n{p.stdout}{p.stderr}"
    )
    # Anchored to the guard's OWN message, not merely to a non-zero exit. Without this the test
    # passes on any failure — which is exactly how its first version stayed green while the guard
    # it protects was deleted.
    assert "the generated tree is not at python/seam_sdk/_gen" in p.stdout + p.stderr, (
        "it failed, but not at the presence check — so this test would not notice that check "
        f"being removed:\n{p.stdout}{p.stderr}"
    )


# ── the floor-pinned wheel install ────────────────────────────────────────────────────────


def _floor_parse_snippet() -> str:
    """Just the `FLOOR=...`/`GRPCIO_FLOOR=...` derivations out of the build step — the part that
    can run without a wheel, a venv, or a network."""
    run = _step("python", "build (")["run"]
    return run[run.index("FLOOR=$(") : run.index("python -m venv /tmp/floorcheck")]


def _run_floor_parse(cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", _floor_parse_snippet()],
        cwd=cwd,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_floor_is_parsed_out_of_pyproject_rather_than_hardcoded(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        _PYPROJECT_STUB.format(floor="7.36.0", cap=8, grpcio="1.64")
    )
    p = _run_floor_parse(tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "declared protobuf floor: 7.36.0" in p.stdout, p.stdout + p.stderr


def test_an_unparseable_pyproject_refuses_to_publish(tmp_path: Path) -> None:
    """Fail closed. If the pin's spelling ever changes, the wheel must not sail through
    unchecked — that silent pass is the shape of the defect this whole step exists for."""
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["protobuf"]\n')
    p = _run_floor_parse(tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "could not parse the declared protobuf floor" in p.stdout + p.stderr


def test_the_floor_pinned_install_has_no_unconstrained_fallback() -> None:
    """A `|| pip install dist/*.whl` rescue would recreate the exact blind spot: the
    unconstrained resolution always satisfies the gencode/convention, so it can only ever pass."""
    run = _step("python", "build (")["run"]
    tail = run[run.index("FLOOR=$(") :]
    assert 'protobuf==$FLOOR" "grpcio==$GRPCIO_FLOOR" dist/*.whl' in tail, (
        "the floor-pinned install is gone, or grpcio is no longer pinned in the SAME install as "
        "protobuf — the wheel's metadata is no longer checked end to end"
    )
    assert tail.count("/tmp/floorcheck/bin/python -m pip install") == 1, (
        "more than one install into the floor venv — a fallback resolution defeats the pin"
    )
    assert "from seam_sdk._gen.seam.api.v1 import seam_pb2" in tail, (
        "the floor venv must import seam_pb2 — that module's preamble is where protobuf's "
        "runtime-version check fires, and it is the entire assertion"
    )
    assert 'importlib.metadata.version("grpcio")' in tail, (
        "the floor venv must read grpcio's installed version back from metadata — 'some grpcio' "
        "installed is not the same assertion as 'grpcio AT the declared floor'"
    )
    assert "from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc" in tail, (
        "the floor venv must exercise the grpc stub module — a calling-convention mismatch "
        "surfaces at stub construction or servicer registration, not at import"
    )
    assert "add_SeamAdmissionServicer_to_server" in tail and "SeamAdmissionStub(channel)" in tail, (
        "the floor venv must both construct a client stub and register a server-side servicer — "
        "the client and server calling conventions split across different grpcio versions"
    )


# ── the tag-ancestry guard ────────────────────────────────────────────────────────────────


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def pushed_and_unpushed(tmp_path: Path) -> tuple[Path, str, str]:
    """A clone whose `origin/main` holds one commit, plus a local commit that never merged."""
    origin = tmp_path / "origin.git"
    wc = tmp_path / "wc"
    wc.mkdir()
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True
    )
    _git(wc, "init", "-q", "-b", "main")
    _git(wc, "config", "user.email", "t@example.invalid")
    _git(wc, "config", "user.name", "t")
    _git(wc, "remote", "add", "origin", str(origin))
    (wc / "a").write_text("a")
    _git(wc, "add", "-A")
    _git(wc, "commit", "-qm", "merged")
    merged = _git(wc, "rev-parse", "HEAD")
    _git(wc, "push", "-q", "origin", "main")
    (wc / "b").write_text("b")
    _git(wc, "add", "-A")
    _git(wc, "commit", "-qm", "never merged")
    unmerged = _git(wc, "rev-parse", "HEAD")
    return wc, merged, unmerged


def _run_ancestry(wc: Path, sha: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", _step("version-check", "ancestor")["run"]],
        cwd=wc,
        env={
            "GITHUB_SHA": sha,
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
            "HOME": str(wc.parent),
        },
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_tag_on_a_merged_commit_publishes(
    pushed_and_unpushed: tuple[Path, str, str],
) -> None:
    wc, merged, _ = pushed_and_unpushed
    p = _run_ancestry(wc, merged)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "is on origin/main — OK" in p.stdout


def test_a_tag_on_a_commit_that_never_merged_is_refused(
    pushed_and_unpushed: tuple[Path, str, str],
) -> None:
    """A tag can be pushed from any local commit. Without this, `ci-green` would happily
    resolve that commit's own CI run and publish code no reviewer ever saw on main."""
    wc, _, unmerged = pushed_and_unpushed
    p = _run_ancestry(wc, unmerged)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "is not an ancestor of origin/main" in p.stdout + p.stderr


def test_the_ancestry_check_has_the_history_it_needs() -> None:
    """`actions/checkout` defaults to a depth-1 clone, in which `merge-base --is-ancestor`
    cannot answer and the guard refuses every release."""
    checkout = next(
        s for s in _steps("version-check") if "checkout" in str(s.get("uses", ""))
    )
    assert str(checkout.get("with", {}).get("fetch-depth")) == "0", (
        "version-check must check out full history for the ancestry assertion"
    )
    run = _step("version-check", "ancestor")["run"]
    commands = [ln for ln in run.splitlines() if not ln.lstrip().startswith("#")]
    assert not any("--depth=0" in ln for ln in commands), (
        "git rejects `--depth=0` outright (\"depth 0 is not a positive number\"), which "
        "would fail every publish"
    )
