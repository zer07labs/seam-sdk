"""The wheel ships `_gen` as ROOTED subpackages and pollutes no global namespace.

The one-way packaging contract (Phase 1):
  * `import seam` FAILS — the old sys.path injection that published a global `seam` package is gone
    (anyone who imported `seam.api.v1` directly must move to `seam_sdk._gen.seam.api.v1`);
  * `from seam_sdk import SeamClient` and `from seam_sdk.aio import SeamClient` both work from the
    wheel alone (no source tree on the path);
  * every `_gen` directory is a real package (`__init__.py` present) so `packages.find` ships it.

The wheel is built with pip and verified by running a subprocess against the EXTRACTED wheel placed
at the FRONT of sys.path (shadowing any editable install) — hermetic, no network. Locally it is
skipped when no wheel could be produced; CI always can and sets `SEAM_REQUIRE_WHEEL_BUILD=1`, so
there a skip for ANY reason is a failure instead.

There are THREE ways to end up without a wheel, and they get three different messages because they
send a reader three different places:

  1. **No builder present** — nothing answered `--version`. A legitimate local state; not a defect.
  2. **A build that RAN and FAILED** — a present builder returned non-zero. A defect in this package.
  3. **A builder that cannot build this package** — exited 0 and emitted no `seam_sdk-*.whl`.
     Measured here: `/usr/bin/pip3` runs Python 3.9 with setuptools 58.0.4. PEP 621 `[project]`
     support landed in setuptools 61, so 58 reads the file, ignores the metadata table, and
     builds `UNKNOWN-0.0.0-py3-none-any.whl` while reporting success.

All three FAIL under the flag — that is the load-bearing property, and it is what `ci-ok` already
does one level up. Only the wording differs. See `_require_wheel_build` for why telling them apart
was worth the code.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import zipfile

import pytest

#: The supported spellings of pytest's outcome types — `_pytest.outcomes` is private API.
Failed = pytest.fail.Exception
Skipped = pytest.skip.Exception

REPO = pathlib.Path(__file__).parents[2]


# Set in CI (`SEAM_REQUIRE_WHEEL_BUILD=1`). Turns "could not build the wheel" from a skip into a
# failure.
#:
#: The original `except` caught `CalledProcessError` — a wheel build that RAN AND FAILED — in the
#: same breath as `FileNotFoundError`, which means no pip exists. Those are opposite situations, and
#: conflating them retired three packaging-contract guards into skips whenever the build broke: no
#: global `seam` leak, `py.typed` ships, and every `_gen` directory is a real package. `pytest`
#: then exits 0, and a green suite reports that a contract was upheld when it was never checked.
#:
#: Splitting on the exception TYPE was not enough, and running the repaired guard here proved it:
#: `python -m pip` on an interpreter without pip raises no `FileNotFoundError` at all — the
#: interpreter exists, so it runs and exits 1 with "No module named pip", landing in the failed-BUILD
#: branch. Presence is a question only a `--version` probe answers, and a third class exists beneath
#: both (exit 0, no wheel). Hence `_builder_is_present` and the three-way split below.
#:
#: CI's separate wheel-import step does not cover the gap — it imports the wheel, which is one of
#: the three properties and not the other two.
#:
#: The reasoning is the one `ci-ok` already applies one level up, where a SKIPPED required job counts
#: as a failure precisely so absence cannot read as success. There was no equivalent at test level;
#: this is it.
#:
#: A flag rather than an unconditional failure because "no pip at all" is a legitimate local state —
#: this repo's own venv is in it — and failing there would make the suite unrunnable for a
#: contributor who has done nothing wrong. CI has pip always, so in CI there is no such excuse.
#: Read at CALL time, not captured at import. A module constant would freeze whatever the
#: environment happened to be when pytest collected this file, which is both harder to test and a
#: quiet dependency on collection order.
def _require_wheel_build() -> bool:
    return os.environ.get("SEAM_REQUIRE_WHEEL_BUILD") == "1"


#: A builder is PRESENT iff it answers `--version`. That probe, not the exception type, is the
#: discriminator — because `python -m pip` on an interpreter with no pip module does not raise
#: `FileNotFoundError`: `sys.executable` exists and runs fine, exiting 1 with "No module named pip"
#: on stderr. Classifying by exception would call that a failed BUILD, which is the same conflation
#: one level down: the first version of this fix did exactly that, and its two tests missed it
#: because both forced the `pip3` branch, where an absent executable really does raise.
def _builder_is_present(base: list[str]) -> bool:
    try:
        return subprocess.run([*base, "--version"], capture_output=True).returncode == 0
    except OSError:
        # `FileNotFoundError` and `PermissionError` are both `OSError`; one clause covers
        # every way an exec can fail to happen at all.
        return False


def _build_wheel(tmp_path: pathlib.Path) -> pathlib.Path:
    candidates = [
        [sys.executable, "-m", "pip"],
        *([[shutil.which("pip3")]] if shutil.which("pip3") else []),
    ]
    builders = [b for b in candidates if _builder_is_present(b)]
    if not builders:
        # `candidates`, not a separately-computed `absent` list: inside this branch every candidate
        # is absent by construction, so a second pass would only probe each one twice and let a
        # probe that flipped between the passes drop a candidate out of both lists.
        message = (
            "no pip available to build the wheel — no candidate answered `--version`: "
            + ", ".join(" ".join(b) for b in candidates)
        )
        if _require_wheel_build():
            pytest.fail(
                f"{message}\n\nSEAM_REQUIRE_WHEEL_BUILD=1 is set, so the packaging contract must "
                "be checked, not skipped. CI always has pip; if this fired in CI, the environment "
                "changed."
            )
        pytest.skip(message)

    build_failure = None
    unusable: list[tuple[list[str], list[str]]] = []
    for base in builders:
        try:
            subprocess.run(
                [
                    *base,
                    "wheel",
                    "--no-deps",
                    "--no-build-isolation",
                    "-w",
                    str(tmp_path),
                    str(REPO / "python"),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            # A present builder RAN and the build FAILED. That is a defect in this package, not a
            # missing tool, and it is the case that must never be reported as a skip in CI.
            build_failure = e
            continue
        wheels = list(tmp_path.glob("seam_sdk-*.whl"))
        if wheels:
            return wheels[0]
        # Exited 0 and produced no `seam_sdk-*.whl`. Measured on this workstation: `/usr/bin/pip3`
        # runs Python 3.9 with setuptools 58.0.4, and PEP 621 `[project]` support landed in
        # setuptools 61 — so it reads pyproject.toml, ignores the metadata table entirely, and
        # emits `UNKNOWN-0.0.0-py3-none-any.whl` while reporting success. The old interpreter is
        # why the old setuptools is there, but the setuptools version is the operative cause. A builder that cannot name the
        # package it just built has not built it — a third class, neither absent nor failed, and the
        # one the earlier version of this function silently reported as "no pip available".
        unusable.append((base, sorted(w.name for w in tmp_path.glob("*.whl"))))

    if build_failure is not None:
        detail = build_failure.stderr or build_failure
        # `--no-build-isolation` keeps this hermetic (no network), but it means the build backend
        # must already be importable. If it is not, pip reports a build failure — indistinguishable
        # in its exit code from a real packaging defect, and under SEAM_REQUIRE_WHEEL_BUILD=1 that
        # would send someone hunting a defect that does not exist. Say which one it is. Checked here
        # rather than up front because it is only interesting once a build has actually failed.
        try:
            import setuptools  # noqa: F401

            backend = ""
        except ImportError:
            backend = (
                "\n\nNOTE: `setuptools` is not importable by this interpreter, and the build runs "
                "with `--no-build-isolation` (deliberately — it keeps this test hermetic). That is "
                "very likely the whole cause, and it is an ENVIRONMENT fault, not a packaging "
                "defect: install setuptools, or run with build isolation and a network."
            )
        message = (
            "the wheel BUILD FAILED — a working builder ran and returned non-zero. This is not a "
            "missing tool, and the three packaging-contract guards below (no global `seam` leak, "
            f"`py.typed` ships, rooted `__init__.py` chain) check nothing without a wheel.\n\n{detail}"
            + backend
        )
        if _require_wheel_build():
            pytest.fail(message)
        # Locally this stays a skip, but it says which of the three things happened — the old
        # message claimed "no working pip" for a build that failed with pip working perfectly.
        pytest.skip(
            f"{message}\n\n(set SEAM_REQUIRE_WHEEL_BUILD=1 to make this a failure)"
        )

    if unusable:
        detail = "; ".join(
            f"`{' '.join(b)}` exited 0 and produced {produced or 'nothing'}"
            for b, produced in unusable
        )
        message = (
            "no builder could build this package. Each one below reported SUCCESS without emitting "
            f"a `seam_sdk-*.whl`: {detail}. A builder whose setuptools predates PEP 621 support "
            "(added in setuptools 61) does this — it ignores the `[project]` table, so it builds "
            "`UNKNOWN-0.0.0` and exits 0. Not a missing tool and not a build failure; the wheel "
            "simply was not built, so the three packaging-contract guards below check nothing."
        )
        if _require_wheel_build():
            pytest.fail(
                f"{message}\n\nSEAM_REQUIRE_WHEEL_BUILD=1 is set, so the packaging contract must "
                "be checked, not skipped."
            )
        pytest.skip(
            f"{message}\n\n(set SEAM_REQUIRE_WHEEL_BUILD=1 to make this a failure)"
        )

    raise AssertionError(
        "unreachable: a builder neither returned, failed, nor came up empty"
    )


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> pathlib.Path:
    return _build_wheel(tmp_path_factory.mktemp("wheel"))


def test_wheel_has_rooted_gen_and_no_global_seam(wheel):
    names = zipfile.ZipFile(wheel).namelist()
    tops = {n.split("/", 1)[0] for n in names if "/" in n}
    # No top-level `seam/` — nothing in this wheel can satisfy `import seam`.
    assert not any(t == "seam" for t in tops), sorted(tops)
    assert "seam_sdk/_gen/seam/api/v1/seam_pb2.py" in names
    assert "seam_sdk/_gen/seam/api/v1/seam_pb2_grpc.py" in names
    assert "seam_sdk/_gen/seam/event/v1/seam_event_pb2.py" in names
    # PEP 561: the marker must SHIP, or downstream type checkers ignore every annotation here.
    assert "seam_sdk/py.typed" in names
    # Every _gen directory level is a real package.
    for pkg in [
        "seam_sdk/_gen",
        "seam_sdk/_gen/seam",
        "seam_sdk/_gen/seam/api",
        "seam_sdk/_gen/seam/api/v1",
        "seam_sdk/_gen/seam/event",
        "seam_sdk/_gen/seam/event/v1",
    ]:
        assert f"{pkg}/__init__.py" in names, pkg


def test_wheel_generated_imports_are_rewritten(wheel):
    zf = zipfile.ZipFile(wheel)
    grpc_src = zf.read("seam_sdk/_gen/seam/api/v1/seam_pb2_grpc.py").decode()
    assert "from seam_sdk._gen.seam.api.v1 import" in grpc_src
    assert "\nfrom seam.api.v1 import" not in grpc_src
    client_src = zf.read("seam_sdk/client.py").decode()
    assert "sys.path.insert" not in client_src


def test_clean_environment_import_contract(wheel, tmp_path):
    """From the extracted wheel at the FRONT of sys.path: `import seam` fails; both clients import;
    and the imported module really is the wheel copy, not this repo's source tree."""
    site = tmp_path / "site"
    with zipfile.ZipFile(wheel) as zf:
        zf.extractall(site)
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(site)!r})\n"
        "try:\n"
        "    import seam\n"
        "except ModuleNotFoundError:\n"
        "    pass\n"
        "else:\n"
        "    raise SystemExit('GLOBAL NAMESPACE LEAK: import seam succeeded')\n"
        "from seam_sdk import SeamClient\n"
        "from seam_sdk.aio import SeamClient as AioSeamClient\n"
        "import seam_sdk\n"
        f"assert seam_sdk.__file__.startswith({str(site)!r}), seam_sdk.__file__\n"
        "print('CONTRACT OK')\n"
    )
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "CONTRACT OK" in out.stdout


# ── The skip condition itself ────────────────────────────────────────────────────────────────────
# These tests are about `_build_wheel`'s failure handling rather than about the wheel, and they exist
# because the handling had a hole exactly the shape of the thing it was guarding: a build that ran
# and failed was reported as "no working pip", retiring three packaging-contract guards into skips
# while pytest exited 0. A guard that disappears when its subject breaks is the failure mode this
# repo keeps a vocabulary for, and it had it.


def _fake_pip(tmp_path: pathlib.Path, exit_code: int) -> pathlib.Path:
    """A `pip3` on PATH that is PRESENT — answers `--version` — and fails the actual build.

    Answering `--version` is not decoration. Presence and success are separate questions, and a fake
    that failed both would be indistinguishable from an absent tool, which is the very distinction
    these tests exist to pin. The first version of this fake failed everything, so it tested the
    missing-tool path while claiming to test the failed-build path.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    fake = bindir / "pip3"
    fake.write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do [ "$a" = "--version" ] && { echo "pip 99.0 (fake)"; exit 0; }; done\n'
        'echo "ERROR: deliberately broken build" >&2\n'
        f"exit {exit_code}\n"
    )
    fake.chmod(0o755)
    return bindir


def _fake_pip_that_builds_nothing(tmp_path: pathlib.Path) -> pathlib.Path:
    """A present `pip3` that exits 0 and emits an `UNKNOWN-0.0.0` wheel — no `seam_sdk-*.whl`.

    This is not hypothetical: it is what `/usr/bin/pip3` (Python 3.9, below this package's
    setuptools 58.0.4) does on this workstation, measured. PEP 621 support landed in setuptools 61,
    so 58 ignores the `[project]` table entirely and reports success on empty metadata.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    fake = bindir / "pip3"
    fake.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "pip 99.0 (fake)"; exit 0; fi\n'
        'out=""\n'
        'while [ $# -gt 0 ]; do if [ "$1" = "-w" ]; then out="$2"; fi; shift; done\n'
        'mkdir -p "$out" && : > "$out/UNKNOWN-0.0.0-py3-none-any.whl"\n'
        'echo "Successfully built UNKNOWN"\n'
        "exit 0\n"
    )
    fake.chmod(0o755)
    return bindir


def test_a_failed_build_is_reported_as_a_failed_build_not_as_a_missing_tool(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", f"{_fake_pip(tmp_path, 1)}:{os.environ.get('PATH', '')}")
    monkeypatch.setattr(
        sys, "executable", "/nonexistent/python"
    )  # force the pip3 branch
    monkeypatch.delenv("SEAM_REQUIRE_WHEEL_BUILD", raising=False)

    # `BaseException`, not `Exception`: pytest's `Skipped` and `Failed` both derive from
    # `BaseException`, so `pytest.raises(Exception)` catches neither and the assertion never runs.
    with pytest.raises(BaseException) as caught:  # noqa: B017
        _build_wheel(tmp_path / "out")
    message = str(caught.value)
    assert "BUILD FAILED" in message, (
        "a wheel build that ran and returned non-zero must say so. The old message said 'no working "
        f"pip', which is the opposite diagnosis: {message}"
    )


def test_the_flag_turns_that_skip_into_a_failure(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With SEAM_REQUIRE_WHEEL_BUILD=1 — as CI sets — a broken build must FAIL, not skip.

    Checked by outcome type, not by message: `pytest.skip` and `pytest.fail` both raise, and the
    whole defect was that the wrong one of those two was being raised.
    """
    monkeypatch.setenv("PATH", f"{_fake_pip(tmp_path, 1)}:{os.environ.get('PATH', '')}")
    monkeypatch.setattr(sys, "executable", "/nonexistent/python")
    monkeypatch.setenv("SEAM_REQUIRE_WHEEL_BUILD", "1")

    with pytest.raises(BaseException) as caught:  # noqa: B017
        _build_wheel(tmp_path / "out")
    assert isinstance(caught.value, Failed), (
        f"expected a FAILURE under SEAM_REQUIRE_WHEEL_BUILD=1, got {type(caught.value).__name__}. "
        "A skip here means a packaging defect retires its own guards and CI still goes green."
    )
    assert not isinstance(caught.value, Skipped)


def test_a_builder_that_cannot_build_this_package_is_not_called_a_missing_tool(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 0 + no `seam_sdk-*.whl` is its own class, and the message must say which one it is.

    Found by running the repaired guard on this workstation rather than by reasoning about it: the
    version before this one reported the real `/usr/bin/pip3` as "no pip available", which is the
    same wrong-diagnosis defect this section is named after, one level further down.
    """
    monkeypatch.setenv(
        "PATH",
        f"{_fake_pip_that_builds_nothing(tmp_path)}:{os.environ.get('PATH', '')}",
    )
    monkeypatch.setattr(sys, "executable", "/nonexistent/python")
    monkeypatch.delenv("SEAM_REQUIRE_WHEEL_BUILD", raising=False)

    with pytest.raises(BaseException) as caught:  # noqa: B017
        _build_wheel(tmp_path / "out")
    message = str(caught.value)
    assert "no builder could build this package" in message, (
        f"a builder that exits 0 without emitting a wheel has its own diagnosis: {message}"
    )
    # The FULL filename, not the `UNKNOWN-0.0.0` stem: the message's own explanatory prose contains
    # that stem as a constant, so asserting it proved nothing about the measured evidence. Dropping
    # `{produced}` from the message left this test green — caught by mutating the message and
    # watching nothing die, which is the only way an assertion satisfied by a constant shows up.
    assert "UNKNOWN-0.0.0-py3-none-any.whl" in message, (
        "the message must list what the builder DID produce — that is what tells a reader their "
        f"setuptools predates PEP 621 rather than pip being broken: {message}"
    )
    assert "BUILD FAILED" not in message, (
        f"nothing failed; the builder reported success. Calling it a failure is a wrong lead: {message}"
    )


def test_that_third_class_also_fails_under_the_flag(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All three no-wheel classes must FAIL in CI. Only the message differs between them.

    The load-bearing property of the whole section is that no route to "the wheel was not checked"
    exits 0 in CI. A third class that skipped would reopen the hole with a new name.
    """
    monkeypatch.setenv(
        "PATH",
        f"{_fake_pip_that_builds_nothing(tmp_path)}:{os.environ.get('PATH', '')}",
    )
    monkeypatch.setattr(sys, "executable", "/nonexistent/python")
    monkeypatch.setenv("SEAM_REQUIRE_WHEEL_BUILD", "1")

    with pytest.raises(BaseException) as caught:  # noqa: B017
        _build_wheel(tmp_path / "out")
    assert isinstance(caught.value, Failed) and not isinstance(caught.value, Skipped), (
        f"expected a FAILURE under SEAM_REQUIRE_WHEEL_BUILD=1, got {type(caught.value).__name__}"
    )


def test_an_absent_builder_is_still_reported_as_absent(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The accepting side: with NO builder present, "no pip available" is the right answer.

    Without this, "never say missing tool" would satisfy every other assertion in this section.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(sys, "executable", "/nonexistent/python")
    monkeypatch.delenv("SEAM_REQUIRE_WHEEL_BUILD", raising=False)

    with pytest.raises(BaseException) as caught:  # noqa: B017
        _build_wheel(tmp_path / "out")
    message = str(caught.value)
    assert "no pip available" in message, message
    # The MEASURED half, not the prose: `"no pip available"` is a constant in the branch's own
    # message and is satisfied whether or not the candidate list survives. Dropping `{candidates}`
    # left this test green — the same constant-satisfied assertion the `unusable` branch already
    # had, one branch over.
    assert "/nonexistent/python -m pip" in message, (
        f"the message must name the candidates it probed, not merely announce the class: {message}"
    )
    assert isinstance(caught.value, Skipped), (
        "a contributor with no pip has done nothing wrong; locally this must stay a skip"
    )


def test_the_absent_class_also_fails_under_the_flag(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The third of three. ALL routes to "no wheel" must fail in CI — that is the whole property.

    The other two classes each had a with-flag twin; this one did not, so deleting its
    `pytest.fail` and leaving a bare skip killed nothing. A route that quietly skips in CI is
    exactly the hole this section exists to close, and it was open in the branch most likely to be
    hit by an environment change.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(sys, "executable", "/nonexistent/python")
    monkeypatch.setenv("SEAM_REQUIRE_WHEEL_BUILD", "1")

    with pytest.raises(BaseException) as caught:  # noqa: B017
        _build_wheel(tmp_path / "out")
    assert isinstance(caught.value, Failed) and not isinstance(caught.value, Skipped), (
        f"expected a FAILURE under SEAM_REQUIRE_WHEEL_BUILD=1, got {type(caught.value).__name__}"
    )


def test_a_real_build_failure_outranks_a_builder_that_built_nothing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both classes at once: the RAN-AND-FAILED diagnosis wins, because it is the actionable one.

    Reachable in the real world — a working `python -m pip` failing on a genuine packaging defect
    beside an old `pip3` that emits `UNKNOWN-0.0.0`. Nothing pinned the order, so swapping the two
    branches killed no test and the more useful message could have been silently displaced by the
    less useful one.
    """
    failing = _fake_pip(tmp_path / "failing", 1)
    nothing = _fake_pip_that_builds_nothing(tmp_path / "nothing")
    # `pip3` resolves to the failing one; `sys.executable -m pip` is redirected at the other via a
    # shim directory earlier on PATH, so both classes are produced in a single call.
    monkeypatch.setenv("PATH", f"{failing}:{os.environ.get('PATH', '')}")
    monkeypatch.setattr(sys, "executable", str(nothing / "pip3"))
    monkeypatch.delenv("SEAM_REQUIRE_WHEEL_BUILD", raising=False)

    with pytest.raises(BaseException) as caught:  # noqa: B017
        _build_wheel(tmp_path / "out")
    message = str(caught.value)
    assert "BUILD FAILED" in message, (
        "with one builder failing and another building nothing, the failure is the diagnosis worth "
        f"showing — it names a defect rather than an environment: {message}"
    )
