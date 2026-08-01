"""The wheel ships `_gen` as ROOTED subpackages and pollutes no global namespace.

The one-way packaging contract (Phase 1):
  * `import seam` FAILS — the old sys.path injection that published a global `seam` package is gone
    (anyone who imported `seam.api.v1` directly must move to `seam_sdk._gen.seam.api.v1`);
  * `from seam_sdk import SeamClient` and `from seam_sdk.aio import SeamClient` both work from the
    wheel alone (no source tree on the path);
  * every `_gen` directory is a real package (`__init__.py` present) so `packages.find` ships it.

The wheel is built with pip and verified by running a subprocess against the EXTRACTED wheel placed
at the FRONT of sys.path (shadowing any editable install) — hermetic, no network. Skipped only when
no pip is available to build the wheel (CI always has one).
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import zipfile

import pytest

REPO = pathlib.Path(__file__).parents[2]


def _build_wheel(tmp_path: pathlib.Path) -> pathlib.Path:
    builders = [
        [sys.executable, "-m", "pip"],
        *([[shutil.which("pip3")]] if shutil.which("pip3") else []),
    ]
    last = None
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
            wheels = list(tmp_path.glob("seam_sdk-*.whl"))
            if wheels:
                return wheels[0]
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            last = e
    pytest.skip(f"no working pip to build the wheel: {last}")


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
