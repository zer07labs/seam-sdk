"""Every third-party module the tests import is declared in `python/pyproject.toml`.

CI installs exactly one thing before running pytest — `pip install -e "./python[dev]"`
(`.github/workflows/ci.yml:124`). Anything a test imports that is not pulled in by that install is
absent on the runner, and an undeclared import is not one failing test: it is a **collection
error**, which aborts the entire run and takes the `python` job and `ci-ok` red with it.

This is not hypothetical. `tests/test_workflows_generate_through_the_makefile.py` was written with
`import yaml` and passed locally for the whole of Phase 4, because PyYAML happened to be installed
by hand in this workstation's venv with nothing depending on it. The sibling `workflow-guards` job
installs `pyyaml` explicitly (`.github/workflows/ci.yml:642`) precisely because the runner does not
have it, and `tests/test_node_engines_floor.py` hand-parses YAML with a regex for the same reason —
the evidence was already in the repo, in two places, and a green local suite still said fine.

So the check is not "is pyyaml declared" but "is EVERY test import declared". A guard against the
one instance would have to be rewritten the next time; this one cannot go stale.

Deliberately regex-parsed rather than `tomllib`-parsed: `requires-python` is `>=3.10` and `tomllib`
arrived in 3.11, so importing it here would make this file the second undeclared dependency. The
sibling floor tests (`test_protobuf_floor.py`, `test_grpcio_floor.py`) read pyproject the same way.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys
from importlib.metadata import packages_distributions

TESTS = pathlib.Path(__file__).parent
PYPROJECT = TESTS.parents[0] / "pyproject.toml"

#: First-party: the package under test, and the test-support modules that sit beside this file.
FIRST_PARTY = {"seam_sdk"} | {p.stem for p in TESTS.glob("*.py")}

#: `_pytest` is pytest's own internals — same distribution, different top-level name. Imported by
#: `test_packaging.py` for the `Skipped`/`Failed` outcome types.
ALIASES = {"_pytest": "pytest"}


def _normalize(name: str) -> str:
    """PEP 503 name normalization — `PyYAML`, `pyyaml` and `py_yaml` are one distribution."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _declared() -> set[str]:
    """Every distribution CI actually installs: `[project].dependencies` plus the `dev` extra.

    Scoped to those two on purpose. The previous pattern was `(?:dependencies|dev|[a-z0-9_-]+)`,
    whose third branch matches every list-valued key in the file — so `packages.find`'s `include`,
    `package-data`, and `build-system.requires` all counted as declarations. Two consequences, the
    second serious:

      * it returned junk names (`-`, `-gen`, `py-typed`, `seam-sdk*`, `typing`);
      * moving `pyyaml` out of `dev` into an extra CI does NOT install left all three tests green,
        including `test_pyyaml_specifically_is_declared`, whose whole subject is that failure.

    CI runs `pip install -e "./python[dev]"`. Anything outside those two lists is not installed, so
    counting it as declared is counting a dependency that will not be there.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    names: set[str] = set()
    blocks = re.findall(r"^(?:dependencies|dev)\s*=\s*\[(.*?)\]", text, re.S | re.M)
    assert len(blocks) == 2, (
        f"expected exactly two dependency lists in {PYPROJECT} — [project].dependencies and the "
        f"dev extra — found {len(blocks)}. If a third was added, decide whether CI installs it "
        "before widening this."
    )
    for block in blocks:
        for req in re.findall(r'"([^"]+)"', block):
            head = re.split(r"[<>=!~;\[\s]", req, 1)[0]
            if head:
                names.add(_normalize(head))
    return names


def _optional_import_nodes(tree: ast.Module) -> set[ast.stmt]:
    """Import statements guarded by `try: … except ImportError:` — the optional-dependency idiom.

    Only the `try` BODY counts, and only when a handler names ImportError or ModuleNotFoundError. A
    bare `except:` or an unrelated handler does not make an import optional, and an import in the
    `except`/`else`/`finally` branch is not guarded by the try at all.
    """
    optional: set[ast.stmt] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        catches_import_error = any(
            any(
                isinstance(n, ast.Name)
                and n.id in {"ImportError", "ModuleNotFoundError"}
                for n in ast.walk(h.type)
            )
            for h in node.handlers
            if h.type is not None
        )
        if not catches_import_error:
            continue
        for stmt in node.body:
            for inner in ast.walk(stmt):
                if isinstance(inner, (ast.Import, ast.ImportFrom)):
                    optional.add(inner)
    return optional


def _imported_top_level_modules() -> dict[str, set[str]]:
    """Top-level module name -> the test files importing it. Parsed, not grepped.

    `ast` sees the import whatever the formatting, and — unlike a regex — cannot be fooled by the
    word `import` inside a docstring or a string literal, of which this repo's tests have many.
    """
    found: dict[str, set[str]] = {}
    for path in sorted(TESTS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        guarded = _optional_import_nodes(tree)
        for node in ast.walk(tree):
            if node in guarded:
                # An import inside `try: … except ImportError:` is a PROBE, not a requirement — the
                # code has already written what to do when it is absent. `test_packaging.py` does
                # exactly this to tell an environment fault (no setuptools) from a packaging defect,
                # and demanding it be declared would break the very case it exists to report.
                continue
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                # `level > 0` is a relative import — first-party by construction.
                mods = [node.module] if node.module and node.level == 0 else []
            else:
                continue
            for mod in mods:
                found.setdefault(mod.split(".")[0], set()).add(path.name)
    return found


def test_every_third_party_test_import_is_declared_in_pyproject() -> None:
    declared = _declared()
    undeclared: list[str] = []
    for mod, importers in sorted(_imported_top_level_modules().items()):
        if mod in sys.stdlib_module_names or mod in FIRST_PARTY:
            continue
        resolved = ALIASES.get(mod, mod)
        dists = (
            packages_distributions().get(resolved)
            or packages_distributions().get(mod)
            or []
        )
        candidates = {_normalize(d) for d in dists} or {_normalize(resolved)}
        if not (candidates & declared):
            undeclared.append(
                f"  `import {mod}` in {', '.join(sorted(importers))} -> distribution "
                f"{sorted(candidates) or '?'}, which pyproject.toml does not declare"
            )
    assert not undeclared, (
        'A test imports a third-party module that `pip install -e "./python[dev]"` does not '
        "install:\n"
        + "\n".join(undeclared)
        + "\n\nOn the CI runner that import fails at "
        "COLLECTION, which aborts the whole suite rather than failing one test — the `python` job "
        "and `ci-ok` both go red. Declare it in python/pyproject.toml's `dev` extra."
    )


def test_the_scan_actually_finds_the_third_party_imports_it_is_checking() -> None:
    """Anti-vacuity: an empty scan would satisfy the test above for free.

    If `ast` walking, the stdlib filter, or the first-party filter ever swallowed everything, the
    guard would pass by examining nothing — this repo's named failure class, and the reason this
    file exists at all.
    """
    mods = _imported_top_level_modules()
    third_party = {
        m for m in mods if m not in sys.stdlib_module_names and m not in FIRST_PARTY
    }
    assert "pytest" in third_party, (
        f"the scan found no `pytest` import across {len(mods)} modules — it is scanning nothing"
    )
    assert len(third_party) >= 2, (
        f"only {third_party} looked third-party; the suite imports more than that, so the "
        "stdlib/first-party filters are over-broad"
    )


def test_pyyaml_specifically_is_declared() -> None:
    """The instance that motivated the rule, pinned separately so its regression is legible.

    The general test above would also catch it, but it would report it as one line in a list. This
    one names the file and the failure mode, because a collection error gives no useful traceback.
    """
    assert _normalize("pyyaml") in _declared(), (
        "tests/test_workflows_generate_through_the_makefile.py does `import yaml`. Without pyyaml "
        "in the `dev` extra the CI runner cannot collect it, and the whole suite errors out."
    )
