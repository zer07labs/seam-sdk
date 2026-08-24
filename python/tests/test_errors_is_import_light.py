"""``seam_sdk/errors.py`` must stay loadable **as a single file**, with no package context and no
generated code.

WHY THIS IS A CONTRACT AND NOT A COINCIDENCE
--------------------------------------------
`seam-sdk#54 <https://github.com/zer07labs/seam-sdk/issues/54>`_. ``seam-adapters`` is building a
scheduled drift lane that asks one question: *has seam-sdk added a non-RPC ``SeamError`` subclass
that seam-adapters does not classify?* It matters because an unclassified non-RPC ``SeamError`` falls
through their transport's ``except Exception`` arm as a policy-resolved ``TransportFailure`` — and
under ``FAIL_OPEN`` that runs a gated tool **ungated**.

The obvious implementation of that lane — ``pip install git+…@main`` — does not work here, and the
reason is structural rather than incidental: ``seam_sdk/_gen/`` is ``.gitignore``d (``.gitignore:18``)
while ``seam_sdk/__init__.py`` imports from it at import time, so a git install yields an unimportable
package. Generating it needs ``buf registry login`` and a ``BUF_TOKEN`` provisioned in *their* repo.

Because ``errors.py`` imports only ``grpc``, they load that one file standalone via
``importlib.util.spec_from_file_location`` and diff its class hierarchy against their rosters — no
token, no ``buf``, no install, no generated code. That property was true by accident. This file makes
it true on purpose, so the cost of breaking it is visible from inside this repo, where it is not
otherwise.

THREE CHECKS, BECAUSE IT CAN BREAK THREE DIFFERENT WAYS
-------------------------------------------------------
1. **The import set** (static). An *unguarded* runtime load could not catch
   ``from seam_sdk._gen.x import y`` — in any environment where this suite runs the package is
   installed, so the import simply succeeds, and it would fail only for the consumer, who has no
   package and never runs these tests. Check 2 closes that with a block hook, so these two overlap
   by design; what only the static pass sees is an import Python never executes, such as one inside
   ``if TYPE_CHECKING:``, which is still a break the moment someone makes it unconditional.
2. **The standalone load** (runtime, fresh interpreter). Replicates the consumer's loader precisely,
   with a ``sys.meta_path`` hook that makes any attempt to reach ``seam_sdk`` a loud failure rather
   than a silent success. This is what catches a relative import, which has no package context to
   resolve against.
3. **Hierarchy completeness.** Moving part of the ``SeamError`` tree into another module breaks the
   lane without touching a single import in this file — the load still succeeds, it just stops
   yielding the whole taxonomy. Checked **statically across the whole package**, deliberately: the
   earlier version of this test read ``__all__`` and filtered for names ending in ``Error``, which
   made the guard silently dependent on a naming convention nothing enforces. A
   ``class BudgetExhausted(SeamError)`` in a new module passed it — while being exactly the event
   the consumer's lane exists to catch.

Deliberately NOT asserted: the number of error classes. The lane exists to notice new ones; pinning a
count here would redden this repo's CI on precisely the event the consumer wants to be told about.
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import textwrap

import pytest

# `sys.stdlib_module_names` is 3.10+, which is also the package's own `requires-python` floor
# (`python/pyproject.toml:10`). Below it these checks cannot run at all — which is an infrastructure
# condition, and must not be reported as "the contract is broken".
pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 10),
    reason="needs Python 3.10+ (sys.stdlib_module_names); matches requires-python >=3.10",
)

REPO = pathlib.Path(__file__).parents[2]
ERRORS = REPO / "python" / "seam_sdk" / "errors.py"
INIT = REPO / "python" / "seam_sdk" / "__init__.py"

#: The only non-stdlib import this file may carry. ``grpc`` is load-bearing — the taxonomy's RPC half
#: subclasses ``grpc.RpcError`` so existing ``except grpc.RpcError`` handlers keep working — and the
#: consumer installs grpcio anyway, since it talks to the runtime.
ALLOWED_THIRD_PARTY = frozenset({"grpc"})

#: Any import naming these is a straight break: the consumer has no such package on its path.
FORBIDDEN_ROOTS = frozenset({"seam_sdk"})


def _module_imports(tree: ast.Module) -> list[tuple[str, int, int]]:
    """Every import in ``tree`` as ``(top_level_module_name, relative_level, lineno)``.

    ``level`` is ``ast.ImportFrom.level`` — 0 for absolute, >0 for ``from .x import y``. A plain
    ``import x`` is always absolute, so it reports 0.
    """
    found: list[tuple[str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((alias.name.split(".")[0], 0, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            # `from . import x` has module=None; the dot itself is the whole reference.
            root = (node.module or "").split(".")[0]
            found.append((root, node.level, node.lineno))
    return found


@pytest.fixture(scope="module")
def imports() -> list[tuple[str, int, int]]:
    tree = ast.parse(ERRORS.read_text(encoding="utf-8"), filename=str(ERRORS))
    found = _module_imports(tree)
    # Guard-the-guard: a parser that finds nothing makes every assertion below vacuously true, which
    # is how a gate stops meaning anything. `errors.py` imports at minimum `__future__` and `grpc`.
    assert found, (
        f"parsed ZERO imports out of {ERRORS} — the check is not looking at anything"
    )
    return found


# ── 1. the import set ────────────────────────────────────────────────────────────────────────────


def test_no_import_reaches_the_package_or_its_generated_code(imports):
    offenders = [
        f"{ERRORS.name}:{lineno} imports {root!r}"
        for root, _level, lineno in imports
        if root in FORBIDDEN_ROOTS
    ]
    assert not offenders, (
        "errors.py must not import the package it lives in (seam-sdk#54).\n"
        + "\n".join(f"  - {o}" for o in offenders)
        + "\n\nseam-adapters loads this file standalone, with no `seam_sdk` on its path and no "
        "generated `_gen/` tree — an absolute import of the package resolves fine here, where the "
        "package is installed, and fails only for them. Keep the dependency in a module that is "
        "already package-coupled (client.py, admin.py), not in the taxonomy."
    )


def test_no_relative_imports(imports):
    offenders = [
        f"{ERRORS.name}:{lineno} uses a level-{level} relative import"
        for _root, level, lineno in imports
        if level > 0
    ]
    assert not offenders, (
        "errors.py must not use package-relative imports (seam-sdk#54).\n"
        + "\n".join(f"  - {o}" for o in offenders)
        + "\n\n`spec_from_file_location` gives the module no package context, so a relative import "
        "raises ImportError there regardless of what is installed."
    )


def test_third_party_imports_are_limited_to_grpc(imports):
    stdlib = sys.stdlib_module_names
    extras = sorted(
        {
            root
            for root, _level, _lineno in imports
            if root
            and root not in stdlib
            and root not in ALLOWED_THIRD_PARTY
            # Package imports are the check above's to report; naming them here too would offer
            # "grew a third-party dependency" as the diagnosis for what is actually a self-import.
            and root not in FORBIDDEN_ROOTS
        }
    )
    assert not extras, (
        f"errors.py grew a third-party dependency: {extras}. Only {sorted(ALLOWED_THIRD_PARTY)} and "
        "the standard library are allowed (seam-sdk#54) — every addition is a package the standalone "
        "consumer must now install to read one file. If the dependency is genuinely needed, widen "
        "ALLOWED_THIRD_PARTY here deliberately and say so on the issue, so it is a decision rather "
        "than a drift."
    )


def test_grpc_is_actually_among_the_imports(imports):
    # The allow-list above only constrains; it would pass an errors.py that imported nothing at all.
    # This pins the positive half, so a refactor that moves the grpc-coupled taxonomy elsewhere trips
    # here rather than leaving a permissive check guarding an empty file.
    assert "grpc" in {root for root, _level, _lineno in imports}, (
        "errors.py no longer imports grpc — the RPC half of the taxonomy is what makes "
        "`except grpc.RpcError` keep working. If it really moved, this contract moved with it."
    )


# ── 2. the standalone load, in a fresh interpreter ───────────────────────────────────────────────

#: Loads errors.py exactly as seam-adapters does, with `seam_sdk` made *unreachable* first so a
#: package import fails loudly instead of succeeding off this environment's installed copy. Emits the
#: class roster as JSON on the last line of stdout.
_STANDALONE = textwrap.dedent(
    """
    import importlib.util, inspect, json, sys

    class _Blocked:
        def find_spec(self, name, path=None, target=None):
            if name == "seam_sdk" or name.startswith("seam_sdk."):
                raise ImportError(
                    "BLOCKED: errors.py tried to import %r. It must load with no package "
                    "present (seam-sdk#54)." % name
                )
            return None

    sys.meta_path.insert(0, _Blocked())
    for mod in [m for m in sys.modules if m == "seam_sdk" or m.startswith("seam_sdk.")]:
        del sys.modules[mod]

    spec = importlib.util.spec_from_file_location("seam_errors_standalone", sys.argv[1])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert "seam_sdk" not in sys.modules, "loading errors.py pulled in the seam_sdk package"
    assert not getattr(module, "__package__", ""), (
        "the standalone module claims a package context: %r" % module.__package__
    )

    base = module.SeamError
    roster = sorted(
        name
        for name, obj in vars(module).items()
        if inspect.isclass(obj) and issubclass(obj, base)
    )
    print(json.dumps({"roster": roster}))
    """
)


@pytest.fixture(scope="module")
def standalone(tmp_path_factory) -> dict:
    script = tmp_path_factory.mktemp("standalone") / "load_errors.py"
    script.write_text(_STANDALONE, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(script), str(ERRORS)],
        capture_output=True,
        text=True,
        timeout=120,
        # cwd outside the repo so the package cannot be picked up implicitly off the working
        # directory — the meta_path hook is the belt, this is the braces.
        cwd=str(script.parent),
    )
    if proc.returncode != 0:
        # Infra, never a verdict. A test environment without grpcio installed cannot load a file that
        # imports grpc — and reporting that as "errors.py no longer loads standalone" would be a
        # confident wrong answer, the failure mode `scripts/probe_framework_coinstall.py` is built
        # around. Scoped to the ALLOWED imports only: a ModuleNotFoundError for anything else means
        # errors.py grew a dependency, which is a real break, and the stderr then says a different
        # module name so this branch does not fire.
        #
        # What a skip here DOES cost, stated honestly rather than waved off: every runtime check
        # goes with it. That is survivable only because each break has a static counterpart that
        # never skips — imports via the AST checks above, and the hierarchy via
        # `test_no_seam_error_subclass_is_defined_outside_errors_py`. It was NOT survivable in the
        # first draft of this file, where the hierarchy check existed only downstream of this
        # fixture: in a venv without grpcio, moving a class out of errors.py exited 0.
        for allowed in ALLOWED_THIRD_PARTY:
            if f"No module named '{allowed}'" in proc.stderr:
                pytest.skip(
                    f"{allowed!r} is not installed in this environment, so errors.py cannot be "
                    f"loaded at all here. This is an environment gap, not a contract break — "
                    f"install it (`pip install grpcio`) to run this guard."
                )
        pytest.fail(
            "errors.py no longer loads standalone (seam-sdk#54). seam-adapters' drift lane loads "
            "this one file with `spec_from_file_location`, no package and no generated code:\n"
            f"{proc.stdout}\n{proc.stderr}"
        )
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_errors_py_loads_with_no_package_present(standalone):
    roster = standalone["roster"]
    assert "SeamError" in roster
    # Not a count assertion — see the module docstring. Just proof the load yielded a taxonomy and
    # not a module that happens to define one class.
    assert len(roster) > 1, f"standalone load yielded only {roster}"


# ── 3. hierarchy completeness ────────────────────────────────────────────────────────────────────

#: Modules that are part of the package but not ours to lint — machine-emitted, regenerated, and
#: absent from a fresh checkout entirely.
SKIP_DIRS = frozenset({"_gen", "__pycache__"})


#: A base name only counts as part of the taxonomy if the module got it from the error module (or
#: from the package root, which re-exports it). Matching on the bare name alone would flag an
#: unrelated ``class InternalError(ValueError)`` in ``client.py`` — a loud, safe, but wrong answer,
#: and a gate that cries wolf gets weakened rather than obeyed.
ERROR_SOURCES = frozenset({"errors", "seam_sdk.errors", "seam_sdk", ""})


def _classes_by_module() -> dict[str, list[tuple[str, list[str], int]]]:
    """``{module_path: [(class_name, [qualifying_base_names], lineno), …]}`` for the whole package.

    A base is kept only when the module could plausibly have obtained it from the error taxonomy:
    imported from ``.errors`` / ``seam_sdk.errors`` / the package root, referenced attribute-style
    (``errors.SeamError``), or defined locally in the same module. Everything else is dropped, so a
    same-named class from an unrelated hierarchy is not reported as an offender.

    KNOWN LIMITS, both directions, because a guard that overstates itself is worse than a narrow one:

    * **False negatives** — matching is by name, so an aliased import
      (``from .errors import SeamError as Base``) or a dynamically built class
      (``type("X", (SeamError,), {})``) escapes. Both are caught by review, not by accident; this
      check exists for the change a person actually makes when splitting a taxonomy.
    * **False positives** — narrower than they were, not zero. A class is reported only when one
      of its own *bases* qualifies, so an unrelated ``class InternalError(ValueError)`` is no longer
      flagged (it was, in the first version, purely for colliding on a name). What remains, because
      ``descendants`` is a set of bare names merged across modules — and the package already has one
      cross-module name collision, ``SeamClient`` in both ``client.py`` and ``aio.py``:

      - a locally shadowed chain (``class InternalError(ValueError)`` then
        ``class SubInternalError(InternalError)``, importing nothing from the taxonomy);
      - an unrelated qualifier, ``class X(vendor.SeamError)``, per the note on attribute bases below.

      - and, in a module using ``from .errors import *``, any base whose bare name collides with
        a taxonomy member — the price of the star fallback below, which has to over-approximate.

      Each fails loudly with file, line and base list, so it diagnoses in seconds — but it is a
      false alarm, and this check is only worth having if that stays rare.

    The precise alternative — import the package and walk ``SeamError.__subclasses__()`` — is exactly
    what this file certifies the consumer does not have to do: it needs the generated ``_gen`` tree
    and therefore a BUF_TOKEN. A static approximation that runs on a bare checkout is the point.
    """
    out: dict[str, list[tuple[str, list[str], int]]] = {}
    for path in sorted((REPO / "python" / "seam_sdk").rglob("*.py")):
        if SKIP_DIRS & set(path.relative_to(REPO).parts):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        # Names this module pulled out of the error taxonomy, plus everything it defines itself
        # (a local subclass can chain off another local one — `class Tier2(Tier1)`).
        from_errors = _taxonomy_imports(tree)
        # `from .errors import *` yields the single name "*", which would otherwise match nothing
        # and silently drop every base in the module — a hole the provenance tightening opened, and
        # the reason this fallback exists. Over-approximating is the safe direction here.
        star = "*" in from_errors
        local = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}

        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = []
            for base in node.bases:
                # `errors.SeamError` — attribute access through a module object. The qualifier
                # is deliberately NOT inspected: resolving it would mean tracking `import
                # seam_sdk.errors as e`, `from . import errors`, and re-binding, for no gain. The
                # cost is that an unrelated `vendor.SeamError` would also be reported — loudly, with
                # its base list printed, which is the safe direction to be wrong in.
                if isinstance(base, ast.Attribute):
                    bases.append(base.attr)
                elif isinstance(base, ast.Name) and (
                    star or base.id in from_errors or base.id in local
                ):
                    bases.append(base.id)
            found.append((node.name, bases, node.lineno))
        out[str(path.relative_to(REPO))] = found
    return out


def _taxonomy_imports(tree: ast.Module) -> set[str]:
    """Names a module pulled out of the error taxonomy (``from .errors import SeamError``, …)."""
    return {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "") in ERROR_SOURCES
        for alias in node.names
    }


def test_the_cross_module_resolution_this_check_depends_on_is_live():
    """Guard-the-guard, aimed at the half the obvious one misses.

    ``test_no_seam_error_subclass_is_defined_outside_errors_py`` asserts its closure found a taxonomy
    in ``errors.py`` — but that chain is carried entirely by locally-defined bases, so it stays green
    even with ``ERROR_SOURCES`` emptied and cross-module resolution completely dead. Verified: with
    that sabotage in place, a real taxonomy split into a new module passed, exit 0.

    So this pins the other half — that a module which is *not* errors.py is actually observed
    importing a taxonomy name. That is the machinery a cross-module split would be caught by.
    """
    # Intersected with what errors.py actually defines, not just "a name from an ERROR_SOURCES
    # module". `from . import aio` (__init__.py) and `from . import client as _client` (admin.py)
    # both match ERROR_SOURCES via its "" entry while having nothing to do with the taxonomy — so
    # without this intersection, dropping "errors" from ERROR_SOURCES (the one entry carrying every
    # real taxonomy import) left this green and a cross-module split exited 0.
    taxonomy = {
        node.name
        for node in ast.walk(
            ast.parse(ERRORS.read_text(encoding="utf-8"), filename=str(ERRORS))
        )
        if isinstance(node, ast.ClassDef)
    }
    assert taxonomy, (
        f"parsed ZERO classes out of {ERRORS} — nothing to intersect against"
    )

    seen = {
        str(path.relative_to(REPO)): _taxonomy_imports(
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        )
        for path in sorted((REPO / "python" / "seam_sdk").rglob("*.py"))
        if not SKIP_DIRS & set(path.relative_to(REPO).parts)
    }
    errors_rel = str(ERRORS.relative_to(REPO))
    live = {
        mod: names & taxonomy
        for mod, names in seen.items()
        if mod != errors_rel and names & taxonomy
    }
    assert live, (
        "no module outside errors.py was observed importing from the error taxonomy "
        f"(sources: {sorted(ERROR_SOURCES)}). Either the package genuinely stopped importing its "
        "own errors anywhere, or ERROR_SOURCES/_taxonomy_imports has broken — in which case "
        "test_no_seam_error_subclass_is_defined_outside_errors_py is still green while being "
        "unable to see a cross-module split at all."
    )


def test_no_seam_error_subclass_is_defined_outside_errors_py():
    """The whole ``SeamError`` tree lives in ``errors.py`` — checked without a naming convention.

    This is the check that makes the contract in ``errors.py``'s docstring true as written. It has no
    runtime dependency, so unlike the roster cross-check below it cannot be skipped away by a missing
    grpcio.
    """
    by_module = _classes_by_module()
    assert by_module, (
        "found no modules under seam_sdk/ — the scan is not looking at anything"
    )

    # Transitive closure from SeamError, across module boundaries, to a fixed point.
    #
    # `qualified` records WHERE each descendant was defined, and membership is earned through a
    # class's own bases — never through its name. Matching on the name alone was the first version
    # of this, and it flagged an unrelated `class InternalError(ValueError)` in client.py purely for
    # colliding with a taxonomy member's name.
    descendants = {"SeamError"}
    qualified: list[tuple[str, str, int]] = []
    while True:
        grew = False
        for module, classes in by_module.items():
            for name, bases, lineno in classes:
                if (module, name, lineno) in qualified or not (
                    descendants & set(bases)
                ):
                    continue
                descendants.add(name)
                qualified.append((module, name, lineno))
                grew = True
        if not grew:
            break

    errors_rel = str(ERRORS.relative_to(REPO))
    # Guard-the-guard: if the closure found nothing beyond the root, the assertion below is vacuous.
    local = [m for m, _n, _l in qualified if m == errors_rel]
    assert len(local) > 1, (
        f"the SeamError closure resolved to {sorted(descendants)} — expected the taxonomy to be "
        f"discoverable in {errors_rel}. The scan's base-name resolution has probably broken; fix it "
        f"rather than letting this pass with nothing to check."
    )

    bases_of = {
        (module, name, lineno): bases
        for module, classes in by_module.items()
        for name, bases, lineno in classes
    }
    offenders = [
        f"{module}:{lineno} defines {name} "
        f"(bases: {', '.join(bases_of[(module, name, lineno)]) or '—'})"
        for module, name, lineno in qualified
        if module != errors_rel
    ]
    assert not offenders, (
        f"these SeamError subclasses are defined outside {ERRORS.name} (seam-sdk#54):\n"
        + "\n".join(f"  - {o}" for o in offenders)
        + "\n\nseam-adapters reads the taxonomy out of that single file, so a class living "
        "elsewhere is invisible to their classification diff — and an unclassified non-RPC "
        "SeamError resolves as a TransportFailure, which under FAIL_OPEN runs the gated tool "
        "ungated. Splitting the hierarchy is a legitimate thing to want; it just needs a "
        "conversation on the issue first, because it is their breakage, not ours."
    )


def _exported_error_names() -> list[str]:
    """The ``*Error`` names in ``seam_sdk.__all__``, read by AST rather than by import.

    Importing ``seam_sdk`` to read ``__all__`` would need the generated ``_gen`` tree — which would
    couple this test to the very machinery it certifies the consumer does not need.

    The ``*Error`` suffix filter is safe *here*, unlike in the check above: this only asks whether
    names that are already known to be errors resolve in the standalone module. A subclass named
    without the suffix is caught by ``test_no_seam_error_subclass_is_defined_outside_errors_py``,
    which does not filter by name at all.
    """
    tree = ast.parse(INIT.read_text(encoding="utf-8"), filename=str(INIT))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
        ):
            return [
                el.value
                for el in node.value.elts  # type: ignore[attr-defined]
                if isinstance(el, ast.Constant)
                and isinstance(el.value, str)
                and el.value.endswith("Error")
            ]
    raise AssertionError(f"no `__all__` assignment found in {INIT}")


def test_every_exported_error_is_importable_from_the_standalone_module(standalone):
    """The complement to the static check: the names the package *exports* must actually be present
    in what a standalone load yields. Catches an export that resolves through a re-export chain the
    consumer's single-file read cannot follow."""
    exported = _exported_error_names()
    # Guard-the-guard again: an `__all__` that parsed to nothing would pass this trivially.
    assert exported, f"parsed ZERO exported *Error names from {INIT}"

    roster = set(standalone["roster"])
    missing = sorted(name for name in exported if name not in roster)
    assert not missing, (
        f"these exported errors are not defined in {ERRORS.name}: {missing} (seam-sdk#54). "
        "seam-adapters reads the taxonomy out of that single file, so a re-exported class is "
        "invisible to their classification diff."
    )
