#!/usr/bin/env python3
"""Resolve, live, whether each agent framework can share a virtualenv with this SDK.

WHY THIS EXISTS
---------------
`COMPATIBILITY.md` §4a states which agent frameworks co-install with `seam-sdk`. That answer depends
on **PyPI**, not on this repository — it changes when a framework or one of its transitive
dependencies moves, with nobody editing anything here. A table of version numbers in prose is
therefore stale the moment it is written, which is the exact failure mode this repo keeps closing
(see `python/tests/test_protobuf_floor.py`, `test_compatibility_citations_resolve.py`).

So the table declares the *expectation* and this script derives the *answer*, and they are checked
against each other. The doc is the input: add a row there and it is covered here automatically.

IT FAILS IN BOTH DIRECTIONS, AND THE SECOND ONE IS THE POINT
------------------------------------------------------------
A row that flips `compatible` -> `incompatible` means a framework moved under us. A row that flips
`incompatible` -> `compatible` means **the upstream fix landed** — and nothing else in this org
watches for that. `seam-adapters`' own resolution-probe installs its shims *without* the `[sdk]`
extra, so it guards the documented two-venv workaround and stays green whether or not the conflict
is still real.

TWO THINGS THAT ARE EASY TO GET WRONG, BOTH FOUND BY GETTING THEM WRONG
-----------------------------------------------------------------------
1. **Resolve with the shim's declared constraint, never the bare framework name.** Asked for a bare
   `crewai`, a resolver happily backtracks to an ancient release that predates the conflict and
   reports success — a false `compatible`. With `crewai>=1.15.3,<2` (what `seam-adapters`' shim
   actually requires) the same resolver proves it unsatisfiable. A probe that reports the wrong
   answer confidently is worse than no probe.
2. **uv exits non-zero for every failure**, including "package not found" and "network disabled",
   and all of them print the word *unsatisfiable*. Exit code alone cannot separate a real
   incompatibility from an outage, so this classifies on the message and treats anything it cannot
   positively identify as INFRA — never as a verdict.

Usage:  scripts/probe_framework_coinstall.py [--python-version 3.12]
Exit:   0 = every row matches the table · 1 = a row disagrees · 2 = infrastructure problem
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile

if sys.version_info < (3, 11):  # noqa: E402 — must run before the tomllib import below
    # Exit 2, not 1: this is an infrastructure condition (wrong interpreter), and 1 is reserved for
    # "a row disagrees with the table". `sys.exit("msg")` would exit 1 and quietly report a tooling
    # problem as a verdict — the exact never-a-verdict property this script is built around.
    print(
        "probe_framework_coinstall.py needs Python 3.11+ for tomllib (found "
        f"{sys.version_info.major}.{sys.version_info.minor}). Run it with the project venv: "
        "python/.venv/bin/python scripts/probe_framework_coinstall.py",
        file=sys.stderr,
    )
    sys.exit(2)

import tomllib  # noqa: E402
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
COMPATIBILITY = REPO / "COMPATIBILITY.md"
PYPROJECT = REPO / "python" / "pyproject.toml"

#: The marker that opens the parsed table in COMPATIBILITY.md.
TABLE_MARKER = "<!-- PROBE-TABLE:"

#: `| `name` | `constraint` | `verdict` | anything |`
ROW = re.compile(
    r"^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|\s*`(compatible|incompatible)`\s*\|",
    re.MULTILINE,
)

VERDICT_COMPATIBLE = "compatible"
VERDICT_INCOMPATIBLE = "incompatible"


class InfraError(RuntimeError):
    """Something prevented us from getting an answer. NEVER reported as a verdict."""


@dataclass(frozen=True)
class Row:
    framework: str
    constraint: str
    expected: str

    @property
    def requirement(self) -> str:
        return f"{self.framework}{self.constraint}"


def sdk_floors() -> list[str]:
    """This SDK's own install-time requirements, read from the manifest — never hardcoded.

    Substituting the floors for the `seam-sdk` package itself is deliberate: `seam-sdk` lives on a
    private Cloudsmith index, and a probe that needed a credential could not run on a schedule. The
    floors are what actually collide with a framework's closure, and reading the full list (rather
    than a hardcoded trio) means a new install-time dependency is picked up automatically.
    """
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", [])
    if not deps:
        raise InfraError(
            f"no [project].dependencies in {PYPROJECT.relative_to(REPO)} — the manifest changed "
            f"shape and this probe would otherwise resolve against nothing at all"
        )
    return list(deps)


def table_rows() -> list[Row]:
    """Parse the expectation table out of COMPATIBILITY.md.

    Guard-the-guard: zero rows is a failure, not an empty pass. An empty parse would make every
    assertion below vacuous, which is precisely how a gate stops meaning anything.
    """
    text = COMPATIBILITY.read_text(encoding="utf-8")
    if TABLE_MARKER not in text:
        raise InfraError(
            f"{COMPATIBILITY.name} no longer contains the {TABLE_MARKER!r} marker. Either the "
            f"section was removed or renamed — this probe reads its expectations from that table "
            f"and has nothing to check without it."
        )
    rows = [Row(m.group(1), m.group(2), m.group(3)) for m in ROW.finditer(text[text.index(TABLE_MARKER):])]
    if not rows:
        raise InfraError(
            f"found the {TABLE_MARKER!r} marker in {COMPATIBILITY.name} but parsed ZERO rows from "
            f"the table under it. The table's shape changed; fix the parser rather than letting "
            f"this pass with nothing to check."
        )
    return rows


def resolve(row: Row, floors: list[str], python_version: str) -> tuple[str, str]:
    """Return (verdict, evidence). Raises InfraError when no verdict can be established."""
    with tempfile.TemporaryDirectory() as tmp:
        req = Path(tmp) / "requirements.in"
        out = Path(tmp) / "resolved.txt"
        req.write_text("\n".join([row.requirement, *floors]) + "\n", encoding="utf-8")

        try:
            proc = subprocess.run(
                # `--no-cache` so a cached index cannot report yesterday's PyPI as today's.
                # Pre-releases stay disabled (uv's default): a framework's dev build is not what a
                # consumer installs, and letting one in would flip a verdict on an artifact nobody
                # depends on.
                ["uv", "pip", "compile", str(req), "--python-version", python_version,
                 "--no-cache", "-o", str(out)],
                capture_output=True, text=True, timeout=300,
            )
        except FileNotFoundError as exc:
            raise InfraError("`uv` is not installed — see https://docs.astral.sh/uv/") from exc
        except subprocess.TimeoutExpired as exc:
            raise InfraError(f"uv timed out resolving {row.requirement}") from exc

        if proc.returncode == 0:
            pinned = ""
            if out.exists():
                for line in out.read_text(encoding="utf-8").splitlines():
                    if line.startswith(("protobuf==", f"{row.framework}==")):
                        pinned += ("" if not pinned else "; ") + line.strip()
            return VERDICT_COMPATIBLE, pinned or "resolved"

        message = f"{proc.stdout}\n{proc.stderr}"

        # uv exits non-zero for an unsatisfiable graph, a missing package AND a network failure,
        # and every one of them says "unsatisfiable". Positively identify the infra cases first;
        # anything left unrecognised is infra too, never a verdict.
        infra_markers = (
            "network was disabled",
            "was not found in the package registry",
            "Failed to fetch",
            "error sending request",
            "Request failed after",
            "os error",
        )
        for marker in infra_markers:
            if marker in message:
                raise InfraError(f"{row.framework}: {marker} — no verdict established")

        if "requirements are unsatisfiable" in message:
            # The last "we can conclude" line is uv's actual conclusion; earlier ones are the
            # intermediate steps it walked to get there. Take the final one and drop uv's
            # line-wrapping so the evidence reads as one sentence.
            because = [ln.strip() for ln in message.splitlines() if "we can conclude" in ln]
            evidence = re.sub(r"\s+", " ", because[-1]) if because else "unsatisfiable"
            return VERDICT_INCOMPATIBLE, evidence

        raise InfraError(
            f"{row.framework}: uv exited {proc.returncode} with a message this probe does not "
            f"recognise. Refusing to guess a verdict.\n{message.strip()[-800:]}"
        )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    # One pinned interpreter, stated once. The question is co-installability, not Python-floor
    # coverage — resolving across every supported Python would multiply runtime for an answer that
    # does not differ today.
    ap.add_argument("--python-version", default="3.12")
    args = ap.parse_args()

    try:
        floors = sdk_floors()
        rows = table_rows()
    except InfraError as exc:
        print(f"::error::{exc}")
        return 2

    print(f"probing {len(rows)} framework(s) against this SDK's floors on Python {args.python_version}")
    print("  floors: " + ", ".join(floors))

    mismatches: list[str] = []
    infra: list[str] = []

    for row in rows:
        try:
            verdict, evidence = resolve(row, floors, args.python_version)
        except InfraError as exc:
            infra.append(str(exc))
            print(f"  ?? {row.requirement}: {exc}")
            continue

        mark = "ok" if verdict == row.expected else "!!"
        print(f"  {mark} {row.requirement}: {verdict} ({evidence})")
        if verdict != row.expected:
            mismatches.append(_explain(row, verdict, evidence))

    if infra:
        print("\n::error::could not establish a verdict for every row — treating as INFRASTRUCTURE,")
        print("::error::not as a matrix change. Re-run; do not edit COMPATIBILITY.md on this basis.")
        for item in infra:
            print(f"::error::  - {item}")
        return 2

    if mismatches:
        print("\n::error::COMPATIBILITY.md's framework table no longer matches what PyPI resolves.")
        for item in mismatches:
            print(item)
        return 1

    print(f"\nall {len(rows)} row(s) match COMPATIBILITY.md.")
    return 0


def _explain(row: Row, verdict: str, evidence: str) -> str:
    if verdict == VERDICT_COMPATIBLE:
        return (
            f"::error::  {row.framework} is marked `incompatible` but now RESOLVES ({evidence}).\n"
            f"::error::    This is the good outcome and the one nothing else watches for: the upstream\n"
            f"::error::    fix has landed. Flip the row in COMPATIBILITY.md §4a, update the tracking\n"
            f"::error::    issue, and tell seam-adapters they can retire the two-virtualenv split."
        )
    return (
        f"::error::  {row.framework} is marked `compatible` but no longer resolves.\n"
        f"::error::    {evidence}\n"
        f"::error::    A framework's transitive closure moved under us. Update COMPATIBILITY.md §4a,\n"
        f"::error::    and check whether a protobuf-floor bump on our side caused it — if so it\n"
        f"::error::    belongs in CHANGELOG.md as a consumer-visible upgrade cost."
    )


if __name__ == "__main__":
    sys.exit(main())
