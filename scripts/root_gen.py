#!/usr/bin/env python3
"""Post-generation rooting: make `python/seam_sdk/_gen` a real package.

Buf managed mode cannot remap Python packages, so the raw output imports its siblings as
top-level `seam.api.v1` / `seam.event.v1` — which forced the old `sys.path.insert` hazard
(a global namespace collision with any installed `seam` package). This step rewrites those
imports to the rooted `seam_sdk._gen.*` form and drops `__init__.py` files throughout, so
the stubs ship as ordinary subpackages and the path hack disappears.

Deterministic by construction: protoc emits exactly the `from seam.<pkg> import` form.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

GEN = Path(__file__).resolve().parents[1] / "python" / "seam_sdk" / "_gen"
IMPORT = re.compile(r"^from seam\.(api|event)\.v1 import ", flags=re.M)


def main() -> int:
    if not GEN.is_dir():
        print(f"root_gen: {GEN} missing — run a generate target first", file=sys.stderr)
        return 1
    rewritten = 0
    files = [p for p in GEN.rglob("*") if p.suffix in (".py", ".pyi")]
    for path in sorted(files):
        text = path.read_text()
        new = IMPORT.sub(lambda m: f"from seam_sdk._gen.seam.{m.group(1)}.v1 import ", text)
        if new != text:
            path.write_text(new)
            rewritten += 1
    for d in [GEN, *[p for p in GEN.rglob("*") if p.is_dir()]]:
        init = d / "__init__.py"
        if not init.exists():
            init.write_text("")
    print(f"root_gen: rooted {rewritten} file(s) under seam_sdk._gen")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
