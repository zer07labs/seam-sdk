#!/usr/bin/env bash
# Stamp both packages to one version — the single implementation of "one version everywhere".
#
# This lived inline in .github/workflows/release-on-runtime.yml, where it could not be tested
# without cutting a release, and it targeted pyproject's `version` key BY LINE NUMBER
# (`perl -pi -e '... if $. < 6'`). That is a positional heuristic in a file whose house style is a
# multi-line explanatory comment above every field — `requires-python` already has a five-line one
# directly below `version`. Three more lines above `version` and the stamp silently stops matching.
#
# The failure that produces is not a clean no-op, because the two files fail differently: the node
# edit to ts/package.json has no line limit and still lands, so `git diff --quiet` is false, the
# release commits a ts-only bump to main, and then main fails its own version-lockstep check while
# publish.yml fails its tag-matches-in-tree check. A broken release, discovered mid-release, in a
# repo that does not choose its own version and so cannot simply re-cut.
#
# Two changes fix that class of thing rather than this instance of it:
#   1. Match the FIRST `^version = "..."` line wherever it sits — the same rule the two check jobs
#      already use (`grep -m1 '^version'`), so the stamp and the assertions cannot disagree.
#   2. ASSERT the postcondition. Reading the versions back is the only step that actually knows
#      whether the edit took; `git diff` only knows that *something* changed.
#
# Usage: scripts/set_version.sh 0.8.0 [repo_root]
set -euo pipefail

VER="${1:?usage: set_version.sh <version> [repo_root]}"
VER="${VER#v}" # tolerate a leading v
ROOT="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

PKG="$ROOT/ts/package.json"
PYPROJECT="$ROOT/python/pyproject.toml"

for f in "$PKG" "$PYPROJECT"; do
    [ -f "$f" ] || {
        echo "::error::set_version.sh: $f does not exist" >&2
        exit 1
    }
done

VER="$VER" node -e '
  const fs = require("fs"), p = process.argv[1];
  const j = JSON.parse(fs.readFileSync(p, "utf8"));
  j.version = process.env.VER;
  fs.writeFileSync(p, JSON.stringify(j, null, 2) + "\n");
' "$PKG"

# The first `version = "..."` at column 0 — [project].version. Later tables ([tool.*]) are
# indented or come after, and `grep -m1` picks this same line, so the two cannot drift apart.
VER="$VER" perl -pi -e '
  if (!$done && s/^version = "[^"]+"/version = "$ENV{VER}"/) { $done = 1 }
' "$PYPROJECT"

# The postcondition, read back from the files. This is the step whose absence let a positional
# match masquerade as a successful stamp.
TS_OUT=$(node -p "require('$PKG').version")
PY_OUT=$(grep -m1 '^version' "$PYPROJECT" | sed -E 's/.*"([^"]+)".*/\1/')

if [ "$TS_OUT" != "$VER" ] || [ "$PY_OUT" != "$VER" ]; then
    echo "::error::set_version.sh failed to stamp $VER — ts=$TS_OUT python=$PY_OUT." \
        "Neither file may be left half-stamped: fix the stamp, do not hand-edit and re-tag." >&2
    exit 1
fi

echo "stamped v$VER  (ts=$TS_OUT  python=$PY_OUT)"
