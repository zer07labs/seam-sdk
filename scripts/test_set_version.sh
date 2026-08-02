#!/usr/bin/env bash
# Tests for scripts/set_version.sh, run in CI on every PR.
#
# The point of this file is that the version stamp was previously only exercised BY CUTTING A
# RELEASE. There is no way to be careful with a mechanism whose only test run is the real one — and
# the SDK does not choose its own version, so a stamp that misfires cannot be corrected by simply
# re-cutting from here.
#
# Everything runs against copies in a temp dir; the repo is never modified.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$ROOT/scripts/set_version.sh"
PASS=0
FAIL=0

ok() {
    PASS=$((PASS + 1))
    echo "  ok — $1"
}
bad() {
    FAIL=$((FAIL + 1))
    echo "  FAIL — $1"
}

# A throwaway repo root holding just the two files the stamp touches.
fixture() {
    local dir
    dir="$(mktemp -d)"
    mkdir -p "$dir/ts" "$dir/python"
    cp "$ROOT/ts/package.json" "$dir/ts/package.json"
    cp "$ROOT/python/pyproject.toml" "$dir/python/pyproject.toml"
    echo "$dir"
}

ts_version() { node -p "require('$1/ts/package.json').version"; }
py_version() { grep -m1 '^version' "$1/python/pyproject.toml" | sed -E 's/.*"([^"]+)".*/\1/'; }

echo "set_version.sh"

# ── The base case ────────────────────────────────────────────────────────────────────────────────
dir="$(fixture)"
if "$STAMP" 9.9.9 "$dir" >/dev/null 2>&1 &&
    [ "$(ts_version "$dir")" = "9.9.9" ] && [ "$(py_version "$dir")" = "9.9.9" ]; then
    ok "stamps both files"
else
    bad "stamps both files (ts=$(ts_version "$dir") py=$(py_version "$dir"))"
fi
rm -rf "$dir"

# ── The regression this file exists for ──────────────────────────────────────────────────────────
# The old stamp matched pyproject's `version` only on lines 1-5. `version` sits on line 3, and every
# other field in that file carries a multi-line comment above it, so this is three lines of headroom
# on a file actively maintained in a style that consumes them.
dir="$(fixture)"
perl -pi -e 'print "# a comment someone adds above version\n" x 4 if $. == 2 && !$done++' \
    "$dir/python/pyproject.toml"
if "$STAMP" 9.9.9 "$dir" >/dev/null 2>&1 && [ "$(py_version "$dir")" = "9.9.9" ]; then
    ok 'stamps python even when comments push the version key past line 5'
else
    bad "comments above \`version\` broke the stamp — py=$(py_version "$dir")"
fi
rm -rf "$dir"

# ── It must not stamp a version key that is not [project].version ────────────────────────────────
# `grep -m1 '^version'` is what both check jobs read, so the stamp has to agree with it: first
# column-0 `version` line wins, and nothing else is touched.
dir="$(fixture)"
printf '\n[tool.other]\nversion = "keep-me"\n' >>"$dir/python/pyproject.toml"
"$STAMP" 9.9.9 "$dir" >/dev/null 2>&1
if [ "$(py_version "$dir")" = "9.9.9" ] && grep -q 'version = "keep-me"' "$dir/python/pyproject.toml"; then
    ok "stamps only the first version key, leaving later tables alone"
else
    bad "stamped a version key it should not have"
fi
rm -rf "$dir"

# ── A leading v is tolerated (the dispatch payload has carried one) ───────────────────────────────
dir="$(fixture)"
"$STAMP" v9.9.9 "$dir" >/dev/null 2>&1
if [ "$(ts_version "$dir")" = "9.9.9" ] && [ "$(py_version "$dir")" = "9.9.9" ]; then
    ok "tolerates a leading v"
else
    bad "leading v not stripped (ts=$(ts_version "$dir") py=$(py_version "$dir"))"
fi
rm -rf "$dir"

# ── It must FAIL, loudly, rather than half-stamp ──────────────────────────────────────────────────
# The half-stamped state is the dangerous one: ts bumped, python not, committed to main by a release
# job that only checked `git diff`. A non-zero exit is what stops that commit from happening.
dir="$(fixture)"
perl -pi -e 's/^version = "[^"]+"/vershion = "0.0.0"/ if $. < 6' "$dir/python/pyproject.toml"
if "$STAMP" 9.9.9 "$dir" >/dev/null 2>&1; then
    bad "exited 0 with no python version key to stamp — a half-stamp would reach main"
else
    ok "exits non-zero when python cannot be stamped"
fi
rm -rf "$dir"

dir="$(fixture)"
rm "$dir/ts/package.json"
if "$STAMP" 9.9.9 "$dir" >/dev/null 2>&1; then
    bad "exited 0 with ts/package.json missing"
else
    ok "exits non-zero when a target file is missing"
fi
rm -rf "$dir"

# ── The invocation the release workflow actually uses ────────────────────────────────────────────
# `./scripts/set_version.sh "$VER"` — ONE argument, root derived from BASH_SOURCE. Every test above
# passes an explicit root, so without this the default-root path would be the one code path that
# only runs during a real release, which is the whole thing this file exists to prevent.
dir="$(fixture)"
mkdir -p "$dir/scripts"
cp "$STAMP" "$dir/scripts/set_version.sh"
if (cd "$dir" && ./scripts/set_version.sh 9.9.9 >/dev/null 2>&1) &&
    [ "$(ts_version "$dir")" = "9.9.9" ] && [ "$(py_version "$dir")" = "9.9.9" ]; then
    ok "works with root derived from its own location (the workflow's invocation)"
else
    bad "default-root invocation failed (ts=$(ts_version "$dir") py=$(py_version "$dir"))"
fi
rm -rf "$dir"

# ── The repo itself is untouched ──────────────────────────────────────────────────────────────────
if git -C "$ROOT" diff --quiet -- ts/package.json python/pyproject.toml; then
    ok "left the real repo files alone"
else
    bad "MODIFIED THE REPO — the tests must run against copies only"
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
