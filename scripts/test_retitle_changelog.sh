#!/usr/bin/env bash
# Tests for scripts/retitle_changelog.sh, run in CI on every PR.
#
# Same reasoning as scripts/test_set_version.sh: the only prior "test" of a CHANGELOG retitle would
# have been cutting a real release, and this repo does not get to re-cut one if a stamp half-writes
# the file. Everything here runs against a throwaway copy; the real CHANGELOG.md is never touched.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$ROOT/scripts/retitle_changelog.sh"
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

# A throwaway dir holding just the one file this script touches.
fixture() {
    local dir
    dir="$(mktemp -d)"
    printf '# Changelog\n\nIntro paragraph.\n\n## Unreleased\n\n### Changed\n\n- something new\n\n## 0.7.26 — 2026-08-14\n\n### Changed\n\n- older entry\n' \
        >"$dir/CHANGELOG.md"
    echo "$dir"
}

unreleased_count() { grep -cx '## Unreleased' "$1/CHANGELOG.md" || true; }
versioned_line_no() { grep -nxF "## $2 — $3" "$1/CHANGELOG.md" | head -1 | cut -d: -f1; }
unreleased_line_no() { grep -nx '## Unreleased' "$1/CHANGELOG.md" | head -1 | cut -d: -f1; }

echo "retitle_changelog.sh"

# ── The base case ────────────────────────────────────────────────────────────────────────────────
dir="$(fixture)"
if "$STAMP" 9.9.9 2026-10-01 "$dir" >/dev/null 2>&1 &&
    [ "$(unreleased_count "$dir")" = "1" ] &&
    grep -qxF "## 9.9.9 — 2026-10-01" "$dir/CHANGELOG.md"; then
    ok "retitles Unreleased to the dated heading and opens a fresh one"
else
    bad "did not produce exactly one Unreleased and one dated heading"
fi
rm -rf "$dir"

# ── The fresh Unreleased heading sits ABOVE the dated one, not below ───────────────────────────────
# Entries have to keep landing in the right place for the NEXT release — a heading opened in the
# wrong order would silently route every future entry into the version that just shipped.
dir="$(fixture)"
"$STAMP" 9.9.9 2026-10-01 "$dir" >/dev/null 2>&1
u="$(unreleased_line_no "$dir")"
v="$(versioned_line_no "$dir" 9.9.9 2026-10-01)"
if [ -n "$u" ] && [ -n "$v" ] && [ "$u" -lt "$v" ]; then
    ok "the new Unreleased heading precedes the dated one"
else
    bad "ordering wrong or headings missing (unreleased=$u versioned=$v)"
fi
rm -rf "$dir"

# ── The release's actual entries land under the dated heading, not lost above it ───────────────────
dir="$(fixture)"
"$STAMP" 9.9.9 2026-10-01 "$dir" >/dev/null 2>&1
if awk '/^## 9\.9\.9/{f=1} f && /something new/{print; found=1} /^## 0\.7\.26/{f=0}' "$dir/CHANGELOG.md" | grep -q .; then
    ok "this release's own entries stayed under its new dated heading"
else
    bad "entries did not land under the dated heading"
fi
rm -rf "$dir"

# ── Older, already-versioned sections are untouched ─────────────────────────────────────────────
dir="$(fixture)"
"$STAMP" 9.9.9 2026-10-01 "$dir" >/dev/null 2>&1
if grep -qxF "## 0.7.26 — 2026-08-14" "$dir/CHANGELOG.md" && grep -q "older entry" "$dir/CHANGELOG.md"; then
    ok "leaves prior versioned sections alone"
else
    bad "disturbed an already-versioned section"
fi
rm -rf "$dir"

# ── A leading v is tolerated (the dispatch payload has carried one) ─────────────────────────────
dir="$(fixture)"
"$STAMP" v9.9.9 2026-10-01 "$dir" >/dev/null 2>&1
if grep -qxF "## 9.9.9 — 2026-10-01" "$dir/CHANGELOG.md"; then
    ok "tolerates a leading v"
else
    bad "leading v not stripped"
fi
rm -rf "$dir"

# ── A rerun for a version already stamped is a tolerated no-op ─────────────────────────────────
# Mirrors the "Commit + tag" step's own tolerance for being rerun after a tag push failed but the
# commit already landed — matched on VERSION ALONE, since a retry a day later carries a different
# DATE and must not retitle the (already reopened, still blank) Unreleased heading a second time.
dir="$(fixture)"
"$STAMP" 9.9.9 2026-10-01 "$dir" >/dev/null 2>&1
before="$(cat "$dir/CHANGELOG.md")"
if "$STAMP" 9.9.9 2026-10-02 "$dir" >/dev/null 2>&1 && [ "$(cat "$dir/CHANGELOG.md")" = "$before" ]; then
    ok "a rerun for an already-stamped version is a no-op, even with a different date"
else
    bad "rerunning for an already-stamped version changed the file or failed"
fi
rm -rf "$dir"

# ── A dot in the version is literal, not "any character" ───────────────────────────────────────
# If the version were used as an unescaped regex, "9.9.9" would also match a heading like
# "9X9X9" (dot = any char), falsely treating an unrelated section as proof this version already
# shipped and silently no-op'ing instead of stamping it.
dir="$(fixture)"
printf '\n## 9X9X9 — 2026-09-01\n\nunrelated\n' >>"$dir/CHANGELOG.md"
if "$STAMP" 9.9.9 2026-10-01 "$dir" >/dev/null 2>&1 && grep -qxF "## 9.9.9 — 2026-10-01" "$dir/CHANGELOG.md"; then
    ok "a dot in the version does not loosely match an unrelated heading"
else
    bad "an unrelated '9X9X9' heading was mistaken for '9.9.9' already being stamped"
fi
rm -rf "$dir"

# ── It must FAIL, loudly, on zero Unreleased headings ───────────────────────────────────────────
# Zero means a prior release already consumed it without reopening one — stamping blind here would
# bury this release's entries under whichever version came before.
dir="$(fixture)"
perl -0777 -pi -e 's/## Unreleased\n\n//' "$dir/CHANGELOG.md"
if "$STAMP" 9.9.9 2026-10-01 "$dir" >/dev/null 2>&1; then
    bad "exited 0 with no Unreleased heading to retitle"
else
    ok "exits non-zero when there is no Unreleased heading"
fi
rm -rf "$dir"

# ── It must FAIL, loudly, on more than one Unreleased heading ───────────────────────────────────
dir="$(fixture)"
printf '\n## Unreleased\n' >>"$dir/CHANGELOG.md"
if "$STAMP" 9.9.9 2026-10-01 "$dir" >/dev/null 2>&1; then
    bad "exited 0 with two Unreleased headings present"
else
    ok "exits non-zero when more than one Unreleased heading exists"
fi
rm -rf "$dir"

# ── It must FAIL, loudly, on a malformed date ────────────────────────────────────────────────────
dir="$(fixture)"
if "$STAMP" 9.9.9 "Oct 1 2026" "$dir" >/dev/null 2>&1; then
    bad "exited 0 with a non-ISO date"
else
    ok "exits non-zero on a malformed date"
fi
rm -rf "$dir"

dir="$(fixture)"
rm "$dir/CHANGELOG.md"
if "$STAMP" 9.9.9 2026-10-01 "$dir" >/dev/null 2>&1; then
    bad "exited 0 with CHANGELOG.md missing"
else
    ok "exits non-zero when CHANGELOG.md is missing"
fi
rm -rf "$dir"

# ── The invocation the release workflow actually uses ────────────────────────────────────────────
dir="$(fixture)"
mkdir -p "$dir/scripts"
cp "$STAMP" "$dir/scripts/retitle_changelog.sh"
if (cd "$dir" && ./scripts/retitle_changelog.sh 9.9.9 2026-10-01 >/dev/null 2>&1) &&
    grep -qxF "## 9.9.9 — 2026-10-01" "$dir/CHANGELOG.md"; then
    ok "works with root derived from its own location (the workflow's invocation)"
else
    bad "default-root invocation failed"
fi
rm -rf "$dir"

# ── The repo itself is untouched ──────────────────────────────────────────────────────────────────
if git -C "$ROOT" diff --quiet -- CHANGELOG.md; then
    ok "left the real repo CHANGELOG.md alone"
else
    bad "MODIFIED THE REPO — the tests must run against copies only"
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
