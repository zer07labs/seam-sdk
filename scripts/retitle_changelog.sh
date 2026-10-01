#!/usr/bin/env bash
# Retitle CHANGELOG.md's accumulating "## Unreleased" heading to the version that just shipped it,
# and open a fresh "## Unreleased" heading above it for whatever lands next.
#
# Until this existed, release-on-runtime.yml stamped ts/package.json + python/pyproject.toml and
# tagged, but never touched CHANGELOG.md — so every entry since 0.7.26 piled up under one
# undifferentiated "## Unreleased" heading. The file's own intro paragraph promises exactly the
# retitling this script does ("accumulate under Unreleased and are retitled to the runtime version
# that carries them once it ships"), and that promise had never once been kept. One concrete cost:
# a Fable review of the seam-sdk 0.13.1->0.19.1 range had to fall back to `git diff` between tags,
# because the CHANGELOG itself could not attribute a single entry to a version.
#
# Usage: scripts/retitle_changelog.sh <version> <date:YYYY-MM-DD> [repo_root]
set -euo pipefail

VER="${1:?usage: retitle_changelog.sh <version> <date:YYYY-MM-DD> [repo_root]}"
VER="${VER#v}" # tolerate a leading v, same convention as set_version.sh
DATE="${2:?usage: retitle_changelog.sh <version> <date:YYYY-MM-DD> [repo_root]}"
ROOT="${3:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CHANGELOG="$ROOT/CHANGELOG.md"

[ -f "$CHANGELOG" ] || {
    echo "::error::retitle_changelog.sh: $CHANGELOG does not exist" >&2
    exit 1
}

[[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || {
    echo "::error::retitle_changelog.sh: date '$DATE' is not YYYY-MM-DD, got '$DATE'" >&2
    exit 1
}

# release-on-runtime.yml's "Commit + tag" step tolerates re-running with nothing left to stamp (the
# recovery path after a tag push failed but the commit already landed) — this has to tolerate the
# same rerun, matched on VERSION ALONE, because a retry on a later day carries a different DATE and
# would otherwise retitle a second, already-blank "Unreleased" heading into a DUPLICATE section for
# a version that was already released. Escaped so "." in the version is literal, not "any char".
VER_RE="$(printf '%s' "$VER" | sed 's/[.[\*^$]/\\&/g')"
if grep -qE "^## ${VER_RE} — " "$CHANGELOG"; then
    echo "CHANGELOG.md already has a '## $VER — ...' heading — nothing to do (tagging-only rerun)."
    exit 0
fi

# Exactly one "## Unreleased" heading is the precondition this script relies on. Zero means a prior
# release already consumed it without this script running to reopen one — stamping blind would bury
# this release's entries under whatever came before. More than one means something hand-edited the
# file into a state this script does not know how to resolve on its own.
BEFORE=$(grep -cx '## Unreleased' "$CHANGELOG") || BEFORE=0
if [ "$BEFORE" -ne 1 ]; then
    echo "::error::retitle_changelog.sh: expected exactly one '## Unreleased' heading in" \
        "$CHANGELOG, found $BEFORE. Fix CHANGELOG.md by hand before releasing; do not re-run this" \
        "hoping it resolves itself." >&2
    exit 1
fi

# The existing "## Unreleased" heading becomes this release's dated heading, and a fresh blank
# "## Unreleased" is opened above it for whatever lands next. Em dash (U+2014), matching every
# existing versioned heading in this file (e.g. "## 0.7.26 — 2026-08-14").
VER="$VER" DATE="$DATE" perl -i -0777 -pe '
  s/^## Unreleased\n/## Unreleased\n\n## $ENV{VER} — $ENV{DATE}\n/m
' "$CHANGELOG"

# The postcondition, read back from the file. This is the step whose absence let set_version.sh's
# positional stamp masquerade as successful — read the same lesson here rather than relearning it.
VERSIONED_LINE="## $VER — $DATE"
AFTER=$(grep -cx '## Unreleased' "$CHANGELOG") || AFTER=0
UNRELEASED_NO=$(grep -nx '## Unreleased' "$CHANGELOG" | head -1 | cut -d: -f1) || UNRELEASED_NO=0
VERSIONED_NO=$(grep -nxF "$VERSIONED_LINE" "$CHANGELOG" | head -1 | cut -d: -f1) || VERSIONED_NO=0

if [ "$AFTER" -ne 1 ] || [ "$VERSIONED_NO" -eq 0 ] || [ "$UNRELEASED_NO" -eq 0 ] ||
    [ "$UNRELEASED_NO" -ge "$VERSIONED_NO" ]; then
    echo "::error::retitle_changelog.sh failed to stamp $CHANGELOG — expected one fresh" \
        "'## Unreleased' heading (found $AFTER) sitting above one '$VERSIONED_LINE' heading" \
        "(Unreleased at line $UNRELEASED_NO, versioned at line $VERSIONED_NO). The file may be" \
        "left half-edited: fix it by hand, do not re-run and risk double-stamping." >&2
    exit 1
fi

echo "retitled CHANGELOG.md: Unreleased -> $VERSIONED_LINE (new Unreleased heading opened above it)"
