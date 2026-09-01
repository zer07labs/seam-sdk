#!/usr/bin/env bash
# check-independence.sh — THE claim, asserted: verify/ links NOTHING of Seam's.
#
# `verify/` exists to check Seam's audit chain WITHOUT trusting Seam, and the only thing that
# makes that true is its dependency list. A verifier that links Seam's own store is Seam checking
# Seam — precisely what "don't trust us, verify it yourself" says you should not have to accept.
#
# This used to be an ALLOWLIST of forbidden names, hand-maintained against a different repo's
# crate list (`\bseam-(store|types|traits|trust|kernel|crypto|api|client|guard|coord|context)`).
# It drifted the moment it was written: measured against seam-runtime/crates today it misses
# seam-acdp-testkit, seam-conformance, seam-kms-vault, seam-serving, seam-serving-router, and the
# seamd binary — six real crates the gate could not see, while `bandit` in the old list matched
# nothing that exists. An allowlist of what is forbidden has to be kept in lockstep with a repo
# this one does not build against, and its failure mode is a SILENT FALSE NEGATIVE — the worst
# possible failure for a gate whose whole job is asserting a negative claim.
#
# So this is a DENYLIST of what is permitted instead: nothing named `seam-*` or `seamd` may appear
# in the dependency tree except the root `seam-verify` crate itself. That is complete by
# construction — it does not need to know the runtime's crate list, today or ever — and its
# failure mode is a LOUD FALSE POSITIVE: a legitimately-named third-party crate would trip it.
# THAT IS THE CORRECT DIRECTION TO FAIL. If this ever fires on a crate that is not actually
# Seam's, the fix is to investigate it — confirm its source registry with `cargo metadata` (a
# crates.io/other-registry source is a different `source = "..."` entry than a path or git dep) —
# and, only once genuinely third-party, add a narrowly-scoped, commented exemption for that exact
# name. Never widen the pattern to make a failure go away; that is exactly how the old allowlist
# went blind.
#
# Scope: `-e normal` only (normal dependencies), not dev-dependencies. A dev-dependency never
# ships in the built artifact a third party audits, so it cannot compromise the independence
# claim the same way — the claim is about what `seam-verify` LINKS, not what its own test suite
# happens to pull in.
#
# Testable by construction: this script's INPUT (a `cargo tree` rendering) is separable from where
# that rendering comes from, so a test can hand it synthetic text without a real cargo invocation
# and without touching the actual `verify/` tree.
#
# Usage:
#   scripts/check-independence.sh              # cd verify && cargo tree -e normal  (real gate)
#   scripts/check-independence.sh -            # read the tree to check from stdin
#   scripts/check-independence.sh <file>       # read the tree to check from a file
#
# Exit codes: 0 clean · 1 a Seam crate (or seamd) appears outside the root line.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SRC="${1:-}"
if [ -z "$SRC" ]; then
  TREE="$(cd "$REPO_ROOT/verify" && cargo tree -e normal)"
elif [ "$SRC" = "-" ]; then
  TREE="$(cat)"
else
  TREE="$(cat "$SRC")"
fi

echo "$TREE"

# The root line is `seam-verify vX.Y.Z ...` at column 0 (cargo tree never indents the root). The
# anchor is `^seam-verify ` — name immediately followed by a space — so it excludes ONLY that
# exact crate name; a hypothetical dependency named e.g. `seam-verify-extra` does not share the
# "name+space" prefix and stays subject to the check below. Indentation/box-drawing prefixes
# (`├── `, `│   `, `└── `) on every OTHER line mean no dependency line can ever start at column 0
# with `seam-verify `, so this exclusion cannot be defeated by formatting.
# `grep -v` exits 1 when EVERY line is filtered out (the all-root, zero-dependency case) — under
# `set -e` that is not an error here, it is acceptance criterion #2, so it is explicitly tolerated.
NON_ROOT="$(echo "$TREE" | grep -vE '^seam-verify ' || true)"

if echo "$NON_ROOT" | grep -qiE '\bseam-[a-z0-9_-]+\b|\bseamd\b'; then
  echo "::error::seam-verify links a Seam crate. The independence claim is now false — that is the whole product."
  echo "Offending line(s):"
  echo "$NON_ROOT" | grep -iE '\bseam-[a-z0-9_-]+\b|\bseamd\b'
  echo
  echo "If this is a genuine third-party crate that merely happens to be named seam-*, do NOT widen this pattern."
  echo "Investigate it instead: confirm its source registry with 'cargo metadata' (path/git dependencies from"
  echo "this repo or seam-runtime are never third-party), then add a narrowly-scoped, commented exemption for"
  echo "that exact crate name only."
  exit 1
fi

echo "OK — zero Seam crates."
