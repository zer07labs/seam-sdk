#!/usr/bin/env bash
# `buf generate <input>`, retried ONLY on a transient BSR server failure.
#
# Generation runs buf's remote plugins on the BSR, so every CI job that builds stubs depends on it.
# The BSR answers `Failure: internal: internal error, contact support …` often enough to matter: in
# two days it failed a PR, then main AND the v0.58.0 tag CI on the release commit, and publish.yml's
# ci-green gate correctly refused that release and filed #296 for a tree with nothing wrong in it. A
# re-run of the same jobs went green unchanged.
#
# The retry is deliberately narrow. Only the server-side Connect codes a re-run can cure are retried
# (internal, unavailable, deadline_exceeded). Everything else — unauthenticated, permission_denied,
# not_found, a bad module ref, a plugin error — fails on the first attempt with buf's own exit code,
# because retrying it would only delay a real refusal and make the log say "tried 3 times" about a
# mistake. Env: BUF_GENERATE_ATTEMPTS (default 3), BUF_GENERATE_BACKOFF seconds (default 10, doubled
# per retry).
set -uo pipefail

[ $# -ge 1 ] || { echo "usage: $0 <buf input> [buf generate args…]" >&2; exit 64; }

attempts="${BUF_GENERATE_ATTEMPTS:-3}"
backoff="${BUF_GENERATE_BACKOFF:-10}"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

for ((n = 1; ; n++)); do
  buf generate "$@" 2>&1 | tee "$log"
  rc="${PIPESTATUS[0]}"
  [ "$rc" -eq 0 ] && exit 0
  if ! grep -qE '^Failure: (internal|unavailable|deadline_exceeded):' "$log"; then
    exit "$rc"
  fi
  if [ "$n" -ge "$attempts" ]; then
    echo "buf generate: transient BSR failure on all $attempts attempts — giving up" >&2
    exit "$rc"
  fi
  echo "buf generate: transient BSR failure (attempt $n/$attempts), retrying in ${backoff}s" >&2
  sleep "$backoff"
  backoff=$((backoff * 2))
done
