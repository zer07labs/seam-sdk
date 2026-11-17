#!/usr/bin/env bash
# Wait for every `ci-ok` check run on one commit to succeed. Usage: wait_ci_ok.sh <sha> <what>
#
# The same resolution as release-on-runtime's main-is-green gate and publish.yml's ci-green: every
# ci-ok run must be `success`, pending waits, an API failure is not a verdict, and a timeout is a
# refusal. Exit 0 only on green. Needs GH_TOKEN and GITHUB_REPOSITORY. CI_WAIT_ATTEMPTS and
# CI_WAIT_INTERVAL exist so scripts/test_release_refire_gate.py can drive it in milliseconds.
set -euo pipefail
SHA="${1:?usage: wait_ci_ok.sh <sha> <what>}"
WHAT="${2:-$SHA}"
ATTEMPTS="${CI_WAIT_ATTEMPTS:-60}"
INTERVAL="${CI_WAIT_INTERVAL:-30}"
STATE="not registered yet"
for attempt in $(seq 1 "$ATTEMPTS"); do
  if ! CONCLUSIONS="$(gh api --paginate "repos/$GITHUB_REPOSITORY/commits/$SHA/check-runs" \
      --jq '.check_runs[] | select(.name == "ci-ok") | (.conclusion // "pending")')"; then
    CONCLUSIONS=""
    STATE="the check-runs API call failed"
  elif [ -z "$CONCLUSIONS" ]; then
    STATE="not registered yet"
  fi
  if [ -n "$CONCLUSIONS" ]; then
    BAD="$(echo "$CONCLUSIONS" | grep -vx 'success' | grep -vx 'pending' || true)"
    if [ -n "$BAD" ]; then
      echo "::error::$WHAT ($SHA) is not green — at least one ci-ok run is not success:"
      while IFS= read -r c; do echo "::error::  - $c"; done <<< "$BAD"
      exit 1
    fi
    if ! echo "$CONCLUSIONS" | grep -qx 'pending'; then
      echo "$WHAT ($SHA) is green."
      exit 0
    fi
    STATE="still running"
  fi
  if [ "$attempt" -lt "$ATTEMPTS" ]; then
    echo "attempt $attempt/$ATTEMPTS: ci-ok $STATE for $WHAT ($SHA); waiting ${INTERVAL}s"
    sleep "$INTERVAL"
  fi
done
echo "::error::Timed out after $(( ATTEMPTS * INTERVAL ))s waiting for ci-ok on $WHAT ($SHA). Last seen: $STATE."
exit 1
