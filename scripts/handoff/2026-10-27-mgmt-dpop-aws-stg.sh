#!/usr/bin/env bash
# Handoff: prove a console-minted DPoP-bound operator token calls SeamAdmin on aws-stg through the Python SDK
#   (seam-sdk#290, acceptance criterion 2)                     Authored by: Claude   Date: 2026-10-27
# Why a human runs this: it needs two things no session holds — the management console's one-time reveal (a bound
#   operator token + its private JWK, behind a human Auth0 login) and an identity the mesh admits to seam-server's
#   management port 9100 (AuthorizationPolicy callers: control-plane, seam-relay; no session kubectl/AWS access).
# Run:  scripts/handoff/2026-10-27-mgmt-dpop-aws-stg.sh            (dry-run: local checks only, no network call)
#       scripts/handoff/2026-10-27-mgmt-dpop-aws-stg.sh --apply    (calls SeamAdmin/ListTenants, read-only)
#
# Inputs, from the environment ONLY (never argv, never a file in the repo; none is ever printed):
#   SEAM_OPERATOR_TOKEN, SEAM_OPERATOR_DPOP_JWK   the console's one-time reveal (mint with the DPoP toggle on; the token shows BOUND TO KEY (DPoP))
#   SEAM_MGMT_TARGET     e.g. localhost:9100 behind a port-forward to svc/seam-server:9100 (namespace seam by default) from
#                        an identity the mesh admits
#   SEAM_MGMT_CA_FILE    the CA that signed SEAM_MGMT_TLS_CERT_PEM (Doppler seam-server/stg)
#   SEAM_MGMT_TLS_NAME   optional: the certificate name to verify, usually seam-server
#   SEAM_UNBOUND_OPERATOR_TOKEN  optional: an unbound token, to exercise the required posture (no_cnf)
#   SEAM_RUNTIME_IMAGE_TAG       optional: quoted in a failure report
#
# Shape follows seam/scripts/handoff/_template.sh + lib.sh (dry-run unless --apply; every step logged; the verify
# step always runs). lib.sh and preflight.sh are not vendored into this repo, so the helpers are inlined (precedent:
# seam-connectors/scripts/handoff/2026-10-23-objstore-live-buckets.sh). There is no typed confirmation: the run is
# read-only (ListTenants, and two calls that must be refused), so nothing in aws-stg changes. Rollback: none needed.
set -euo pipefail
# Secrets are in the environment: never trace this script (bash -x would print them), and never let gRPC's
# C-core trace the calls (GRPC_TRACE/GRPC_VERBOSITY=debug logs the authorization header to stderr).
set +x
unset GRPC_TRACE
export GRPC_VERBOSITY=NONE

HANDOFF_NAME="2026-10-27-mgmt-dpop-aws-stg"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${SEAM_SMOKE_PYTHON:-$ROOT/python/.venv/bin/python}"
SMOKE="$ROOT/scripts/smoke/mgmt_dpop_aws_stg.py"

APPLY=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    -h|--help) sed -n '2,24p' "$0" >&2; exit 0 ;;
    *) echo "unknown argument (not shown; inputs come from the environment, never argv)" >&2; exit 2 ;;
  esac
done

LOG_DIR="${SEAM_HANDOFF_LOG_DIR:-$HOME/.cache/seam/handoff}"; mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/$HANDOFF_NAME-$(date +%Y%m%dT%H%M%S).log"
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
die() { say "✗ $*"; exit "${2:-1}"; }

say "== $HANDOFF_NAME — bound operator token + DPoP → SeamAdmin/ListTenants on aws-stg"
say "   rollback: none needed (read-only)"
say "   mode: $([ $APPLY = 1 ] && echo APPLY || echo 'DRY-RUN (pass --apply to execute)')"
[ -x "$PY" ] || die "no Python at $PY (create python/.venv, or set SEAM_SMOKE_PYTHON)" 2

# Inputs are named, never shown: the Python side redacts anything that could quote them.
for name in SEAM_OPERATOR_TOKEN SEAM_OPERATOR_DPOP_JWK SEAM_MGMT_TARGET SEAM_MGMT_CA_FILE \
            SEAM_MGMT_TLS_NAME SEAM_UNBOUND_OPERATOR_TOKEN SEAM_RUNTIME_IMAGE_TAG; do
  state="${!name:+set}"; say "   input $name: ${state:-unset}"
done

say "[verify] local preconditions (inputs, CA, seam_sdk, token/JWK pairing) — no network"
rc=0; "$PY" "$SMOKE" 2>&1 | tee -a "$LOG" || rc=${PIPESTATUS[0]}
[ "$rc" = 0 ] || die "preconditions failed (rc=$rc) — see $LOG" "$rc"

if [ $APPLY = 1 ]; then
  say "[1] live checks against \$SEAM_MGMT_TARGET"
  rc=0; "$PY" "$SMOKE" --apply 2>&1 | tee -a "$LOG" || rc=${PIPESTATUS[0]}
  [ "$rc" = 0 ] || die "a live check failed (rc=$rc) — see $LOG" "$rc"
else
  say "[1] live checks against \$SEAM_MGMT_TARGET"
  say "    (dry-run: skipped)"
fi
say "== done. log: $LOG"
