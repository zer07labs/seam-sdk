#!/usr/bin/env bash
# check-contract — the SDK's contract-freshness gate.
#
# The SDK's transport stubs are generated (git-ignored) from the `seam.api.v1` contract — either the
# published BSR module (`make generate`) or a local runtime checkout (`make generate-local`). Nothing
# guarantees the stubs the hand-written clients compile against actually expose the surface those clients
# call. This is the SDK's equivalent of the runtime's published-surface gate: it asserts the *active*
# generated stubs carry the symbols the SDK depends on, and FAILS LOUD when they don't — so a stale
# contract is caught here, at the SDK, not days later by a consumer.
#
# Two independent probes (the two are decoupled — one can be fresh while the other is stale):
#
#   1. RPC probe (HARD GATE, always) — `SeamTrust.VerifyPartyAttestation` (A4). The Phase-2 client wrapper
#      calls it; absent stubs mean the wrapper cannot even import. A missing RPC exits non-zero.
#
#   2. Streamed-payload probe (reported; hard only under STREAM=1) — the four fields the SDK-facing
#      contract must mirror from the canonical wire so a `StreamEvents` consumer can decode them:
#      `session_lifecycle` (tag 21), `chain_head_attestation` (tag 22), `ciphertext_digest` (tag 10),
#      `AuditEntryEvent.actor` (tag 4). These land on the BSR only after the runtime's Phase-0 mirror is
#      pushed; until then `make generate` (BSR) lacks them while `make generate-local` has them. This probe
#      REPORTS their state by default (Phase 6 is optional/pending the BSR push) and becomes a hard gate
#      when STREAM=1 is set (the Phase-6 CI mode).
#
# Usage:  scripts/check-contract.sh            # RPC hard gate + stream report
#         STREAM=1 scripts/check-contract.sh   # additionally hard-gate the streamed-payload fields
#
# Run it AFTER `make generate` / `make generate-local` — it inspects the emitted stubs, it does not
# generate them.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PY_GEN="python/seam_sdk/_gen/seam/api/v1/seam_pb2.py"
PY_GRPC="python/seam_sdk/_gen/seam/api/v1/seam_pb2_grpc.py"
TS_GEN="ts/gen/seam/api/v1/seam_pb.ts"

err()  { echo "ERROR: $*" >&2; }
note() { echo "  $*"; }

# A stub file must exist before we can probe it — a missing file is "you didn't generate", not "absent
# symbol"; those are different failures and conflating them would hide a forgotten `make generate`.
missing=0
for f in "$PY_GEN" "$PY_GRPC" "$TS_GEN"; do
  if [ ! -f "$f" ]; then
    err "generated stub not found: $f"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  err "the transport stubs are not generated. Run 'make generate' (BSR) or 'make generate-local' first."
  exit 3
fi

# Probe a symbol across the stub files that should carry it; echo PRESENT/ABSENT and return 0/1.
# $1 = human label, then the files to search, then '--' , then one-or-more grep patterns (ANY match ⇒ present).
probe() {
  local label="$1"; shift
  local files=() patterns=()
  local seen_dd=0
  for a in "$@"; do
    if [ "$a" = "--" ]; then seen_dd=1; continue; fi
    if [ "$seen_dd" -eq 0 ]; then files+=("$a"); else patterns+=("$a"); fi
  done
  local found=1
  for p in "${patterns[@]}"; do
    if grep -qE "$p" "${files[@]}" 2>/dev/null; then found=0; break; fi
  done
  if [ "$found" -eq 0 ]; then
    echo "PRESENT $label"
  else
    echo "ABSENT  $label"
  fi
  return "$found"
}

echo "== check-contract: probing the active generated stubs =="

# ── Probe 1: the VerifyPartyAttestation RPC (HARD GATE) ───────────────────────────────────────────────
rpc_status="$(probe "SeamTrust.VerifyPartyAttestation (A4)" "$PY_GRPC" "$PY_GEN" "$TS_GEN" -- "VerifyPartyAttestation" "verifyPartyAttestation")"
rpc_rc=$?
note "$rpc_status"

# ── Probe 2: the streamed-payload mirror fields (reported; hard under STREAM=1) ────────────────────────
# All four must be present together (they land in one Phase-0 push); probe each so a partial mirror shows.
stream_rc=0
for spec in \
  "SeamEvent.session_lifecycle (tag 21)|session_lifecycle|sessionLifecycle" \
  "SeamEvent.chain_head_attestation (tag 22)|chain_head_attestation|chainHeadAttestation" \
  "DecisionSealed.ciphertext_digest (tag 10)|ciphertext_digest|ciphertextDigest" \
  "AuditEntryEvent.actor (tag 4)|\\bactor\\b" ; do
  label="${spec%%|*}"; rest="${spec#*|}"
  # split the remaining |-separated patterns
  IFS='|' read -r -a pats <<< "$rest"
  s="$(probe "$label" "$PY_GEN" "$TS_GEN" -- "${pats[@]}")"
  st=$?
  note "$s"
  [ "$st" -ne 0 ] && stream_rc=1
done

echo
if [ "$rpc_rc" -ne 0 ]; then
  err "the active contract is STALE for Phase 2: VerifyPartyAttestation is not in the stubs."
  err "Regenerate from a contract that has it: 'make generate-local RUNTIME=../seam-runtime' (always fresh),"
  err "or 'make generate' once the BSR carries it."
  exit 1
fi
echo "OK — VerifyPartyAttestation present (Phase 2 unblocked)."

if [ "${STREAM:-0}" = "1" ]; then
  if [ "$stream_rc" -ne 0 ]; then
    err "STREAM=1: the streamed-payload mirror fields are not all present (Phase-0 mirror not in this"
    err "contract). The BSR carries them only after the runtime's Phase-0 push; use 'make generate-local'"
    err "for development until then."
    exit 2
  fi
  echo "OK — all streamed-payload mirror fields present (Phase 6 unblocked)."
else
  if [ "$stream_rc" -ne 0 ]; then
    echo "NOTE — streamed-payload mirror fields not all present. Phase 6 (live event decoding) needs the"
    echo "       runtime Phase-0 BSR push; 'make generate-local' has them today. (Set STREAM=1 to hard-gate.)"
  else
    echo "OK — streamed-payload mirror fields present (Phase 6 also unblocked)."
  fi
fi
