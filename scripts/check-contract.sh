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
# Four probe groups, each checked PER LANGUAGE (Python and TypeScript are probed independently — the
# two stub trees are generated together but can go stale separately, e.g. a stale ts/gen beside a fresh
# python/_gen; a symbol present in one language must never vouch for the other):
#
#   1.  RPC probe (HARD GATE, always) — `SeamTrust.VerifyPartyAttestation` (A4). The Phase-2 client wrapper
#       calls it; absent stubs mean the wrapper cannot even import. A missing RPC exits non-zero.
#
#   1b. Authorize-surface probe (HARD GATE, always) — SeamAuthorization / AdmissionTicket / call_sig /
#       on_behalf_of, the Phase-1 client surface.
#
#   2.  Streamed-payload probe (reported; hard under STREAM=1) — the four fields a `StreamEvents` consumer
#       decodes: `session_lifecycle` (tag 21), `chain_head_attestation` (tag 22), `ciphertext_digest`
#       (tag 10), `AuditEntryEvent.actor` (tag 4). The BSR module now carries all four (the runtime's
#       Phase-0 mirror is published), so CI runs with STREAM=1 as a permanent hard gate; the plain default
#       stays report-only for local trees mid-regeneration.
#
#   3.  ReportEventsConsumed probe (reported; hard under EVENTS=1) — `SeamEvents.ReportEventsConsumed`
#       (R1). Also on the BSR now; CI runs with EVENTS=1 as a permanent hard gate.
#
# Usage:  scripts/check-contract.sh                     # hard gates 1+1b; report 2+3
#         STREAM=1 EVENTS=1 scripts/check-contract.sh   # additionally hard-gate 2 and 3 (the CI mode)
#
# Exit codes: 0 OK · 1 RPC/Authorize surface stale · 2 streamed-payload fields stale (STREAM=1) ·
#             3 stubs not generated at all · 4 ReportEventsConsumed stale (EVENTS=1).
#
# Run it AFTER `make generate` / `make generate-local` — it inspects the emitted stubs, it does not
# generate them.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Python is probed via the .pyi type stubs, not the _pb2.py modules: the _pb2 files carry field names
# only inside the serialized descriptor blob, where escape sequences make a grep unreliable (a name can
# match or not depending on the bytes around it — `session_lifecycle` happened to survive while
# `ciphertext_digest` didn't, which shipped a false ABSENT). The .pyi files declare every field as plain
# source text and ship in the wheel. The _grpc.py file stays for service/RPC probes (RPCs aren't in .pyi
# message stubs).
PY_GEN="python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi"
PY_GRPC="python/seam_sdk/_gen/seam/api/v1/seam_pb2_grpc.py"
PY_EV="python/seam_sdk/_gen/seam/event/v1/seam_event_pb2.pyi"
TS_GEN="ts/gen/seam/api/v1/seam_pb.ts"
TS_EV="ts/gen/seam/event/v1/seam_event_pb.ts"

err()  { echo "ERROR: $*" >&2; }
note() { echo "  $*"; }

# A stub file must exist before we can probe it — a missing file is "you didn't generate", not "absent
# symbol"; those are different failures and conflating them would hide a forgotten `make generate`.
missing=0
for f in "$PY_GEN" "$PY_GRPC" "$PY_EV" "$TS_GEN" "$TS_EV"; do
  if [ ! -f "$f" ]; then
    err "generated stub not found: $f"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  err "the transport stubs are not generated. Run 'make generate' (BSR) or 'make generate-local' first."
  exit 3
fi

# Probe a symbol within ONE language's stub files; echo PRESENT/ABSENT (tagged with the language) and
# return 0/1. $1 = human label, $2 = language tag, then the files to search, then '--', then one-or-more
# grep patterns (ANY match ⇒ present).
probe_lang() {
  local label="$1" lang="$2"; shift 2
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
    echo "PRESENT $label [$lang]"
  else
    echo "ABSENT  $label [$lang]"
  fi
  return "$found"
}

# Probe a seam.api.v1 symbol in the Python AND TypeScript stubs INDEPENDENTLY — one line per language,
# non-zero if EITHER lacks it. Never let one language's freshness vouch for the other's: the stub trees
# regenerate together but a stale ts/gen can sit beside a fresh python/_gen (and vice versa).
# $1 = human label, then the grep patterns.
probe_api() {
  local label="$1"; shift
  local rc=0 s st
  s="$(probe_lang "$label" python "$PY_GEN" "$PY_GRPC" -- "$@")"; st=$?
  note "$s"; [ "$st" -ne 0 ] && rc=1
  s="$(probe_lang "$label" ts "$TS_GEN" -- "$@")"; st=$?
  note "$s"; [ "$st" -ne 0 ] && rc=1
  return "$rc"
}

# Same, for the seam.event.v1 stubs (the event contract split out of api).
probe_event() {
  local label="$1"; shift
  local rc=0 s st
  s="$(probe_lang "$label" python "$PY_EV" -- "$@")"; st=$?
  note "$s"; [ "$st" -ne 0 ] && rc=1
  s="$(probe_lang "$label" ts "$TS_EV" -- "$@")"; st=$?
  note "$s"; [ "$st" -ne 0 ] && rc=1
  return "$rc"
}

echo "== check-contract: probing the active generated stubs =="

# ── Probe 1: the VerifyPartyAttestation RPC (HARD GATE) ───────────────────────────────────────────────
probe_api "SeamTrust.VerifyPartyAttestation (A4)" "VerifyPartyAttestation" "verifyPartyAttestation"
rpc_rc=$?

# ── Probe 1b: the advisory Authorize surface (HARD GATE) ──────────────────────────────────────────────
# The Phase-1 clients construct AuthorizeRequest and dial SeamAuthorization.Authorize + SeamAdmission.
# Admit; every CI job regenerates from the BSR, so without this probe a stale BSR would pass freshness
# while the new client fails to import. All three symbols land in one runtime push — probe each so a
# partial mirror shows.
authz_rc=0
for spec in \
  "SeamAuthorization.Authorize (Phase 1)|SeamAuthorization" \
  "SeamAdmission.Admit → AdmissionTicket|AdmissionTicket" \
  "AuthorizeRequest.call_sig|call_sig|callSig" \
  "RunDecisionRequest.on_behalf_of (Phase 0b)|on_behalf_of|onBehalfOf" ; do
  label="${spec%%|*}"; rest="${spec#*|}"
  IFS='|' read -r -a pats <<< "$rest"
  probe_api "$label" "${pats[@]}" || authz_rc=1
done

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
  probe_event "$label" "${pats[@]}" || stream_rc=1
done

# ── Probe 3: the ReportEventsConsumed RPC (reported; hard under EVENTS=1) ──────────────────────────────
# R1: the seam-event.v1 relay reports its durably-consumed cursor via SeamEvents.ReportEventsConsumed so
# the runtime can bound its outbox. The BSR module now carries it (verified 2026-08 via `buf export`), so
# CI runs with EVENTS=1 as a permanent hard gate; the plain default stays report-only for local trees.
probe_api "SeamEvents.ReportEventsConsumed (R1)" "ReportEventsConsumed" "reportEventsConsumed"
report_consumed_rc=$?

echo
if [ "$rpc_rc" -ne 0 ]; then
  err "the active contract is STALE for Phase 2: VerifyPartyAttestation is not in the stubs."
  err "Regenerate from a contract that has it: 'make generate-local RUNTIME=../seam-runtime' (always fresh),"
  err "or 'make generate' once the BSR carries it."
  exit 1
fi
echo "OK — VerifyPartyAttestation present (Phase 2 unblocked)."

if [ "$authz_rc" -ne 0 ]; then
  err "the active contract is STALE for Phase 1: the Authorize surface (SeamAuthorization / AdmissionTicket /"
  err "call_sig / on_behalf_of) is not fully in the stubs. Regenerate from a contract that has it:"
  err "'make generate-local RUNTIME=../seam-runtime' (always fresh), or 'make generate' once the BSR carries it."
  exit 1
fi
echo "OK — Authorize surface present (Phase 1 unblocked)."

if [ "${STREAM:-0}" = "1" ]; then
  if [ "$stream_rc" -ne 0 ]; then
    err "STREAM=1: the streamed-payload mirror fields are not all present in every language's stubs."
    err "The BSR module carries them, so this is a stale/partial generation — rerun 'make generate'"
    err "(or 'make generate-local RUNTIME=../seam-runtime') and check both python/_gen and ts/gen."
    exit 2
  fi
  echo "OK — all streamed-payload mirror fields present (Phase 6 unblocked)."
else
  if [ "$stream_rc" -ne 0 ]; then
    echo "NOTE — streamed-payload mirror fields not all present in every language's stubs. The BSR carries"
    echo "       them; rerun 'make generate' / 'make generate-local'. (Set STREAM=1 to hard-gate, as CI does.)"
  else
    echo "OK — streamed-payload mirror fields present (Phase 6 also unblocked)."
  fi
fi

if [ "${EVENTS:-0}" = "1" ]; then
  if [ "$report_consumed_rc" -ne 0 ]; then
    err "EVENTS=1: SeamEvents.ReportEventsConsumed is not in every language's stubs. The BSR module"
    err "carries it, so this is a stale/partial generation — rerun 'make generate' (or 'make"
    err "generate-local RUNTIME=../seam-runtime') and check both python/_gen and ts/gen."
    exit 4
  fi
  echo "OK — ReportEventsConsumed present (relay cursor reporting unblocked)."
else
  if [ "$report_consumed_rc" -ne 0 ]; then
    echo "NOTE — SeamEvents.ReportEventsConsumed not present in every language's stubs. The BSR carries"
    echo "       it; rerun 'make generate' / 'make generate-local'. (Set EVENTS=1 to hard-gate, as CI does.)"
  else
    echo "OK — ReportEventsConsumed present (relay cursor reporting unblocked)."
  fi
fi
