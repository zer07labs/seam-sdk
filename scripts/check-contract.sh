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
# Five probe groups, each checked PER LANGUAGE (Python and TypeScript are probed independently — the
# two stub trees are generated together but can go stale separately, e.g. a stale ts/gen beside a fresh
# python/_gen; a symbol present in one language must never vouch for the other):
#
#   1.  RPC probe (HARD GATE, always) — `SeamTrust.VerifyPartyAttestation` (A4). The Phase-2 client wrapper
#       calls it; absent stubs mean the wrapper cannot even import. A missing RPC exits non-zero.
#
#   1b. Authorize-surface probe (HARD GATE, always) — SeamAuthorization / AdmissionTicket / call_sig /
#       on_behalf_of, the Phase-1 client surface.
#
#   1c. Admin-surface probe (HARD GATE, always) — SeamAdmin + RemoveParty / PlaceGrant / RevokeGrant /
#       ListGrants, the party-registry and grant surface. Hard rather than flag-gated for the same reason
#       as 1b: `python/seam_sdk/admin.py` and `ts/src/admin.ts` import and call these, so admin-less stubs
#       break those clients at import — this is not a "not mirrored yet" condition, it is a regression.
#       Without it the gate stayed green through exactly the failure it exists to catch, on the most
#       recently added surface (a BSR label slip or a `buf.gen.yaml` change is enough to cause it).
#       Only Python and TS carry an admin surface; Go/Java/Kotlin are crypto + conformance by design and
#       are not probed here.
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
#   4.  RPC-completeness meta-check (HARD GATE, always) — the probes above name symbols one at a time,
#       and for a long time none of them named a `SeamCoordination` verb. So a verb could land on the
#       contract, regenerate into the stubs, and never be wired into the hand-written clients, with
#       this gate green throughout: THAT is what happened to SubmitApprovalRequest / SubmitBallot.
#       Adding two more named probes would have moved the gap one release down the road, not closed
#       it. Instead the whole verb surface is declared in `contract/rpc-manifest.txt` and compared as
#       a SET, per language, in both directions:
#         * an RPC in the manifest but missing from a language's stubs -> stale/partial generation;
#         * an RPC in the stubs but missing from the manifest -> a NEW verb landed. Refusing here is
#           the point: it forces someone to wire it into the clients (or record why not) before the
#           surface can move. A count comparison would not do this — two verbs renamed in one release
#           keeps the count identical while the surface changes underneath.
#
# Usage:  scripts/check-contract.sh                     # hard gates 1+1b+1c+4; report 2+3
#         STREAM=1 EVENTS=1 scripts/check-contract.sh   # additionally hard-gate 2 and 3 (the CI mode)
#         scripts/check-contract.sh --write-manifest    # rewrite contract/rpc-manifest.txt from the
#                                                       # active stubs (review the diff — it is the
#                                                       # record of a contract surface change)
#
# Exit codes: 0 OK · 1 RPC/Authorize/admin surface stale · 2 streamed-payload fields stale (STREAM=1) ·
#             3 stubs not generated at all · 4 ReportEventsConsumed stale (EVENTS=1) ·
#             5 RPC surface disagrees with contract/rpc-manifest.txt.
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
# The three paths the FIELD gate reads are overridable by environment variable, defaulting to the real
# trees. This exists so `python/tests/test_field_manifest_gate.py` can drive the REAL script against
# TEMPORARY COPIES of the stubs instead of mutating the originals — `python/seam_sdk/_gen` and `ts/gen`
# are gitignored, so a test that corrupted them could not restore them with git, and recovery would
# need a `make generate` (and a BSR login). Nothing in CI sets these.
PY_GEN="${SEAM_PY_GEN:-python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi}"
PY_GRPC="python/seam_sdk/_gen/seam/api/v1/seam_pb2_grpc.py"
PY_EV="python/seam_sdk/_gen/seam/event/v1/seam_event_pb2.pyi"
TS_GEN="${SEAM_TS_GEN:-ts/gen/seam/api/v1/seam_pb.ts}"
TS_EV="ts/gen/seam/event/v1/seam_event_pb.ts"
MANIFEST="${SEAM_RPC_MANIFEST:-contract/rpc-manifest.txt}"
FIELD_MANIFEST="${SEAM_FIELD_MANIFEST:-contract/field-manifest.txt}"

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

# ── RPC surface extraction (Probe 4) ──────────────────────────────────────────────────────────────────
# Each language is read from the artifact that actually declares its RPCs, not from a shared source:
#   * Python — the grpc stub emits the full method path once per RPC: '/seam.api.v1.<Svc>/<Method>'.
#   * TS     — protobuf-es annotates each RPC: `@generated from rpc seam.api.v1.<Svc>.<Method>`.
# The char class is [A-Za-z0-9_]+, not [A-Za-z]+: proto identifiers admit digits and underscores, so a
# verb like `AuthorizeV2` would otherwise extract MANGLED — the gate still fails, but on a truncated
# name the Python extractor cannot see at all and `--write-manifest` can never record, which is a
# permanently red gate rather than an actionable one.
# Reading them independently is what makes a stale ts/gen beside a fresh python/_gen visible; deriving
# one from the other would let either vouch for the other, which is exactly what this script refuses to
# do everywhere else.
rpcs_python() {
  grep -oE "'/seam\.api\.v1\.[A-Za-z0-9_]+/[A-Za-z0-9_]+'" "$PY_GRPC" \
    | tr -d "'" | sed 's|^/seam\.api\.v1\.||' | sort -u
}

rpcs_ts() {
  grep -oE '@generated from rpc seam\.api\.v1\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+' "$TS_GEN" \
    | sed 's|^@generated from rpc seam\.api\.v1\.||' | tr '.' '/' | sort -u
}

# The manifest, minus comments and blank lines.
manifest_rpcs() {
  grep -vE '^\s*(#|$)' "$MANIFEST" | sort -u
}

# ── Field extraction, one level below the RPC surface ────────────────────────────────────────────────
# Same discipline as rpcs_python/rpcs_ts: read each language INDEPENDENTLY so a stale ts/gen beside a
# fresh python/_gen is visible, and never derive one from the other.
#
# Python reads `<NAME>_FIELD_NUMBER: _ClassVar[int]`, lowercased — deliberately NOT `__slots__`.
# `ResumeRequest.raise` and `AdminResumeRequest.raise` are real proto fields, but `raise` is a Python
# keyword, so the .pyi generator cannot emit it in `__slots__` or as an attribute annotation. It DOES
# emit RAISE_FIELD_NUMBER. A __slots__-derived set yields 221 against protobuf-es's 223 and is
# permanently red on two fields no escape hatch can clear.
#
# Nesting is the map-entry filter, NOT the name. Python emits synthetic `AuthorizeRequest.FeaturesEntry`
# / `RunDecisionRequest.FeaturesEntry`; protobuf-es emits no type for either. Top-level classes match at
# column 0 and their own fields at exactly four spaces, so a nested class's fields (eight spaces) are
# skipped structurally. Filtering on the name `*Entry` instead would drop `AuditEntry` — a REAL
# top-level message — from BOTH sides: symmetric, so the gate would stay green while going blind, which
# is precisely the failure this manifest exists to prevent.
fields_python() {
  awk '
    /^class [A-Za-z0-9_]+\(_message\.Message\):/ {
        cls=$2; sub(/\(_message\.Message\):/,"",cls); next
    }
    /^    [A-Z0-9_]+_FIELD_NUMBER: _ClassVar\[int\]/ {
        if (cls == "") next
        f=$1; sub(/_FIELD_NUMBER:$/,"",f); print cls "/" tolower(f)
    }
  ' "$PY_GEN" | LC_ALL=C sort -u
}

# TS reads protobuf-es's `@generated from field: <type...> <name> = <tag>;` under the enclosing
# `Message<"seam.api.v1.X">`. The name is the last token before `=`, which handles qualified and
# generic types (`seam.api.v1.Foo bar = 3;`, `map<string, string> features = 9;`) without a type grammar.
fields_ts() {
  awk '
    # A NESTED type name carries a dot (`seam.api.v1.Outer.Inner`). Match it explicitly and blank
    # `cls`, so its fields are skipped instead of being attributed to the previous top-level message.
    # Without this the TS side does not exclude nesting at all — it MISATTRIBUTES, which is worse.
    /^export type [A-Za-z0-9_]+ = Message<"seam\.api\.v1\.[A-Za-z0-9_]+\.[A-Za-z0-9_.]+">/ {
        cls=""; next
    }
    /^export type [A-Za-z0-9_]+ = Message<"seam\.api\.v1\.[A-Za-z0-9_]+">/ {
        m=$0; sub(/^.*Message<"seam\.api\.v1\./,"",m); sub(/">.*$/,"",m); cls=m; next
    }
    /@generated from field: / {
        if (cls == "") next
        line=$0
        sub(/^.*@generated from field: /,"",line)
        sub(/ *= *[0-9]+;.*$/,"",line)
        n=split(line, parts, " ")
        print cls "/" tolower(parts[n])
    }
  ' "$TS_GEN" | LC_ALL=C sort -u
}

manifest_fields() {
  grep -vE '^\s*(#|$)' "$FIELD_MANIFEST" | LC_ALL=C sort -u
}

if [ "${1:-}" = "--write-manifest" ]; then
  if [ ! -f "$PY_GRPC" ]; then
    err "cannot write the manifest: $PY_GRPC is absent. Run 'make generate' first."
    exit 3
  fi
  tmp="$(mktemp)"
  # Keep the existing header verbatim — it is the rationale, and regenerating must never silently
  # drop it. Only the RPC lines are rewritten.
  grep -E '^\s*(#|$)' "$MANIFEST" > "$tmp" 2>/dev/null || true
  rpcs_python >> "$tmp"
  mv "$tmp" "$MANIFEST"
  echo "wrote $MANIFEST ($(manifest_rpcs | wc -l | tr -d ' ') RPCs) — REVIEW THE DIFF."
  echo "A line added here is a contract surface change: wire the verb into the hand-written clients"
  echo "(python/seam_sdk/client.py + aio.py, ts/src/client.ts) or record why not, before committing."

  # The field manifest is written by the SAME command, from the SAME authoritative side (Python), so
  # there is exactly one escape to document and remember. Writing from Python and cross-checking
  # against TS is deliberate and is the reason the Python extractor must not read `__slots__`: a
  # TS-only field would otherwise produce a failure this escape could never clear, which is exactly
  # what `raise` does under a __slots__-derived extractor.
  if [ ! -f "$PY_GEN" ]; then
    err "cannot write the field manifest: $PY_GEN is absent. Run 'make generate' first."
    exit 3
  fi
  ftmp="$(mktemp)"
  grep -E '^\s*(#|$)' "$FIELD_MANIFEST" > "$ftmp" 2>/dev/null || true
  fields_python >> "$ftmp"
  mv "$ftmp" "$FIELD_MANIFEST"
  echo "wrote $FIELD_MANIFEST ($(manifest_fields | wc -l | tr -d ' ') fields) — REVIEW THE DIFF."
  echo "A line added here is a contract surface change one level below a verb: wire the field into the"
  echo "hand-written clients, or record in the PR why not, before committing."
  exit 0
fi

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

# ── Probe 1c: the admin surface (HARD GATE) ───────────────────────────────────────────────────────────
# SeamAdmin + the party-registry/grant RPCs the hand-written admin clients call
# (python/seam_sdk/admin.py, ts/src/admin.ts). These landed together in #36; probe each so a partial
# generation shows which one is missing rather than just "admin is broken".
admin_rc=0
for spec in \
  "SeamAdmin (service)|SeamAdmin" \
  "SeamAdmin.RemoveParty|RemoveParty|removeParty" \
  "SeamAdmin.PlaceGrant|PlaceGrant|placeGrant" \
  "SeamAdmin.RevokeGrant|RevokeGrant|revokeGrant" \
  "SeamAdmin.ListGrants|ListGrants|listGrants" ; do
  label="${spec%%|*}"; rest="${spec#*|}"
  IFS='|' read -r -a pats <<< "$rest"
  probe_api "$label" "${pats[@]}" || admin_rc=1
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

# ── Probe 4: RPC-completeness against the manifest (HARD GATE) ─────────────────────────────────────────
# See the header. Set comparison, per language, in BOTH directions.
rpc_surface_rc=0
rpc_surface_report=""
if [ ! -f "$MANIFEST" ]; then
  err "$MANIFEST is absent — the RPC surface has no declared expectation to check against."
  err "Create it with: scripts/check-contract.sh --write-manifest"
  rpc_surface_rc=1
else
  _want="$(manifest_rpcs)"
  for lang in python ts; do
    case "$lang" in
      python) _have="$(rpcs_python)" ;;
      ts)     _have="$(rpcs_ts)" ;;
    esac
    _missing="$(comm -23 <(echo "$_want") <(echo "$_have"))"
    _extra="$(comm -13 <(echo "$_want") <(echo "$_have"))"
    if [ -n "$_missing" ]; then
      rpc_surface_rc=1
      rpc_surface_report+="  MISSING from the $lang stubs (stale/partial generation):"$'\n'
      while IFS= read -r r; do [ -n "$r" ] && rpc_surface_report+="    - $r"$'\n'; done <<< "$_missing"
    fi
    if [ -n "$_extra" ]; then
      rpc_surface_rc=1
      rpc_surface_report+="  NOT IN THE MANIFEST, present in the $lang stubs (a new verb landed):"$'\n'
      while IFS= read -r r; do [ -n "$r" ] && rpc_surface_report+="    + $r"$'\n'; done <<< "$_extra"
    fi
    if [ -z "$_missing" ] && [ -z "$_extra" ]; then
      note "PRESENT all $(echo "$_want" | wc -l | tr -d ' ') declared RPCs [$lang]"
    fi
  done
fi

# ── Probe: the FIELD surface against contract/field-manifest.txt (HARD GATE) ─────────────────────────
# One level below the RPC manifest, and for the same reason. The RPC manifest catches a new VERB
# landing unwired; it is blind to a new FIELD on an existing message. That blindness has already cost
# two unwired surfaces (`collective_outcome` regenerated in and sat unread), and it is what let the
# five ACDP D3 slots arrive on ContextBinding with every gate green.
#
# Scoped to seam.api.v1 on purpose: seam.event.v1 fields are covered by the STREAM/EVENTS probes and by
# the vendored-spec gate, and pulling them in here would duplicate a gate that fails for other reasons.
field_surface_rc=0
field_surface_report=""
if [ ! -f "$FIELD_MANIFEST" ]; then
  err "$FIELD_MANIFEST is absent — the field surface has no declared expectation to check against."
  err "Create it with: scripts/check-contract.sh --write-manifest"
  field_surface_rc=1
else
  _fwant="$(manifest_fields)"
  for lang in python ts; do
    case "$lang" in
      python) _fhave="$(fields_python)" ;;
      ts)     _fhave="$(fields_ts)" ;;
    esac
    _fmissing="$(comm -23 <(echo "$_fwant") <(echo "$_fhave"))"
    _fextra="$(comm -13 <(echo "$_fwant") <(echo "$_fhave"))"
    if [ -n "$_fmissing" ]; then
      field_surface_rc=1
      field_surface_report+="  MISSING from the $lang stubs (stale/partial generation, or a REMOVED field):"$'\n'
      while IFS= read -r r; do [ -n "$r" ] && field_surface_report+="    - $r"$'\n'; done <<< "$_fmissing"
    fi
    if [ -n "$_fextra" ]; then
      field_surface_rc=1
      field_surface_report+="  NOT IN THE MANIFEST, present in the $lang stubs (a new field landed):"$'\n'
      while IFS= read -r r; do [ -n "$r" ] && field_surface_report+="    + $r"$'\n'; done <<< "$_fextra"
    fi
    if [ -z "$_fmissing" ] && [ -z "$_fextra" ]; then
      note "PRESENT all $(echo "$_fwant" | wc -l | tr -d ' ') declared fields [$lang]"
    fi
  done
fi

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

if [ "$admin_rc" -ne 0 ]; then
  err "the active contract is STALE for the admin surface: SeamAdmin / RemoveParty / PlaceGrant /"
  err "RevokeGrant / ListGrants are not fully in the stubs. seam_sdk/admin.py and ts/src/admin.ts import"
  err "these, so they cannot even load against this generation. Regenerate from a contract that has them:"
  err "'make generate-local RUNTIME=../seam-runtime' (always fresh), or 'make generate' from the BSR."
  exit 1
fi
echo "OK — admin surface present (party registry + grants unblocked)."

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


if [ "$rpc_surface_rc" -ne 0 ]; then
  echo
  err "the generated RPC surface disagrees with $MANIFEST:"
  printf '%s' "$rpc_surface_report" >&2
  echo "" >&2
  err "A verb MISSING from the stubs is a stale or partial generation — rerun 'make generate' (BSR)"
  err "or 'make generate-local RUNTIME=../seam-runtime'."
  echo "" >&2
  err "A verb NOT IN THE MANIFEST is a new one on the contract, and this refusal is deliberate: it is"
  err "the moment someone decides whether the hand-written clients take it. Wire it into"
  err "python/seam_sdk/client.py AND python/seam_sdk/aio.py AND ts/src/client.ts (or record in the PR"
  err "why not — e.g. a server-to-server verb no client calls), then run:"
  err "    scripts/check-contract.sh --write-manifest"
  err "and commit the manifest diff alongside the client change."
  exit 5
fi
echo "OK — the RPC surface matches $MANIFEST in both languages."

if [ "$field_surface_rc" -ne 0 ]; then
  echo
  err "the generated FIELD surface disagrees with $FIELD_MANIFEST:"
  printf '%s' "$field_surface_report" >&2
  echo "" >&2
  # Print ONLY the explanation for the direction that fired. A refusal whose whole job is to say what
  # happened should not hand the reader both stories and make them work out which one applies.
  if [[ "$field_surface_report" == *"MISSING from the"* ]]; then
  err "A field MISSING from the stubs is either a stale generation — rerun 'make generate' (BSR) or"
  err "'make generate-local RUNTIME=../seam-runtime' — or a field REMOVED from the contract, which is"
  err "a breaking change and must be handled, never silently rewritten away."
  echo "" >&2
  fi
  if [[ "$field_surface_report" == *"NOT IN THE MANIFEST"* ]]; then
  err "A field NOT IN THE MANIFEST is a new one on the contract, and this refusal is deliberate: it is"
  err "the moment someone DECIDES whether this SDK carries it. Decide first — wire it into the"
  err "hand-written clients, or record in the PR why not — and only then run:"
  err "    scripts/check-contract.sh --write-manifest"
  err "and commit the manifest diff alongside that decision. Running the escape first turns a"
  err "deliberate refusal back into the silent pass this gate exists to remove."
  fi
  exit 6
fi
echo "OK — the field surface matches $FIELD_MANIFEST in both languages."
