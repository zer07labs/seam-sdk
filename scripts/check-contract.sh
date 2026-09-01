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
#             5 RPC surface disagrees with contract/rpc-manifest.txt ·
#             6 field or enum-value surface disagrees with contract/field-manifest.txt ·
#             7 a structural precondition the extractors assume failed: a nested enum was found (see
#               assert_no_nested_enums), a nested message was found outside the known map-entry
#               synthetics (see assert_known_nested_messages_only), or seam.event.v1 grew an enum or a
#               nested message (see assert_event_surface_preconditions). Two contracts share this code
#               on purpose — it names a FAILURE CLASS, not a contract, and the message says which
#               surface fired ·
#             8 the seam.event.v1 field surface disagrees with contract/event-field-manifest.txt.
#               DISTINCT from 6, and it wins when both disagree at once: 6 is the code a local
#               checkout produces every single run (the recorded pre-ACDP api lag) and that CI and
#               CLAUDE.md's Gotchas both say to read past. An event regression exiting 6 would be
#               hidden behind a message telling the reader to ignore it. 8 means "not the known lag".
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
# PY_EV/TS_EV are overridable for the same reason PY_GEN/TS_GEN are, and it is not optional now that
# they are read by a manifest gate rather than only by presence probes: a test that mutated the real
# event tree could not restore it (`python/seam_sdk/_gen` and `ts/gen` are gitignored), and recovery
# would need `make generate` and a BSR login.
PY_EV="${SEAM_PY_EV:-python/seam_sdk/_gen/seam/event/v1/seam_event_pb2.pyi}"
TS_GEN="${SEAM_TS_GEN:-ts/gen/seam/api/v1/seam_pb.ts}"
TS_EV="${SEAM_TS_EV:-ts/gen/seam/event/v1/seam_event_pb.ts}"
MANIFEST="${SEAM_RPC_MANIFEST:-contract/rpc-manifest.txt}"
FIELD_MANIFEST="${SEAM_FIELD_MANIFEST:-contract/field-manifest.txt}"
# A SEPARATE file from FIELD_MANIFEST, not a partition of it — see contract/event-field-manifest.txt's
# own header for the three reasons, the first of which is that `manifest_fields`' filter is NEGATIVE
# ("everything that is not an enum line"), so no delimiter choice can carve out a third partition.
EVENT_FIELD_MANIFEST="${SEAM_EVENT_FIELD_MANIFEST:-contract/event-field-manifest.txt}"
# The recorded pre-ACDP local/BSR field lag — see the file's own header. Overridable for the same
# reason PY_GEN/TS_GEN/FIELD_MANIFEST are: so tests can drive the real script against a SCRATCH copy
# without ever touching (or deleting, via --write-manifest) the committed file.
EXPECTED_LOCAL_LAG="${SEAM_EXPECTED_LOCAL_LAG:-contract/expected-local-lag.txt}"

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

# A seam.event.v1 FIELD probe, message-scoped. `$1` = human label, `$2` = the `Message/field` line the
# extractors must yield, `$3` = the proto tag. Defined here beside `probe_event` but used only by
# probe 2; see that block for why a raw grep of the stub file is not sufficient. The extractors are
# defined further down, which is fine — this is a function body, evaluated when probe 2 calls it.
probe_event_field() {
  local label="$1" want="$2" tag="$3"
  local rc=0 field="${2#*/}"
  if fields_python "$PY_EV" | grep -qxF "$want"; then
    note "PRESENT $label [python]"
  else
    note "ABSENT  $label [python]"; rc=1
  fi
  # BOTH conditions on the TS side: the field is declared on that message, AND it still carries the
  # tag this probe's label advertises. `grep -qxF` for the first (exact line, no regex), `grep -qE`
  # for the second (the tag lives in protobuf-es's generated comment, not in the extracted set).
  if fields_ts "$TS_EV" seam.event.v1 | grep -qxF "$want" \
     && grep -qE "\\b${field} = ${tag};" "$TS_EV"; then
    note "PRESENT $label [ts]"
  else
    note "ABSENT  $label [ts]"; rc=1
  fi
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
#
# PARAMETERISED over the stub file, so `seam.event.v1` is extracted by THIS function rather than by a
# second copy of it. A second pair of extractors would be a second place for the nesting and
# keyword-name bugs recorded above to reappear, and only one of the two copies would get the fix.
# $1 = the .pyi to read. There is deliberately no package argument: the CLASS HEADERS this awk keys on
# are bare names, unqualified by package, so the file IS the package selector here. (Package-qualified
# names do appear elsewhere in a `.pyi` — the cross-package imports at the top, and field types like
# `_seam_event_pb2.ChainHeadAttestation` — but never on a line this extractor reads.) `fields_ts` needs
# a package argument because protobuf-es qualifies every type it declares.
fields_python() {
  awk '
    /^class [A-Za-z0-9_]+\(_message\.Message\):/ {
        cls=$2; sub(/\(_message\.Message\):/,"",cls); next
    }
    /^    [A-Z0-9_]+_FIELD_NUMBER: _ClassVar\[int\]/ {
        if (cls == "") next
        f=$1; sub(/_FIELD_NUMBER:$/,"",f); print cls "/" tolower(f)
    }
  ' "$1" | LC_ALL=C sort -u
}

# TS reads protobuf-es's `@generated from field: <type...> <name> = <tag>;` under the enclosing
# `Message<"seam.api.v1.X">`. The name is the last token before `=`, which handles qualified and
# generic types (`seam.api.v1.Foo bar = 3;`, `map<string, string> features = 9;`) without a type grammar.
# $1 = the .ts to read, $2 = the proto package (`seam.api.v1` or `seam.event.v1`), passed as an awk
# variable rather than interpolated into the program text, so a package name can never be spliced into
# the shell's view of the awk program. It IS still concatenated into a dynamic regex inside awk — which
# is exactly why `pkgre` escapes the dots first; without that, `seam.api.v1` would match `seamXapiYv1`.
# A broken escape fails loudly (an empty extraction reports every field MISSING), never silently.
fields_ts() {
  awk -v pkg="$2" '
    BEGIN { pkgre = pkg; gsub(/\./, "\\.", pkgre) }
    # A NESTED type name carries a dot (`seam.api.v1.Outer.Inner`). Match it explicitly and blank
    # `cls`, so its fields are skipped instead of being attributed to the previous top-level message.
    # Without this the TS side does not exclude nesting at all — it MISATTRIBUTES, which is worse.
    $0 ~ ("^export type [A-Za-z0-9_]+ = Message<\"" pkgre "\\.[A-Za-z0-9_]+\\.[A-Za-z0-9_.]+\">") {
        cls=""; next
    }
    $0 ~ ("^export type [A-Za-z0-9_]+ = Message<\"" pkgre "\\.[A-Za-z0-9_]+\">") {
        m=$0; sub("^.*Message<\"" pkgre "\\.","",m); sub(/">.*$/,"",m); cls=m; next
    }
    /@generated from field: / {
        if (cls == "") next
        line=$0
        sub(/^.*@generated from field: /,"",line)
        sub(/ *= *[0-9]+;.*$/,"",line)
        n=split(line, parts, " ")
        print cls "/" tolower(parts[n])
    }
  ' "$1" | LC_ALL=C sort -u
}

manifest_fields() {
  grep -vE '^\s*(#|$)' "$FIELD_MANIFEST" | grep -v '#' | LC_ALL=C sort -u
}

# The event manifest holds ONLY field lines — `seam.event.v1` has no enums (asserted below, not
# assumed), so there is no partition to separate and the second `grep -v '#'` that manifest_fields
# needs is deliberately absent here. Stripping comments and blanks is the whole rule.
manifest_event_fields() {
  grep -vE '^\s*(#|$)' "$EVENT_FIELD_MANIFEST" | LC_ALL=C sort -u
}

# ── The recorded local/BSR field lag ────────────────────────────────────────────────────────────────
# See $EXPECTED_LOCAL_LAG's own header for why this exists. Reading it is the same discipline as
# manifest_fields: comments and blanks stripped, sorted, deduplicated — so an EXACT string comparison
# against a MISSING set (also sorted via comm) is a correct test of "these two sets are equal", not an
# approximation of one.
expected_local_lag_fields() {
  [ -f "$EXPECTED_LOCAL_LAG" ] || return 1
  grep -vE '^\s*(#|$)' "$EXPECTED_LOCAL_LAG" | LC_ALL=C sort -u
}

expected_local_lag_date() {
  grep -oE '^# EXPECTED-FROM: [0-9]{4}-[0-9]{2}-[0-9]{2}' "$EXPECTED_LOCAL_LAG" 2>/dev/null \
    | awk '{print $3}'
}

# Age in whole days since EXPECTED-FROM, printed on every match so the file cannot quietly become
# permanent scenery. `date` parsing differs between GNU (Linux CI) and BSD (macOS dev) — try both
# rather than assume one.
expected_local_lag_age_days() {
  local d="$1" now_epoch d_epoch
  [ -z "$d" ] && { echo "unknown age"; return; }
  now_epoch="$(date -u +%s)"
  if d_epoch="$(date -u -d "$d" +%s 2>/dev/null)"; then
    :
  elif d_epoch="$(date -u -j -f '%Y-%m-%d' "$d" +%s 2>/dev/null)"; then
    :
  else
    echo "unknown age"
    return
  fi
  echo "$(( (now_epoch - d_epoch) / 86400 )) day(s)"
}

# ── Nested-message guard ────────────────────────────────────────────────────────────────────────────
# fields_python/fields_ts exclude a nested message BY NESTING (see their own header above), which is
# correct for the two known map-entry synthetics — but that exclusion is SYMMETRIC across both
# languages, so a genuine nested message (not a map entry) is invisible to BOTH extractors at once:
# exactly the "the gate stays green while going blind" failure the manifest header warns about,
# reproduced here by the fix for the *other* case of it. Proven by mutation: adding
# `EscrowDirective.Hold{amount_cents, release_after_ms}` to both scratch stub trees left the gate
# reporting only the top-level sibling field (`EscrowDirective/amount_cents`) and exiting 0 — `Hold`'s
# two fields never reached either extractor, so nothing could ever disagree about them.
#
# The contract has ZERO real nested messages today, so this is a tripwire, not a speculative
# extractor: assert the only nested message types are the known map-entry synthetics, with an EXACT
# allowlist (not a floor) — removing a known synthetic must trip this exactly as loudly as an unknown
# one appearing, or the allowlist could decay silently in either direction.
#
# Python reads the same column-0-header-tracks-owner discipline as fields_python, printing
# `<Owner>.<Nested>` for every INDENTED `class ...(_message.Message):` under a top-level message. TS
# reads `Message<"seam.api.v1.<Owner>.<Nested...>">` — the same dotted-name shape fields_ts already
# matches to SKIP a nested type, extracted here instead of discarded. Both read only $PY_GEN/$TS_GEN
# (seam.api.v1) — never seam.event.v1, which is out of this gate's scope.
nested_messages_python() {
  awk '
    /^class [A-Za-z0-9_]+\(_message\.Message\):/ {
        cls=$2; sub(/\(_message\.Message\):/,"",cls); next
    }
    /^class / { cls=""; next }
    /^[[:space:]]+class [A-Za-z0-9_]+\(_message\.Message\):/ {
        if (cls == "") next
        n=$0; sub(/^[[:space:]]+class /,"",n); sub(/\(_message\.Message\):.*$/,"",n)
        print cls "." n
    }
  ' "$PY_GEN" | LC_ALL=C sort -u
}

nested_messages_ts() {
  grep -oE 'Message<"seam\.api\.v1\.[A-Za-z0-9_]+\.[A-Za-z0-9_.]+">' "$TS_GEN" \
    | sed -E 's/^Message<"seam\.api\.v1\.//; s/">$//' | LC_ALL=C sort -u
}

# The two known map-entry synthetics — see fields_python's own comment above for why they exist and why
# they are excluded by nesting rather than by an `*Entry` name filter. protobuf-es emits NO type for
# either, so the TS allowlist is empty: today, ANY nested `Message<...>` at all in TS means a real
# nested message landed.
_KNOWN_NESTED_MESSAGES_PY="AuthorizeRequest.FeaturesEntry
RunDecisionRequest.FeaturesEntry"
_KNOWN_NESTED_MESSAGES_TS=""

assert_known_nested_messages_only() {
  local py_have py_want py_extra py_missing ts_have ts_want ts_extra
  py_have="$(nested_messages_python)"
  py_want="$(printf '%s\n' "$_KNOWN_NESTED_MESSAGES_PY" | LC_ALL=C sort -u)"
  ts_have="$(nested_messages_ts)"
  ts_want="$_KNOWN_NESTED_MESSAGES_TS"
  py_extra="$(comm -23 <(echo "$py_have") <(echo "$py_want"))"
  py_missing="$(comm -13 <(echo "$py_have") <(echo "$py_want"))"
  ts_extra="$(comm -23 <(echo "$ts_have") <(echo "$ts_want"))"
  if [ -n "$py_extra" ] || [ -n "$py_missing" ] || [ -n "$ts_extra" ]; then
    err "the nested-message allowlist disagrees with the stubs — fields_python/fields_ts silently drop"
    err "ANY nested message's fields (see their own comment above), so this must be exact, not a floor:"
    if [ -n "$py_extra" ]; then
      err "  python ($PY_GEN) has an UNKNOWN nested message not in the allowlist:"
      while IFS= read -r r; do [ -n "$r" ] && err "    + $r"; done <<< "$py_extra"
    fi
    if [ -n "$py_missing" ]; then
      err "  python ($PY_GEN) is MISSING a known synthetic the allowlist still expects:"
      while IFS= read -r r; do [ -n "$r" ] && err "    - $r"; done <<< "$py_missing"
    fi
    if [ -n "$ts_extra" ]; then
      err "  ts ($TS_GEN) has a nested message the allowlist does not expect (should be empty today):"
      while IFS= read -r r; do [ -n "$r" ] && err "    + $r"; done <<< "$ts_extra"
    fi
    err "if this is a genuine new nested message, extend fields_python/fields_ts to extract its fields"
    err "(with a concrete example in hand, not a guess) before adding it to the allowlist deliberately."
    exit 7
  fi
}

# ── Enum-value extraction, one level below FIELD, same discipline ─────────────────────────────────────
# Same design as fields_python/fields_ts: read each language's stubs INDEPENDENTLY, never derive one
# from the other, spelling `<Enum>#<VALUE>` (see contract/field-manifest.txt's own header for why `#`
# and why it shares that file rather than a second one).
#
# Python reads the `<VALUE>: _ClassVar[<Enum>]` lines under each
# `class <Enum>(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):`. Tracking "current enum" the same
# column-0-header way fields_python tracks "current message" — and with the same blind spot: an enum
# NESTED inside a message would vanish silently. assert_no_nested_enums (below) turns that into a loud
# failure instead of a trusted assumption.
enums_python() {
  awk '
    /^class [A-Za-z0-9_]+\(int, metaclass=_enum_type_wrapper\.EnumTypeWrapper\):/ {
        cls=$2; sub(/\(int,$/,"",cls); next
    }
    /^class / { cls=""; next }
    /^    [A-Z0-9_]+: _ClassVar\[[A-Za-z0-9_]+\]/ {
        if (cls == "") next
        v=$1; sub(/:$/,"",v); print cls "#" v
    }
  ' "$PY_GEN" | LC_ALL=C sort -u
}

# TS reads protobuf-es's `@generated from enum value: <VALUE> = <n>;` doc comment, under the enclosing
# `@generated from enum seam.api.v1.<Enum>` doc comment — the GENERATOR'S OWN record of the value name,
# not the TS identifier: protobuf-es strips `AuthorizeVerdict`'s common prefix from its bare TS members
# (`ALLOW`, not `AUTHORIZE_VERDICT_ALLOW`), so the identifier alone cannot be compared against Python's
# unstripped `_ClassVar` names, and TS syntax could be reformatted without the contract changing under it.
enums_ts() {
  awk '
    /@generated from enum seam\.api\.v1\.[A-Za-z0-9_]+$/ {
        m=$0; sub(/^.*@generated from enum seam\.api\.v1\./,"",m); cls=m; next
    }
    /@generated from enum value: / {
        if (cls == "") next
        line=$0
        sub(/^.*@generated from enum value: /,"",line)
        sub(/ *= *[0-9]+;.*$/,"",line)
        print cls "#" line
    }
  ' "$TS_GEN" | LC_ALL=C sort -u
}

manifest_enums() {
  grep -vE '^\s*(#|$)' "$FIELD_MANIFEST" | grep '#' | LC_ALL=C sort -u
}

# ── Nested-enum guard ───────────────────────────────────────────────────────────────────────────────
# No enum is nested inside a message today — only nested TYPES are the two FeaturesEntry map
# synthetics, and those are messages, not enums. enums_python/enums_ts above assume that structurally
# (column-0 class headers in Python, un-dotted `seam.api.v1.<Enum>` doc-comment anchors in TS) exactly
# the way fields_python/fields_ts assume no real message is itself nested — and would fail the same
# way: a nested enum would disappear from BOTH languages at once, symmetrically, so the gate would stay
# green while going blind to it. Assert the assumption instead of trusting it forever.
assert_no_nested_enums() {
  local py_bad ts_bad
  py_bad="$(grep -nE '^[[:space:]]+class [A-Za-z0-9_]+\(int, metaclass=_enum_type_wrapper\.EnumTypeWrapper\):' "$PY_GEN" 2>/dev/null || true)"
  ts_bad="$(grep -nE '@generated from enum seam\.api\.v1\.[A-Za-z0-9_]+\.[A-Za-z0-9_.]+' "$TS_GEN" 2>/dev/null || true)"
  if [ -n "$py_bad" ] || [ -n "$ts_bad" ]; then
    err "a NESTED enum was found — enums_python/enums_ts assume none exist and would silently drop it"
    err "from BOTH languages at once instead of comparing it:"
    if [ -n "$py_bad" ]; then
      err "  python ($PY_GEN):"
      echo "$py_bad" >&2
    fi
    if [ -n "$ts_bad" ]; then
      err "  ts ($TS_GEN):"
      echo "$ts_bad" >&2
    fi
    err "extend enums_python/enums_ts in scripts/check-contract.sh to track nesting before proceeding."
    exit 7
  fi
}

# ── The event surface's structural preconditions ─────────────────────────────────────────────────────
# `seam.event.v1` has ZERO enums and ZERO nested messages today, in both languages. The event field
# gate below reuses fields_python/fields_ts, which skip a nested message's fields structurally, and it
# has NO enum partition at all — so both facts are load-bearing, and both would fail SILENTLY and
# SYMMETRICALLY if they stopped holding: a nested message's fields vanish from Python and TS at once,
# and an enum value has nothing on either side to be compared against.
#
# The alternative — an empty event-enum partition compared in both directions — is worse, and is the
# specific defect plans/gate-blindness-hardening.md exists about: an empty set compared against an
# empty set passes for the wrong reason, and keeps passing after the contract grows an enum. Assert
# the preconditions instead, and refuse the moment either stops holding.
#
# Exit 7, shared with the api-side asserts above, is deliberate and is NOT inconsistent with exit 8
# being distinct from exit 6. Exit 7 names a FAILURE CLASS — "a structural precondition the extractors
# assume failed" — which is the same class for either contract, and the message says which surface it
# fired on. Exit 6 and 8 name a CONTRACT ("this manifest disagrees"), and two contracts sharing one of
# those would make a real event drift indistinguishable from the recorded api lag that CI is told to
# read past.
assert_event_surface_preconditions() {
  local py_enum py_nested ts_enum ts_nested
  # Python: ANY enum at ANY indentation (the api side only guards NESTED enums; here even a top-level
  # one is a precondition failure, because there is no event enum extractor to route it to).
  py_enum="$(grep -nE '^[[:space:]]*class [A-Za-z0-9_]+\(int, metaclass=_enum_type_wrapper\.EnumTypeWrapper\):' "$PY_EV" 2>/dev/null || true)"
  py_nested="$(grep -nE '^[[:space:]]+class [A-Za-z0-9_]+\(_message\.Message\):' "$PY_EV" 2>/dev/null || true)"
  ts_enum="$(grep -nE '@generated from enum seam\.event\.v1\.' "$TS_EV" 2>/dev/null || true)"
  ts_nested="$(grep -nE '^export type [A-Za-z0-9_]+ = Message<"seam\.event\.v1\.[A-Za-z0-9_]+\.[A-Za-z0-9_.]+">' "$TS_EV" 2>/dev/null || true)"
  if [ -n "$py_enum" ] || [ -n "$py_nested" ] || [ -n "$ts_enum" ] || [ -n "$ts_nested" ]; then
    err "a structural precondition of the EVENT field gate failed: seam.event.v1 is asserted to have"
    err "ZERO enums and ZERO nested messages, and the stubs now have at least one."
    if [ -n "$py_enum" ];    then err "  an ENUM in python ($PY_EV):";           echo "$py_enum" >&2;    fi
    if [ -n "$py_nested" ];  then err "  a NESTED MESSAGE in python ($PY_EV):";  echo "$py_nested" >&2;  fi
    if [ -n "$ts_enum" ];    then err "  an ENUM in ts ($TS_EV):";               echo "$ts_enum" >&2;    fi
    if [ -n "$ts_nested" ];  then err "  a NESTED MESSAGE in ts ($TS_EV):";      echo "$ts_nested" >&2;  fi
    err "This is not something to work around. A nested message's fields are dropped by"
    err "fields_python/fields_ts from BOTH languages symmetrically, so the event gate would go green"
    err "while going blind to them; an enum has no event-side extractor at all. Extend the extractors"
    err "deliberately — with the concrete new shape in hand — and add an enum partition to"
    err "$EVENT_FIELD_MANIFEST before removing this refusal."
    exit 7
  fi
}

if [ "${1:-}" = "--write-manifest" ]; then
  if [ ! -f "$PY_GRPC" ]; then
    err "cannot write the manifest: $PY_GRPC is absent. Run 'make generate' first."
    exit 3
  fi
  # The field manifest is written by the SAME command, from the SAME authoritative side (Python), so
  # there is exactly one escape to document and remember. Writing from Python and cross-checking
  # against TS is deliberate and is the reason the Python extractor must not read `__slots__`: a
  # TS-only field would otherwise produce a failure this escape could never clear, which is exactly
  # what `raise` does under a __slots__-derived extractor.
  if [ ! -f "$PY_GEN" ]; then
    err "cannot write the field manifest: $PY_GEN is absent. Run 'make generate' first."
    exit 3
  fi
  # Both asserts run BEFORE either manifest is written, not just before the field one. They used to
  # sit between the RPC-manifest write and the field-manifest write, so a nested-message/nested-enum
  # exit 7 left a HALF-APPLIED write: contract/rpc-manifest.txt already rewritten, field-manifest.txt
  # not, with no way to tell from the tree alone that the run aborted partway through. Moved to the
  # top of this branch, an exit 7 here means neither manifest has been touched yet.
  assert_known_nested_messages_only
  assert_no_nested_enums
  assert_event_surface_preconditions

  tmp="$(mktemp)"
  # Keep the existing header verbatim — it is the rationale, and regenerating must never silently
  # drop it. Only the RPC lines are rewritten.
  grep -E '^\s*(#|$)' "$MANIFEST" > "$tmp" 2>/dev/null || true
  rpcs_python >> "$tmp"
  mv "$tmp" "$MANIFEST"
  echo "wrote $MANIFEST ($(manifest_rpcs | wc -l | tr -d ' ') RPCs) — REVIEW THE DIFF."
  echo "A line added here is a contract surface change: wire the verb into the hand-written clients"
  echo "(python/seam_sdk/client.py + aio.py, ts/src/client.ts) or record why not, before committing."

  ftmp="$(mktemp)"
  grep -E '^\s*(#|$)' "$FIELD_MANIFEST" > "$ftmp" 2>/dev/null || true
  fields_python "$PY_GEN" >> "$ftmp"
  enums_python >> "$ftmp"
  mv "$ftmp" "$FIELD_MANIFEST"
  echo "wrote $FIELD_MANIFEST ($(manifest_fields | wc -l | tr -d ' ') fields, $(manifest_enums | wc -l | tr -d ' ') enum values) — REVIEW THE DIFF."
  echo "A line added here is a contract surface change one level below a verb: wire the field or enum"
  echo "value into the hand-written clients, or record in the PR why not, before committing."

  # The event manifest is written by the SAME command and from the SAME authoritative side (Python) as
  # the other two — one escape to document, one authoritative side, for the same reason stated above.
  # It is a separate FILE but not a separate escape hatch: a second command would be a second thing to
  # forget.
  etmp="$(mktemp)"
  grep -E '^\s*(#|$)' "$EVENT_FIELD_MANIFEST" > "$etmp" 2>/dev/null || true
  fields_python "$PY_EV" >> "$etmp"
  mv "$etmp" "$EVENT_FIELD_MANIFEST"
  echo "wrote $EVENT_FIELD_MANIFEST ($(manifest_event_fields | wc -l | tr -d ' ') fields) — REVIEW THE DIFF."
  echo "seam.event.v1 is the outbox contract seam-connectors and the verifier consume: a line added"
  echo "here reaches every consumer through this SDK, so decide what carries it before committing."

  # The manifest just written is a NEW forward set — a recorded "expected to be missing exactly these
  # fields locally" from before this write may no longer even parse against it. Delete rather than
  # leave a stale recording that could downgrade a REAL new gap into a NOTE by coincidence.
  #
  # Scoped to the API write, deliberately: $EXPECTED_LOCAL_LAG records an *api* gap and nothing else.
  # The event surface has no recorded lag (90/90/90, both languages agreeing with the manifest), and
  # if it ever acquires one the answer is a second file scoped to it — never this one widened, since
  # the two contracts have different owners and different publish cadences. Rewriting the event
  # manifest must therefore not destroy the api recording as a side effect.
  if [ -f "$EXPECTED_LOCAL_LAG" ]; then
    rm -f "$EXPECTED_LOCAL_LAG"
    echo "removed $EXPECTED_LOCAL_LAG — the recorded local/BSR lag no longer matches the manifest just"
    echo "written. Re-record it deliberately (see the file's own header) if a real gap is still expected."
  fi
  exit 0
fi

# The probing path below (unlike --write-manifest, which checks this itself just before it writes)
# needs the same guarantee before it trusts what fields_python/fields_ts/enums_python/enums_ts return.
assert_known_nested_messages_only
assert_no_nested_enums
assert_event_surface_preconditions

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
#
# Each probe is MESSAGE-SCOPED, and that is the property a raw grep of the stub file cannot have.
# Two measured failures got it here:
#
#   1. A grep for the bare name is satisfied by a COMMENT about the field. `actor`'s pattern was
#      `\bactor\b`, and `ts/gen`'s generated comment carries "Mirrors `AuditEntryPb.actor` (tag 4)."
#      verbatim from the proto — renaming the TS declaration to `principal` still reported PRESENT.
#   2. Anchoring to the declaration fixed that and left a bigger hole open: a file-wide grep does not
#      know which MESSAGE declares the field. Moving `actor` from `AuditEntryEvent` to
#      `ChainHeadAttestation` in both trees and re-recording the manifest left the whole gate green
#      at exit 0, with `PRESENT AuditEntryEvent.actor (tag 4)` printed against an `AuditEntryEvent`
#      that no longer declares it. The label named a message; nothing checked the message.
#
# So the presence half is decided by `fields_python`/`fields_ts` — the same class-scoped extractors the
# manifest gate uses — asked for an exact `Message/field` line. Reusing them rather than writing a
# third parser is the same argument the extractors' own header makes for being parameterised.
#
# The TAG is checked on the TS side only, and that asymmetry is real rather than an oversight: a
# `.pyi` records no tag values anywhere, so Python is structurally tag-blind, and the manifest gate is
# tag-blind too (it compares `Message/field`). protobuf-es's `@generated from field:` comment is the
# only place either tree states a tag, which makes this the gate's ONLY tag check — on four fields, the
# four a `StreamEvents` consumer decodes, where a silently renumbered tag is the failure that matters.
# The leading `\b` is not decoration: without it `actor = 4;` matches inside `renamedactor = 4;`.
stream_rc=0
for spec in \
  "SeamEvent.session_lifecycle (tag 21)|SeamEvent/session_lifecycle|21" \
  "SeamEvent.chain_head_attestation (tag 22)|SeamEvent/chain_head_attestation|22" \
  "DecisionSealed.ciphertext_digest (tag 10)|DecisionSealed/ciphertext_digest|10" \
  "AuditEntryEvent.actor (tag 4)|AuditEntryEvent/actor|4" ; do
  label="${spec%%|*}"; rest="${spec#*|}"
  want="${rest%%|*}"; tag="${rest#*|}"
  probe_event_field "$label" "$want" "$tag" || stream_rc=1
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
# Scoped to seam.api.v1 — and seam.event.v1 is now manifested too, in its own file, by the event probe
# further down. This paragraph used to record that gap as an open one ("seam.event.v1 has NO
# field-surface manifest ... closing it needs its own manifest"); issue #88 asked for exactly that and
# it is `contract/event-field-manifest.txt`, compared per language in both directions and exiting 8.
#
# The four STREAM/EVENTS presence probes above are NOT made redundant by it and must not be deleted as
# duplication. They differ in two ways that matter: they fire even when the event manifest is absent or
# has just been rewritten by --write-manifest (the manifest gate reports "absent" there, the probes
# still assert), and they name the four fields a consumer actually decodes
# (session_lifecycle, chain_head_attestation, ciphertext_digest, AuditEntryEvent.actor) rather than the
# surface as a whole — a narrower, load-bearing assertion about what the SDK reads, not about what the
# contract contains.
#
# `scripts/check_vendored_spec.py` (the "vendored-spec gate") remains a third, different thing: it only
# catches drift in `verify/docs/seam-event.v1.md` when the RUNTIME also edits that markdown spec doc, so
# a field added to the .proto with no matching spec-doc edit is still invisible to it. The event
# manifest is what catches that one.
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
      python) _fhave="$(fields_python "$PY_GEN")" ;;
      ts)     _fhave="$(fields_ts "$TS_GEN" seam.api.v1)" ;;
    esac
    _fmissing="$(comm -23 <(echo "$_fwant") <(echo "$_fhave"))"
    _fextra="$(comm -13 <(echo "$_fwant") <(echo "$_fhave"))"
    # Kept per-language, past the loop, so the local/BSR expected-lag check below can compare each
    # language's MISSING set against the recorded file individually — the exact-match rule requires
    # BOTH languages to match it, not just the union of the two.
    case "$lang" in
      python) _fmissing_python="$_fmissing"; _fextra_python="$_fextra" ;;
      ts)     _fmissing_ts="$_fmissing"; _fextra_ts="$_fextra" ;;
    esac
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

# ── Probe: the ENUM-VALUE surface against contract/field-manifest.txt (HARD GATE) ────────────────────
# One level below the FIELD probe, for the same reason it exists one level below the RPC manifest:
# `buf breaking` upstream treats an additive enum value as compatible and passes it BY DESIGN, and this
# SDK does not get that leniency for free — `python/seam_sdk/_collective.py` and `errors.py` are
# deliberately fail-closed and raise `UnknownCollectiveVerdictError` on any value they do not recognise.
# Same spelling, same file (see its header), same two-directional-per-language shape as the FIELD probe
# above — PLUS a third check the field probe does not need: Python and TS are compared with EACH OTHER
# directly, not only against the manifest, because a value one language's stubs carry and the other's
# do not is a GENERATION skew (one tree regenerated stale), never a manifest decision, and must never
# be reported as if it were one.
enum_surface_rc=0
enum_surface_report=""
if [ ! -f "$FIELD_MANIFEST" ]; then
  err "$FIELD_MANIFEST is absent — the enum-value surface has no declared expectation to check against."
  err "Create it with: scripts/check-contract.sh --write-manifest"
  enum_surface_rc=1
else
  _ewant="$(manifest_enums)"
  _epy="$(enums_python)"
  _ets="$(enums_ts)"
  for lang in python ts; do
    case "$lang" in
      python) _ehave="$_epy" ;;
      ts)     _ehave="$_ets" ;;
    esac
    _emissing="$(comm -23 <(echo "$_ewant") <(echo "$_ehave"))"
    _eextra="$(comm -13 <(echo "$_ewant") <(echo "$_ehave"))"
    if [ -n "$_emissing" ]; then
      enum_surface_rc=1
      enum_surface_report+="  MISSING from the $lang stubs (stale/partial generation, or a REMOVED enum value):"$'\n'
      while IFS= read -r r; do [ -n "$r" ] && enum_surface_report+="    - $r"$'\n'; done <<< "$_emissing"
    fi
    if [ -n "$_eextra" ]; then
      enum_surface_rc=1
      enum_surface_report+="  NOT IN THE MANIFEST, present in the $lang stubs (a new enum value landed):"$'\n'
      while IFS= read -r r; do [ -n "$r" ] && enum_surface_report+="    + $r"$'\n'; done <<< "$_eextra"
    fi
    if [ -z "$_emissing" ] && [ -z "$_eextra" ]; then
      note "PRESENT all $(echo "$_ewant" | wc -l | tr -d ' ') declared enum values [$lang]"
    fi
  done
  _eskew_py="$(comm -23 <(echo "$_epy") <(echo "$_ets"))"
  _eskew_ts="$(comm -13 <(echo "$_epy") <(echo "$_ets"))"
  if [ -n "$_eskew_py" ] || [ -n "$_eskew_ts" ]; then
    enum_surface_rc=1
    enum_surface_report+="  GENERATION SKEW — the python and ts stubs disagree with EACH OTHER, not just the manifest:"$'\n'
    while IFS= read -r r; do [ -n "$r" ] && enum_surface_report+="    python has it, ts does not: $r"$'\n'; done <<< "$_eskew_py"
    while IFS= read -r r; do [ -n "$r" ] && enum_surface_report+="    ts has it, python does not: $r"$'\n'; done <<< "$_eskew_ts"
  fi
fi

# ── Probe: the seam.event.v1 FIELD surface against contract/event-field-manifest.txt (HARD GATE) ─────
# The third member of the same set as the FIELD and ENUM-VALUE probes above, and computed here for
# exactly the reason they are: in ONE pass, with the report held, so the decision at the bottom sees
# all three. Placement is the whole design and is not stylistic.
#
#   * After the field/enum exit — the event probe would never run on a local checkout at all. Every
#     local tree disagrees on the api field surface (the recorded ACDP lag), so `exit 6` always fires;
#     `make check-contract` would gate nothing on seam.event.v1, forever, while looking identical to a
#     run that did.
#   * Before them, exiting 8 on the spot — an event disagreement preempts the api report, and a run
#     with both problems shows one.
#   * Here, reported alongside them and decided once at the end — which is what :784-787 already
#     argues for the enum probe: "a script that exited on the field report first would never show the
#     enum one".
#
# Same shape as the two above: set comparison, per language, in BOTH directions, plus the direct
# python-vs-ts comparison the enum probe uses, since a field one tree carries and the other does not
# is a generation skew rather than a manifest decision and must not be reported as one.
event_field_surface_rc=0
event_field_surface_report=""
if [ ! -f "$EVENT_FIELD_MANIFEST" ]; then
  err "$EVENT_FIELD_MANIFEST is absent — the seam.event.v1 field surface has no declared expectation."
  err "Create it with: scripts/check-contract.sh --write-manifest"
  event_field_surface_rc=1
else
  _evwant="$(manifest_event_fields)"
  _evpy="$(fields_python "$PY_EV")"
  _evts="$(fields_ts "$TS_EV" seam.event.v1)"
  for lang in python ts; do
    case "$lang" in
      python) _evhave="$_evpy" ;;
      ts)     _evhave="$_evts" ;;
    esac
    _evmissing="$(comm -23 <(echo "$_evwant") <(echo "$_evhave"))"
    _evextra="$(comm -13 <(echo "$_evwant") <(echo "$_evhave"))"
    if [ -n "$_evmissing" ]; then
      event_field_surface_rc=1
      event_field_surface_report+="  MISSING from the $lang event stubs (stale/partial generation, or a REMOVED field):"$'\n'
      while IFS= read -r r; do [ -n "$r" ] && event_field_surface_report+="    - $r"$'\n'; done <<< "$_evmissing"
    fi
    if [ -n "$_evextra" ]; then
      event_field_surface_rc=1
      event_field_surface_report+="  NOT IN THE MANIFEST, present in the $lang event stubs (a new field landed):"$'\n'
      while IFS= read -r r; do [ -n "$r" ] && event_field_surface_report+="    + $r"$'\n'; done <<< "$_evextra"
    fi
    if [ -z "$_evmissing" ] && [ -z "$_evextra" ]; then
      note "PRESENT all $(echo "$_evwant" | wc -l | tr -d ' ') declared seam.event.v1 fields [$lang]"
    fi
  done
  _evskew_py="$(comm -23 <(echo "$_evpy") <(echo "$_evts"))"
  _evskew_ts="$(comm -13 <(echo "$_evpy") <(echo "$_evts"))"
  if [ -n "$_evskew_py" ] || [ -n "$_evskew_ts" ]; then
    event_field_surface_rc=1
    event_field_surface_report+="  GENERATION SKEW — the python and ts event stubs disagree with EACH OTHER, not just the manifest:"$'\n'
    while IFS= read -r r; do [ -n "$r" ] && event_field_surface_report+="    python has it, ts does not: $r"$'\n'; done <<< "$_evskew_py"
    while IFS= read -r r; do [ -n "$r" ] && event_field_surface_report+="    ts has it, python does not: $r"$'\n'; done <<< "$_evskew_ts"
  fi
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

# ── Is this FIELD disagreement exactly the recorded local/BSR lag? ────────────────────────────────
# See $EXPECTED_LOCAL_LAG's own header. A local checkout regenerates stubs from the BSR, which is
# EXPECTED to lag the committed manifest by a known, recorded set of fields until it republishes them
# — CI always regenerates fresh and remains the sole authority on the contract itself, so this NEVER
# changes the exit code below, only whether the reader has to parse the full refusal or a short,
# unmistakable NOTE. Requires an EXACT match: both languages' MISSING sets equal to the file, AND
# nothing else disagreeing (no NOT-IN-THE-MANIFEST/"extra" entries, no enum failure at all) — a
# superset, subset, or any other kind of disagreement alongside it is real drift and stays undowngraded.
lag_match=0
_lag_declared=""
if [ "$field_surface_rc" -ne 0 ] && [ "$enum_surface_rc" -eq 0 ] \
   && [ -z "${_fextra_python:-}" ] && [ -z "${_fextra_ts:-}" ] \
   && [ -f "$EXPECTED_LOCAL_LAG" ]; then
  _lag_declared="$(expected_local_lag_fields)"
  if [ -n "$_lag_declared" ] \
     && [ "${_fmissing_python:-}" = "$_lag_declared" ] \
     && [ "${_fmissing_ts:-}" = "$_lag_declared" ]; then
    lag_match=1
  fi
fi

# FIELD and ENUM-VALUE surfaces share one exit code (6) and are reported TOGETHER, in one pass, before
# either can exit: if both disagree at once, a script that exited on the field report first would never
# show the enum one, and a re-run-after-fixing-only-the-first-thing-you-saw loop is exactly the kind of
# blindness this gate exists to prevent one level up. The seam.event.v1 field surface joins that single
# pass, reported here alongside them and decided once below.
if [ "$field_surface_rc" -ne 0 ] || [ "$enum_surface_rc" -ne 0 ] || [ "$event_field_surface_rc" -ne 0 ]; then
  echo
  # Print the event surface's CLEAN result here too, not only on the all-green path below. On every
  # local checkout the api lag makes this block the exit route, so without this line a reader could
  # not tell "the event probe ran and found nothing" from "the event probe never ran" — which is the
  # exact failure a probe placed after the exit would produce, and it must not be indistinguishable.
  if [ "$event_field_surface_rc" -eq 0 ]; then
    echo "OK — the event field surface matches $EVENT_FIELD_MANIFEST in both languages."
    echo
  fi
  if [ "$field_surface_rc" -ne 0 ] && [ "$lag_match" -eq 1 ]; then
  _lag_date="$(expected_local_lag_date)"
  _lag_age="$(expected_local_lag_age_days "$_lag_date")"
  echo "NOTE — the FIELD surface disagrees with $FIELD_MANIFEST, but EXACTLY as recorded in"
  echo "       $EXPECTED_LOCAL_LAG (expected from ${_lag_date:-an unrecorded date}, $_lag_age old):"
  while IFS= read -r r; do [ -n "$r" ] && echo "         - $r"; done <<< "$_lag_declared"
  echo "       This is the known local-checkout/BSR gap (stubs regenerate from a BSR module that has"
  echo "       not yet republished these), not a new regression. CI always regenerates fresh from the"
  echo "       BSR and remains the sole authority on the contract itself."
  # What this run actually exits with, said out loud — and NOT unconditionally. This NOTE prints on
  # every local checkout, so a fixed "this STILL exits 6" would be a false statement in precisely the
  # case exit 8 was added for: the api lag matching (as it always does) while the EVENT surface has a
  # real regression. Telling that reader the run ended in the code CLAUDE.md says to read past is the
  # exact confusion 8 exists to prevent, printed by the gate itself.
  if [ "$event_field_surface_rc" -eq 0 ]; then
  echo "       The api field surface is the only thing that fired, so this STILL exits 6 below — only"
  echo "       the output is different."
  else
  echo "       This run does NOT exit 6. The seam.event.v1 field surface ALSO disagrees, and that"
  echo "       exits 8 — reported below, and it is NOT covered by this recorded lag. Read the event"
  echo "       report; this NOTE accounts for the api half only."
  fi
  echo "       If a run ever names anything beyond exactly these fields, THAT is real drift, not this"
  echo "       recorded lag. See CLAUDE.md's Gotchas."
  elif [ "$field_surface_rc" -ne 0 ]; then
  err "the generated FIELD surface disagrees with $FIELD_MANIFEST:"
  printf '%s' "$field_surface_report" >&2
  echo "" >&2
  # Print ONLY the explanation for the direction that fired. A refusal whose whole job is to say what
  # happened should not hand the reader both stories and make them work out which one applies.
  if [[ "$field_surface_report" == *"MISSING from the"* ]]; then
  err "A field MISSING from the stubs is either a stale generation — rerun 'make generate' (BSR) or"
  err "'make generate-local RUNTIME=../seam-runtime' — or a field REMOVED from the contract, which is"
  err "a breaking change and must be handled, never silently rewritten away."
  if [ -f "$EXPECTED_LOCAL_LAG" ]; then
  err "(This did not match the recorded lag in $EXPECTED_LOCAL_LAG exactly — a superset, subset, or"
  err "other deviation from that file is treated as real, not the known gap.)"
  fi
  echo "" >&2
  fi
  if [[ "$field_surface_report" == *"NOT IN THE MANIFEST"* ]]; then
  err "A field NOT IN THE MANIFEST is a new one on the contract, and this refusal is deliberate: it is"
  err "the moment someone DECIDES whether this SDK carries it. Decide first — wire it into the"
  err "hand-written clients, or record in the PR why not — and only then run:"
  err "    scripts/check-contract.sh --write-manifest"
  err "and commit the manifest diff alongside that decision. Running the escape first turns a"
  err "deliberate refusal back into the silent pass this gate exists to remove."
  echo "" >&2
  fi
  fi
  if [ "$enum_surface_rc" -ne 0 ]; then
  err "the generated ENUM-VALUE surface disagrees with $FIELD_MANIFEST:"
  printf '%s' "$enum_surface_report" >&2
  echo "" >&2
  if [[ "$enum_surface_report" == *"MISSING from the"* ]]; then
  err "An enum value MISSING from the stubs is either a stale generation — rerun 'make generate' (BSR)"
  err "or 'make generate-local RUNTIME=../seam-runtime' — or a value REMOVED from the contract, which"
  err "is a breaking change for any consumer holding that value and must be handled, never silently"
  err "rewritten away."
  echo "" >&2
  fi
  if [[ "$enum_surface_report" == *"NOT IN THE MANIFEST"* ]]; then
  err "An enum value NOT IN THE MANIFEST is a new one on the contract, and this refusal is deliberate:"
  err "it is the moment someone DECIDES whether the fail-closed consumers of this enum (e.g."
  err "python/seam_sdk/_collective.py, errors.py) are updated to recognise it, before it can reach them"
  err "as a hard 'unknown value' error. Decide first, then run:"
  err "    scripts/check-contract.sh --write-manifest"
  err "and commit the manifest diff alongside that decision. Running the escape first turns a"
  err "deliberate refusal back into the silent pass this gate exists to remove."
  echo "" >&2
  fi
  if [[ "$enum_surface_report" == *"GENERATION SKEW"* ]]; then
  err "A GENERATION SKEW is neither of the above: it is not what the manifest expects, it is python and"
  err "ts disagreeing with EACH OTHER. Both languages regenerate from the same contract in the same"
  err "push, so this means one tree's generation went stale while the other's did not — rerun 'make"
  err "generate' (BSR) or 'make generate-local RUNTIME=../seam-runtime' and check BOTH python/_gen and"
  err "ts/gen landed the same contract. --write-manifest cannot fix this: it writes from Python only,"
  err "so it would silently canonicalise whichever language is currently ahead."
  fi
  fi
  if [ "$event_field_surface_rc" -ne 0 ]; then
  err "the generated seam.event.v1 FIELD surface disagrees with $EVENT_FIELD_MANIFEST:"
  printf '%s' "$event_field_surface_report" >&2
  echo "" >&2
  if [[ "$event_field_surface_report" == *"MISSING from the"* ]]; then
  err "A field MISSING from the event stubs is either a stale generation — rerun 'make generate' (BSR)"
  err "or 'make generate-local RUNTIME=../seam-runtime' — or a field REMOVED from seam.event.v1, which"
  err "breaks every outbox consumer holding it and must be handled, never silently rewritten away."
  echo "" >&2
  fi
  if [[ "$event_field_surface_report" == *"NOT IN THE MANIFEST"* ]]; then
  err "A field NOT IN THE MANIFEST is a new one on the outbox contract. This is the refusal #88 asked"
  err "for: seam.event.v1 reaches seam-connectors and the verifier through this SDK, and until now a"
  err "field could land there with every gate green. Decide what carries it, then run:"
  err "    scripts/check-contract.sh --write-manifest"
  err "and commit the manifest diff alongside that decision."
  echo "" >&2
  fi
  if [[ "$event_field_surface_report" == *"GENERATION SKEW"* ]]; then
  err "A GENERATION SKEW on the event surface is python and ts disagreeing with EACH OTHER, not with"
  err "the manifest. Both trees regenerate from the same contract in the same push, so one went stale."
  err "--write-manifest cannot fix it: it writes from Python only, and would canonicalise whichever"
  err "language happens to be ahead."
  echo "" >&2
  fi
  fi
  # Precedence, decided rather than inherited: an event disagreement exits 8 EVEN WHEN the api surface
  # also disagrees. 6 is the code CI and CLAUDE.md's Gotchas already treat as "the known local lag,
  # read the NOTE and move on" — so an event failure that exited 6 would be a real regression hidden
  # behind a message telling the reader to ignore it. 8 means "something here is not the known lag".
  if [ "$event_field_surface_rc" -ne 0 ]; then
    exit 8
  fi
  exit 6
fi
echo "OK — the field surface matches $FIELD_MANIFEST in both languages."
echo "OK — the enum-value surface matches $FIELD_MANIFEST in both languages."
echo "OK — the event field surface matches $EVENT_FIELD_MANIFEST in both languages."
