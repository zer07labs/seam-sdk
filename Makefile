# Seam SDK generation.
#
# `make generate`         — generate all language stubs from the published BSR contract module.
# `make generate-local`   — generate from a local seam-runtime checkout (set RUNTIME=/path, default ../seam-runtime).
# `make check-contract`   — assert the ACTIVE generated stubs expose the surface the SDK depends on.
# `make clean`            — remove generated output.
#
# Generation uses buf remote plugins (run on the BSR) — no local protoc-gen-* installs needed, but a
# one-time `buf registry login` is required.
#
# Which contract to build against:
#   * `generate` (BSR) is the RELEASE source — immutable, published, what shipped wheels are built from.
#   * `generate-local` (a runtime checkout) is the DEVELOPMENT baseline — always current with the runtime's
#     working tree, so SDK work is never blocked waiting on a BSR push (which is a runtime-side, user-gated
#     step). Use it for local iteration; the BSR is the release of record.
# `check-contract` makes "what surface does the active contract actually expose?" a verifiable fact rather
# than an assumption — the SDK's equivalent of the runtime's published-surface gate.

BUF_MODULE ?= buf.build/zer07labs/seam
RUNTIME    ?= ../seam-runtime

.PHONY: generate generate-local check-contract clean lint probe-frameworks

generate:
	buf generate $(BUF_MODULE)
	python3 scripts/root_gen.py

generate-local:
	buf generate $(RUNTIME)
	python3 scripts/root_gen.py

# Assert the active stubs carry the surface the hand-written clients call, probing the Python and TS
# stub trees INDEPENDENTLY (one can be stale beside the other). The RPC + Authorize probes are always
# hard gates; STREAM=1 additionally hard-gates the streamed-payload mirror fields and EVENTS=1 hard-gates
# SeamEvents.ReportEventsConsumed — CI sets both, since the BSR module carries that surface. Exit codes:
# 0 OK · 1 RPC/Authorize/admin surface stale · 2 stream fields stale (STREAM=1) · 3 stubs not
# generated · 4 ReportEventsConsumed stale (EVENTS=1) · 5 RPC surface disagrees with
# contract/rpc-manifest.txt · 6 field or enum-value surface disagrees with contract/field-manifest.txt · 7 a structural
# precondition the extractors assume failed (a nested enum or message, or an enum/nested message on
# seam.event.v1) · 8 the seam.event.v1 field surface disagrees with contract/event-field-manifest.txt,
# which is deliberately NOT 6 and wins when both disagree — 6 is the code a local checkout produces on
# every run and is told to read past. (5-7 were already implemented and missing from this list before
# 8 was added; adding 8 to a list that stopped at 4 would have shipped a comment more wrong than the
# one it replaced. Code 1 was wrong here too, and for the same reason: the admin surface was added to
# it in #36 and never reached this list.) Run AFTER a `generate` / `generate-local`; it inspects the
# emitted stubs, it does not generate them.
check-contract:
	./scripts/check-contract.sh

# Resolve, against live PyPI, whether each agent framework in COMPATIBILITY.md §4a can still share a
# virtualenv with this SDK. The doc's table is the expectation; this derives the answer and fails on
# any disagreement — in BOTH directions, because a row flipping to `compatible` is the signal that an
# upstream fix landed and nothing else in the org watches for it.
#
# Needs `uv` and Python 3.11+ (tomllib). Hits the network; not part of the default test suite by
# design — the answer changes when PyPI changes, not when this repo does.
# PROBE_PYTHON prefers the project venv, because a system `python3` older than 3.11 has no tomllib
# and the target would fail for a reason that has nothing to do with the answer. Override to point
# at any 3.11+ interpreter: `make probe-frameworks PROBE_PYTHON=python3.12`.
PROBE_PYTHON ?= $(shell [ -x python/.venv/bin/python ] && echo python/.venv/bin/python || echo python3)

probe-frameworks:
	$(PROBE_PYTHON) scripts/probe_framework_coinstall.py

clean:
	rm -rf gen python/seam_sdk/_gen ts/gen ts/dist

# Sanity-check the contract module the SDKs are generated from (lints the runtime checkout).
lint:
	buf lint $(RUNTIME)
