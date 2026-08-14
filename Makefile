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

.PHONY: generate generate-local check-contract clean lint

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
# 0 OK · 1 RPC/Authorize stale · 2 stream fields stale (STREAM=1) · 3 stubs not generated ·
# 4 ReportEventsConsumed stale (EVENTS=1). Run AFTER a `generate` / `generate-local`; it inspects the
# emitted stubs, it does not generate them.
check-contract:
	./scripts/check-contract.sh

clean:
	rm -rf gen python/seam_sdk/_gen ts/gen ts/dist

# Sanity-check the contract module the SDKs are generated from (lints the runtime checkout).
lint:
	buf lint $(RUNTIME)
