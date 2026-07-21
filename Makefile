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

generate-local:
	buf generate $(RUNTIME)

# Assert the active stubs carry the RPC the hand-written clients call (hard gate), and report whether the
# streamed-payload mirror fields are present (hard-gated under STREAM=1 — the Phase-6 mode). Run AFTER a
# `generate` / `generate-local`; it inspects the emitted stubs, it does not generate them.
check-contract:
	./scripts/check-contract.sh

clean:
	rm -rf gen python/seam_sdk/_gen ts/gen ts/dist

# Sanity-check the contract module the SDKs are generated from (lints the runtime checkout).
lint:
	buf lint $(RUNTIME)
