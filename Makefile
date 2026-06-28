# Seam SDK generation.
#
# `make generate`        — generate all language stubs from the published BSR contract module.
# `make generate-local`  — generate from a local seam-runtime checkout (set RUNTIME=/path, default ../seam-runtime).
# `make clean`           — remove generated output.
#
# Generation uses buf remote plugins (run on the BSR) — no local protoc-gen-* installs needed, but a
# one-time `buf registry login` is required.

BUF_MODULE ?= buf.build/zer07labs/seam
RUNTIME    ?= ../seam-runtime

.PHONY: generate generate-local clean lint

generate:
	buf generate $(BUF_MODULE)

generate-local:
	buf generate $(RUNTIME)

clean:
	rm -rf gen

# Sanity-check the contract module the SDKs are generated from (lints the runtime checkout).
lint:
	buf lint $(RUNTIME)
