# Flows W5 — seam-sdk pre-vendor for seam-runtime#1910 (0.117.0)

Wave 5 (board `.waves/flows`), unit seam-sdk. Source: rt#1910 head `a196a6c1` (contract files frozen since
`7cbfea74`): `seam_event.proto` ChainManifest fields 10/11 (`tenant_len`/`tenant_head`), signing domain
`seam.audit.chain-manifest.v2` (D-163), `docs/specs/seam-event.v1.md`, `fixtures/chain/chain_manifest_vectors.json`.
`seam.api.v1` unchanged. One PR. Decisions: DECISIONS.md 2026-11-24.

| Phase | What | Status |
|---|---|---|
| P1 | Vendor byte-verbatim at `a196a6c1`: `verify/proto/.../seam_event.proto`, `verify/docs/seam-event.v1.md` (header tracks `lanes/w5-train-2`), `conformance/chain/chain_manifest_vectors.json` (new) | DONE |
| P2 | `verify/`: model `CHAIN_MANIFEST` (tag 30) on both transports and in the dedup identity; v2 signed preimage, signature, entry digest (b′); structural refusals; D-163 `MANIFEST_TENANT_HEAD_MISMATCH`; V7 `MANIFEST_HEAD_MISMATCH`/`CHAIN_MISSING`; vector tests; seam-verify 0.7.0 | DONE |
| P3 | `contract/event-field-manifest.txt` + gate test: `ChainManifest/tenant_len`, `ChainManifest/tenant_head`; CHANGELOG, COMPATIBILITY, README | DONE |

Not carried (no seam-sdk consumer): `fixtures/seam_event_descriptor.json`, `golden_seam_events_pb.b64` — nothing here
reads either. Out of scope (unchanged from W5 clients): `--issuer` over chain-keyed chains (needs attestation v3),
V9(a) `CHAIN_UNDECLARED` completeness, V10.

Merge order (DECISIONS 2026-11-04 process gap; memory contract-train order): the event-field gate reads BSR `main`,
which carries fields 10/11 only after rt#1910 merges and pushes. The PR is green locally against `a196a6c1`
(`make generate-local`); CI's contract job turns green after that push. Merge then, before/at the dispatch.
