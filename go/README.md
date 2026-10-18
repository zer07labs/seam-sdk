# Seam SDK — Go

The Go **crypto shim**: client-side Ed25519/SHA-256 crypto only, pure stdlib, no generated transport
and no gRPC dependency. That scope is a decision, not an accident (see the repo root README's status
table): Python is the reference implementation each shim mirrors byte-for-byte; an ergonomic Go client
over the generated transport is a follow-up.

## What it covers

Pinned against `conformance/vectors.json` (generated from the Rust reference):

- **`admission`** — the pinned-key admission presentation (Ed25519 proof-of-possession, AID
  derivation, deterministic message id).
- **`tct`** — independent verification of a sealed commitment's rooted TCT (EdDSA JWS, self-issued
  claims, truncated-seconds `exp`, `seam-commitment-digest:v2` grant binding over the committer and the sealed explanation).

Also, outside `vectors.json`:

- **`crypto.Agent`** — `GenerateAgent()` (CSPRNG) / `NewAgent(seed)`; prints its AID, never its seed.
- **`identity`** — `CreateIdentityFile(path, agentID, tenant, endpoint) (path, aid, error)` and
  `LoadIdentityFile(path)` (`""` reads `$SEAM_BOOTSTRAP_FILE`): the schema-v1 bootstrap file, written
  0600 / `O_EXCL|O_NOFOLLOW` / fsync / hard-link publish that never clobbers (#201).
- **`crypto.RequestCredentials`** — the `seam-request-call-v1` credential (pinned by
  `conformance/request_sig_payload_vector.json`) with the bound-agent default (#202): an explicit
  credential wins, else the bound `Agent`, else no headers. The ticket comes from your own transport.

The vector file's `chain_head_attestation` and `record_digest_v2` sections — like the call-sig/JCS
surface — are exercised by the full Python/TypeScript clients only, not by this shim.

## Module path and versions

```
go get github.com/zer07labs/seam-sdk/go@vX.Y.Z
```

The module is nested at `go/`, so Go resolves its versions from the **`go/vX.Y.Z`** tags the release
workflow pushes alongside each root `vX.Y.Z` tag (same commit, same "one version everywhere" number
as the runtime and the other SDKs).
