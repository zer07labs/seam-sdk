# Seam SDK — Go

The Go **crypto shim**: client-side Ed25519/SHA-256 crypto only, pure stdlib, no generated transport
and no gRPC dependency. That scope is a decision, not an accident (see the repo root README's status
table): Python is the reference implementation each shim mirrors byte-for-byte; an ergonomic Go client
over the generated transport is a follow-up.

## What it covers

Pinned against `conformance/vectors.json` (generated from the Rust reference):

- **`admission`** — the pinned-key admission presentation (Ed25519 proof-of-possession, AID
  derivation, deterministic message id `derivedUuid("seam-pop-mid-v1", nonce)`).
- **`tct`** — independent verification of a sealed commitment's rooted TCT (EdDSA JWS, self-issued
  claims, truncated-seconds `exp`, the single `aitp.attestation` grant, and the
  `ext["com.zer07labs.seam"]` statement binding `seam-commitment-digest:v3` over the committer and the
  sealed explanation).

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

## Management-plane DPoP (`mgmtdpop`)

A DPoP-bound operator token (one whose claims carry `cnf.jkt`) is refused as Bearer. Every management
call needs `authorization: DPoP <token>` plus a fresh proof signed with the Ed25519 key the management
console revealed **once**, next to the token (seam-sdk#290). `mgmtdpop` signs those proofs. It is pinned
byte for byte by `conformance/mgmt_dpop_vector.json`, the same vector the other four SDKs pass.

```go
// The console's one-time reveal: the private JWK, exactly as shown. Load it from your secret store,
// never from source control; the Key prints only its thumbprint. A typo in the reveal fails here,
// by name (errors.Is(err, mgmtdpop.ErrKey)).
key, err := mgmtdpop.ParseJWK([]byte(os.Getenv("SEAM_OPERATOR_DPOP_JWK")))
if err != nil {
	return err
}
// aud "" means the token's own aud, else "seam-runtime". Misuse fails here, before any call:
// an unbound token, a token bound to another key, or a list aud with no override.
opts, err := mgmtdpop.DialOptions(key, os.Getenv("SEAM_OPERATOR_TOKEN"), "")
if err != nil {
	return err
}
cc, err := grpc.NewClient(target, append(opts, grpc.WithTransportCredentials(creds))...)
```

Each unary call, and the one request of each server stream, gets its own proof over the exact request
bytes. The runtime burns a proof on first use, so never use a retry policy that resends a call's
metadata. Retry by making the call again.

For the HTTP management plane, `mgmtdpop.HTTPHeaders(key, token, method, url, body)` returns both headers
for one request. Send exactly `body` to exactly `url`, because the proof binds both.

## Module path and versions

```
go get github.com/zer07labs/seam-sdk/go@vX.Y.Z
```

The module is nested at `go/`, so Go resolves its versions from the **`go/vX.Y.Z`** tags the release
workflow pushes alongside each root `vX.Y.Z` tag (same commit, same "one version everywhere" number
as the runtime and the other SDKs).
