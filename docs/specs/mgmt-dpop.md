<!-- Pinned copy of seam-runtime/docs/specs/mgmt-dpop.md @ 7ea99e96 (vendored 2026-10-27 for seam-sdk#290).
     The normative grammar for the operator DPoP signer every SDK ships (`OperatorDpopKey`, the proof
     primitive, the gRPC interceptor and the HTTP header helper). Its Golden vector table is the source of
     `conformance/mgmt_dpop_vector.json`'s `golden` group; the vector's `derived` group is SDK-computed. -->

# Management-plane DPoP (P19)

Proof of possession for operator tokens on the management plane: HTTP 9099 and gRPC 9100 (`SeamAdmin`,
`SeamEvents`). It follows [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), with one extension claim. The
plan is `plans/k8s-multicloud-deployment.md` P19.

**Status: R2 (enforcing).** Each management listener's DPoP policy follows from its transport posture at
boot (`MgmtBindPosture::dpop` in `crates/seamd/src/boot.rs`):

| Listener posture | DPoP |
|---|---|
| loopback bind | optional: an unbound `Bearer` token is accepted |
| non-loopback, server TLS (no client CA) | **required** |
| non-loopback, plaintext acked (`SEAM_MGMT_ALLOW_PLAINTEXT_NONLOOPBACK`) | **required** |

- On a required listener, an unbound token is refused: as `Bearer` with `no_cnf`, as `DPoP` with `scheme_mismatch` (as on any listener).
- A token **with** `cnf.jkt` must come with a valid proof on every call, on every listener.
- The management listeners never take a client CA. One inherited from the shared `SEAM_TLS_*` or
  `SEAM_GRPC_TLS_*` family is dropped, so a data-plane mTLS CA never puts a certificate request on the
  management plane.
- R3 (mgmt mTLS retired): a set `SEAM_MGMT_TLS_CLIENT_CA` or `SEAM_MGMT_TLS_CLIENT_CA_PEM` refuses boot by
  name (`TlsConfig::check_retired_mgmt_client_ca` in `crates/seamd/src/config.rs`). There is no mTLS
  rollback; a caller that cannot send DPoP is fixed at the caller.

Source: `crates/seam-trust-aitp/src/mgmt_dpop.rs` (the pure check and the reference minter),
`Seam::verify_mgmt_dpop` in `crates/seamd/src/lib.rs` (the binding decision and the burn),
`require_management_auth` in `crates/seamd/src/server.rs` (HTTP), and `MgmtDpopBodyLayer` and
`management_interceptor` in `crates/seamd/src/grpc.rs` (gRPC).

## Token

The operator JWS gains an optional claim:

```json
"cnf": { "jkt": "<RFC 7638 thumbprint of an Ed25519 public key>" }
```

- `jkt` is the base64url (no padding) SHA-256 of the canonical JWK `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`,
  so it is exactly 43 characters. Anything else, or any other member in `cnf`, is a malformed token.
- The minter puts in `cnf.jkt` only a key it has verified, never a value the caller supplies.
- The reference minter is `seam_trust_aitp::mint_operator_token_dpop_bound`.

## Presenting a call

| | HTTP | gRPC |
|---|---|---|
| Credential | `Authorization: DPoP <token>` | metadata `authorization: DPoP <token>` |
| Proof | header `DPoP: <proof>` | metadata `dpop: <proof>` |

The scheme is case-insensitive. Exactly one proof per call: a repeated header is `malformed`.

Binding rules:

| Token | Scheme | Result |
|---|---|---|
| no `cnf` | `Bearer` | DPoP optional: accepted, a `dpop` header is ignored (RFC 9449 §7.1). DPoP required: refused, `no_cnf` |
| no `cnf` | `DPoP` | refused, `scheme_mismatch` |
| `cnf` | `Bearer` | refused, `scheme_mismatch` |
| `cnf` | `DPoP` | proof required and checked |

## Proof

A compact JWS signed by the bound key.

**Header.** Exactly these members:

- `typ`: `dpop+jwt`.
- `alg`: `EdDSA`.
- `jwk`: `{"kty":"OKP","crv":"Ed25519","x":...}`. It is public only: a `d` member is refused. Its thumbprint
  must equal `cnf.jkt`.

**Claims.** Exactly these members:

| Claim | Rule |
|---|---|
| `jti` | non-empty, at most 256 bytes |
| `htm` | HTTP: the request method. gRPC: `POST` |
| `htu` | see below |
| `iat` | seconds; within ±60 s of the runtime clock |
| `ath` | base64url SHA-256 of the token's ASCII bytes |
| `seam_bd` | base64url SHA-256 of the request body (HTTP) or of the encoded request message (gRPC) |

- A proof over 8 KiB is refused.
- `nonce` is not used, and a proof that carries one is refused.

### `htu`

**HTTP.** The proof's `htu` is compared against `https://<authority><path>`, where the authority is the
request URI's (or else the `Host` header).
- `http` and `https` are interchangeable, because TLS may terminate at an edge.
- The host is compared case-insensitively.
- A default port (`:443` for https, `:80` for http) is dropped.
- Query and fragment are dropped.
- Userinfo is refused.
- The path must match exactly.

**gRPC.** `grpc://<operator aud><full method>`, matched exactly. For example:

```
grpc://seam-runtime/seam.api.v1.SeamAdmin/EnrollTenant
```

The authority is the runtime's operator audience (`SEAM_RUNTIME_AUD`, default `seam-runtime`), not the address
the client dialled, which varies by network.

### `seam_bd`

**HTTP.** The SHA-256 of the exact body bytes. An empty body hashes the empty string. When a call needs a proof,
its body is buffered up to 1 MiB; a larger body is refused with **413**.

**gRPC.** The SHA-256 of the protobuf-encoded request message, without the 5-byte gRPC frame prefix. An `Empty`
message hashes the empty string.
- Every management RPC is unary or server-streaming, so the request is exactly one frame.
- When the call carries `dpop` metadata, it is buffered up to 1 MiB plus 5 bytes. Over the cap, the call is
  refused with **`RESOURCE_EXHAUSTED`**.
- A compressed frame, several frames, or trailing bytes cannot be bound. Such a call is refused as
  `body_unreadable`, whatever its credential.

## Replay

Each accepted proof is burned once, through the store's durable `burn_jti`, which every replica shares:
- the key is `mgmt-dpop:` + hex(SHA-256(proof));
- it is kept until `iat` + 61 s.

The prefix keeps the key out of the operator-token `jti` namespace. A second use is `replayed`.

If the store cannot answer, the call is refused with **500 / `INTERNAL`** (fail-closed). This is reported as a
store fault, never as a bad credential, and logs `replay_check_unavailable`.

## Errors

Every refusal is 401 / `UNAUTHENTICATED` with one fixed message:

```
management call refused: DPoP proof of possession failed
```

The only exceptions are 413 or `RESOURCE_EXHAUSTED` for an oversized body, and the store-outage 500 above. The
reason is never sent on the wire. It goes to `seam_mgmt_auth_rejected_total{reason}` and, for every 401, to a
`seam.security` WARN with `event="mgmt_dpop_rejected"`. An oversized body (`body_too_large`) only counts.

Reasons: `no_cnf`, `no_proof`, `scheme_mismatch`, `malformed`, `unsupported_alg`, `key_mismatch`, `bad_signature`,
`htm_mismatch`, `htu_mismatch`, `iat_skew`, `ath_mismatch`, `body_mismatch`, `body_too_large`,
`body_unreadable`, `replayed`, `replay_check_unavailable`.

Each accepted proof counts on `seam_mgmt_auth_dpop_total`. Both series are always exported, at zero too.

## Golden vector

The control plane, the relay and seam-ops pin this vector. Its source of truth is
`mgmt_dpop::tests::golden_vector`.

Inputs:

| | |
|---|---|
| key seed | 32 × `0x42` |
| `htm` | `POST` |
| `htu` | `grpc://seam-runtime/seam.api.v1.SeamAdmin/EnrollTenant` |
| token | `eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJnb2xkZW4ifQ.c2ln` |
| message bytes | `0a 03 61 63 6d` |
| `iat` | `1800000000` |
| `jti` | `golden-1` |

Outputs:

| | |
|---|---|
| `jkt` | `nEArpjG3kYMcxbdzInyGlBEYQUw7RfAfe3Tw1fZvAA0` |
| `x` | `IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI` |
| `ath` | `n1FytbIY93hACMMcdHGLdjoDGzuCNcVj8E2IkVX7NXA` |
| `seam_bd` | `KCyo4Anqvy3Kl15wJyQwoWwl6lSQQEUMzbCg9-OQ7jc` |
| burn key | `mgmt-dpop:bf374b63f24c25ea8d22e26cb3a0e0e22f0468245e5da05058a683712b1f2853` |

The proof's header and claims are serialised in the member order shown below (Ed25519 is deterministic, so the
whole proof is byte-stable):

```
eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVkRFNBIiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiSVZMNDBadDVIU1JGTWtMaFh5NnJiTGZQLW50cVh0TUFsNVlPQnBpQjJ4SSJ9fQ
.eyJqdGkiOiJnb2xkZW4tMSIsImh0bSI6IlBPU1QiLCJodHUiOiJncnBjOi8vc2VhbS1ydW50aW1lL3NlYW0uYXBpLnYxLlNlYW1BZG1pbi9FbnJvbGxUZW5hbnQiLCJpYXQiOjE4MDAwMDAwMDAsImF0aCI6Im4xRnl0YklZOTNoQUNNTWNkSEdMZGpvREd6dUNOY1ZqOEUySWtWWDdOWEEiLCJzZWFtX2JkIjoiS0N5bzRBbnF2eTNLbDE1d0p5UXdvV3dsNmxTUVFFVU16YkNnOS1PUTdqYyJ9
.OrJGI6MSd-Fgp_pV3CvQjZPmCtwBMV-obVlg7JMZeLjoxe7bQi0QLC2ndDUDdl1Z9YEb6Kn_ks_3nav310mRCg
```

The proof is one line; the line breaks above are for reading only.

- Header: `{"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":...}}`.
- Claims: `{"jti","htm","htu","iat","ath","seam_bd"}`.

The runtime does not require this member order: any order verifies.
