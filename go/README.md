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
  `ext["com.zer07labs.seam"]` statement binding `seam-commitment-digest:v5` over the committer, the
  governing document digest (field 11) and the sealed explanation, `seam-explanation-digest:v2` with each vote/ballot/objection's voter record).

Also pinned, by `conformance/selection_rule_v1_vectors.json`:

- **Option selection (runtime 0.90.0)** — the `proposal` explanation word, and the sealed selection
  block's codec: `crypto.SelectionBody(SelectionBlock{…})` and `crypto.SelectionDigest(body)` frame v5
  field 9 (set `Commitment.Selection`, or `Commitment.SelectionDigest` to the digest). A block the runtime
  could not have sealed is refused, never hashed. `crypto.DecodeSelectionBody` is the strict decoder.
  The winner is **recomputed**, as in Python and the Rust verifier: `crypto.Decide(record, entries)`
  (§3, every `rule_cases` entry) and `crypto.VerifySelection(block, entries, action)` (§5 steps 6-9,
  every `sealed_cases` entry, by result name). `VerifyTCT` runs `VerifySelection` whenever
  `Commitment.Selection` is set, and fails closed when the block comes without `Explanation` entries.

Also, outside `vectors.json`:

- **`crypto.Agent`** — `GenerateAgent()` (CSPRNG) / `NewAgent(seed)`; prints its AID, never its seed.
- **`identity`** — `CreateIdentityFile(path, agentID, tenant, endpoint) (path, aid, error)` and
  `LoadIdentityFile(path)` (`""` reads `$SEAM_BOOTSTRAP_FILE`): the schema-v1 bootstrap file, written
  0600 / `O_EXCL|O_NOFOLLOW` / fsync / hard-link publish that never clobbers (#201).
- **`crypto.RequestCredentials`** — the `seam-request-call-v1` credential (pinned by
  `conformance/request_sig_payload_vector.json`) with the bound-agent default (#202): an explicit
  credential wins, else the bound `Agent`, else no headers. The ticket comes from your own transport.
- **Voter proofs (`seam-voter-pop-v1`, #359)**, pinned by `conformance/voter_pop_v1_payload_vector.json`:
  runtime 0.87.0+ refuses a vote, ballot or objection without one (`voter_proof_required`). Use
  `crypto.VoteContentDigest(VoteContent{…})` and `crypto.SignVoterPop(voterSeed, VoterPopTarget{…},
  digest[:], VoteEntry{…})`, or `SignVoterPopAt` with an explicit window of at most 15 minutes. The
  seed is the voter's own enrolled `voter` key (`VoterEnrolmentProof`). Set the resulting
  `VoterPopProof` field for field on your generated `VoterProof{Pop: &VoterPop{…}}`, as
  `VoteRequest.proof`, `BallotRequest.proof`, `ObjectionRequest.proof` or a one-shot `Vote.proof`.
  `ToREST()` gives the REST `proof` object. Two cases set the target and content:
  - A **session** vote is addressed by `SessionStep.opened_at_millis` and signs the session's
    `vote_policy`.
  - A **one-shot** `RunDecision` is addressed with `OpenedAtMillis: 0` and signs the request `Features`
    with no policy.

  `VerifyVoterPop`, `VerifyVoterRecord` and `VerifyCommitmentVoters` re-check proofs and sealed
  records offline.

- **`clearance`** (#384) — the caller's decrypt clearance on the decision reads (`GetDecision`,
  `ReplayDecision` on runtime 0.101.0+, `GetCommitmentProof`), per call:
  `ctx, err := clearance.NewContext(ctx, clearance.Financial)`, then call the generated stub with `ctx`.
  The value is exactly one of `Public`, `Internal`, `Confidential`, `Financial`, `Pii`, `Phi`
  (case-sensitive); anything else returns `ErrClearance` and sends nothing. A second `NewContext`
  replaces the value. Without it, no `x-seam-clearance` is sent. The runtime honours the header only
  on a plane in `allow` subject-header posture; a `deny` or peer-cert plane strips it, so the read is
  at `Public`.

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
