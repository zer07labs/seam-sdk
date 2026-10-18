<!-- Pinned copy of seam-runtime/docs/specs/evidence-bundle.v1.md @ 8a65349 (vendored 2026-10-10).
     The normative text `seam-verify bundle` implements (seam-sdk#225); it landed with the runtime 0.44.0
     train (seam-runtime#1269, #806). It links two sibling specs by relative path: `seam-event.v1.md`
     (vendored beside this file) and `seam-commitment-digest.v2.md` (NOT vendored; its commitment and
     explanation digests are implemented in `src/commitment.rs` and pinned there by the spec's own worked
     examples and by `conformance/commitment_digest_v2_vector.json`). -->

# `seam-evidence-bundle.v1` — the self-contained evidence bundle

**Status:** normative · **Format tag:** `seam-evidence-bundle.v1` · **Binding domain:** `seam.evidence-binding.v1` · **Owner:** `seam-runtime` · **Issue:** #806

An evidence bundle is what an operator hands to an **adverse party**: someone who disputes a decision,
has no runtime access and no reason to trust the operator. With the bundle and the issuer AID, pinned
independently, that party can check, offline:

- that the decision is a link of its tenant's hash chain, inside a window the issuer signed at both ends;
- what was committed (the decrypted Commitment), and that the issuer rooted it (its TCT);
- that this Commitment is the content of that chain link, which the chain alone cannot show;
- what context the decision consumed, and which policy rules gated it, if the exporter disclosed them;
- what was left out, and why.

It builds on the decision-scoped window of `seam-event.v1` (#421 sub-step B) and adds no wire change:
no `seam.api.v1` field, no `seam-event.v1` field, and no change to any record digest, checksum or
attestation.

## Producing one

```
seam-ops export-evidence --decision <decision_id> --bundle <DIR> [--disclose context,policy]
```

The export has the scoped window's refusals, unchanged: the decision must be in the retained outbox,
an attestation of its partition must precede it, and one must cover it. `DIR` must not already hold a
`manifest.json`.

## Files

All files sit flat in one directory. `manifest.json` lists every other file.

| File | Always | Content |
|---|---|---|
| `manifest.json` | yes | The index (below). |
| `events.jsonl` | yes | The window: `seam-event.v1` JSON lines from the anchor attestation through the first attestation of the same partition that covers the decision. |
| `anchor.json` | yes | The bare `ChainHeadAttestationEvent` the window starts from (the `seam-verify --from-anchor` shape). |
| `commitment.json` | when the record opens | The decrypted Commitment and its TCT. |
| `binding.json` | with `commitment.json` | The issuer's signed binding of that Commitment to the chain link. |
| `context.json` | `--disclose context` | The record's context bindings, in stored order. |
| `policy.json` | `--disclose policy` | The bound policy definition as its JCS bytes. |

`commitment.json` and `binding.json` always come as a pair. A Commitment without its binding is
unlinked from the chain, and a binding without its Commitment proves nothing.

### `manifest.json`

```json
{
  "format": "seam-evidence-bundle.v1",
  "scope": "decision",
  "decision_id": "dec:…",
  "tenant": "…",
  "exported_at": 1700000000000,
  "issuer": { "aid": "aid:pubkey:…", "ed25519_public_key": "<64 hex>", "pin": "…" },
  "inclusion": {
    "decision_offset": 0, "record_checksum": "<base64>", "anchor_offset": 0,
    "anchor_attested_len": 0, "window_events": 0, "window_links": 0, "window_attestations": 2
  },
  "files": { "events.jsonl": { "sha256": "<64 hex>", "bytes": 0 }, "…": {} },
  "disclosed": ["commitment", "binding", "context", "policy"],
  "withheld": [ { "item": "participation", "reason": "…" } ],
  "verify": [
    "seam-verify chain events.jsonl --issuer <AID> --from-anchor anchor.json",
    "seam-verify bundle . --issuer <AID>"
  ]
}
```

**The manifest is an index, not evidence.** It is unsigned. Every claim in it can be re-derived from
the other files and the pinned AID, and a verifier MUST refuse a manifest that disagrees with them.
`issuer.aid` in particular says which AID the exporter used. It is never a reason to trust that AID:
an adverse party pins the AID out of band, from `GET /v1/trust/issuer-aid` or from anchors a notary
holds, and refuses a bundle naming any other. The AID is self-certifying
(`aid:pubkey:<base64url Ed25519 key>`), so `ed25519_public_key` is that same key in hex, for
convenience.

### `commitment.json`

```json
{ "id": "…", "action": "…", "authority": "…", "auth_method": "…", "trust_basis": "…",
  "supersedes": null, "signed_artifact": "<compact JWS>", "committer": "…",
  "explanation": [ { "kind": "vote", "participant": "…", "proposal_id": "…", "value": "…",
                     "reason": "…", "confidence": null, "rationale_ref": null } ],
  "issuer_aid": "…", "commitment_digest": "<64 hex>" }
```

`id`, `action`, `authority`, `auth_method`, `trust_basis`, `supersedes`, `committer` and
`explanation` are the `Commitment` exactly as the [`seam-commitment-digest:v2`](seam-commitment-digest.v2.md)
framing reads them (`supersedes` is `null` when absent; `explanation` is in sealed order, each entry's
`kind` is the lowercase digest word, and `confidence` / `rationale_ref` are `null` when absent — never
`0.0`). A verifier recomputes the `seam-explanation-digest:v1` from the entries, so a re-worded entry
fails the TCT. `signed_artifact` is the TCT. It is empty
only for a record sealed under `identity: local-sealed`, which has no TCT; such a Commitment is bound
to the chain by `binding.json` alone. `commitment_digest` is informational: a verifier recomputes it.

### `binding.json` — `seam.evidence-binding.v1`

The chain carries only `ciphertext_digest` for a decision. Linking a decrypted Commitment to it
otherwise needs the record's DEK, and the TCT does not name the decision or its chain position. The
runtime holds the key, so at export it decrypts the record and signs this statement with the issuer
key that signs the chain-head attestations:

```json
{ "decision_id": "…", "tenant": "…", "record_checksum": "<base64, 32 bytes>",
  "commitment_digest": "<64 hex>", "bound_at": 1700000000000, "issuer_aid": "…",
  "signature": "<base64, 64 bytes>" }
```

`record_checksum` is the `checksum` of the decision's `DECISION_SEALED` link. `commitment_digest` is
the raw 32-byte `seam-commitment-digest:v2`, rendered as lowercase hex. The signature is Ed25519 over
the 32-byte digest:

```
binding_digest = SHA256(
    frame("seam.evidence-binding.v1")
  ‖ frame(decision_id) ‖ frame(tenant)
  ‖ frame(record_checksum)          // 32 raw bytes
  ‖ frame(commitment_digest)        // 32 raw bytes
  ‖ frame(le64(bound_at))
  ‖ frame(issuer_aid)
)
```

`frame(x) = le32(len(x)) ‖ x`, the framing the chain-head attestation uses. Strings are their raw
UTF-8 bytes, with no normalization.

**Worked example.** With `decision_id = "dec:s1"`, `tenant = "acme"`, `record_checksum` = 32 × `0xab`,
`commitment_digest` = 32 × `0xcd`, `bound_at = 1700000` and the issuer seed 32 × `0x09`
(`issuer_aid = aid:pubkey:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg`):

```
binding_digest = ce1b699d3e67cfd8c16a3c0686eb22e1ea525b926d9d3a44a393ed838aa84ce6
```

This is pinned by `evidence_binding_payload_golden` in `crates/seam-trust-aitp/src/lib.rs`, and was
reproduced independently from this text in Python.

The binding is a statement the issuer makes at export time and cannot later deny. It does not replace
the chain: it ties the Commitment to a link, and the chain and its attestations prove the link.

### `context.json`

```json
{ "bindings": [ { "ctx_ref": "…", "fidelity": "Digest", "classification": "Internal",
  "lineage_id": null, "version": 1, "derived_from": [], "content_hash": null,
  "receipt_hash": null, "key_status": null, "resolved_status": null } ] }
```

One object per binding, in the record's stored order, carrying exactly the fields the v3
`context_digest` preimage reads ([`seam-event.v1.md` § `context_digest`](seam-event.v1.md#context_digest--seamauditcontext-provenancev3)),
with the same string encodings. `null` is an absent `opt` slot. A verifier recomputes `context_digest`
from these objects and compares it with the chained `DECISION_SEALED.context_digest`.

The context's bodies are not included. A binding names a body by reference or digest.

### `policy.json`

The bound `PolicyDefinition`, serialized as JCS (RFC 8785) bytes. `SHA256(policy.json)` is the chained
`DECISION_SEALED.policy_rules_digest`, so a verifier hashes the file as is and never re-canonicalizes
it. The exporter discloses it only when the definition it can load today still digests to the sealed
value. Otherwise the policy is withheld with that reason and is never replaced by today's definition.

## What is withheld, and why

Each item left out is listed in `withheld` with its reason. A verifier prints these. They are part of
what the adverse party is told.

| Item | When | Reason |
|---|---|---|
| `participation` | always | `participation[].subject` is the GDPR erasure predicate. Only `participation_digest` is chained and published. |
| `context` | without `--disclose context` | A disclosure decision, made by the exporter per bundle. |
| `policy` | without `--disclose policy`, no policy bound, or the bound bytes are no longer loadable | As stated in the reason. |
| `commitment`, `binding` | the record is crypto-shredded, tiered to cold storage, or missing | A shredded record's plaintext is unrecoverable, though its link still verifies. A cold record must be replayed from its archive bundle first. |

## Verifying

`seam-verify bundle <DIR> --issuer <AID>` runs these steps in order and refuses (exit 2) at the first
failure:

1. **Manifest.** `format` is `seam-evidence-bundle.v1`. `issuer.aid` equals the pinned AID. Every
   listed file exists with the listed `sha256` and `bytes`. `events.jsonl` and `anchor.json` are
   listed. `commitment.json` and `binding.json` are both listed or both absent. `disclosed` agrees
   with `files`.
2. **Chain.** `seam-verify chain events.jsonl --issuer <AID> --from-anchor anchor.json --strict`
   passes: the anchor is signed by the pinned issuer, every link holds from the anchored head, and
   a covering attestation authenticates the window.
3. **Inclusion.** The window holds exactly one chained `DECISION_SEALED` for `decision_id`, in
   `tenant`, and its `checksum` is `inclusion.record_checksum`.
4. **Commitment.** If `signed_artifact` is present, the TCT verifies against the pinned AID and its
   grant carries this Commitment's digest. The Commitment's `supersedes` equals the chained payload's.
5. **Binding.** The signature verifies against the pinned AID. `decision_id`, `tenant` and
   `record_checksum` are the decision link's, and `commitment_digest` is the recomputed digest of
   `commitment.json`.
6. **Disclosures.** `context.json` recomputes the chained `context_digest`. `SHA256(policy.json)` is
   the chained `policy_rules_digest`.

Exit `0` verified · `1` usage/IO error · `2` verification failed.

A verifier with only the published chain verifier still runs step 2 with the manifest's first
`verify` command. Steps 4 and 5 need only the TCT verification every SDK already ships plus the
binding framing above.

## Versioning

Any change to the file set's meaning, a file's shape, or the binding framing is a new format tag
(`seam-evidence-bundle.v2`) or a new binding domain (`seam.evidence-binding.v2`). Adding a new
optional file with its own `disclosed` item is not a change to an existing file, but a v1 verifier
does not check it. A verifier MUST refuse a `format` it does not know.

## Reference implementations

| Role | Location |
|---|---|
| Export | `crates/seamd/src/evidence.rs` — `Seam::export_evidence_bundle`; CLI `seam-ops export-evidence --bundle` |
| Binding sign / verify | `crates/seam-trust-aitp/src/lib.rs` — `ErasureSigner::sign_evidence_binding`, `verify_evidence_binding_by_aid`, `commitment_digest` |
| Verifier (internal oracle) | `crates/seam-verify/src/bundle.rs` — `seam-verify bundle` |
| Tests | `crates/seam-verify/tests/bundle.rs`, `crates/seamd/tests/evidence_bundle.rs` |
