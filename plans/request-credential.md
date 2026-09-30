# Carry the `seam-request-call-v1` per-request credential

> **Owner:** `seam-sdk`. **Filed by:** `seam-runtime`, 2026-09-27, as #508 Phase 6, and adopted here
> in the same change — so this is the single home; `seam-runtime/plans/cross-repo/seam-sdk-request-credential.md`
> is the filed ask it came from, kept there as the runtime's record of what it handed over.
> **Spec:** `seam-runtime/docs/specs/authorize.v1.md`, "The per-request credential —
> `seam-request-call-v1` (#508)" — the normative text; this plan is the implementation brief.
> **Vector:** `conformance/request_sig_payload_vector.json`, vendored byte-identical with this plan.
> **Anchors were true on 2026-09-27; re-verify before editing.**

---

## Why this exists

A generated SDK client cannot read a subject-scoped verb on a production Seam deployment.

The runtime's data plane authorizes subject-scoped verbs against the caller's AID. Until #508 the
only way to *supply* that AID on a verb other than `RunDecision` / `OpenSession` / `Authorize` was
the `x-seam-subject` transport header — and the only sound production posture
(`SEAM_SUBJECT_HEADERS=deny`, #710) strips it at the edge, because behind a TLS-terminating edge the
runtime cannot distinguish a trusted gateway's header from a caller's. So `deny` and
"subject-scoped work" were mutually exclusive, and the symptom was a canary that sealed a decision
successfully and then took a `401` reading its own decision back.

#508 fixed the runtime: a caller may now prove identity **in band**, per request, with the admission
ticket it already has plus a per-call Ed25519 PoP. The runtime resolves that into the trusted subject
before any handler runs. **The SDKs do not send it**, so from a client's point of view nothing has
changed yet — which is the whole of this ask.

Shipping the runtime first is safe and deliberate: the SDKs' hand-written clients send no
`x-seam-subject` today either, so a subject-scoped read under enforcement fails exactly as it does
now until this lands. Nothing regresses; a capability simply stays unavailable.

## What to implement

One function per language, and its use on the subject-scoped calls. The framing is a **frozen
signed-wire construction** — treat it the way `seam-authorize-call-v2` is already treated in
`python/seam_sdk/crypto.py::call_sig_payload` and its four siblings.

```text
request_sig_payload = frame("seam-request-call-v1")
                    ‖ frame(ticket_bytes)
                    ‖ frame(rpc_full_name)
                    ‖ frame(resource_id)
                    ‖ frame(body_digest)

frame(x) = u32_LITTLE_endian(len_in_BYTES(x)) ‖ x
```

`ticket_bytes` is raw bytes; the other three are UTF-8. The agent key Ed25519-signs those bytes.

Carriage is transport metadata, never a proto field:

| Transport | Ticket | Signature | Encoding |
|---|---|---|---|
| HTTP | `x-seam-ticket` | `x-seam-call-sig` | standard padded base64 |
| gRPC | `x-seam-ticket-bin` | `x-seam-call-sig-bin` | raw bytes (the stack base64-codes `-bin` keys) |

Send **both or neither** — a ticket without a signature is refused, never downgraded. Send **no**
`x-seam-subject` alongside a credential: a credential that disagrees with an already-trusted subject
is refused rather than preferred.

### The three field rules that are easy to get wrong

1. **`rpc_full_name` is the gRPC full method path on BOTH transports** —
   `/seam.api.v1.SeamCoordination/GetDecision`, never `GET /v1/decisions/:id`. That is what makes one
   credential valid over either plane for a bodyless verb.
2. **`body_digest` is `""` for a bodyless verb**, and `"sha256:<lowercase hex>"` over the exact bytes
   sent for one that carries a body. Digest the bytes you actually put on the wire, never a
   re-serialization — a digest taken after parse-and-re-encode lets two different payloads share one
   digest, and the binding is then forgeable by construction.
3. **A bodied verb's credential is per-transport.** HTTP frames a session verb as JSON and binds the
   path id plus the body digest; gRPC frames protobuf, leaves `resource_id` **empty** and digests the
   whole request message (the id is inside it). The five bodyless reads are the only portable ones.

### The verbs

Bodyless reads: `GetDecision`, `ReplayDecision`, `GetCommitmentProof`, `GetEscalation`,
`SessionStatus`. Bodied: `OpenSession`, `SubmitProposal`, `SubmitEvaluation`, `SubmitObjection`,
`SubmitVote`, `SubmitCommit`, `SubmitApprovalRequest`, `SubmitBallot`, `CancelSession`,
`ExpireSession`, and HTTP-only `POST /v1/archive/replay`.

`ReportOutcome` is **deliberately excluded** and must not be credentialed client-side either. It
appends a `LEARNING_OUTCOME` to the outbox and the credential does not defend against replay, so a
replayed report duplicates a durable record. See `seam-runtime/DECISIONS.md`, #508 Phase 5.

## The conformance vector

`conformance/request_sig_payload_vector.json` — vendored into `seam-sdk` byte-identical from
`seam-runtime/crates/seam-api/tests/fixtures/request_sig_payload_vector.json`, the same contract
`conformance/call_sig_payload_vector.json` has. Nine cases, lowercase hex, deliberately the same
shape and encoding as that sibling so both can be implemented in one sitting.

Three cases are load-bearing rather than illustrative. An implementation that passes the other six
while failing any of these is **exploitable**, not merely non-conformant:

- **`same-ticket-and-resource-different-verb`** — identical ticket and `decision_id` to
  `bodyless-read`, only the verb differs. Omit `rpc_full_name` and both produce the same bytes, so a
  captured signature for the structural read reaches the *decrypted commitment proof*.
- **`length-prefix-disambiguation-a` / `-b`** — the same concatenated characters split at a different
  field boundary. Unprefixed concatenation makes these one payload, re-opening (1) by another route.
- **`multibyte-resource-id`** — lengths are **bytes**. JavaScript's `String.length` and Python's
  `len()` on `str` are code units / code points; both emit a short prefix and sign something the
  server will never reconstruct.
- **`body_input_hex` on the two bodied cases** — these pin the DIGEST COMPUTATION, not just the
  framing around it. `body_digest` must equal `"sha256:" + lowercase_hex(sha256(those bytes))`. On
  HTTP the input is the exact JSON you put on the wire; on gRPC it is the **decoded** protobuf
  message, **without** the 5-byte length-prefixed-message header (1 compression flag + u32
  big-endian length). Digesting the framed bytes is the single most likely gRPC divergence, and
  without these two fields an implementation could reproduce all nine payloads and still get the
  digest wrong for eleven of the sixteen verbs.

There is **no bless mode**, in either repo. A mismatch is a contract break: moving these bytes costs a
`v2` domain tag, a second vector and a migration for every published SDK.

## The trap `seam-authorize-call-v2` already sprang once

`seam-request-call-v1` is a **different domain tag** from `seam-authorize-call-v2`, deliberately, so
that a captured `Authorize` `call_sig` is never spendable as a request credential and vice versa.
Four of the five languages already have a `call_sig_payload` with a nearly identical five-field
u32-LE shape. Copy-pasting it and changing only the verb name produces a function that signs the
wrong context tag and fails uniformly with `UNAUTHENTICATED: admission ticket is not valid` — which
names the wrong artifact entirely, and is exactly the failure mode that produced the 0.7.17–0.7.19
band (runtime #286: the SDK kept signing v1 for three releases because its own tests verified a
signature it had produced itself). **A self-consistent signature is not a conformant one.** Pin
against the vector, not against a round trip.

## Sequence

1. Vendor `conformance/request_sig_payload_vector.json` (done as part of this handoff).
2. `request_sig_payload` + `request_sig` per language, pinned by a per-language test over the vector
   — the shape `python/tests/test_call_sig_payload.py` and `ts/tests/call_sig_payload.test.ts`
   already use.
3. Wire it into the client's subject-scoped calls, behind an explicit opt-in (a session credential
   the caller installs), so a caller that has no agent key is unaffected.
4. A live check against a `deny` plane. `seam-runtime/integration/tests/subject_headers_deny.rs` is
   the end-to-end shape, and `seam-runtime/integration/src/client/http.rs::signed_post` is a working
   reference client for the HTTP half.

## Status

**Sequence steps 1–3 done; step 4 (the live `deny`-plane check) deferred.** The runtime half is
complete under #508.

- **Step 1** (vector) and **step 2** (`request_sig_payload`/`request_sig`, pinned per language
  against the vector): done. `python/seam_sdk/crypto.py` and `ts/src/crypto.ts`; conformance tests
  in `python/tests/test_request_sig_payload.py` and `ts/tests/request_sig_payload.test.ts`.
- **Step 3** (wired into the client's subject-scoped calls, behind an explicit opt-in): done, as a
  **per-call optional parameter** — `credential: Optional[Agent] = None` (Python, sync and async)
  / `credential?: Agent` (TypeScript) — rather than a session-installed default, so the opt-in is
  explicit at each call site and a caller that never passes it is provably unaffected. Wired into
  all 15 target verbs: the 5 bodyless reads (`GetDecision`, `ReplayDecision`,
  `GetCommitmentProof`, `GetEscalation`, `SessionStatus`) and 10 of the bodied verbs
  (`OpenSession`, `SubmitProposal`, `SubmitEvaluation`, `SubmitObjection`, `SubmitVote`,
  `SubmitCommit`, `SubmitApprovalRequest`, `SubmitBallot`, `CancelSession`, `ExpireSession`) —
  everything above except HTTP-only `POST /v1/archive/replay`, which neither hand-written client
  calls over HTTP. `ReportOutcome` stays excluded per this plan's own rule; `ResumeSession` is
  additionally excluded because the data-plane verb is a tombstone in this SDK (resume moved to
  the management plane, rt-D) — not itself a verb this plan's list names either way. Wiring is
  Python- and TypeScript-only: Go, Java and Kotlin do not yet carry `call_sig_payload`'s sibling,
  so they were never in scope for this pass (the plan's "four of the five languages already have"
  in the trap section above overstates it for `seam-request-call-v1` specifically — verified
  empirically rather than assumed, since only Python and TypeScript carry the primitive at all).
  Tests: `python/tests/test_credential_wiring.py` and the credential-wiring block in
  `ts/tests/unit_plumbing.test.ts` — server-free, over a recording fake transport/stub, asserting
  both that `credential=` omitted sends no metadata and that supplying it produces a ticket +
  signature that independently verifies against the credential's own Ed25519 key.
- **Step 4** (a live check against a `deny` plane): **not started, and out of scope without a live
  runtime to check against.** `seam-runtime/integration/tests/subject_headers_deny.rs` remains the
  end-to-end shape to drive this against once one is available.

Nothing regresses for a caller that does not opt in: omitting `credential` sends no metadata, and
behavior is byte-for-byte what it was before this work landed.
