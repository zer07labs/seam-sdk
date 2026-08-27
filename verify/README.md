# `seam-verify` — check Seam's claims without trusting Seam

Seam says: *"don't trust us — verify it yourself."*

This is the tool that makes that sentence mean something. It takes bytes you already hold and a public key,
and answers **yes** or **no**.

```bash
cargo run -- chain events.jsonl                                  # INTEGRITY — the hash chain links
cargo run -- chain events.jsonl --issuer aid:pubkey:ed25519:...  # AUTHENTICITY — + issuer-signed heads
cargo run -- erasure-cert cert.json --issuer aid:pubkey:ed25519:...
```

Exit **0** = verified · **1** = usage/IO error · **2** = **verification FAILED**.

---

## The dependency list is the argument

```
seam-verify
├── prost          decode protobuf
├── sha2           SHA-256 — the chain link, and the certificate's signed digest
├── ed25519-dalek  verify the issuer's signature
├── base64         the AID's key encoding, and the JSON projection's bytes
└── serde_json     the JSON projection
```

**Not one line of Seam's code.** No client, no SDK, no store, no server, no network call. A verifier that
linked Seam's own library would be *Seam checking Seam* — which is precisely what "don't trust us" says you
should not have to accept.

It is written from the two specs in `docs/`, and nothing else. `cargo tree` is the assertion: if a Seam
crate ever appears in it, the claim has quietly stopped being true.

**You do not have to use this program.** Everything it does is specified in `docs/`, precisely enough to
reimplement — that is the actual deliverable. This is a reference, and a demonstration that the spec is
sufficient.

---

## What it verifies

### 1. The audit chain — `chain <FILE>`

Seam's outbox is a hash chain. Each entry carries the head it extends (`prev_checksum`), its own digest,
and the head it produces (`checksum = SHA256(prev_checksum ‖ digest)`).

Give it the events you were sent — one per line, either the JSON projection (what a webhook delivers) or
base64 protobuf (what an outbox relay carries) — and it walks the chain from genesis:

```
CHAIN VERIFIED
  events            : 767
  links checked     : 767
  advisory (skipped): 0
  head              : 9f2c…
```

It detects a **forged, inserted, rewritten, reordered or dropped** event. Integrity alone cannot detect a
**fabricated** chain — a self-consistent chain a transport-controlling adversary rebuilt from a fork point,
whose links all hash correctly — nor a **payload rewrite** that keeps the `(prev, digest, checksum)` triple
intact. For those, add `--issuer` (below).

**Chained-ness is by field presence, never by kind.** Advisory events (`LEARNING_*`, `BUDGET_BREACH`,
`SESSION_LIFECYCLE`, `AUTHORIZE_EVALUATED`) and the off-chain `chain_anchor` carry no digest and do not
advance the head. A verifier that keys on `kind` instead breaks on the first advisory event in an
unfiltered stream.

#### AUTHENTICITY — `chain <FILE> --issuer <AID>`

Integrity proves the chain is *internally consistent*. It does not prove Seam *wrote* it: an unkeyed
SHA-256 chain over a public genesis can be rebuilt by anyone who controls the bytes you receive. `--issuer`
closes that — it upgrades the check from integrity to **authenticity**, against a key **you** pinned out of
band (Seam serves it at `GET /v1/trust/issuer-aid`):

```
CHAIN AUTHENTICATED (integrity + issuer-signed head)
  events            : 767
  links checked     : 767
  attestations      : 3 (issuer-signed)
  covered prefix    : 750 links
  records recomputed: 764 (v2/v3 record-digest recompute)
  head              : 9f2c…
```

Two things a forger cannot fake:

* **Signed chain heads.** Seam periodically signs its audit-chain `(length, head)` with the issuer key
  (`CHAIN_HEAD_ATTESTATION`). `--issuer` verifies every one against the **pinned** AID *and* checks the
  attested head is the running head at that position — so a fabricated chain (which carries no valid
  attestation) is **REFUSED**, and an authentic attestation spliced onto a different chain fails the
  position check. A stream with no attestation at all is refused, not passed: its absence is the tell.
* **Recomputable record digests.** Every v2 and v3 `DECISION_SEALED` commits to its structural columns via
  `digest = SHA256(record-digest framing)`. `--issuer` recomputes it from the payload and compares — so
  a **payload rewrite** (flip an `outcome`, keep the triple) is caught even in an unattested tail, and a
  record stripped of its `ciphertext_digest` (a downgrade) is refused. v3 additionally binds what context
  the decision consumed, who participated, and which policy rules gated it; a v3 record missing its
  `context_digest` or `participation_digest` is refused as a **STRIP**, worded distinctly from a digest
  mismatch — "someone removed a field" and "someone rewrote one" call for different responses, so the
  verifier does not blur them. A `schema_version` this build does not implement is refused outright: a
  formula it does not have is not a record it can vouch for, and "cannot check, therefore fine" is the
  shape of a downgrade.

The pin is load-bearing for exactly the reason it is on the erasure certificate (below): deriving the key
from the chain's own attestation would let a forgery verify against its forger. `--issuer` is strictly
stronger than plain `chain`, never weaker.

**`--issuer` is repeatable — key rotation.** A chain that spans an issuer-key rotation carries
attestations signed by the retired key *and* the new one. Pass `--issuer` once per trusted AID
(`--issuer <OLD> --issuer <NEW>`): an attestation verifies if it matches **any** pinned AID, and one
naming an issuer outside the pinned set is a **FAIL** — exactly as a single-pin mismatch always was. A
stream with zero valid attestations is still refused.

**A green banner is not the whole verdict — read the `unverifiable` count.** `CHAIN AUTHENTICATED` can
legitimately coexist with a disclosed non-zero `UNVERIFIABLE` count: events with no `digest`/`checksum`
that are not advisory (pre-cutover history — or a spec-condoned *tail-strip*, where chain fields were
stripped from events after the last attested head; the next link catches an interior strip, but a strip
at the very tail has no next link to catch it). The tool **discloses** these, it cannot check them. A CI
consumer parsing the `--json` output should therefore assert `verified == true` **and**
`unverifiable == 0` (or run with `--strict`, which refuses such streams outright).

> ### ⚠️ `--strict`, and why you probably want it
>
> The `digest`/`checksum` fields were added *after* Seam began emitting events. Events written before that
> carry neither — and to a verifier reading bytes, such an event is **indistinguishable from an advisory
> one**.
>
> So by default they are **skipped and counted**, and reported as `UNVERIFIABLE`. If you ignore that line,
> a green result is a claim about history that was *never actually checked*.
>
> `--strict` refuses the stream instead. **Use it, unless you know exactly why you are not.**

#### ANCHORED START — `chain <FILE> --issuer <AID> --from-anchor <FILE>`

Both checks above assume you hold the stream **from genesis**. A consumer often holds only a *window*
of it — a transport has a retention horizon, or an evidence bundle is deliberately scoped — and
`--from-anchor` verifies exactly that window, seeded from an issuer-signed `CHAIN_HEAD_ATTESTATION`
**anchor** instead of the public genesis constant:

```
seam-verify chain window.jsonl --issuer <AID> --from-anchor anchor.json
```

```
WINDOW AUTHENTICATED (issuer-anchored start)
  events            : 42
  links checked     : 42
  attestations      : 2 (issuer-signed)
  covered prefix    : 793 links
  records recomputed: 41 (v2/v3 record-digest recompute)
  anchored start    : base_len 750 / base_head 9f2c…
  covering (len > base_len): 1 (these satisfy spec clause (f4))
  head              : a01d…
```

`anchor.json` is one `CHAIN_HEAD_ATTESTATION` — either a bare six-field object (byte-for-byte one
element of the public `GET /v1/anchors` feed) or a full `seam-event.v1` event line carrying one (what
an outbox consumer already holds). **An anchored start relocates the trust root**, so it is validated
before anything is verified from it:

* the anchor's signature MUST verify against the **pinned** `--issuer` AID — an unsigned, forged, or
  wrong-issuer anchor is REFUSED (`ANCHOR REJECTED`), never silently seeded, and never falls back to
  genesis;
* a **vacuous** anchor (`attested_len == 0`) is REFUSED (`VACUOUS ANCHOR`) — it claims nothing, so
  accepting it would re-create genesis seeding through the back door.

A forger cannot mint an issuer-signed anchor over a tampered prefix, so an anchored verdict is no
weaker than a genesis one *for the window it covers* — within-window truncation, insertion, and
reorder are caught exactly as from genesis. What is different is scope: `covered prefix`/`covering`
report the window's own coverage, and **the anchor itself never counts as the attestation that
authenticates the window** — at least one attestation strictly past the anchor's position is required,
the same "zero valid attestations ⇒ REFUSE" discipline plain `--issuer` applies, re-scoped to the
window. An attestation that lands *below* the window (a legitimate race: the head is read, signed, and
appended without a lock, so the chain can advance underneath it) is signature-verified but not
checkable against a window that does not contain it — it is skipped and reported (`below_window`),
never silently dropped and never treated as covering.

`docs/seam-event.v1.md` §"Anchored verification (clause (f))" is the full normative text this
implements.

### 2. A GDPR erasure certificate — `erasure-cert <FILE> --issuer <AID>`

When Seam erases a data subject, it destroys the encryption key (the ciphertext is unreadable forever) and
issues a **signed certificate**: what was erased, what was withheld under legal hold, when, and the
audit-chain head at that moment.

```
ERASURE CERTIFICATE VERIFIED
  subject   : aid:pubkey:ed25519:…
  erased    : 42 decision(s)
  held      : 3 (withheld under legal hold — NOT erased)
  erased_at : 1700000000000
```

**The `--issuer` pin is load-bearing.** Get the AID out of band — Seam serves it at
`GET /v1/trust/issuer-aid` — and pass it yourself.

A certificate is verified against the key it *names*. If you let the certificate supply its own issuer, the
check is **tautological**: an attacker forges a certificate, signs it with their own key, names their own
AID, and it verifies perfectly — against themselves. A signature only means something relative to a key you
already trusted. The pin is where that trust enters.

`fixtures/erasure_certificate_vector.json` is a real signature, produced by the real signer. Verify it, and
you have checked this tool against something you did not have to take on faith.

---

## What it cannot tell you

Stated plainly, because a verifier that oversells itself is worse than none:

* **It cannot prove you were sent everything.** A chain that verifies is internally consistent; if Seam
  never handed you events 500–600, the events you *do* hold still chain. `--issuer` narrows this — a signed
  head pins the length and content of the prefix it covers, so a truncation *below* an attestation is
  caught — but beyond the last attested head, the published anchor (`docs/audit-anchor.md`) is still what
  pins a head at a time so a truncated history fails to reach it.
* **It cannot read your decisions.** The digest is over the *sealed* record. The plaintext is not on the
  wire, by design — verification discloses nothing.
* **It cannot verify pre-cutover history** (see `--strict` above). It will say so rather than pretend.

---

## Layout

| | |
|---|---|
| `docs/seam-event.v1.md` | the wire format and the chain rule — **normative**, a verbatim pinned copy of the runtime's spec (see Drift) |
| `docs/erasure-certificate.v1.md` | the certificate signing framing — **normative** |
| `docs/audit-anchor.md` | the out-of-band anchor |
| `proto/seam/event/v1/seam_event.proto` | the canonical protobuf schema |
| `fixtures/erasure_certificate_vector.json` | a real signed certificate to check against |
| `src/` | the reference implementation (~600 lines) |

## Drift

The runtime carries a second implementation of this check, and a **differential test** drives both over the
same streams — including streams produced by Seam's real seal path — and fails if their verdicts ever
diverge. It covers **both** surfaces: integrity *and* `--issuer` authenticity (a genuine attested chain, a
fabricated one, a payload rewrite, a spliced attestation — the two verifiers must agree on all four). It
runs in the runtime's CI against this public verifier, so drift is caught at the source.

That test exists because a hand-transcribed verifier that quietly stops matching the encoder is worse than
no verifier at all: it becomes a rubber stamp that agrees with everything, including a forgery.

`docs/seam-event.v1.md` is the other half of the same problem, and it drifted for longer. It is a **pinned,
byte-identical copy** of `seam-runtime/docs/specs/seam-event.v1.md`, and its header names the commit — but
for a long time nothing checked that claim, and it went stale three times. Once it omitted an advisory event
kind, which shipped a real verifier bug. That matters here specifically: if you have no `seam-runtime`
checkout, this file is the spec you build against, so a stale copy describes a verifier other than the one
you are running.

`scripts/check_vendored_spec.py` now checks it against the real repository (the `spec-pin` CI job):
byte-identical at the pinned commit, that commit reachable from the ref the header names, and
byte-identical to that ref's tip. Drift is red and blocks the merge. Run it yourself with
`python scripts/check_vendored_spec.py --from local:../seam-runtime` if you have a sibling checkout, or
`--from gh` to read the repository directly.

One honest limit: `seam-runtime` is private, so the job reads it with a short-lived App token and **skips**
on a pull request that cannot see the org's secrets (a fork). Drift introduced that way is caught on the
next push to `main` rather than at merge time. The job is also only triggered by pushes and pull requests here — if this repo goes quiet while the
runtime spec moves, nothing notices until the next push.

The copy may deliberately sit **ahead** of the runtime's default branch, which happens when this verifier
implements something whose spec text is still on an unmerged runtime branch. When it does, the header must
say so explicitly (`tracking <branch>`) and the gate refuses an undeclared one. The declaration expires by
itself, three ways: the branch stops existing, the pinned commit reaches the default branch, or the file
becomes byte-identical on both refs — the last being what catches a squash or rebase merge, where the
pinned commit never appears on the default branch at all.

## Licence

Apache-2.0.
