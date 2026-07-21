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
`SESSION_LIFECYCLE`) and the off-chain `chain_anchor` carry no digest and do not advance the head. A
verifier that keys on `kind` instead breaks on the first advisory event in an unfiltered stream.

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
  records recomputed: 764 (v2 digest-v2 recompute)
  head              : 9f2c…
```

Two things a forger cannot fake:

* **Signed chain heads.** Seam periodically signs its audit-chain `(length, head)` with the issuer key
  (`CHAIN_HEAD_ATTESTATION`). `--issuer` verifies every one against the **pinned** AID *and* checks the
  attested head is the running head at that position — so a fabricated chain (which carries no valid
  attestation) is **REFUSED**, and an authentic attestation spliced onto a different chain fails the
  position check. A stream with no attestation at all is refused, not passed: its absence is the tell.
* **Recomputable record digests.** Every v2 `DECISION_SEALED` commits to its structural columns via
  `digest = SHA256(record-digest-v2 framing)`. `--issuer` recomputes it from the payload and compares — so
  a **payload rewrite** (flip an `outcome`, keep the triple) is caught even in an unattested tail, and a v2
  record stripped of its `ciphertext_digest` (a downgrade) is refused.

The pin is load-bearing for exactly the reason it is on the erasure certificate (below): deriving the key
from the chain's own attestation would let a forgery verify against its forger. `--issuer` is strictly
stronger than plain `chain`, never weaker.

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
| `docs/seam-event.v1.md` | the wire format and the chain rule — **normative** |
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

## Licence

Apache-2.0.
