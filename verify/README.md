# `seam-verify` — check Seam's claims without trusting Seam

Seam says: *"don't trust us — verify it yourself."*

This is the tool that makes that sentence mean something. It takes bytes you already hold and a public key,
and answers **yes** or **no**.

```bash
cargo run -- chain events.jsonl                                  # INTEGRITY — the hash chain links
cargo run -- chain events.jsonl --issuer aid:pubkey:ed25519:...  # AUTHENTICITY — + issuer-signed heads
cargo run -- erasure-cert cert.json --issuer aid:pubkey:ed25519:...
cargo run -- bundle ./evidence --issuer aid:pubkey:...           # an evidence bundle, end to end
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

It is written from the specs in `docs/` (plus the runtime's `seam-commitment-digest.v2.md`, which the bundle
spec cites and the shared `conformance/` vectors pin), and nothing else, with the one named exception below.
`cargo tree` is the assertion: if a Seam crate ever appears in it, the claim has quietly stopped being true.

**The named exception: the (b′) entry preimages.** Spec clause (b′) requires `--issuer` to recompute every
chained `AUDIT_ENTRY`, `CHAIN_HEAD_ATTESTATION` and `ERASURE_CERTIFICATE`, but the spec's text points at the
runtime's own code for how, instead of carrying it. Until the spec carries them (seam-runtime#1561), five
things are **transcribed** from seam-runtime `crates/seam-verify/src/entry.rs` @ `37576658`: the action-entry
framing, the `seam.audit.chain-attest-entry.v1` and `seam.audit.erasure-cert.v2` framings, the action→domain
table, and the action→classification map. They were read, not linked, so `cargo tree` is unchanged. They are
checked against vectors the runtime's own code produced (`tests/goldens/entry_domains*.jsonl`), not against
a second transcription. `DECISIONS.md` D-043 records the carve-out and when it ends: a test turns red with
"retire the D-043 carve-out" once the vendored spec carries the tables.

**You do not have to use this program.** Everything it does is specified in `docs/`, precisely enough to
reimplement, apart from the exception above — that is the actual deliverable. This is a reference, and a
demonstration that the spec is sufficient.

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
  unverified content: 0 (every link's kind is modelled by this build)
  head              : 9f2c…
```

It detects a **forged, inserted, rewritten, reordered or dropped** event. Integrity alone cannot detect a
**fabricated** chain — a self-consistent chain a transport-controlling adversary rebuilt from a fork point,
whose links all hash correctly — nor a **payload rewrite** that keeps the `(prev, digest, checksum)` triple
intact. For those, add `--issuer` (below).

**Chained-ness is by field presence, never by kind.** Advisory events (`LEARNING_*`, `BUDGET_BREACH`,
`SESSION_LIFECYCLE`, `AUTHORIZE_EVALUATED`, `POLICY_DENIED`) and the off-chain `chain_anchor` carry no
digest and do not
advance the head. A verifier that keys on `kind` instead breaks on the first advisory event in an
unfiltered stream.

**Payload binds to kind** (seam-event.v1, runtime A4). Each payload field belongs to exactly one kind, and
a known kind carries its own. An event carrying another kind's payload, or a known kind without its own,
is refused with `KIND/PAYLOAD MISMATCH`. An advisory event or the `chain_anchor` that carries
`digest`/`checksum` is refused with `ADVISORY EVENT WITH CHAIN FIELDS`, never linked. Both refusals apply
to `chain` (plain, `--strict` and `--issuer`) and to `bundle`, and exit 2; `erasure-cert` checks only the certificate
(D-041).

**A `kind` this build has never seen is still verified — and still disclosed.** `seam-event.v1` grows
kinds additively, so a stream can legitimately outrun the verifier reading it. Such an event is a link
like any other (the link check needs no payload semantics; skipping it would falsely report the chain
broken at the *next* link) — but its digest cannot be recomputed from a payload this build cannot parse.
That costs **content** coverage, not linkage, and the `unverified content` line above says so on every
run, zero included, naming the kinds:

```
  unverified content: 2 link(s) of unmodelled kind: GRAPH_COMMIT, RETENTION_HOLD (first seq 2)
                      LINKAGE verified — folded into the head above, exactly as for a kind
                      this build models. CONTENT not verified: no payload model, so the
                      digest was not recomputed, and these are in NO recompute count.
```

Do not try to infer this from `links` minus `records recomputed`: that difference is already non-zero on
a healthy stream, because `records recomputed` counts only `DECISION_SEALED`. Plain `chain` recomputes no
entry digest at all. Under `--issuer`, `AUDIT_ENTRY`, `ERASURE_CERTIFICATE` and `CHAIN_HEAD_ATTESTATION`
are recomputed and counted on their own line, `entries recomputed` (below). Under `--json` the same
disclosure is `"unverified_content"` (a count) and `"unmodelled_kinds"` (the distinct names).

Under `--issuer`, a link of an unmodelled kind is **uncovered** as well, and refused (below): a build
that cannot read a payload cannot vouch for it.

`unverified content` is a claim about **kinds**, not actions. Without `--issuer`, an `AUDIT_ENTRY` whose
`action` this build does not know still shows `unverified content: 0`: its kind is modelled, and plain
`chain` recomputes no entry, whatever its action. The action-level claim, "every chained entry was
recomputed", exists only under `--issuer`, where such an entry is counted under `uncovered` and refused.

`--strict` does **not** refuse on this. It refuses on a different thing — non-advisory events carrying
no chain fields at all — and a stream that merely outran your verifier is not the same failure as
history nobody can check. The spec permits refusing (a MAY) and requires disclosing (a MUST); this tool
discloses, and leaves refusing to the caller, who has the number.

#### AUTHENTICITY — `chain <FILE> --issuer <AID>`

Integrity proves the chain is *internally consistent*. It does not prove Seam *wrote* it: an unkeyed
SHA-256 chain over a public genesis can be rebuilt by anyone who controls the bytes you receive. `--issuer`
closes that — it upgrades the check from integrity to **authenticity**, against a key **you** pinned out of
band (Seam serves it at `GET /v1/trust/issuer-aid`). Over `tests/goldens/entry_domains.jsonl`, a stream the
runtime's own code wrote with one entry from every audit writer, an erasure certificate, and signed heads for
three tenants:

```
seam-verify chain tests/goldens/entry_domains.jsonl --issuer aid:pubkey:1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No
```

```
CHAIN AUTHENTICATED (integrity + issuer-signed head, per tenant)
  events            : 25
  links checked     : 0 (top-level — N/A across 3 tenants, see below)
  advisory (skipped): 0
  unverified content: 0 (every link's kind is modelled by this build)
  entries recomputed: 19 (audit, attestation and erasure entry digests)
  uncovered         : 0
  tenants           : 3
    "": links 2, head ed218495295782755877f245fd62fde9881ed93258439ba9e68c8c26fc4f3aaf
      attestations 1 (issuer-signed), covered prefix 1 links, records recomputed 0, entries recomputed 2, uncovered 0
    "acme": links 19, head f1a9f53f8b5ed5c6d2ac43b080bbc603a88da339651c49d3c0f716948022faab
      attestations 1 (issuer-signed), covered prefix 18 links, records recomputed 5, entries recomputed 14, uncovered 0
    "beta": links 4, head 4d970cd71e545b68637f3a7bfdcc28d1dabe254ebe3e2e7aeca520aef0421f0c
      attestations 1 (issuer-signed), covered prefix 3 links, records recomputed 1, entries recomputed 3, uncovered 0
```

A single-tenant stream prints `attestations`, `covered prefix` and `records recomputed` as top-level lines
instead, and its `head`. `entries recomputed` and `uncovered` are printed on every `--issuer` run, zero
included, for the same reason as `unverified content`: a coverage line that disappears at zero cannot be
told apart from one that was never measured.

Three things a forger cannot fake:

* **Signed chain heads.** Seam periodically signs its audit-chain `(length, head)` with the issuer key
  (`CHAIN_HEAD_ATTESTATION`). `--issuer` verifies every one against the **pinned** AID *and* checks the
  attested head is the running head at that position — so a fabricated chain (which carries no valid
  attestation) is **REFUSED**, and an authentic attestation spliced onto a different chain fails the
  position check. A stream with no attestation at all is refused, not passed: its absence is the tell.
  **Each attestation is bound to its tenant** (seam-runtime #835 step 4): its payload `tenant` must
  equal its envelope's — an empty payload tenant under a named envelope included — or it is refused as
  `ATTESTATION TENANT MISMATCH`, with or without `--strict`; and its signature must verify under the one
  framing that tenant selects, v2 (tenant inside the signature) for a named tenant and v1 for the empty
  system partition, with no fallback. A tenant attestation minted before the runtime signed v2 (#835
  step 3) is v1 and is therefore **refused**: verify that history from a v2 anchor onward
  (`--from-anchor`, below).
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
* **Recomputed entries** (spec clause (b′), runtime A4). Every other chained entry is recomputed from its
  own fields too: an `AUDIT_ENTRY` under the domain its `action` selects, a `CHAIN_HEAD_ATTESTATION` under
  `seam.audit.chain-attest-entry.v1`, and an `ERASURE_CERTIFICATE` under `seam.audit.erasure-cert.v2`. A
  field rewritten after chaining (an actor, a session, an attested head, an erased id) leaves the link
  hashing but no longer recomputes its digest, and is refused as `ENTRY REWRITE`. **The envelope
  classification is bound** too. It sits outside the digest, so the label is fixed by the action or kind
  instead (`Pii` for `gdpr_erasure` and the certificate; `Confidential` for `execute.scope_deny` and
  `boundary.data_flagged`; `Internal` for every other action and the attestation; matched as exact,
  case-sensitive bytes), and a relabel is an `ENTRY REWRITE` as well. The recompute runs over the whole
  window before any attestation is checked, so an entry below an attested head is caught too. The
  `--from-anchor` / `--expect-anchor` document and the `erasure-cert` subcommand are not window links, and
  are not entry-recomputed: the anchor is checked by its signature, and `erasure-cert` checks the
  certificate's signature as it always has.

**An entry this build cannot recompute is refused, not passed.** An `AUDIT_ENTRY` with an action this
build has no domain for, a `fact_appended` entry (the runtime leaves it uncovered too), or a chained link
of a kind it does not model is **uncovered**: its content was never checked. Spec (b′) refuses it under
`--issuer`, and so does this build, in the library as well as the CLI and `bundle`:

```
REFUSED (--issuer)

UNCOVERED ENTRY — 1 chained entry carries an action or kind this build cannot recompute, so its content is unverified, and --issuer refuses to report a green chain over content it never checked (spec (b′): uncovered is REFUSED under --issuer). A rewritten entry relabelled to an unknown action would otherwise verify. A newer producer needs a newer seam-verify.
  seq 7, tenant "acme", kind "AUDIT_ENTRY", action "hold_extended"
  (`chain --issuer <AID> --allow-uncovered` prints a diagnostic report of them; it still exits 2)
```

(That is `entry_domains.jsonl` with one `hold_placed` relabelled `hold_extended`. Plain `chain` still
passes it, with `unverified content: 0`: the link hashes and the kind is modelled.) `--strict` does not
change this, and one uncovered entry in any tenant refuses the whole call.

**`--allow-uncovered` is a diagnosis, never a pass.** It is accepted only on `chain`, only with
`--issuer`, and never with `--json` (each is a usage error, exit 1). On the same stream it prints the full
report under a banner that says neither VERIFIED nor AUTHENTICATED, lists each uncovered entry, and **still
exits 2**:

```
AUTHENTICITY NOT ESTABLISHED: 1 uncovered chained entry (--allow-uncovered diagnostic report)
  events            : 25
  links checked     : 0 (top-level — N/A across 3 tenants, see below)
  advisory (skipped): 0
  unverified content: 0 (every link's kind is modelled by this build)
  entries recomputed: 18 (audit, attestation and erasure entry digests)
  uncovered         : 1
    seq 7, tenant "acme", kind "AUDIT_ENTRY", action "hold_extended"
  tenants           : 3
    "": links 2, head ed218495295782755877f245fd62fde9881ed93258439ba9e68c8c26fc4f3aaf
      attestations 1 (issuer-signed), covered prefix 1 links, records recomputed 0, entries recomputed 2, uncovered 0
    "acme": links 19, head f1a9f53f8b5ed5c6d2ac43b080bbc603a88da339651c49d3c0f716948022faab
      attestations 1 (issuer-signed), covered prefix 18 links, records recomputed 5, entries recomputed 13, uncovered 1
    "beta": links 4, head 4d970cd71e545b68637f3a7bfdcc28d1dabe254ebe3e2e7aeca520aef0421f0c
      attestations 1 (issuer-signed), covered prefix 3 links, records recomputed 1, entries recomputed 3, uncovered 0
```

Over a stream with nothing uncovered the flag changes nothing: normal banner, exit 0. **This differs from
the runtime's verifier**, whose `--allow-uncovered` prints its AUTHENTICATED banner and exits 0 over an
uncovered entry. That is a green claim over content nobody checked, which spec §Versioning forbids
(seam-runtime#1561); here exit 0 means verified and nothing else (D-042). The `--json` shape is unchanged:
no `entries recomputed` or `uncovered` keys, and a rewrite or uncovered entry arrives as
`{"verified":false,"error":…}`, exit 2.

**Three more places this build and the runtime's verifier differ**, all on purpose (D-042):

* **Unchained seals.** A `DECISION_SEALED` with no chain fields whose `schema_version` is not 4, or that
  lacks `ciphertext_digest`, is refused here under `--issuer` (exit 2). The runtime's verifier skips it: it
  checks only events carrying a payload, a digest and a checksum. Spec clause (c) and §Versioning refuse
  such a record with no link qualifier.
* **The first defect named.** This build recomputes every entry before it checks any attestation; the
  runtime does both per event, in sequence order. On a stream with an attestation defect at seq 3 and a
  rewritten entry at seq 9, the runtime names the attestation and this build names the `ENTRY REWRITE`.
  Both exit 2, and on a single-defect stream they agree.
* **Library placement.** The uncovered refusal lives in the library, so an embedder and `bundle` get it
  too; the runtime refuses in its CLI only. An embedder can opt into the diagnostic with
  `AuthOptions::allow_uncovered`, and the `Ok` it gets back is a report, not an authentication.

**No `chain --bridge`.** The runtime's verifier has a bridge mode (verifying a tenant's chain across a cell move), with
A4 obligations of its own. This crate has no bridge mode, so there is nothing for them to attach to;
porting it is a separate feature, out of scope here.

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

Over the runtime-produced window in `tests/goldens/`:

```
seam-verify chain tests/goldens/entry_domains.window.jsonl --issuer aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw --from-anchor tests/goldens/entry_domains.anchor.json
```

```
WINDOW AUTHENTICATED (issuer-anchored start)
  events            : 4
  links checked     : 4
  advisory (skipped): 0
  unverified content: 0 (every link's kind is modelled by this build)
  attestations      : 2 (issuer-signed)
  covered prefix    : 5 links
  records recomputed: 2 (v4 record-digest recompute)
  anchored start    : base_len 2 / base_head d87a7ef9f47d5040ae7bef93f4df00879d0b4a890ffb675cba9f63e47029a914
  covering (len > base_len): 1 (these satisfy spec clause (f4))
  entries recomputed: 2 (audit, attestation and erasure entry digests)
  uncovered         : 0
  head              : 8930c13a371a3e4bbe79bcababd4ba85c4f3014ad321d790c894d40a3a185442
```

`anchor.json` is one `CHAIN_HEAD_ATTESTATION` — either a bare anchor object (byte-for-byte one element
of the public `GET /v1/anchors` feed) or a full `seam-event.v1` event line carrying one (what an outbox
consumer already holds). **An anchored start relocates the trust root**, so it is validated before
anything is verified from it:

* the anchor's signature MUST verify against the **pinned** `--issuer` AID — an unsigned, forged, or
  wrong-issuer anchor is REFUSED (`ANCHOR REJECTED`), never silently seeded, and never falls back to
  genesis;
* a **vacuous** anchor (`attested_len == 0`) is REFUSED (`VACUOUS ANCHOR`) — it claims nothing, so
  accepting it would re-create genesis seeding through the back door;
* the anchor seeds **exactly the tenant it names** — the tenant inside its v2 signature — and every
  other tenant in the window is walked from genesis. An anchor with no tenant is a v1 signature and
  seeds only the system partition (`""`), never a tenant's chain; over a window with no `""` chain it
  is refused (`NO VALID ATTESTATION`). A full-event anchor whose payload tenant differs from its
  envelope's is refused (`ANCHOR SELF-CONTRADICTS`). The same attribution applies to
  `--expect-anchor`.

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

### 3. An evidence bundle — `bundle <DIR> --issuer <AID>`

An evidence bundle (`docs/evidence-bundle.v1.md`) is what an operator hands an **adverse party**: someone
who disputes a decision, has no runtime access, and has no reason to trust the operator. It is one flat
directory, produced by `seam-ops export-evidence --decision <id> --bundle <DIR>`:

| File | |
|---|---|
| `manifest.json` | the index: per-file SHA-256 and size, the decision's coordinates, what was disclosed and withheld. **Unsigned** |
| `events.jsonl` + `anchor.json` | the anchored window around the decision (the `chain --from-anchor` shape) |
| `commitment.json` | the decrypted Commitment and its TCT |
| `binding.json` | the issuer's signed statement that *this* Commitment is the content of *that* chain link |
| `context.json`, `policy.json` | opt-in disclosures of what the decision consumed and which rules gated it |

```
EVIDENCE BUNDLE VERIFIED (seam-evidence-bundle.v1)
  decision  : dec:d1
  tenant    : design-partner
  head      : f8c1…
  - manifest: seam-evidence-bundle.v1, issuer is the pinned AID, every listed file matches its SHA-256 and size
  - window authenticated from the issuer-signed anchor (base_len 2): 4 link(s), 1 covering attestation(s)
  - decision 'dec:d1' is a chained link of tenant 'design-partner' inside the authenticated window
  - the Commitment's TCT verifies against the pinned issuer and binds its seam-commitment-digest:v3
  - the issuer's signed binding ties this Commitment to the decision's chain link
  - context.json recomputes the chained context_digest
  - SHA-256(policy.json) is the chained policy_rules_digest
  - withheld: participation (participation[].subject is the GDPR erasure predicate; …)
```

The six steps run in the spec's order and the first failure refuses with exit 2, naming the step:

1. **Manifest** — `format` is `seam-evidence-bundle.v1` (any other is refused), `issuer.aid` is the AID
   **you** pinned, every listed file exists with its listed SHA-256 and size, `events.jsonl` and
   `anchor.json` are listed, `commitment.json`/`binding.json` come as a pair, and `disclosed` agrees with
   `files`. A listed member that is missing is a refusal, not an IO error.
2. **Chain** — the window, through exactly the code `chain events.jsonl --issuer <AID> --from-anchor
   anchor.json --strict` runs: the anchor's signature, every link, every attestation, a covering one.
3. **Inclusion** — exactly one chained `DECISION_SEALED` for the manifest's decision, in its tenant, whose
   checksum is `inclusion.record_checksum`.
4. **Commitment** — the self-attestation TCT verifies against the pinned AID (`iss == sub == aud`,
   grants exactly `["aitp.attestation"]`) and its `ext` binding carries the recomputed
   `seam-commitment-digest:v3` (the sealed explanation included, so a re-worded reason fails), and
   `supersedes` matches the chained record. A Commitment with no TCT (`identity: local-sealed`) is bound
   by step 5 alone, and the output says so.
5. **Binding** — the `seam.evidence-binding.v1` signature verifies against the pinned AID, and it names
   this decision, tenant, chain link and Commitment digest.
6. **Disclosures** — `context.json` recomputes the chained `context_digest`; `SHA-256(policy.json)` is the
   chained `policy_rules_digest`.

What was **withheld** is printed with the exporter's reason: it is part of what the adverse party is told.
The manifest is an index, never evidence — every claim in it that this tool reads is re-derived from the
other files, and trust enters only through `--issuer`. Exactly one `--issuer` is accepted.

`fixtures/evidence-bundle/` holds four bundles written by the runtime's own exporter (a full one, one with
no disclosures, one whose record was crypto-shredded, and one from another issuer). They also verify under
the runtime's internal oracle. `tests/bundle.rs` copies them and makes one edit per case, covering a
refusal at every step.

---

## What it cannot tell you

Stated plainly, because a verifier that oversells itself is worse than none:

* **It cannot prove you were sent everything.** A chain that verifies is internally consistent; if Seam
  never handed you events 500–600, the events you *do* hold still chain. `--issuer` narrows this — a signed
  head pins the length and content of the prefix it covers, so a truncation *below* an attestation is
  caught — but beyond the last attested head, the published anchor (`docs/audit-anchor.md`) is still what
  pins a head at a time so a truncated history fails to reach it.
* **It cannot read your decisions.** The digest is over the *sealed* record. The plaintext is not on the
  wire, by design — verification discloses nothing. A bundle is the exception the operator chooses: it
  discloses the Commitment, and the binding proves it is the sealed content of the link.
* **It cannot prove a bundle disclosed everything.** Withheld items are listed with a reason, and the
  participation list is always withheld. A v1 verifier also does not check a disclosure file the v1 spec
  does not define; an unknown `format` is refused.
* **It cannot verify pre-cutover history** (see `--strict` above). It will say so rather than pretend.
* **It cannot tell a newer entry domain from a rewrite.** No entry domain is carried on the wire, and the
  runtime plans no discriminator. If the runtime ever bumps one (a `seam.audit.chain-attest-entry.v2`, say),
  its entries will not recompute under this build's domain and are refused as `ENTRY REWRITE`, not as
  uncovered. The refusal is still correct (nothing green is claimed), but its wording is wrong for that
  case. If a stream from a newer runtime reads as `ENTRY REWRITE` on every entry of one kind, try a newer
  `seam-verify` before concluding it was tampered with.

---

## Layout

| | |
|---|---|
| `docs/seam-event.v1.md` | the wire format and the chain rule — **normative**, a verbatim pinned copy of the runtime's spec (see Drift) |
| `docs/erasure-certificate.v1.md` | the certificate signing framing — **normative** |
| `docs/evidence-bundle.v1.md` | the evidence bundle and its binding framing — **normative**, a verbatim pinned copy of the runtime's spec (see Drift) |
| `docs/audit-anchor.md` | the out-of-band anchor |
| `proto/seam/event/v1/seam_event.proto` | the canonical protobuf schema, a byte-verbatim copy of seam-runtime `crates/seam-api/proto/seam/event/v1/seam_event.proto` @ `37576658` (it has no header to carry a pin, so the commit is recorded here; not checked by `check_vendored_spec.py`) |
| `fixtures/erasure_certificate_vector.json` | a real signed certificate to check against |
| `fixtures/evidence-bundle/` | four real bundles from the runtime's exporter (byte-exact: `.gitattributes` keeps git off them) |
| `src/` | the reference implementation |

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
`--from gh` to read the repository directly. `docs/evidence-bundle.v1.md` is pinned and checked the same
way.

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
