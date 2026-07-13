# Erasure-certificate signing framing — `seam.erasure-certificate.v1`

**Status:** Normative (v1). The exact byte framing an **erasure certificate** (enterprise 2.6 — GDPR
right-to-erasure attestation) is signed over, so a **data subject or regulator can verify it from the
published issuer key alone**, with **zero Seam state** — the same trust story as the TCT and the audit
anchor. This document exists because the certificate's entire value is third-party verifiability: the
framing must be written down, not left as one implementation's Rust.

> The reference implementation is `seam-trust-aitp::erasure_payload` / `verify_erasure_certificate`
> (`crates/seam-trust-aitp/src/lib.rs`). This spec and that code are pinned together by a **signed
> reference vector** (`crates/seam-trust-aitp/tests/fixtures/erasure_certificate_vector.json`): any
> implementation, in any language, is correct **iff it verifies that vector**.

## The certificate

```
ErasureCertificate {
  subject:     string    // the data subject the request named (an AID or operator-scoped subject id)
  erased:      [string]  // decision ids whose keys are destroyed (crypto-shredded) — ORDER IS SIGNED
  held:        [string]  // decision ids NOT erased because a legal hold pins them — disclosed, not silent
  erased_at:   u64       // injected wall time of the erasure run (millis)
  chain_head:  bytes     // the audit-chain head at certification (anchors the cert to the shred ledger)
  issuer_aid:  string    // the issuer's AID handle (see "Issuer AID form" below)
  signature:   bytes     // Ed25519 over the 32-byte digest below
}
```

## Signing framing

Let `put(x)` feed a length-prefixed field into a running SHA-256:

```
put(x)  ≡  SHA256.update( u32le( len(x) ) ) ;  SHA256.update( x )
```

The signed digest is `SHA256` of, **in this exact order**:

```
put("seam.erasure-certificate.v1")     # ASCII, no NUL terminator — the domain tag is length-PREFIXED
put(subject)                           # UTF-8 bytes
put(u32le(len(erased)))                # the COUNT is itself put(): u32le(4) ‖ u32le(count)
for id in erased:  put(id)             # in list order
put(u32le(len(held)))                  # likewise a put() of a 4-byte count
for id in held:    put(id)             # in list order
put(u64le(erased_at))                  # 8-byte little-endian, wrapped by put() → u32le(8) ‖ u64le(ts)
put(chain_head)                        # raw bytes
put(issuer_aid)                        # UTF-8 bytes of the AID string

digest    = SHA256.finalize()          # 32 bytes
signature = Ed25519_sign(issuer_key, digest)   # signs the DIGEST, not the framed byte string
```

Three details are invisible from the wire and each **fails every genuine certificate** if guessed wrong
(the failure is asymmetric — a wrong framing can only *defame* a real certificate, never forge a false
`VERIFIED`, because Ed25519 does not verify by accident):

1. the domain tag is **length-prefixed**, not NUL-terminated;
2. the `erased` / `held` **counts are themselves `put()`** — `u32le(4) ‖ u32le(count)`, not a bare count;
3. **Ed25519 signs the 32-byte SHA-256 digest**, not the framed byte string.

## Issuer AID form

`issuer_aid` is the **untagged** `aid:pubkey:<base64url>` form (aitp's native `SigningKey::aid()`) —
**NOT** the algorithm-tagged `aid:pubkey:ed25519:<…>` form used for *subject/agent* AIDs. It is byte-for-byte
the same string the platform publishes as the TCT issuer AID (`GET /v1/trust/issuer-aid`) and embeds in
every TCT, so a regulator comparing the certificate's issuer against the published handle sees an exact
match. Getting this wrong makes every certificate read as `UNKNOWN_ISSUER` ("we could not verify these")
when the truth is a misconfigured verifier — a materially different auditor finding. Verification binds at
the **key** level (parse AID → ed25519 pubkey → check it signed the digest), so the textual form is not
security-relevant, only its stability is.

## Verification (any language, zero Seam state)

```
1. parse issuer_aid → ed25519 public key K       # reject if it doesn't parse to 32 key bytes
2. assert K == the published issuer key           # the key the subject/regulator already holds
3. digest = the framing above over the cert's fields
4. assert Ed25519_verify(K, digest, signature)    # any tampered id/order/count/head/time fails here
```

## Reference vector

`crates/seam-trust-aitp/tests/fixtures/erasure_certificate_vector.json` is a real signature from
`ErasureSigner::from_seed([7u8; 32])` (also mirrored at
`seam-connectors/contract/golden/erasure-certificate/signed_reference_vector.json`). Its `chain_head` is
32 bytes of `0xCC`; its `issuer_aid` is the untagged form. The test
`the_published_reference_vector_regenerates_and_verifies` regenerates it byte-for-byte from the framing and
verifies it with `verify_erasure_certificate` — closing the loop between this document and the code.
