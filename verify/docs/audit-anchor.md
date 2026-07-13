# Audit-chain anchor — language-neutral spec

**Status:** Normative. The **notary** that produces anchors is an **external** service (or an
RFC 3161 TSA / public ledger); its value is independence, so it never runs in-process with a local
key. The runtime only **emits chain heads**. **Verification** is folded into `seam-trust-aitp`
(`verify_anchor` / `PartyRegistry`) — the same Ed25519 primitive.

This spec is the on-the-wire anchor format so any-language verifiers can check an anchor with only the
issuer's public key.

## Anchor

```
Anchor {
  chain_head:       bytes    // the audit-chain head being attested
  timestamp_millis: u64      // when the notary anchored it (injected; never wall-clock-read in core)
  signature:        bytes    // 64-byte Ed25519 signature over `payload` below
}
```

## Signing payload

The signature is over a 32-byte SHA-256 digest:

```
payload = SHA256( chain_head || little_endian_u64(timestamp_millis) )
```

- `chain_head` bytes first, verbatim.
- Then the 8-byte little-endian encoding of `timestamp_millis`.

## Verification

Given the issuer's Ed25519 public key `vk`:

1. The `signature` must be exactly 64 bytes (else reject).
2. Recompute `payload` from `chain_head` and `timestamp_millis`.
3. Accept iff Ed25519-verify(`vk`, `payload`, `signature`) succeeds.

A cross-party registry maps `party_id → vk` (operator-managed config, cached per R7); an anchor from
an unknown party verifies to `false`.
