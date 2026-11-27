#!/usr/bin/env python3
"""Emit `conformance/tct_sealed_at_vector.json` — the cross-language evidence-grade seal-binding vector.

Deep-cleanup S-4 (seam-runtime #2031, 0.123.0). A seal-key TCT's `iat` is self-asserted: a leaked seal
key can mint a token backdated anywhere inside its certificate window. The evidence-grade check binds it
to the record's chained seal time — the `sealed_at` of the `DECISION_SEALED` link, bound by the record
digest, never a value from the token:

    0 <= sealed_at_ms <= i64::MAX   and   iat == floor(sealed_at_ms / 1000)
    and   jti == derived_uuid("seam-tct-jti-v1", be32(len decision_id) || decision_id || be64(sealed_at_ms))

The `jti` clause is seam-runtime 0.127.0 P4 (`seam-commitment-digest.v6.md` §Seal key step 7): `decision_id`
is the chained record's id, never `Commitment.id`, and it is what refuses a genuine seal replayed onto
another record, or with `sealed_at` shifted inside its second (same `iat`, different `jti`).

Normative source: seam-runtime `seam_trust_aitp::check_commitment_sealed_for` (it refuses a `sealed_at_ms`
beyond i64) and seam-sdk `verify/src/commitment.rs::verify_tct_sealed_at`. Every SDK
verifier's sealed_at variant (Python `verify_tct(..., sealed_at_ms=)`, TS `verifyTct(..., {sealedAtMs})`,
Go `VerifyTCTSealedAt`, Java/Kotlin `SeamCrypto.verifyTctSealedAt`, Rust `verify_tct_sealed_at`) answers
every case here.

The runtime ships no dedicated sealed_at vector, so this one is derived — reproducibly — from the
runtime's own byte-identical signed vector: case `OVER` of `commitment_digest_v6_signed_vector.json`,
which the runtime minted at `seal_ms` with `iat = seal_ms / 1000` and `jti` derived over its generator's
`RECORD_ID` (`crates/seam-trust-aitp/tests/commitment_digest_v6_vector.rs`). The source vector does not
carry that id, so it is recorded here and asserted against the token's own `jti`. The token is not copied: a consumer
verifies that vector case's `signed_artifact` over its `commitment` (+ `trailers`) with each
`sealed_at_ms` below. Every `expect` is computed from the rule above out of the token's own `iat`, never
by running an SDK. `sealed_at_ms` is a decimal string, because the beyond-i64 case does not survive a
JSON double.

Run: `python scripts/emit_tct_sealed_at_vector.py` (writes the file; `--check` exits 1 on drift).
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = "conformance/commitment_digest_v6_signed_vector.json"
OUT = REPO / "conformance" / "tct_sealed_at_vector.json"
OVER = "v6_ungoverned"
I64_MAX = 2**63 - 1
#: The record id the runtime's v6 vector generator seals its signed cases into (its `RECORD_ID`).
RECORD_ID = "dec:acme:s-digest-v6-vector-0000"
#: The runtime's own `seam-tct-jti-v1` known answer (seam-runtime
#: `crates/seam-client/tests/conformance_vectors.json` `derived_uuid.tct_jti`).
JTI_KAT = {
    "source": "seam-runtime crates/seam-client/tests/conformance_vectors.json derived_uuid.tct_jti",
    "decision_id": "dec:acme:s-conformance-0000000",
    "sealed_at_ms": "1700000000000",
    "input_hex": "0000001e6465633a61636d653a732d636f6e666f726d616e63652d303030303030300000018bcfe56800",
    "jti": "c7321ce4-62f1-4e38-ac23-212dc9e0055b",
}


def _claims(token: str) -> dict:
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def _jti_input(decision_id: str, sealed_at_ms: int) -> bytes:
    i = decision_id.encode("utf-8")
    return struct.pack(">I", len(i)) + i + struct.pack(">q", sealed_at_ms)


def tct_jti(decision_id: str, sealed_at_ms: int) -> str:
    h = bytearray(hashlib.sha256(b"seam-tct-jti-v1\x00" + _jti_input(decision_id, sealed_at_ms)).digest()[:16])
    h[6] = (h[6] & 0x0F) | 0x40
    h[8] = (h[8] & 0x3F) | 0x80
    x = h.hex()
    return f"{x[0:8]}-{x[8:12]}-{x[12:16]}-{x[16:20]}-{x[20:32]}"


def _expected(iat: int, jti: str, decision_id: str, sealed_at_ms: int) -> bool:
    return (
        0 <= sealed_at_ms <= I64_MAX
        and iat == sealed_at_ms // 1000
        and jti == tct_jti(decision_id, sealed_at_ms)
    )


def build() -> dict:
    src = json.loads((REPO / SOURCE).read_text())
    case = next(c for c in src["cases"] if c["name"] == OVER)
    claims = _claims(case["signed_artifact"])
    iat, jti = claims["iat"], claims["jti"]
    seal_ms = src["seal_ms"]
    # The runtime mints iat = sealed_at / 1000 and jti over (RECORD_ID, sealed_at); the source vector
    # must satisfy both, or the derivation below is about some other token.
    assert iat == seal_ms // 1000, (iat, seal_ms)
    assert jti == tct_jti(RECORD_ID, seal_ms), (jti, RECORD_ID, seal_ms)
    kat = JTI_KAT
    assert _jti_input(kat["decision_id"], int(kat["sealed_at_ms"])).hex() == kat["input_hex"]
    assert tct_jti(kat["decision_id"], int(kat["sealed_at_ms"])) == kat["jti"]
    s = seal_ms
    assert s % 1000 == 0, s  # an exact second boundary
    r = RECORD_ID
    rows = [
        ("exact_second_boundary", r, s, "the chained record: iat == sealed_at / 1000 and jti over (decision_id, sealed_at)"),
        ("last_ms_of_the_second", r, s + 999, "same iat, but the jti is over the exact ms: a seal time shifted inside its second"),
        ("iat_plus_1s_at_boundary", r, s - 1000, "the token's iat is 1 s AFTER the chained seal second"),
        ("iat_plus_1s_last_ms", r, s - 1, "1 ms before the boundary is the previous second: iat is +1 s"),
        ("iat_minus_1s_at_boundary", r, s + 1000, "the token's iat is 1 s BEFORE the chained seal second (backdated)"),
        ("iat_minus_1s_last_ms", r, s + 1999, "still the next second: iat is -1 s"),
        ("zero", r, 0, "the epoch: a valid sealed_at, not this token's"),
        ("beyond_i64", r, I64_MAX + 1, "a sealed_at beyond i64 is refused outright (runtime check_commitment_sealed_for)"),
        ("replayed_onto_another_record", "dec:acme:s-digest-v6-vector-0001", s, "a genuine seal replayed onto another record: right time, other decision_id"),
        ("commitment_id_is_not_the_record_id", case["commitment"]["id"], s, "the jti is over the record id, never Commitment.id"),
        ("empty_decision_id", "", s, "no record id names this token"),
    ]
    return {
        "spec": "docs/specs/seam-commitment-digest.v6.md §Seal key steps 6 and 7; evidence-bundle.v1 §Verifying step 4",
        "rule": "0 <= sealed_at_ms <= i64::MAX and iat == floor(sealed_at_ms / 1000) and "
        "jti == derived_uuid(\"seam-tct-jti-v1\", be32(len decision_id) || decision_id || be64(sealed_at_ms))",
        "generator": "scripts/emit_tct_sealed_at_vector.py -- every expect is computed from the rule, no SDK run",
        "source": SOURCE,
        "over": OVER,
        "iat": iat,
        "jti": jti,
        "decision_id": RECORD_ID,
        "jti_kat": kat,
        "cases": [
            {
                "name": name,
                "decision_id": did,
                "sealed_at_ms": str(ms),
                "expect": "verified" if _expected(iat, jti, did, ms) else "refused",
                "note": note,
            }
            for name, did, ms, note in rows
        ],
    }


def main(argv: list[str]) -> int:
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in argv:
        if OUT.read_text() != text:
            print(f"{OUT.relative_to(REPO)} is not what this script emits; re-run it", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
