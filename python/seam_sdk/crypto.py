"""Client-side crypto for the Seam SDK — pure stock primitives (Ed25519 + SHA-256), no AITP binding.

The admission proof-of-possession is Ed25519 over SHA-256 of a documented, domain-separated canonical
byte layout (RFC-AITP-0002 §3); the seed never leaves the client. Conformance vectors in
``conformance/vectors.json`` (generated from the Rust reference) pin the exact bytes.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import uuid

import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_PROOF_DOMAIN = b"aitp-pinned-key-v1\x00"


def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def aid_from_pubkey(pubkey: bytes) -> str:
    """The agent's ``aid:pubkey:ed25519:`` identity for a 32-byte Ed25519 public key."""
    return "aid:pubkey:ed25519:" + _b64url_nopad(pubkey)


def build_presentation(
    agent_seed: bytes, receiver_aid: str, pop_nonce: str, now_ms: int
) -> dict:
    """Build the pinned-key admission presentation the Seam server verifies.

    ``proof = base64url(Ed25519_sign( SHA256( domain || sender_aid \\0 || receiver_aid \\0 ||
    message_id \\0 || timestamp_be_i64 \\0 || b64url_decode(pop_nonce) ) ))``.
    """
    sk = Ed25519PrivateKey.from_private_bytes(agent_seed)
    pub = sk.public_key().public_bytes_raw()
    sender_aid = aid_from_pubkey(pub)

    # message_id: deterministic from the nonce (no RNG); raw 16 bytes, not version-munged.
    mid = uuid.UUID(
        bytes=hashlib.sha256(b"seam-pop-mid" + pop_nonce.encode("ascii")).digest()[:16]
    )
    timestamp = now_ms // 1000

    proof_input = (
        _PROOF_DOMAIN
        + sender_aid.encode()
        + b"\x00"
        + receiver_aid.encode()
        + b"\x00"
        + str(mid).encode()
        + b"\x00"
        + struct.pack(">q", timestamp)
        + b"\x00"
        + _b64url_decode(pop_nonce)
    )
    proof = _b64url_nopad(sk.sign(hashlib.sha256(proof_input).digest()))

    return {
        "sender_aid": sender_aid,
        "descriptor": {
            "type": "pinned_key",
            "subject": sender_aid,
            "proof": proof,
            "public_key": _b64url_nopad(pub),
        },
        "message_id": str(mid),
        "timestamp": timestamp,
        "pop_nonce": pop_nonce,
    }


def _aid_to_pubkey(aid: str) -> bytes:
    """Recover the 32-byte Ed25519 public key embedded in an `aid:pubkey:[ed25519:]<43-b64url>`."""
    for prefix in ("aid:pubkey:ed25519:", "aid:pubkey:"):
        if aid.startswith(prefix):
            return _b64url_decode(aid[len(prefix) :])
    raise ValueError(f"unsupported AID form: {aid!r}")


def _seam_commitment_digest(commitment: dict) -> str:
    """SHA-256 (hex) over a length-prefixed framing of a domain tag + the commitment fields.

    Each field is prefixed with its 8-byte big-endian byte length (no separator), so the digest is
    injective over `(domain, id, action, authority, supersedes, auth_method, trust_basis)` regardless of
    content — a `\\0` separator would let boundary-shifted fields collide. Mirrors the runtime byte-for-byte.
    """
    h = hashlib.sha256()
    for field in (
        b"seam-commitment-digest:v1",
        commitment["id"].encode(),
        commitment["action"].encode(),
        commitment["authority"].encode(),
        (commitment.get("supersedes") or "").encode(),
        commitment["auth_method"].encode(),
        commitment["trust_basis"].encode(),
    ):
        h.update(len(field).to_bytes(8, "big"))
        h.update(field)
    return h.hexdigest()


def verify_tct(
    issuer_aid: str, tct_jws: str, commitment: dict, now_s: int | None = None
) -> bool:
    """Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only.

    Verifies the EdDSA JWS against the issuer's key (recovered from its AID), checks the self-issued
    claims (`typ`, `iss==sub==aud==issuer_aid`, `exp`), and that the bound `seam-commitment-digest` grant
    matches this exact commitment (tamper-evidence over the decided content + committer attribution).
    """
    # Any malformed/forged input must fail closed (return False), never raise.
    try:
        parts = tct_jws.split(".")
        if len(parts) != 3:
            return False
        header_b64, payload_b64, sig_b64 = parts
        Ed25519PublicKey.from_public_bytes(_aid_to_pubkey(issuer_aid)).verify(
            _b64url_decode(sig_b64), f"{header_b64}.{payload_b64}".encode("ascii")
        )
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        if header.get("alg") != "EdDSA" or header.get("typ") != "aitp-tct+jwt":
            return False
        if not (
            payload.get("iss") == payload.get("sub") == payload.get("aud") == issuer_aid
        ):
            return False
        now = now_s if now_s is not None else int(time.time())
        if now >= int(payload.get("exp", 0)):  # RFC 7519: reject at/after expiry
            return False
        want = "seam-commitment-digest:" + _seam_commitment_digest(commitment)
        return want in payload.get("grants", [])
    except Exception:
        return False


# ── RFC 8785 (JCS) canonicalization + the Authorize call binding ─────────────────────────────────────
# `tool_input_digest` is what `call_sig` signs and what the advisory audit row records — a one-way door
# pinned by the runtime's cross-language vector (`conformance/authorize_jcs_digest_vector.json`). There
# is deliberately NO bless mode: a mismatch is a CONTRACT BREAK, not a prompt to regenerate.

_JCS_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}

# ECMAScript can only represent integers exactly within ±2^53; beyond that a decimal rendering here
# would not round-trip through the runtime's f64 path, so it is rejected rather than silently skewed.
_MAX_SAFE_INT = 2**53


def _jcs_string(s: str) -> str:
    """JSON-escape per RFC 8785 §3.2.2.2: only what JSON requires; non-ASCII stays literal UTF-8."""
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _JCS_ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_number(v: float) -> str:
    """ECMAScript ``Number::toString`` (ECMA-262 §6.1.6.1.20) — the JCS number rendering.

    Python's ``repr`` already yields the shortest round-trip digits for a double; this reformats them
    into the ES6 surface form (integral doubles lose their ``.0``, exponents normalize to ``e±d`` with
    no zero-padding, decimal notation for 10^-6 ≤ |v| < 10^21).
    """
    import math

    if math.isnan(v) or math.isinf(v):
        raise ValueError("NaN and Infinity cannot be canonicalized (RFC 8785)")
    if v == 0:
        return "0"  # covers -0.0: ES6 renders negative zero as "0"
    sign = "-" if v < 0 else ""
    from decimal import Decimal

    _, digit_tuple, dexp = Decimal(repr(abs(v))).as_tuple()
    raw = "".join(map(str, digit_tuple))
    digits = raw.rstrip("0") or "0"
    dexp += len(raw) - len(digits)
    n = len(digits) + dexp  # value = 0.<digits> × 10^n
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        mant = digits[0] + ("." + digits[1:] if k > 1 else "")
        e = n - 1
        body = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _jcs_write(v, out: list) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(_jcs_string(v))
    elif isinstance(v, int):
        if abs(v) > _MAX_SAFE_INT:
            raise ValueError(
                f"integer {v} exceeds 2^53 and cannot round-trip as an IEEE double"
            )
        out.append(str(v))
    elif isinstance(v, float):
        out.append(_jcs_number(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _jcs_write(item, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        for key in v:
            if not isinstance(key, str):
                raise TypeError(
                    f"JSON object keys must be strings, got {type(key).__name__}"
                )
        # RFC 8785 §3.2.3: keys sort by UTF-16 code units — UTF-16BE byte order IS code-unit order.
        for i, key in enumerate(sorted(v, key=lambda k: k.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(_jcs_string(key))
            out.append(":")
            _jcs_write(v[key], out)
        out.append("}")
    else:
        raise TypeError(f"{type(v).__name__} is not JSON-serializable")


def jcs_canonicalize(obj) -> bytes:
    """RFC 8785 (JCS) canonical JSON bytes for ``obj`` — sorted keys (UTF-16 code-unit order),
    ES6 number rendering, minimal string escaping, UTF-8 encoded, no whitespace."""
    out: list = []
    _jcs_write(obj, out)
    return "".join(out).encode("utf-8")


def tool_input_digest(canonical: bytes) -> str:
    """``"sha256:<hex>"`` over already-canonical JCS bytes (from :func:`jcs_canonicalize`)."""
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# Domain separation for the per-call proof-of-possession. `v2` because the signed payload grew from
# `ticket || digest` to additionally cover `tool_name` and `agent_id`; the distinct tag means a v1
# signature can NEVER verify as a v2 one, so a version skew between SDK and runtime is a clean
# rejection rather than a parse ambiguity. Bump it here only in lockstep with the runtime.
CALL_SIG_CONTEXT = b"seam-authorize-call-v2"


def call_sig_payload(
    ticket: bytes, tool_input_digest: str, tool_name: str, agent_id: str
) -> bytes:
    """The exact bytes :func:`call_sig` signs — ``frame(context) || frame(ticket) ||
    frame(tool_input_digest) || frame(tool_name) || frame(agent_id)``, where
    ``frame(x) = u32le(len(x)) || x`` over UTF-8.

    Length prefixing is load-bearing now that the payload is multi-field: concatenating raw would
    frame ``("read", "x")`` and ``("read_x", "")`` identically, re-opening the re-pointing gap this
    closes. Lengths are BYTE counts.

    ``agent_id`` is the raw wire value — the empty string when the caller omits it, signed verbatim
    rather than skipped, matching the server's framing at verify time.

    Pinned by ``conformance/call_sig_payload_vector.json``, whose bytes come from executing the
    runtime's Rust ``call_sig_payload``. Exposed publicly so a caller can reproduce or verify the
    binding without re-deriving it from prose.
    """
    parts = (
        CALL_SIG_CONTEXT,
        ticket,
        tool_input_digest.encode("utf-8"),
        tool_name.encode("utf-8"),
        agent_id.encode("utf-8"),
    )
    return b"".join(struct.pack("<I", len(p)) + p for p in parts)


def call_sig(
    agent_seed: bytes,
    ticket: bytes,
    digest: str,
    *,
    tool_name: str,
    agent_id: str,
) -> bytes:
    """The per-call proof-of-possession for :meth:`SeamClient.authorize`: Ed25519 by the agent key
    over :func:`call_sig_payload`.

    Binding the *digest* stops a captured signature being re-pointed at a different input; binding
    the *tool_name* and *agent_id* stops it being re-pointed at a different tool call or registry
    agent while the ticket is live; binding the *ticket bytes* stops replay against a later ticket.

    ``tool_name`` and ``agent_id`` are keyword-ONLY and have no defaults on purpose. They arrived
    with the v2 framing, and defaulting them would let existing callers keep compiling while
    producing a signature the runtime rejects — surfacing as ``UNAUTHENTICATED: admission ticket is
    not valid``, which names the wrong artifact entirely. A TypeError here is the cheaper failure.
    """
    return Ed25519PrivateKey.from_private_bytes(agent_seed).sign(
        call_sig_payload(ticket, digest, tool_name, agent_id)
    )


# ── A14 authenticity framing (seam-event.v1) ─────────────────────────────────────────────────────────
# frame(x) = u32le(len(x)) || x ; opt(x) = 0x00 if None else 0x01 || frame(x). Both transcribed from
# `seam-event.v1.md`; they let a client verify a chain-head attestation or recompute a v2 record digest
# in-language, from the published spec alone (the same framing the independent `verify/` tool uses).


def _frame(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def _opt(s: str | None) -> bytes:
    return b"\x00" if s is None else b"\x01" + _frame(s.encode("utf-8"))


def record_digest_v2(
    decision_id: str,
    tenant: str,
    namespace: str,
    ciphertext_digest: bytes,
    sealed_at: int,
    outcome: str,
    mode: str | None,
    policy_version: str | None,
    supersedes: str | None,
    schema_version: int = 2,
) -> bytes:
    """Recompute a v2 ``DECISION_SEALED`` record digest (``seam.audit.record-digest.v2``) from its on-wire
    structural columns + ``ciphertext_digest`` (SHA256(ciphertext), tag 10). Compare to the event's wire
    ``digest`` (tag 19) to catch a payload rewrite. Preimage order is NOT wire-tag order: ``outcome``
    precedes the optional ``mode``/``policy_version``/``supersedes``; the ``opt`` presence byte is raw, so
    ``None`` and ``""`` are distinct."""
    pre = (
        _frame(b"seam.audit.record-digest.v2")
        + _frame(decision_id.encode())
        + _frame(tenant.encode())
        + _frame(namespace.encode())
        + _frame(ciphertext_digest)
        + _frame(struct.pack("<Q", sealed_at))
        + _frame(outcome.encode())
        + _opt(mode)
        + _opt(policy_version)
        + _opt(supersedes)
        + _frame(struct.pack("<I", schema_version))
    )
    return hashlib.sha256(pre).digest()


#: The three v3 sub-digests are fixed-width by the spec. A wrong-length value is refused rather than
#: framed, because framing one would produce a garbage digest that a caller reports as a *rewrite* —
#: mislabelling "this field is malformed" as "someone altered the record".
_V3_DIGEST_LEN = 32


class RecordDigestStripError(ValueError):
    """A ``schema_version = 3`` record is missing a field the v3 formula requires (wire tag 11 or 12).

    **This is deliberately not a digest mismatch, and must never be reported as one.** The spec
    (`seam-event.v1.md`, "Strip semantics for tags 11/12/13") makes `context_digest` and
    `participation_digest` mandatory on a v3 payload and requires a consumer to *refuse* — never to
    substitute an empty digest, and never to fall back to the v2 formula. Absent-when-required is a
    strip attack, and an operator has to be able to tell "someone removed a field" from "someone
    rewrote one", because the two have different responses.

    Raising is what makes that distinction structural rather than advisory: a mismatch is a `False`
    from a comparison, a strip is an exception, and no caller can conflate them by accident.

    Subclasses ``ValueError`` so existing ``except ValueError`` handlers around the digest helpers
    keep working — the same additive discipline `SeamRpcError` follows for `grpc.RpcError`.
    """


def _v3_required(name: str, tag: int, value: bytes | None) -> bytes:
    """A mandatory v3 sub-digest: present, and exactly 32 bytes. Absent or malformed ⇒ refuse."""
    if value is None:
        raise RecordDigestStripError(
            f"a schema_version=3 record carries no {name} (wire tag {tag}), which the v3 formula "
            f"requires. This is a STRIP, not a digest mismatch: refuse the record, do not substitute "
            f"an empty digest and do not fall back to the v2 formula."
        )
    if len(value) != _V3_DIGEST_LEN:
        raise RecordDigestStripError(
            f"{name} (wire tag {tag}) is {len(value)} bytes, not {_V3_DIGEST_LEN} — malformed, so no "
            f"v3 digest can be computed from it. Reported as a refusal rather than hashed, because "
            f"hashing it would surface a malformed field as though the record had been rewritten."
        )
    return value


def _opt_bytes(b: bytes | None) -> bytes:
    """``opt`` over raw bytes. Same presence byte as :func:`_opt`, which takes a `str`."""
    return b"\x00" if b is None else b"\x01" + _frame(b)


def record_digest_v3(
    decision_id: str,
    tenant: str,
    namespace: str,
    ciphertext_digest: bytes,
    sealed_at: int,
    outcome: str,
    mode: str | None,
    policy_version: str | None,
    supersedes: str | None,
    context_digest: bytes,
    participation_digest: bytes,
    policy_rules_digest: bytes | None,
    schema_version: int = 3,
) -> bytes:
    """Recompute a v3 ``DECISION_SEALED`` record digest (``seam.audit.record-digest.v3``).

    v3 is v2 plus the three columns carrying the product's actual claims — what context the decision
    consumed, who participated, and which policy rules gated the commitment. They arrive as **opaque
    32-byte sub-digests on the wire** (tags 11/12/13); their internal formulas belong to the runtime
    and to auditors, and are deliberately not reimplemented here. This function is a wire-input
    recompute, exactly as :func:`record_digest_v2` is.

    Three things the spec singles out as easy to get wrong, all of them load-bearing:

    * **Digest slots are offset by one from the proto tags.** ``context_digest`` is preimage slot 10
      but wire tag 11. The new slots are *inserted before* ``schema_version``, never appended after
      it — a verifier selects the whole formula by ``schema_version``, so position is fixed by the
      spec rather than by append order.
    * **Slots 10 and 11 are framed; slot 12 is opted.** The asymmetry is deliberate, not an
      oversight: framing the two mandatory digests is precisely what stops "no participants" from
      aliasing with "field stripped". ``policy_rules_digest`` is genuinely optional — absent means
      no policy was bound, today's common case.
    * **``None`` is not ``b""``.** ``opt(None)`` is one byte; ``opt(b"")`` is five. A present-but-
      empty value is data, not absence, and the presence byte is what keeps them apart.

    Raises :class:`RecordDigestStripError` when ``context_digest`` or ``participation_digest`` is
    absent or is not 32 bytes, and when a *present* ``policy_rules_digest`` is not 32 bytes. That is
    a refusal, categorically distinct from the digest mismatch this function's *return value* is
    compared for — see the class docstring.
    """
    context_digest = _v3_required("context_digest", 11, context_digest)
    participation_digest = _v3_required(
        "participation_digest", 12, participation_digest
    )
    if policy_rules_digest is not None and len(policy_rules_digest) != _V3_DIGEST_LEN:
        raise RecordDigestStripError(
            f"policy_rules_digest (wire tag 13) is present but {len(policy_rules_digest)} bytes, not "
            f"{_V3_DIGEST_LEN} — malformed. Absent is legitimate (no policy was bound); present and "
            f"wrong-length is not, and is refused rather than hashed."
        )

    pre = (
        _frame(b"seam.audit.record-digest.v3")
        + _frame(decision_id.encode())
        + _frame(tenant.encode())
        + _frame(namespace.encode())
        + _frame(ciphertext_digest)
        + _frame(struct.pack("<Q", sealed_at))
        + _frame(outcome.encode())
        + _opt(mode)
        + _opt(policy_version)
        + _opt(supersedes)
        + _frame(context_digest)
        + _frame(participation_digest)
        + _opt_bytes(policy_rules_digest)
        + _frame(struct.pack("<I", schema_version))
    )
    return hashlib.sha256(pre).digest()


def _chain_head_attestation_digest(
    attested_len: int,
    attested_head: bytes,
    attested_at: int,
    digest_schema: int,
    issuer_aid: str,
) -> bytes:
    """The 32-byte digest a ``CHAIN_HEAD_ATTESTATION`` signs over (``seam.audit.chain-head-attestation.v1``)."""
    pre = (
        _frame(b"seam.audit.chain-head-attestation.v1")
        + _frame(struct.pack("<Q", attested_len))
        + _frame(attested_head)
        + _frame(struct.pack("<Q", attested_at))
        + _frame(struct.pack("<I", digest_schema))
        + _frame(issuer_aid.encode())
    )
    return hashlib.sha256(pre).digest()


def verify_chain_head_attestation(
    issuer_aid: str,
    attested_len: int,
    attested_head: bytes,
    attested_at: int,
    digest_schema: int,
    signature: bytes,
) -> bool:
    """Verify a chain-head attestation's Ed25519 signature against the PINNED issuer AID (A14). Returns
    ``True`` iff the signature checks out over the recomputed digest; ``False`` on any tamper. The key comes
    from ``issuer_aid`` (which the caller pinned out of band), never from the attestation itself."""
    digest = _chain_head_attestation_digest(
        attested_len, attested_head, attested_at, digest_schema, issuer_aid
    )
    try:
        Ed25519PublicKey.from_public_bytes(_aid_to_pubkey(issuer_aid)).verify(
            signature, digest
        )
        return True
    except Exception:
        return False
