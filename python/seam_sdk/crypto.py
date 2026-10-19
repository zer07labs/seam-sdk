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
from typing import Any
from typing import NamedTuple as _NamedTuple

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


def derived_uuid(tag: str, data: bytes) -> uuid.UUID:
    """The runtime's derived-UUID rule (seam-runtime ``docs/specs/authorize.v1.md``, P9).

    ``h = SHA-256(tag || 0x00 || data)``; the id is ``h[0..16]`` with the RFC 9562 version-4 and
    variant bits forced (``h[6] = (h[6] & 0x0f) | 0x40``, ``h[8] = (h[8] & 0x3f) | 0x80``). ``str()``
    of the result is the lowercase hyphenated form the wire carries. One primitive serves every
    derived id — the PoP ``message_id`` and the commitment TCT ``jti`` — so a new one is a call, not
    a second transcription. Pinned by ``conformance/vectors.json``'s ``derived_uuid`` block.
    """
    h = bytearray(hashlib.sha256(tag.encode("ascii") + b"\x00" + data).digest()[:16])
    h[6] = (h[6] & 0x0F) | 0x40
    h[8] = (h[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(h))


#: Domain tag of the PoP ``message_id`` derivation (P9).
POP_MESSAGE_ID_TAG = "seam-pop-mid-v1"


def pop_message_id(pop_nonce: str) -> uuid.UUID:
    """The admission ``message_id``: ``derived_uuid("seam-pop-mid-v1", pop_nonce_ascii)``.

    The input is the nonce's base64url ASCII text exactly as sent, not its decoded bytes.
    """
    return derived_uuid(POP_MESSAGE_ID_TAG, pop_nonce.encode("ascii"))


def build_presentation(
    agent_seed: bytes, receiver_aid: str, pop_nonce: str, now_ms: int
) -> dict:
    """Build the pinned-key admission presentation the Seam server verifies.

    ``proof = base64url(Ed25519_sign( SHA256( domain || sender_aid \\0 || receiver_aid \\0 ||
    message_id \\0 || timestamp_ascii_decimal \\0 || b64url_decode(pop_nonce) ) ))``.
    """
    sk = Ed25519PrivateKey.from_private_bytes(agent_seed)
    pub = sk.public_key().public_bytes_raw()
    sender_aid = aid_from_pubkey(pub)

    # message_id: derived from the nonce (no RNG) under the P9 rule — see `pop_message_id`.
    mid = pop_message_id(pop_nonce)
    timestamp = now_ms // 1000

    proof_input = (
        _PROOF_DOMAIN
        + sender_aid.encode()
        + b"\x00"
        + receiver_aid.encode()
        + b"\x00"
        + str(mid).encode()
        + b"\x00"
        + str(timestamp).encode("ascii")
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


#: The ``kind`` words the explanation digest frames — lowercase ASCII, exactly; never the proto enum name.
EXPLANATION_KINDS = ("vote", "evaluation", "objection", "ballot")


def _be64_frame(field: bytes) -> bytes:
    return len(field).to_bytes(8, "big") + field


def explanation_digest(entries) -> bytes:
    """``seam-explanation-digest:v1`` over a sealed explanation (32 raw bytes).

    ``entries`` is the list of explanation entries in the order the runtime sealed them, each a mapping
    with ``kind`` (one of :data:`EXPLANATION_KINDS`), ``participant``, ``proposal_id``, ``value``,
    ``reason``, and optional ``confidence`` / ``rationale_ref`` (``None`` or missing = absent). An absent
    confidence and a stated ``0.0`` are different bytes — that distinction is the point of this digest.
    Raises ``ValueError`` on an unknown kind or a non-canonical confidence (NaN, ±inf, outside
    ``[0.0, 1.0]``, or ``-0.0``) rather than hashing it. Normative:
    ``seam-runtime/docs/specs/seam-commitment-digest.v3.md``."""
    import math

    entries = list(entries)
    out = [_be64_frame(b"seam-explanation-digest:v1"), len(entries).to_bytes(8, "big")]
    for e in entries:
        kind = e["kind"]
        if kind not in EXPLANATION_KINDS:
            raise ValueError(f"unknown explanation kind {kind!r}")
        out += [
            _be64_frame(kind.encode()),
            _be64_frame(e["participant"].encode()),
            _be64_frame(e["proposal_id"].encode()),
            _be64_frame(e["value"].encode()),
            _be64_frame(e["reason"].encode()),
        ]
        conf = e.get("confidence")
        if conf is None:
            out.append(b"\x00")
        else:
            if isinstance(conf, bool) or not isinstance(conf, (int, float)):
                raise ValueError(f"confidence must be a number, got {conf!r}")
            conf = float(conf)
            if (
                not math.isfinite(conf)
                or not 0.0 <= conf <= 1.0
                or math.copysign(1.0, conf) < 0
            ):
                raise ValueError(f"non-canonical confidence {conf!r}")
            out.append(b"\x01" + struct.pack(">d", conf))
        ref = e.get("rationale_ref")
        out.append(b"\x00" if ref is None else b"\x01" + _be64_frame(ref.encode()))
    return hashlib.sha256(b"".join(out)).digest()


def _commitment_explanation_digest(commitment: dict) -> bytes:
    """The explanation digest a commitment binds as field 8, checked when the entries are present.

    With ``explanation`` (the entries): recomputed from them, and if ``explanation_digest`` is ALSO
    given the two must agree (spec §Verification step 1) — otherwise ``ValueError``. With only
    ``explanation_digest`` (32 bytes, or 64 hex chars): used as published, which verifies *who* and
    *what* but not *why*. With neither: the empty explanation, the runtime's value when nothing was
    deliberated."""
    published = commitment.get("explanation_digest")
    if isinstance(published, str):
        published = bytes.fromhex(published)
    elif published is not None:
        published = bytes(published)
    entries = commitment.get("explanation")
    if entries is None:
        return published if published is not None else explanation_digest([])
    computed = explanation_digest(entries)
    if published is not None and published != computed:
        raise ValueError("explanation_digest does not match the explanation entries")
    return computed


def _seam_commitment_digest(commitment: dict) -> str:
    """``seam-commitment-digest:v3`` (hex): SHA-256 over the length-prefixed domain tag and fields.

    Spec: seam-runtime ``docs/specs/seam-commitment-digest.v3.md``. Every field is ``F(x) = be64(len) ||
    x`` (no separator), so the digest is injective over ``(domain, id, action, authority, supersedes,
    auth_method, trust_basis, committer, explanation_digest)``. The length prefixes are load-bearing:
    with a NUL separator instead, ``("a\\0b", "c")`` and ``("a", "b\\0c")`` would collide — identical
    preimages, so one Commitment could verify under another's TCT — and these fields are arbitrary
    text that may itself contain NUL. Never "simplify" them away. ``supersedes`` alone carries a presence
    byte: ``0x00`` when absent (key missing or ``None``), ``0x01 || F(value)`` when present — so an
    absent prior and a present empty one are different digests. Field 8 is the 32 raw bytes of the
    explanation digest (see :func:`_commitment_explanation_digest`). v1 and v2 are deleted, not
    dual-verified.
    """
    supersedes = commitment.get("supersedes")
    out = [
        _be64_frame(b"seam-commitment-digest:v3"),
        _be64_frame(commitment["id"].encode()),
        _be64_frame(commitment["action"].encode()),
        _be64_frame(commitment["authority"].encode()),
        b"\x00" if supersedes is None else b"\x01" + _be64_frame(supersedes.encode()),
        _be64_frame(commitment["auth_method"].encode()),
        _be64_frame(commitment["trust_basis"].encode()),
        _be64_frame((commitment.get("committer") or "").encode()),
        _be64_frame(_commitment_explanation_digest(commitment)),
    ]
    return hashlib.sha256(b"".join(out)).hexdigest()


#: The ``ext`` key a Seam commitment self-attestation carries its statement under (RFC-AITP-0005).
COMMITMENT_EXT_KEY = "com.zer07labs.seam"
#: The only grant a commitment self-attestation TCT may carry.
ATTESTATION_GRANT = "aitp.attestation"


def _no_duplicate_keys(pairs: list) -> dict:
    """``json.loads`` hook: refuse a duplicate object key rather than keep the last one silently."""
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON key {k!r}")
        out[k] = v
    return out


def verify_tct(
    issuer_aid: str, tct_jws: str, commitment: dict, now_s: int | None = None
) -> bool:
    """Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only.

    The TCT is an RFC-AITP-0005 self-attestation. Verifies the EdDSA JWS against the issuer's key
    (recovered from its AID), the self-issued claims (`typ`, `iss==sub==aud==issuer_aid`, `exp`),
    that `grants` is exactly `["aitp.attestation"]`, and that `ext` is exactly
    `{"com.zer07labs.seam": {"type": "seam:commitment", "commitment_digest": <hex>}}` whose digest is
    `seam-commitment-digest:v3` of this exact commitment (tamper-evidence over the decided content,
    the committer, and the sealed explanation). A duplicate JSON key anywhere in the header or
    payload, a statement carried in `grants` (the retired v2 shape), or an extra grant verifies
    ``False``. ``commitment`` carries ``committer`` and the ``explanation`` entries and/or the published
    ``explanation_digest``; entries that disagree with the published digest, an unknown kind, or a
    non-canonical confidence verify ``False``.
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
        header = json.loads(
            _b64url_decode(header_b64), object_pairs_hook=_no_duplicate_keys
        )
        payload = json.loads(
            _b64url_decode(payload_b64), object_pairs_hook=_no_duplicate_keys
        )
        if header.get("alg") != "EdDSA" or header.get("typ") != "aitp-tct+jwt":
            return False
        if not (
            payload.get("iss") == payload.get("sub") == payload.get("aud") == issuer_aid
        ):
            return False
        now = now_s if now_s is not None else int(time.time())
        # ``exp`` must be a JSON NUMBER. ``int(payload.get("exp", 0))`` accepted a numeric STRING —
        # ``int("10000000000")`` is a perfectly good integer — which Go's ``payload["exp"].(float64)``
        # and Java's ``instanceof Number`` both refuse. And ``bool`` subclasses ``int``, so
        # ``exp: true`` became ``1``: at any ``now`` below 1 the token VERIFIED. That is invisible at
        # a realistic clock, which is why the shared vector pins ``now = 0``.
        #
        # The ``bool`` exclusion has to come first for the same reason it does in ``_uint_slot``:
        # ``isinstance(True, int)`` is ``True``, so the type test alone lets it through.
        exp = payload.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            return False
        # The normative rule is bounded to int64, because in Go it has to be: `int64(exp)` is
        # implementation-defined when the value does not fit, and `exp: 1e300` verified on arm64
        # (saturating to MaxInt64) while amd64 refused it. Python has no such hazard — `int()` is
        # arbitrary precision — so this bound buys Python nothing on its own. It is here so that all
        # five SDKs answer the same thing, which is the only reason any of this code is shaped the
        # way it is. 2^63 is exactly representable as a float, so the comparison is exact.
        if not (-(2**63) <= exp < 2**63):
            return False
        if now >= int(
            exp
        ):  # RFC 7519: reject at/after expiry, truncating to whole seconds
            return False
        if payload.get("grants") != [ATTESTATION_GRANT]:
            return False
        ext = payload.get("ext")
        if not isinstance(ext, dict) or list(ext) != [COMMITMENT_EXT_KEY]:
            return False
        stmt = ext[COMMITMENT_EXT_KEY]
        if not isinstance(stmt, dict) or set(stmt) != {"type", "commitment_digest"}:
            return False
        if stmt["type"] != "seam:commitment":
            return False
        # Exact string compare: the runtime emits lowercase hex, and an uppercase spelling is a
        # different statement, not a normalization opportunity.
        return stmt["commitment_digest"] == _seam_commitment_digest(commitment)
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

# ECMAScript represents every JSON number as an IEEE double, and integers exactly only within ±2^53.
# Inside that range a plain decimal rendering is always what JCS emits, so it is used directly.
# Outside it, see `_jcs_int`: the question is not magnitude but whether JCS renders the integer AS
# ITSELF, and anything that would be silently skewed is rejected rather than digested.
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


def _jcs_int(v: int) -> str:
    """Render an integer the way JCS renders it, or refuse it — never silently a different number.

    JCS numbers are IEEE doubles, so the only integers that can appear in canonical output are the
    ones ES6 ``Number::toString`` prints as themselves. That is the predicate here, stated literally:
    render the double and require it to equal the integer's own decimal form.

    **Why not "is it exactly representable as a double".** That is the obvious test and it is wrong.
    ``2**60`` is exactly representable, but ES6 prints the *shortest round-tripping* digits, so it
    renders as ``1152921504606847000`` — a different number. Accepting it would sign a digest over a
    value the caller never supplied. The two renderings part company from about ``2**55``, not at
    ``10**21`` as a decimal-vs-exponential intuition suggests; roughly 43% of exactly-representable
    integers just above 2^53 diverge. Above ``10**21`` ES6 switches to exponential notation, which a
    plain decimal form can never match, so that boundary needs no separate rule — it falls out.

    **What this buys.** Every byte string this arm can emit is one the float arm could already have
    emitted, so widening what is accepted introduces no new wire shape for any conformant
    implementation to disagree with. And `json.loads(jcs_canonicalize(x))` now re-canonicalizes to
    the same bytes: an integral double in [2^53, 10^21) prints as a bare integer literal that JSON
    parses back as a Python `int`, which the old ``> 2^53`` rule then refused outright (seam-sdk#60).

    ``int.__repr__`` rather than ``str``: ``int`` defines no ``__str__``, so a subclass that overrides
    it — an ``IntEnum`` on Python 3.10, this package's floor, renders as ``Color.RED`` — would emit
    invalid JSON into a signed digest. The unbound ``int.__str__`` is *not* the fix; it falls through
    to ``object.__str__`` and re-enters the subclass's ``__repr__``, which is strictly worse.
    """
    text = int.__repr__(v)  # unspoofable; every check below reads from this
    n = int(text)  # a plain int, free of any subclass's opinions about arithmetic
    if -_MAX_SAFE_INT <= n <= _MAX_SAFE_INT:
        return text
    try:
        rendered = _jcs_number(float(n))
    except OverflowError:
        raise ValueError(
            f"integer {text} is too large to represent as an IEEE double, so JCS cannot render it"
        ) from None
    if rendered != text:
        raise ValueError(
            f"integer {text} is not JCS-renderable as itself: canonicalizing it would emit "
            f"{rendered}, a different value. JSON numbers are IEEE doubles; this integer is not one "
            f"a double prints back unchanged, so digesting it would sign a value nobody supplied."
        )
    return rendered


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
        out.append(_jcs_int(v))
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


# ── The per-request credential (`seam-request-call-v1`, #508) ──────────────────────────────────────
# A DIFFERENT domain tag from `seam-authorize-call-v2` above, deliberately, so a captured `Authorize`
# call_sig is never spendable as a request credential and vice versa. See
# `plans/archive/request-credential.md` for the full contract; pinned by
# `conformance/request_sig_payload_vector.json`, generated from the runtime's Rust reference.
REQUEST_SIG_CONTEXT = b"seam-request-call-v1"


def request_sig_payload(
    ticket: bytes, rpc_full_name: str, resource_id: str, body_digest: str
) -> bytes:
    """The exact bytes :func:`request_sig` signs — ``frame(context) || frame(ticket) ||
    frame(rpc_full_name) || frame(resource_id) || frame(body_digest)``, where
    ``frame(x) = u32le(len(x)) || x``. Lengths are BYTE counts, not character counts.

    ``rpc_full_name`` is the gRPC full method path on BOTH transports (e.g.
    ``"/seam.api.v1.SeamCoordination/GetDecision"``), never the HTTP route pattern — that is what
    makes one credential valid over either plane for a bodyless verb. For a bodyless read,
    ``resource_id`` is the verb's id argument and ``body_digest`` is the empty string. For a bodied
    verb over gRPC, ``resource_id`` is the empty string (the id lives inside the message) and
    ``body_digest`` covers the whole DECODED request message, without the 5-byte gRPC
    length-prefixed-message header — see :func:`tool_input_digest` for the ``"sha256:<hex>"``
    formatting, computed over ``request.SerializeToString()``.

    This function pins the FRAMING only, not the digest computation — see
    ``conformance/request_sig_payload_vector.json``'s ``body_input_hex`` cases, which separately pin
    that a digest taken after parse-and-re-encode diverges from one taken over the exact wire bytes.
    """
    parts = (
        REQUEST_SIG_CONTEXT,
        ticket,
        rpc_full_name.encode("utf-8"),
        resource_id.encode("utf-8"),
        body_digest.encode("utf-8"),
    )
    return b"".join(struct.pack("<I", len(p)) + p for p in parts)


def request_sig(
    agent_seed: bytes,
    ticket: bytes,
    rpc_full_name: str,
    resource_id: str,
    body_digest: str,
) -> bytes:
    """Ed25519 by the agent key over :func:`request_sig_payload` — the per-request credential a
    caller sends as ``x-seam-ticket-bin`` + ``x-seam-call-sig-bin`` (gRPC) or ``x-seam-ticket`` +
    ``x-seam-call-sig`` (base64, HTTP) alongside a request, to prove identity in band on a
    deployment that strips ``x-seam-subject`` at its edge (``SEAM_SUBJECT_HEADERS=deny``, #710).

    Binding ``rpc_full_name`` stops a captured signature for one verb being re-pointed at a more
    privileged one over the same ticket and resource id (e.g. ``GetDecision`` → the decrypted
    ``GetCommitmentProof``). Binding ``resource_id``/``body_digest`` stops it being re-pointed at a
    different resource or request body. Binding the ticket bytes stops replay against a later one.
    """
    return Ed25519PrivateKey.from_private_bytes(agent_seed).sign(
        request_sig_payload(ticket, rpc_full_name, resource_id, body_digest)
    )


# ── A14 authenticity framing (seam-event.v1) ─────────────────────────────────────────────────────────
# frame(x) = u32le(len(x)) || x ; opt(x) = 0x00 if None else 0x01 || frame(x). Both transcribed from
# `seam-event.v1.md`; they let a client verify a chain-head attestation or recompute a v4 record digest
# in-language, from the published spec alone (the same framing the independent `verify/` tool uses).


def _frame(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


#: The four v4 sub-digests (tags 11/12/13/15) are fixed-width by the spec. A wrong-length value is refused rather than
#: framed, because framing one would produce a garbage digest that a caller reports as a *rewrite* —
#: mislabelling "this field is malformed" as "someone altered the record".
_SUB_DIGEST_LEN = 32


class RecordDigestStripError(ValueError):
    """A v4 record is missing a field the formula requires (wire tag 11, 12, 14, 15, 16 or 17), or
    carries a malformed sub-digest.

    **This is deliberately not a digest mismatch, and must never be reported as one.** The spec
    (`seam-event.v1.md`, "Strip semantics for tags 11-17") makes those six fields mandatory on every
    payload and requires a consumer to *refuse* — never to substitute an empty value; there is no
    older formula to fall back to. Absent-when-required is a
    strip attack, and an operator has to be able to tell "someone removed a field" from "someone
    rewrote one", because the two have different responses.

    Raising is what makes that distinction structural rather than advisory: a mismatch is a `False`
    from a comparison, a strip is an exception, and no caller can conflate them by accident.

    Subclasses ``ValueError`` so existing ``except ValueError`` handlers around the digest helpers
    keep working — the same additive discipline `SeamRpcError` follows for `grpc.RpcError`.

    ``field`` and ``wire_tag`` carry the same information as the message, structurally: a caller
    routing a refusal (to an alert, a metric label, a retry decision) should never have to parse
    English to learn *which* field was stripped. The TypeScript twin exposes the same two.
    """

    def __init__(self, message: str, field: str, wire_tag: int) -> None:
        super().__init__(message)
        #: The spec's field name, e.g. ``context_digest``.
        self.field = field
        #: The ``DecisionSealed`` wire tag the field occupies — 11 through 17.
        self.wire_tag = wire_tag


def _as_bytes(value: object) -> bytes | None:
    """The bytes a caller actually holds, or ``None`` if this is not a byte sequence.

    ``memoryview`` needs care: ``len(mv)`` is the ELEMENT count, not the byte count. A
    ``memoryview(array("I", [0] * 32))`` has ``len() == 32`` and ``nbytes == 128``, so a length check
    over ``len()`` would frame it as 32 bytes and then append 128 — a length prefix that lies about
    its own content, which is precisely the property framing exists to provide. Converting through
    ``bytes()`` here settles it: what gets measured is what gets hashed.
    """
    # NOTE there is no `isinstance(value, bytes)` fast path, and its absence is the point.
    # `bytes(value)` HONORS `__bytes__`, so a `bytes` subclass whose real buffer is 32 zeros but whose
    # `__bytes__` returns 32 `0xff`s would be hashed as the bytes it CLAIMS rather than the bytes it
    # HOLDS — the same "ask the object what it would like to be hashed as" mistake `_rd_enc` avoids
    # for text. `memoryview(...).tobytes()` reads the C buffer, which no Python method can override.
    try:
        view = memoryview(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        # TypeError: not a buffer at all — a str, an int, a list.
        # ValueError: a RELEASED memoryview or a closed mmap. Both are "no readable bytes here", and
        # both must come back as this function's named refusal rather than as whatever exception the
        # buffer protocol happened to raise.
        return None
    try:
        if view.itemsize != 1 or not view.c_contiguous:
            return None
        return view.tobytes()
    except (BufferError, ValueError):  # released, or otherwise unreadable
        return None
    finally:
        view.release()


def _sub_digest(name: str, tag: int, value: object, optional: bool) -> bytes | None:
    """One of the four v4 sub-digests (wire tags 11/12/13/15), validated as the spec requires: tags 11,
    12 and 15 are mandatory, tag 13 is genuinely optional, and all four must be exactly 32 bytes when
    present. ``optional`` selects which of those two contracts applies.

    Every refusal is a :class:`RecordDigestStripError`, whatever the proximate cause — absent, wrong
    type, wrong length. From the caller's side those are one condition: *this field is not a usable
    32-byte digest, so no v4 digest exists.* Splitting them into different exception types would push
    the work of re-joining them onto every caller, for no gain.

    The type check matters more in the TypeScript twin than here — there a 32-character string
    coerces to 32 zero bytes and produces a well-formed digest that ALIASES a legitimate all-zeros
    one. Python would raise inside ``_frame`` instead, but as a bare ``TypeError`` naming neither the
    field nor the tag: a caller mistake reported as an internal one. Both are worth refusing by name.
    """
    if value is None or (not optional and _as_bytes(value) == b""):
        # A mandatory slot read off the wire arrives as b"" when absent (`len == 0` IS absence on
        # tags 11/12/15), so the empty value is the same strip as None, reported as such.
        if optional:
            return None
        raise RecordDigestStripError(
            f"a v4 record carries no {name} (wire tag {tag}), which the v4 formula requires. "
            f"This is a STRIP, not a digest mismatch: refuse the record and do not substitute an "
            f"empty digest.",
            name,
            tag,
        )
    raw = _as_bytes(value)
    if raw is None:
        raise RecordDigestStripError(
            f"{name} (wire tag {tag}) is a {type(value).__name__}, not bytes — malformed.",
            name,
            tag,
        )
    if len(raw) != _SUB_DIGEST_LEN:
        raise RecordDigestStripError(
            f"{name} (wire tag {tag}) is {len(raw)} bytes, not {_SUB_DIGEST_LEN} — malformed, so no "
            f"v4 digest can be computed from it. Reported as a refusal rather than hashed, because "
            f"hashing it would surface a malformed field as though the record had been rewritten.",
            name,
            tag,
        )
    return raw


def _rd_enc(s: str) -> bytes:
    """UTF-8 bytes of ``s``, read through the UNBOUND ``str.encode``.

    The Python analogue of the TypeScript twin's shadowed-``length`` hole: a ``str`` subclass may
    override ``.encode()`` and return whatever bytes it likes, so ``value.encode()`` asks the value
    what it would like to be hashed as. ``str.encode(value)`` asks the string. Same discipline as
    :func:`_as_bytes` — measure what you hash — applied to text.

    The record-digest optionals use :func:`_rd_opt_text` below for the same reason.
    """
    return str.encode(s)


def _rd_opt_text(x: str | None) -> bytes:
    """``opt`` over text, encoded the same honest way. ``opt(x) = 0x00`` when absent, ``0x01 || frame(x)`` when present."""
    return b"\x00" if x is None else b"\x01" + _frame(_rd_enc(x))


def _rd_text(name: str, value: object, optional: bool) -> str | None:
    """A string slot of the v4 preimage, type-checked before it is encoded. Python's ``.encode()``
    already refuses a non-string (``AttributeError``) and a lone surrogate (``UnicodeEncodeError``);
    naming the slot turns both into a diagnosis instead of a traceback, and keeps the refusal set
    identical to the TypeScript twin's, where neither refusal comes for free."""
    if optional and value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a str{' (or None when absent)' if optional else ''}, not "
            f"{type(value).__name__}"
        )
    return value


def _mandatory_text(name: str, tag: int, value: object) -> str:
    """A mandatory v4 string slot (tags 14/16/17). Empty or ``None`` is a strip, never data: the spec
    reads ``len == 0`` on these tags as absence, and absence is refused."""
    if value is None or value == "":
        raise RecordDigestStripError(
            f"a v4 record carries no {name} (wire tag {tag}), which the v4 formula requires. "
            f"This is a STRIP, not a digest mismatch: refuse the record.",
            name,
            tag,
        )
    return _rd_text(name, value, False)  # type: ignore[return-value]


def _uint_slot(name: str, value: int, bits: int) -> int:
    """A fixed-width unsigned integer slot, range-checked before ``struct.pack`` refuses it less
    legibly. Python raises here either way; the TypeScript twin did NOT — ``DataView`` applies
    ToBigUint64/ToUint32 and wraps silently, so ``2**64 + 5`` wrote the same bytes as ``5``. Checking
    in both keeps the two implementations agreeing on which inputs have a digest at all.

    The ``bool`` exclusion is why it is shared: ``bool`` subclasses ``int``, so ``0 <= True < 1 << 64``
    is simply true and a range comparison alone digests ``sealed_at=True`` as ``1``. Once TypeScript's
    ``uintSlot`` began refusing ``true``, any framing that skipped this check disagreed across
    languages about a signed value. One shared rule, not a copy per framing."""
    _require_int(name, value)
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{name} is {value}, outside [0, 2^{bits})")
    return value


def _require_int(name: str, value: object) -> None:
    """The TYPE half of :func:`_uint_slot`, split out so it has one definition and two callers.

    ``verify_chain_head_attestation`` needs to apply this to every slot *before* range-checking any
    of them: it answers a range failure with ``False`` and a type failure by raising, so checking
    slot-by-slot lets a tampered value in an early slot short-circuit past a caller bug in a later
    one. Inlining a second copy here is what this phase spent two verification rounds learning not
    to do — the bug was never a missing check, it was a rule living in more than one place."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, not {type(value).__name__}")


def _opt_bytes(b: bytes | None) -> bytes:
    """``opt`` over raw bytes. Same presence byte as :func:`_rd_opt_text`, which takes a `str`."""
    return b"\x00" if b is None else b"\x01" + _frame(b)


#: Domain tag of the v4 participants sub-digest (wire tag 15).
PARTICIPANTS_DIGEST_DOMAIN_V4 = b"seam.audit.participants.v4"
#: The only record-digest ``schema_version`` this SDK recomputes (P7).
RECORD_DIGEST_SCHEMA_VERSION = 4


class UnsupportedRecordDigestVersion(ValueError):
    """A record's ``schema_version`` is not 4, so this SDK cannot verify it — **cannot-verify**, never a
    pass and never a mismatch.

    ``seam-event.v1.md`` §"Record digest" makes v4 the only formula and requires a verifier to *refuse*
    every other ``schema_version`` as unknown: it must never skip one and never default to a formula it
    was not asked for. v1-v3 were retired by the runtime's protocol pass (P7); a record sealed under
    them is not verifiable by this SDK, by design. ``schema_version`` carries the value refused.
    Subclasses ``ValueError`` so an existing ``except ValueError`` keeps catching it.
    """

    def __init__(self, schema_version: object) -> None:
        super().__init__(
            f"record digest schema_version {schema_version!r} cannot be verified: this SDK "
            f"recomputes v{RECORD_DIGEST_SCHEMA_VERSION} only (v1-v3 were retired by P7)"
        )
        #: The ``schema_version`` that was refused.
        self.schema_version = schema_version


def participants_digest_v4(participants: list[str]) -> bytes:
    """``participants_digest`` (wire tag 15) — ``seam.audit.participants.v4``.

    ``SHA256(frame(domain) || le32(count) || frame(id) for each id in STORED order)``: no sorting, no
    de-duplication, and the count is a bare ``le32``. The empty roster is a real 32-byte digest, never
    an absent slot. Spec: ``seam-event.v1.md`` §"participants_digest".
    """
    if isinstance(participants, (str, bytes)):
        raise TypeError("participants must be a list of str, not a single string")
    ids = [_rd_text(f"participants[{i}]", x, False) for i, x in enumerate(participants)]
    pre = _frame(PARTICIPANTS_DIGEST_DOMAIN_V4) + struct.pack("<I", len(ids))
    for x in ids:
        pre += _frame(_rd_enc(x))
    return hashlib.sha256(pre).digest()


def record_digest_v4(
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
    classification: str,
    participants_digest: bytes,
    trust_basis_commitment: str,
    auth_method: str,
    schema_version: int = 4,
) -> bytes:
    """Recompute a ``DECISION_SEALED`` record digest (``seam.audit.record-digest.v4``) — the only formula.

    Transcribed from ``seam-event.v1.md`` §"Record digest (v4)"::

        SHA256( frame(domain) ‖ frame(decision_id) ‖ frame(tenant) ‖ frame(namespace)
              ‖ frame(ciphertext_digest) ‖ frame(le64(sealed_at)) ‖ frame(outcome)
              ‖ opt(mode) ‖ opt(policy_version) ‖ opt(supersedes)
              ‖ frame(context_digest) ‖ frame(participation_digest) ‖ opt(policy_rules_digest)
              ‖ frame(classification) ‖ frame(participants_digest)
              ‖ frame(trust_basis_commitment) ‖ frame(auth_method) ‖ frame(le32(schema_version)) )

    The sub-digests (tags 11/12/13/15) are **opaque 32-byte wire inputs**; this is a wire-input
    recompute. The argument order is the one seam-runtime's ``sdk-digest-parity`` gate calls with, so
    do not reorder it.

    * **Digest slots are offset by one from the proto tags**, and new slots sit before
      ``schema_version``, which is always last.
    * **``None`` is not ``b""``.** ``policy_rules_digest`` is genuinely optional (``opt``); absence is
      spelled ``None`` here, and a wire consumer maps ``len == 0`` to ``None`` first (``seam-event.v1``
      §"Presence on the wire"). ``mode``/``policy_version``/``supersedes`` are ``opt`` text, where
      ``""`` is data.
    * **Tags 11, 12, 14, 15, 16 and 17 are mandatory.** An absent (``None`` or empty) one raises
      :class:`RecordDigestStripError` — a refusal, categorically distinct from the digest mismatch
      this function's return value is compared for.

    Raises :class:`UnsupportedRecordDigestVersion` for any ``schema_version`` other than 4.
    """
    # The version gate comes first: a record of another version has no v4 digest at all, so nothing
    # below (including a strip check) is meaningful for it.
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != RECORD_DIGEST_SCHEMA_VERSION
    ):
        raise UnsupportedRecordDigestVersion(schema_version)
    # Every slot is validated before a single byte is hashed: this function refuses any input it
    # cannot faithfully represent, rather than coercing it, so Python and TypeScript agree on which
    # inputs have a digest at all.
    context_digest = _sub_digest("context_digest", 11, context_digest, False)
    participation_digest = _sub_digest(
        "participation_digest", 12, participation_digest, False
    )
    policy_rules_digest = _sub_digest(
        "policy_rules_digest", 13, policy_rules_digest, True
    )
    participants_digest = _sub_digest(
        "participants_digest", 15, participants_digest, False
    )
    classification = _mandatory_text("classification", 14, classification)
    trust_basis_commitment = _mandatory_text(
        "trust_basis_commitment", 16, trust_basis_commitment
    )
    auth_method = _mandatory_text("auth_method", 17, auth_method)
    ciphertext_bytes = _as_bytes(ciphertext_digest)
    if ciphertext_bytes is None:
        raise TypeError(
            f"ciphertext_digest (wire tag 10) must be bytes, not "
            f"{type(ciphertext_digest).__name__}"
        )
    decision_id = _rd_text("decision_id", decision_id, False)
    tenant = _rd_text("tenant", tenant, False)
    namespace = _rd_text("namespace", namespace, False)
    outcome = _rd_text("outcome", outcome, False)
    mode = _rd_text("mode", mode, True)
    policy_version = _rd_text("policy_version", policy_version, True)
    supersedes = _rd_text("supersedes", supersedes, True)
    sealed_at = _uint_slot("sealed_at", sealed_at, 64)

    pre = (
        _frame(b"seam.audit.record-digest.v4")
        + _frame(_rd_enc(decision_id))
        + _frame(_rd_enc(tenant))
        + _frame(_rd_enc(namespace))
        + _frame(ciphertext_bytes)
        + _frame(struct.pack("<Q", sealed_at))
        + _frame(_rd_enc(outcome))
        + _rd_opt_text(mode)
        + _rd_opt_text(policy_version)
        + _rd_opt_text(supersedes)
        + _frame(context_digest)
        + _frame(participation_digest)
        + _opt_bytes(policy_rules_digest)
        + _frame(_rd_enc(classification))
        + _frame(participants_digest)
        + _frame(_rd_enc(trust_basis_commitment))
        + _frame(_rd_enc(auth_method))
        + _frame(struct.pack("<I", schema_version))
    )
    return hashlib.sha256(pre).digest()


CHAIN_HEAD_ATTESTATION_DOMAIN_V1 = b"seam.audit.chain-head-attestation.v1"
#: seam-runtime #835: the v1 frames under a new domain tag, then ``frame(tenant)``. Pinned by
#: ``conformance/chain_head_attestation_v2_vector.json``.
CHAIN_HEAD_ATTESTATION_DOMAIN_V2 = b"seam.audit.chain-head-attestation.v2"


def _chain_head_attestation_digest(
    attested_len: int,
    attested_head: bytes,
    attested_at: int,
    digest_schema: int,
    issuer_aid: str,
    tenant: str | None = None,
) -> bytes:
    """The 32-byte digest a ``CHAIN_HEAD_ATTESTATION`` signs over. ``tenant=None`` is the **v1** framing
    (``seam.audit.chain-head-attestation.v1``); a ``str`` is **v2** (``…v2``, then ``frame(tenant)``)."""
    pre = (
        _frame(
            CHAIN_HEAD_ATTESTATION_DOMAIN_V1
            if tenant is None
            else CHAIN_HEAD_ATTESTATION_DOMAIN_V2
        )
        + _frame(struct.pack("<Q", attested_len))
        + _frame(attested_head)
        + _frame(struct.pack("<Q", attested_at))
        + _frame(struct.pack("<I", digest_schema))
        + _frame(issuer_aid.encode())
    )
    if tenant is not None:
        pre += _frame(tenant.encode())
    return hashlib.sha256(pre).digest()


def verify_chain_head_attestation(
    issuer_aid: str,
    attested_len: int,
    attested_head: bytes,
    attested_at: int,
    digest_schema: int,
    signature: bytes,
    *,
    tenant: str,
) -> bool:
    """Verify a chain-head attestation's Ed25519 signature against the PINNED issuer AID (A14). Returns
    ``True`` iff the signature checks out over the recomputed digest; ``False`` on any tamper. The key comes
    from ``issuer_aid`` (which the caller pinned out of band), never from the attestation itself.

    ``tenant`` is the attestation's own payload ``tenant`` and selects exactly one signed framing,
    mirroring seam-runtime #835 step 4 (strict, no fallback): an empty tenant verifies under **v1 only**
    (the system partition; a v2 signature over ``""`` is refused), and a non-empty tenant under **v2
    only**, so the tenant is always inside the signature and relabelling it breaks verification. A v1
    attestation carrying a non-empty tenant — what the runtime minted before #835 step 3 — returns
    ``False``; there is no grace period and no toggle.

    ``tenant`` is **required** (keyword-only, no default): pass the attestation's own ``tenant``, or call
    :func:`verify_chain_head_attestation_message`, which takes every field — the tenant included — from
    the ``ChainHeadAttestation`` message itself. ``tenant=""`` is still a valid, explicit answer: it names
    the system partition and selects v1. There is deliberately no default, because a defaulted ``""``
    let a caller who dropped the argument verify the v1 signature alone and never look at the tenant the
    attestation carries on the wire, so a v1 attestation relabelled to a tenant came back ``True``.
    Omitting it raises ``TypeError``.
    """
    # An out-of-range integer is tampered input, not a caller bug, and this function's whole contract
    # is that tampered input returns ``False``. ``struct.pack`` raises ``struct.error`` on it, and the
    # recompute below sits OUTSIDE the try, so that error escaped a function documented to return
    # ``False`` on any tamper — a caller who wrote ``if not verify(...)`` got an exception instead of a
    # rejection, which is the difference between refusing an attestation and crashing on one.
    #
    # Checked here rather than by moving the recompute inside the try: that block ends in a blanket
    # ``except Exception: return False``, which would also swallow the ``TypeError`` a genuinely wrong
    # TYPE raises — turning a caller bug into a silent "unverified", the one outcome worse than the
    # crash. Comparison is the right instrument for exactly that reason: ``0 <= "5"`` still raises.
    #
    # (TypeScript's twin had the harsher version of this — ``DataView`` wrapped silently instead of
    # raising, so ``2**64 + 5`` and ``5`` reached one digest. Python's ``struct`` never aliased; only
    # the error's escape route was wrong. Same phase, different defect, and worth not conflating.)
    # Type first, then range, and the two are answered differently on purpose. A wrong TYPE is a
    # caller bug and raises; an out-of-RANGE integer is tampered input and returns ``False``.
    #
    # ``bool`` is excluded because it subclasses ``int``: ``0 <= True < 1 << 64`` is true, so a
    # comparison alone would digest ``attested_len=True`` as ``1`` — which TypeScript's ``uintSlot``
    # refuses outright, making it a cross-language divergence of exactly the kind this phase exists
    # to close. ``float`` is excluded for the same reason one slot along: ``5.0`` passed the range
    # comparison and then hit ``struct.pack``, which raised ``struct.error`` — a third answer, in a
    # function that should only ever give two.
    #
    # TYPES for every slot first, THEN ranges — not slot-by-slot. Interleaving them lets a tampered
    # value in an early slot short-circuit past a caller bug in a later one: with
    # ``attested_len=2**64`` and ``attested_at="7"`` this returned ``False``, reporting "did not
    # verify" about a call that never had a chance to. Tampered input would be masking exactly the
    # caller error this guard exists to surface, and only when both are present at once — the
    # combination nobody writes a test for.
    slots = (
        ("attested_len", attested_len, 64),
        ("attested_at", attested_at, 64),
        ("digest_schema", digest_schema, 32),
    )
    for name, value, _bits in slots:
        _require_int(name, value)
    # The two non-integer arguments belong in the same pass, for the same reason. Without them
    # ``attested_len=2**64`` with a str ``attested_head`` still returned ``False`` — the range check
    # answered first and the ``TypeError`` that ``_frame`` would have raised never happened. "Types
    # first" has to mean every type, or it is just a different interleaving.
    #
    # Through `_as_bytes`, NOT a bare isinstance. The first cut of this check wrote
    # `isinstance(attested_head, (bytes, bytearray, memoryview))`, which narrowed the argument from
    # any buffer-protocol object to those three: `array.array("B", ...)` verified `True` before and
    # raised after. `_as_bytes` is this module's one definition of "is this a byte sequence", it is
    # what `record_digest_v4` uses, and it also settles the `memoryview` itemsize trap its own
    # docstring describes — so a bare isinstance here would have left `record_digest_v4` and this
    # function disagreeing about what bytes are. Writing a second copy of a rule the module already
    # owns is the exact mistake this phase spent three verification rounds learning not to make, and
    # it was made again, here, in the fix for it.
    head = _as_bytes(attested_head)
    if head is None:
        raise TypeError(
            f"attested_head must be a byte sequence, not {type(attested_head).__name__}"
        )
    if not isinstance(issuer_aid, str):
        raise TypeError(f"issuer_aid must be a str, not {type(issuer_aid).__name__}")
    if not isinstance(tenant, str):
        raise TypeError(f"tenant must be a str, not {type(tenant).__name__}")
    # ``signature`` belongs in this pass too, and its absence was a hole in the rule rather than an
    # exemption from it. Every other argument answered a wrong TYPE with ``TypeError``; a wrong-typed
    # signature fell through to the blanket ``except`` below and came back ``False`` — and the slip
    # that produces it is the ordinary one, passing the hex STRING instead of the decoded bytes. A
    # caller who does that is told the attestation did not verify, and goes looking for a compromised
    # audit chain. A rule applied to five arguments out of six is a rule with a hole in the shape of
    # the sixth.
    if _as_bytes(signature) is None:
        raise TypeError(
            f"signature must be a byte sequence, not {type(signature).__name__} — hex and base64 "
            "are str, not bytes; decode at the boundary, where the encoding is visible"
        )
    for name, value, bits in slots:
        try:
            _uint_slot(name, value, bits)
        except ValueError:
            # Out of RANGE is tampered input, and this function's contract is that tampered input
            # returns ``False``. The ``TypeError`` `_uint_slot` raises for a wrong TYPE is left to
            # propagate on purpose — see above.
            return False
    try:
        key = Ed25519PublicKey.from_public_bytes(_aid_to_pubkey(issuer_aid))
    except Exception:
        return False

    def under(framing_tenant: str | None) -> bool:
        digest = _chain_head_attestation_digest(
            attested_len, head, attested_at, digest_schema, issuer_aid, framing_tenant
        )
        try:
            key.verify(signature, digest)
            return True
        except Exception:
            return False

    return under(tenant) if tenant else under(None)


def verify_chain_head_attestation_message(issuer_aid: str, attestation: Any) -> bool:
    """Verify a ``ChainHeadAttestation`` **message** (the ``seam.event.v1`` proto, or anything with its
    fields) against the PINNED ``issuer_aid``, taking every signed field — ``tenant`` included — from the
    artifact itself, so the framing is always the one its own tenant selects (seam-runtime #835 step 4).
    Prefer it to :func:`verify_chain_head_attestation` whenever you hold the message: the keyword form
    requires ``tenant`` too, but this one cannot be handed a tenant other than the artifact's.

    The attestation must also NAME the pinned issuer: one naming another AID returns ``False`` before
    any signature work (the pin is what makes the signature mean anything). Same contract otherwise —
    ``False`` on any tamper, ``TypeError`` on a wrong-typed field."""
    if not isinstance(issuer_aid, str):
        raise TypeError(f"issuer_aid must be a str, not {type(issuer_aid).__name__}")
    if attestation.issuer_aid != issuer_aid:
        return False
    return verify_chain_head_attestation(
        issuer_aid,
        attestation.attested_len,
        attestation.attested_head,
        attestation.attested_at,
        attestation.digest_schema,
        attestation.signature,
        tenant=attestation.tenant,
    )


# ── call_sig v3 (`seam-authorize-call-v3`, seam-runtime #1125 / #1059) ───────────────────────────────
# v3 additionally signs the attribution fields v2 left unsigned: subject, subjects, client_request_id,
# session_id and features. The runtime tries v3 first, then v2. v2 stays accepted for two published SDK
# minors after the first one that signs v3, and then it is refused. Pinned by
# `conformance/call_sig_v3_payload_vector.json`, generated by an independent implementation.
CALL_SIG_V3_CONTEXT = b"seam-authorize-call-v3"


def _frame(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def call_sig_v3_payload(
    ticket: bytes,
    tool_input_digest: str,
    tool_name: str,
    agent_id: str,
    *,
    subject: str = "",
    subjects: list[str] | tuple[str, ...] = (),
    client_request_id: str = "",
    session_id: str = "",
    features: dict[str, str] | None = None,
) -> bytes:
    """The exact bytes :func:`call_sig_v3` signs:

    ``frame(context) || frame(ticket) || frame(tool_input_digest) || frame(tool_name) ||
    frame(agent_id) || frame(subject) || frame(u32le(n)) || frame(subjects[i])... ||
    frame(client_request_id) || frame(session_id) || frame(u32le(m)) || (frame(key) || frame(value))...``

    ``frame(x) = u32le(len(x)) || x`` over UTF-8, lengths in BYTES. Note the counts are framed too.
    ``subjects`` are signed **in the order sent**: not deduped and not sorted, because the server
    verifies what is on the wire. ``features`` are signed **sorted by (key bytes, value bytes)**,
    because a protobuf map has no order on the wire. An absent optional field is the empty string.

    Every argument must be the exact WIRE value of the ``AuthorizeRequest``. The runtime rebuilds
    this payload from the request it received, so any divergence is a rejected call.
    """
    feats = sorted(
        (k.encode("utf-8"), v.encode("utf-8")) for k, v in (features or {}).items()
    )
    parts = [
        _frame(CALL_SIG_V3_CONTEXT),
        _frame(ticket),
        _frame(tool_input_digest.encode("utf-8")),
        _frame(tool_name.encode("utf-8")),
        _frame(agent_id.encode("utf-8")),
        _frame(subject.encode("utf-8")),
        _frame(struct.pack("<I", len(subjects))),
        *(_frame(s.encode("utf-8")) for s in subjects),
        _frame(client_request_id.encode("utf-8")),
        _frame(session_id.encode("utf-8")),
        _frame(struct.pack("<I", len(feats))),
        *(_frame(k) + _frame(v) for k, v in feats),
    ]
    return b"".join(parts)


def call_sig_v3(
    agent_seed: bytes,
    ticket: bytes,
    digest: str,
    *,
    tool_name: str,
    agent_id: str,
    subject: str,
    subjects: list[str] | tuple[str, ...],
    client_request_id: str,
    session_id: str,
    features: dict[str, str] | None,
) -> bytes:
    """The v3 per-call proof-of-possession: Ed25519 by the agent key over :func:`call_sig_v3_payload`.

    On top of v2's bindings, v3 stops a captured signature being replayed with a different subject,
    session, client request id or feature set while the ticket is live. Every field is keyword-only
    with no default, for the same reason :func:`call_sig` gives: a defaulted field is a silent
    mismatch the server reports as a bad ticket.
    """
    return Ed25519PrivateKey.from_private_bytes(agent_seed).sign(
        call_sig_v3_payload(
            ticket,
            digest,
            tool_name,
            agent_id,
            subject=subject,
            subjects=subjects,
            client_request_id=client_request_id,
            session_id=session_id,
            features=features,
        )
    )


# ── Enrolment proof-of-possession (`seam-enroll-pop-v1`, seam-runtime #1157 / #1164, SDK #205) ─────────
# `EnrollTenantRequest.pop` is the subject AID's own consent to ONE enrolment: an Ed25519 signature, by
# the key the AID embeds, over the tenant and namespace it is being bound to. Without it a tenant-scoped
# operator could enrol any AID it has merely seen. Pinned by `conformance/enroll_pop_v1_payload_vector.json`,
# generated by an independent implementation. `EnrollProof` is a NamedTuple, not a dataclass:
# `scripts/` and the import-light tests load this file standalone by path, outside `sys.modules`, and
# `@dataclass` looks its own module up there.

ENROLL_POP_V1_CONTEXT = b"seam-enroll-pop-v1"
ENROLL_POP_NONCE_MAX_LEN = 128
_ENROLL_POP_NONCE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)


def validate_enroll_pop_nonce(nonce: str) -> str:
    """Refuse a nonce the runtime would refuse: 1..=128 characters of ``[A-Za-z0-9_-]``. Returns it
    unchanged. Raises :class:`TypeError` for a non-``str`` and :class:`ValueError` otherwise, naming the
    rule, so the mistake surfaces at the client instead of as a server-side ``INVALID_ARGUMENT``."""
    if not isinstance(nonce, str):
        raise TypeError(f"enrol pop nonce must be a str, got {type(nonce).__name__}")
    if not 1 <= len(nonce) <= ENROLL_POP_NONCE_MAX_LEN:
        raise ValueError(
            f"enrol pop nonce must be 1..={ENROLL_POP_NONCE_MAX_LEN} characters, got {len(nonce)}"
        )
    if not set(nonce) <= _ENROLL_POP_NONCE_CHARS:
        raise ValueError("enrol pop nonce must use only [A-Za-z0-9_-]")
    return nonce


def new_enroll_pop_nonce() -> str:
    """A fresh nonce: 16 random bytes as unpadded base64url — 22 characters, inside the contract."""
    import secrets

    return _b64url_nopad(secrets.token_bytes(16))


def enroll_pop_payload(
    subject_aid: str, tenant: str, namespace: str, issued_at_ms: int, nonce: str
) -> bytes:
    """The exact bytes an enrolment proof signs:

    ``frame("seam-enroll-pop-v1") || frame(subject_aid) || frame(tenant) || frame(namespace) ||
    frame(u64le(issued_at_ms)) || frame(nonce)``, with ``frame(x) = u32le(len(x)) || x`` over UTF-8,
    lengths in BYTES. ``issued_at_ms`` is Unix epoch MILLISECONDS as 8 raw little-endian bytes, not
    ASCII decimal. Every argument must be exactly what goes on the wire: the runtime rebuilds this
    payload from the request it received."""
    return b"".join(
        (
            _frame(ENROLL_POP_V1_CONTEXT),
            _frame(subject_aid.encode("utf-8")),
            _frame(tenant.encode("utf-8")),
            _frame(namespace.encode("utf-8")),
            _frame(struct.pack("<Q", _uint_slot("issued_at_ms", issued_at_ms, 64))),
            _frame(nonce.encode("utf-8")),
        )
    )


class EnrollProof(_NamedTuple):
    """The parts of ``EnrollTenantRequest.pop`` (``EnrollPop``), produced by the AGENT being enrolled
    and handed to the operator who calls ``SeamAdminClient.enroll_tenant(..., pop=proof)``.

    ``signature`` is the RAW 64-byte Ed25519 signature, as the gRPC ``bytes`` field carries it;
    :meth:`to_rest` gives the ``POST /v1/tenants`` form, where it is unpadded base64url. The runtime
    accepts a proof at most 5 minutes old and at most 60 s in the future, so produce it just before
    the enrolment call."""

    issued_at_ms: int
    nonce: str
    signature: bytes

    @property
    def signature_b64url(self) -> str:
        return _b64url_nopad(self.signature)

    def to_rest(self) -> dict:
        """The REST body's ``pop`` object."""
        return {
            "issued_at_ms": self.issued_at_ms,
            "nonce": self.nonce,
            "signature": self.signature_b64url,
        }


def enroll_pop(
    agent_seed: bytes,
    tenant: str,
    namespace: str,
    *,
    issued_at_ms: int,
    nonce: str,
) -> EnrollProof:
    """Sign an enrolment proof with the agent's own key. The subject AID is DERIVED from the seed —
    a proof can only ever speak for the key that signs it — and the nonce is validated first, since a
    proof the runtime will refuse is not worth producing. Prefer :meth:`seam_sdk.Agent.enrolment_proof`,
    which defaults ``issued_at_ms`` to now and ``nonce`` to a fresh random one."""
    validate_enroll_pop_nonce(nonce)
    sk = Ed25519PrivateKey.from_private_bytes(agent_seed)
    subject_aid = aid_from_pubkey(sk.public_key().public_bytes_raw())
    payload = enroll_pop_payload(subject_aid, tenant, namespace, issued_at_ms, nonce)
    return EnrollProof(
        issued_at_ms=issued_at_ms, nonce=nonce, signature=sk.sign(payload)
    )


def verify_enroll_pop(
    subject_aid: str,
    tenant: str,
    namespace: str,
    issued_at_ms: int,
    nonce: str,
    signature: bytes,
) -> bool:
    """``True`` iff ``signature`` is ``subject_aid``'s Ed25519 signature over :func:`enroll_pop_payload`
    of these exact fields. Checks the binding only — freshness is the runtime's call, on its clock."""
    try:
        Ed25519PublicKey.from_public_bytes(_aid_to_pubkey(subject_aid)).verify(
            signature,
            enroll_pop_payload(subject_aid, tenant, namespace, issued_at_ms, nonce),
        )
        return True
    except Exception:
        return False


# ── context_digest (wire tag 11) — seam.audit.context-provenance.v4 ─────────────────────────────────

#: Domain tag of the v4 context-provenance sub-digest (wire tag 11). ``.v4`` is the only formula:
#: ``.v1``-``.v3`` are not dispatched (``seam-event.v1.md`` §"Sub-digest domain tags").
CONTEXT_PROVENANCE_DOMAIN_V4 = b"seam.audit.context-provenance.v4"
#: The closed, PascalCase ``receipt_key_status`` vocabulary (``ContextBinding`` tag 14). ACDP's own JSON
#: form is lowercase; Seam seals the variant name, so ``"historical"`` is refused, not case-folded.
RECEIPT_KEY_STATUSES = ("Current", "Historical")


class ContextProvenanceError(ValueError):
    """A binding cannot enter the ``context-provenance.v4`` preimage — refused **before** hashing.

    Raised when ``receipt_key_status`` and ``receipt_hash`` are not paired (the spec requires the first
    to be present *exactly when* the second is) or when ``receipt_key_status`` is outside
    :data:`RECEIPT_KEY_STATUSES`. The runtime refuses such a record at seal, so one reaching a verifier
    was not produced by an honest seal: hashing it as given would hand back a digest for a record that
    cannot exist. ``index`` is the binding's position in stored order; ``field`` names the slot.
    Subclasses ``ValueError`` so an existing ``except ValueError`` keeps catching it.
    """

    def __init__(self, message: str, index: int, field: str) -> None:
        super().__init__(message)
        #: The binding's 0-based position in stored order.
        self.index = index
        #: The slot refused: ``receipt_key_status``.
        self.field = field


_CTX_TEXT = ("ctx_ref", "fidelity", "classification")
_CTX_OPT_TAIL = (
    "content_hash",
    "receipt_hash",
    "key_status",
    "resolved_status",
    "receipt_key_status",
)


def _ctx_get(binding: object, name: str, optional: bool) -> object:
    """A slot from a mapping (spec field names) or a ``pb.ContextBinding``. On the message an unset
    ``optional`` field reads as ``None`` through ``HasField`` — never as the proto default ``""``,
    which would frame an absent slot as present-and-empty."""
    if isinstance(binding, dict):
        return binding.get(name) if optional else binding[name]
    if optional and name != "derived_from":  # repeated: no presence bit
        return getattr(binding, name) if binding.HasField(name) else None  # type: ignore[attr-defined]
    return getattr(binding, name)


def context_digest_v4(bindings) -> bytes:
    """``context_digest`` (wire tag 11) — ``seam.audit.context-provenance.v4``.

    Transcribed from ``seam-event.v1.md`` §"context_digest"::

        SHA256( frame(domain) ‖ le32(len(bindings))
              ‖ per binding, STORED order:
                    frame(ctx_ref) ‖ frame(fidelity) ‖ frame(classification)
                  ‖ opt(lineage_id) ‖ frame(le32(version))
                  ‖ le32(len(derived_from)) ‖ frame(each)
                  ‖ opt(content_hash) ‖ opt(receipt_hash) ‖ opt(key_status) ‖ opt(resolved_status)
                  ‖ opt(receipt_key_status) )

    ``bindings`` is a list of ``pb.ContextBinding`` or of dicts keyed by the spec's field names. Stored
    order is hashed as given: nothing is sorted or de-duplicated, and no string is case-folded —
    ``key_status``/``receipt_key_status`` are closed PascalCase and ``resolved_status`` is open
    lowercase, all byte-identical to the preimage. ``retraction`` and the revocation pair are not in
    the preimage.

    Raises :class:`ContextProvenanceError` on an unpaired ``receipt_key_status``/``receipt_hash`` or an
    out-of-vocabulary ``receipt_key_status``; every binding is checked before any byte is hashed.
    """
    if isinstance(bindings, (str, bytes, dict)):
        raise TypeError(
            "bindings must be a list of ContextBinding (or dicts), not a single value"
        )
    rows = []
    for i, bd in enumerate(bindings):
        text = [
            _rd_text(f"bindings[{i}].{n}", _ctx_get(bd, n, False), False)
            for n in _CTX_TEXT
        ]
        lineage = _rd_text(
            f"bindings[{i}].lineage_id", _ctx_get(bd, "lineage_id", True), True
        )
        version = _uint_slot(
            f"bindings[{i}].version", _ctx_get(bd, "version", False), 32
        )
        derived = _ctx_get(bd, "derived_from", True)
        derived = [] if derived is None else list(derived)
        derived = [
            _rd_text(f"bindings[{i}].derived_from[{j}]", d, False)
            for j, d in enumerate(derived)
        ]
        tail = [
            _rd_text(f"bindings[{i}].{n}", _ctx_get(bd, n, True), True)
            for n in _CTX_OPT_TAIL
        ]
        receipt_hash, receipt_key_status = tail[1], tail[4]
        if (receipt_key_status is None) != (receipt_hash is None):
            raise ContextProvenanceError(
                f"bindings[{i}]: receipt_key_status is present exactly when receipt_hash is, and here "
                f"{'receipt_hash' if receipt_key_status is None else 'receipt_key_status'} stands "
                f"alone. The runtime refuses this at seal; refuse it rather than hash it.",
                i,
                "receipt_key_status",
            )
        if (
            receipt_key_status is not None
            and receipt_key_status not in RECEIPT_KEY_STATUSES
        ):
            raise ContextProvenanceError(
                f"bindings[{i}]: receipt_key_status {receipt_key_status!r} is outside the closed "
                f"vocabulary {RECEIPT_KEY_STATUSES} (PascalCase; ACDP's lowercase form is not it)",
                i,
                "receipt_key_status",
            )
        rows.append((text, lineage, version, derived, tail))
    pre = _frame(CONTEXT_PROVENANCE_DOMAIN_V4) + struct.pack("<I", len(rows))
    for text, lineage, version, derived, tail in rows:
        for t in text:
            pre += _frame(_rd_enc(t))
        pre += _rd_opt_text(lineage) + _frame(struct.pack("<I", version))
        pre += struct.pack("<I", len(derived))
        for d in derived:
            pre += _frame(_rd_enc(d))
        for t in tail:
            pre += _rd_opt_text(t)
    return hashlib.sha256(pre).digest()
