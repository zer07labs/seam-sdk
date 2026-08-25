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
    text = int.__repr__(v)  # unspoofable, and the value all further checks are taken from
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

    ``field`` and ``wire_tag`` carry the same information as the message, structurally: a caller
    routing a refusal (to an alert, a metric label, a retry decision) should never have to parse
    English to learn *which* field was stripped. The TypeScript twin exposes the same two.
    """

    def __init__(self, message: str, field: str, wire_tag: int) -> None:
        super().__init__(message)
        #: The spec's field name, e.g. ``context_digest``.
        self.field = field
        #: The ``DecisionSealed`` wire tag the field occupies — 11, 12 or 13.
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
    # HOLDS — the same "ask the object what it would like to be hashed as" mistake `_v3_enc` avoids
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


def _v3_sub_digest(name: str, tag: int, value: object, optional: bool) -> bytes | None:
    """One of the three v3 sub-digests (wire tags 11/12/13), validated as the spec requires: tags 11
    and 12 are mandatory, tag 13 is genuinely optional, and all three must be exactly 32 bytes when
    present. ``optional`` selects which of those two contracts applies.

    Every refusal is a :class:`RecordDigestStripError`, whatever the proximate cause — absent, wrong
    type, wrong length. From the caller's side those are one condition: *this field is not a usable
    32-byte digest, so no v3 digest exists.* Splitting them into different exception types would push
    the work of re-joining them onto every caller, for no gain.

    The type check matters more in the TypeScript twin than here — there a 32-character string
    coerces to 32 zero bytes and produces a well-formed digest that ALIASES a legitimate all-zeros
    one. Python would raise inside ``_frame`` instead, but as a bare ``TypeError`` naming neither the
    field nor the tag: a caller mistake reported as an internal one. Both are worth refusing by name.
    """
    if value is None:
        if optional:
            return None
        raise RecordDigestStripError(
            f"a schema_version=3 record carries no {name} (wire tag {tag}), which the v3 formula "
            f"requires. This is a STRIP, not a digest mismatch: refuse the record, do not substitute "
            f"an empty digest and do not fall back to the v2 formula.",
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
    if len(raw) != _V3_DIGEST_LEN:
        raise RecordDigestStripError(
            f"{name} (wire tag {tag}) is {len(raw)} bytes, not {_V3_DIGEST_LEN} — malformed, so no "
            f"v3 digest can be computed from it. Reported as a refusal rather than hashed, because "
            f"hashing it would surface a malformed field as though the record had been rewritten.",
            name,
            tag,
        )
    return raw


def _v3_enc(s: str) -> bytes:
    """UTF-8 bytes of ``s``, read through the UNBOUND ``str.encode``.

    The Python analogue of the TypeScript twin's shadowed-``length`` hole: a ``str`` subclass may
    override ``.encode()`` and return whatever bytes it likes, so ``value.encode()`` asks the value
    what it would like to be hashed as. ``str.encode(value)`` asks the string. Same discipline as
    :func:`_as_bytes` — measure what you hash — applied to text.

    Deliberately NOT routed through :func:`_opt`, which ``record_digest_v2`` shares and issue #56
    freezes; the v3 optionals use :func:`_v3_opt_text` below instead. The duplication is the safety
    property, as it is for the rest of the v3 formula.
    """
    return str.encode(s)


def _v3_opt_text(x: str | None) -> bytes:
    """``opt`` over text, encoded the same honest way. Same presence byte as :func:`_opt`."""
    return b"\x00" if x is None else b"\x01" + _frame(_v3_enc(x))


def _v3_text(name: str, value: object, optional: bool) -> str | None:
    """A string slot of the v3 preimage, type-checked before it is encoded. Python's ``.encode()``
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


def _v3_uint(name: str, value: int, bits: int) -> int:
    """A fixed-width unsigned integer slot, range-checked before ``struct.pack`` refuses it less
    legibly. Python raises here either way; the TypeScript twin does NOT — ``DataView`` applies
    ToBigUint64/ToUint32 and wraps silently, so ``2**64 + 5`` writes the same bytes as ``5``. Checking
    in both keeps the two implementations agreeing on which inputs have a digest at all."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, not {type(value).__name__}")
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{name} is {value}, outside [0, 2^{bits})")
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
    * **``None`` is not ``b""`` — and at THIS layer they are two different refusals, not two
      different digests.** ``opt(None)`` is one byte and ``opt(b"")`` is five, so the presence byte
      does keep them apart in the preimage. But the empty digest is outside these slots' value
      domain entirely ({absent} ∪ {32 bytes}), so this function never hashes ``b""``: it refuses it.
      Absence is spelled ``None`` here. A **wire** consumer must not pass ``b""`` through expecting
      ``opt(Some(b""))`` — on the wire ``len == 0`` IS absence (a total mapping, per
      ``seam-event.v1`` §"Presence on the wire"), so the caller maps it to ``None`` first. That
      mapping is the streamed helpers' job; see :func:`seam_sdk.admin.verify_streamed_record_digest`.
      (The "present-but-empty is data" rule is real, but it belongs to the *string* slots — ``mode``,
      ``policy_version``, ``supersedes`` — where the empty string IS in the domain.)

    Raises :class:`RecordDigestStripError` when ``context_digest`` or ``participation_digest`` is
    absent or is not 32 bytes, and when a *present* ``policy_rules_digest`` is not 32 bytes. That is
    a refusal, categorically distinct from the digest mismatch this function's *return value* is
    compared for — see the class docstring.
    """
    # Every slot is validated before a single byte is hashed. The rule is one sentence: this
    # function refuses any input it cannot faithfully represent, rather than coercing it. Python
    # refuses most of these on its own, but as bare `TypeError`/`AttributeError`/`struct.error` from
    # somewhere inside the preimage — and the TypeScript twin refuses almost none of them without
    # help. Validating explicitly is what makes the two agree on which inputs have a digest at all.
    context_digest = _v3_sub_digest("context_digest", 11, context_digest, False)
    participation_digest = _v3_sub_digest(
        "participation_digest", 12, participation_digest, False
    )
    policy_rules_digest = _v3_sub_digest(
        "policy_rules_digest", 13, policy_rules_digest, True
    )
    ciphertext_bytes = _as_bytes(ciphertext_digest)
    if ciphertext_bytes is None:
        raise TypeError(
            f"ciphertext_digest (wire tag 10) must be bytes, not "
            f"{type(ciphertext_digest).__name__}"
        )
    decision_id = _v3_text("decision_id", decision_id, False)
    tenant = _v3_text("tenant", tenant, False)
    namespace = _v3_text("namespace", namespace, False)
    outcome = _v3_text("outcome", outcome, False)
    mode = _v3_text("mode", mode, True)
    policy_version = _v3_text("policy_version", policy_version, True)
    supersedes = _v3_text("supersedes", supersedes, True)
    sealed_at = _v3_uint("sealed_at", sealed_at, 64)
    schema_version = _v3_uint("schema_version", schema_version, 32)

    pre = (
        _frame(b"seam.audit.record-digest.v3")
        + _frame(_v3_enc(decision_id))
        + _frame(_v3_enc(tenant))
        + _frame(_v3_enc(namespace))
        + _frame(ciphertext_bytes)
        + _frame(struct.pack("<Q", sealed_at))
        + _frame(_v3_enc(outcome))
        + _v3_opt_text(mode)
        + _v3_opt_text(policy_version)
        + _v3_opt_text(supersedes)
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
