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
from typing import Any, Optional
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
#: ``proposal`` (runtime 0.90.0, option selection) is one accepted option of a selection session; it never
#: carries a voter record.
EXPLANATION_KINDS = ("vote", "evaluation", "objection", "ballot", "proposal")


def _be64_frame(field: bytes) -> bytes:
    return len(field).to_bytes(8, "big") + field


#: The ``method`` words ``seam-explanation-digest:v2`` frames in a voter verification record (#1687).
#: ``cp_signed`` is declared, not yet served; ``UNSPECIFIED`` is never sealed and is refused.
VOTER_VERIFICATION_METHODS = ("pop", "cp_signed")
#: The entry kinds that MUST carry a voter verification record, and the one that must not (#1687).
VOTER_VERIFIED_KINDS = ("vote", "ballot", "objection")

# The VV block's fields in normative order: (name, encoding). "t" = F(UTF-8), "b" = F(raw bytes),
# "u" = be64 unsigned.
_VV_FIELDS = (
    ("method", "t"),
    ("principal", "t"),
    ("content_digest", "b"),
    ("issued_at_ms", "u"),
    ("expires_at_ms", "u"),
    ("signature", "b"),
    ("signer_certificate", "b"),
    ("tenant", "t"),
    ("namespace", "t"),
    ("session_id", "t"),
    ("opened_at_millis", "u"),
    ("issuer", "t"),
    ("audience", "t"),
    ("accepted_at_ms", "u"),
)


def _vv_bytes(vv, name: str) -> bytes:
    """A bytes field of a voter verification record: ``name`` as bytes, or ``name + "_hex"`` as hex (the
    vector form). Missing means empty."""
    if vv.get(name) is not None:
        return bytes(vv[name])
    h = vv.get(name + "_hex")
    return bytes.fromhex(h) if h else b""


def voter_verification_frame(vv) -> bytes:
    """The ``VV`` block of ``seam-explanation-digest:v2`` for one entry: ``0x00`` when ``vv`` is ``None``,
    else ``0x01`` followed by all fourteen record fields, always framed. Raises ``ValueError`` on an
    unknown ``method`` or a ``content_digest`` that is not 32 bytes, rather than hash a record no
    runtime sealed."""
    if vv is None:
        return b"\x00"
    if vv.get("method") not in VOTER_VERIFICATION_METHODS:
        raise ValueError(f"unknown voter verification method {vv.get('method')!r}")
    out = [b"\x01"]
    for name, enc in _VV_FIELDS:
        if enc == "t":
            out.append(_be64_frame((vv.get(name) or "").encode()))
        elif enc == "b":
            b = _vv_bytes(vv, name)
            if name == "content_digest" and len(b) != 32:
                raise ValueError(
                    f"voter verification content_digest must be 32 bytes, got {len(b)}"
                )
            out.append(_be64_frame(b))
        else:
            out.append(_uint_slot(name, int(vv.get(name) or 0), 64).to_bytes(8, "big"))
    return b"".join(out)


def _canonical_confidence(conf) -> float:
    import math

    if isinstance(conf, bool) or not isinstance(conf, (int, float)):
        raise ValueError(f"confidence must be a number, got {conf!r}")
    conf = float(conf)
    if (
        not math.isfinite(conf)
        or not 0.0 <= conf <= 1.0
        or math.copysign(1.0, conf) < 0
    ):
        raise ValueError(f"non-canonical confidence {conf!r}")
    return conf


def explanation_digest(entries) -> bytes:
    """``seam-explanation-digest:v2`` over a sealed explanation (32 raw bytes).

    ``entries`` is the list of explanation entries in the order the runtime sealed them, each a mapping
    with ``kind`` (one of :data:`EXPLANATION_KINDS`), ``participant``, ``proposal_id``, ``value``,
    ``reason``, optional ``confidence`` / ``rationale_ref`` (``None`` or missing = absent), and optional
    ``voter_verification`` (a record mapping, see :func:`voter_verification_frame`; ``None`` = absent).
    An absent confidence and a stated ``0.0`` are different bytes. Raises ``ValueError`` on an unknown
    kind, a non-canonical confidence (NaN, ±inf, outside ``[0.0, 1.0]``, or ``-0.0``) or a malformed
    voter record rather than hashing it. Normative: seam-runtime
    ``docs/specs/seam-commitment-digest.v4.md`` (#1687)."""
    entries = list(entries)
    out = [_be64_frame(b"seam-explanation-digest:v2"), len(entries).to_bytes(8, "big")]
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
        out.append(
            b"\x00"
            if conf is None
            else b"\x01" + struct.pack(">d", _canonical_confidence(conf))
        )
        ref = e.get("rationale_ref")
        out.append(b"\x00" if ref is None else b"\x01" + _be64_frame(ref.encode()))
        out.append(voter_verification_frame(e.get("voter_verification")))
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


def _digest_slot(commitment: dict, name: str) -> bytes:
    """Commitment digest v5 fields 9/10/11: ``0x00`` when ``name`` is absent (missing or ``None``), else
    ``0x01 || F(digest)`` over exactly 32 raw bytes (bytes, or 64 hex chars). Any other length is refused,
    never hashed."""
    v = commitment.get(name)
    if v is None:
        return b"\x00"
    b = bytes.fromhex(v) if isinstance(v, str) else bytes(v)
    if len(b) != 32:
        raise ValueError(f"{name} must be 32 bytes, got {len(b)}")
    return b"\x01" + _be64_frame(b)


def _selection_block(commitment: dict) -> dict | None:
    """The commitment's selection block, strictly decoded, or ``None`` when it carries none ("not a
    selection decision"). ``selection`` is the canonical body (bytes) or a block mapping /
    ``SelectionRecord``; anything that does not strictly decode raises, never reads as absent."""
    v = commitment.get("selection")
    if v is None:
        return None
    body = (
        bytes(v) if isinstance(v, (bytes, bytearray, memoryview)) else selection_body(v)
    )
    return decode_selection_body(body)


def _selection_slot(commitment: dict) -> bytes:
    """v5 field 9. With a ``selection`` block it is framed from this verifier's own recomputation over the
    block (spec: never from anywhere else); a ``selection_digest`` given beside it must agree. Without one,
    the plain ``selection_digest`` slot."""
    blk = _selection_block(commitment)
    if blk is None:
        return _digest_slot(commitment, "selection_digest")
    d = selection_digest(selection_body(blk))
    given = commitment.get("selection_digest")
    if given is not None:
        g = bytes.fromhex(given) if isinstance(given, str) else bytes(given)
        if g != d:
            raise ValueError("selection_digest does not match the selection block")
    return b"\x01" + _be64_frame(d)


def _seam_commitment_digest(commitment: dict) -> str:
    """``seam-commitment-digest:v5`` (hex): SHA-256 over the length-prefixed domain tag and fields.

    Spec: seam-runtime ``docs/specs/seam-commitment-digest.v5.md`` (v4 plus field 11; v4 holds the
    framing it does not restate). Every field is ``F(x) = be64(len) ||
    x`` (no separator), so the digest is injective over ``(domain, id, action, authority, supersedes,
    auth_method, trust_basis, committer, explanation_digest, selection_digest, certificate_digest,
    governing_doc_sha256)``.
    The length prefixes are load-bearing: with a NUL separator instead, ``("a\\0b", "c")`` and
    ``("a", "b\\0c")`` would collide, and these fields are arbitrary text that may itself contain NUL.
    Never "simplify" them away. ``supersedes`` carries a presence byte: ``0x00`` when absent (key missing
    or ``None``), ``0x01 || F(value)`` when present. Field 8 is the 32 raw bytes of the v2 explanation
    digest (see :func:`_commitment_explanation_digest`). Fields 9 and 10 are the optional
    ``selection_digest`` and ``certificate_digest`` (32 bytes each, :func:`_digest_slot`). Field 9 is
    framed from the ``selection`` block when the commitment carries one (runtime 0.90.0,
    :func:`_selection_slot`), and is ``0x00`` on every record that did not run under selection. Field 11 is ``governing_doc_sha256`` (#1711), the SHA-256 of
    the tenant governing document the decision was opened under: the same slot, present on every
    governed record and absent on an ungoverned one. v1-v4 are deleted, not dual-verified: a v4 TCT
    does not verify here, and there is no fallback.
    """
    supersedes = commitment.get("supersedes")
    out = [
        _be64_frame(b"seam-commitment-digest:v5"),
        _be64_frame(commitment["id"].encode()),
        _be64_frame(commitment["action"].encode()),
        _be64_frame(commitment["authority"].encode()),
        b"\x00" if supersedes is None else b"\x01" + _be64_frame(supersedes.encode()),
        _be64_frame(commitment["auth_method"].encode()),
        _be64_frame(commitment["trust_basis"].encode()),
        _be64_frame((commitment.get("committer") or "").encode()),
        _be64_frame(_commitment_explanation_digest(commitment)),
        _selection_slot(commitment),
        _digest_slot(commitment, "certificate_digest"),
        _digest_slot(commitment, "governing_doc_sha256"),
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


#: The ``ext`` member carrying the seal-key certificate (seam-runtime #2031, deep-cleanup S-4), beside
#: the commitment statement under :data:`COMMITMENT_EXT_KEY`.
SEAL_KEY_CERT_EXT_KEY = "com.zer07labs.seam.seal-key-cert"
#: The seal-key certificate's domain tag (``seam_types::chain::SEAL_KEY_CERT_DOMAIN``).
SEAL_KEY_CERT_DOMAIN = b"seam.seal-key-cert.v1"
#: The widest certificate window a verifier accepts, ``not_after - not_before``: one hour plus 30 s skew.
SEAL_KEY_MAX_WINDOW_MS = 3_600_000 + 30_000
#: The longest issuer AID a certificate may carry (the tagged Ed25519 form).
_SEAL_KEY_ISSUER_AID_MAX = 62
_I64_MAX = 2**63 - 1

# The 14 32-byte encodings that decode to an Ed25519 point of small order (the 8 torsion points, their
# non-canonical ``y + p`` aliases and sign-bit variants). ed25519-dalek's ``verify_strict``, which the
# runtime uses for the certificate, refuses a small-order public key or ``R``; OpenSSL's verify already
# refuses a non-canonical ``S`` and compares ``R`` byte-exactly, so this set is the whole difference.
_SMALL_ORDER_ENCODINGS = frozenset(
    bytes.fromhex(h)
    for h in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
)

_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _b64url_decode_strict(s: object) -> bytes:
    """Strict unpadded base64url: alphabet only, no ``=``, a valid length, canonical trailing bits."""
    if not isinstance(s, str) or len(s) % 4 == 1 or not set(s) <= _B64URL_ALPHABET:
        raise ValueError("not strict base64url")
    out = _b64url_decode(s)
    if _b64url_nopad(out) != s:
        raise ValueError("non-canonical base64url")
    return out


def _ed25519_verify_strict(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """Ed25519 verify with ed25519-dalek ``verify_strict`` semantics (see :data:`_SMALL_ORDER_ENCODINGS`)."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    if pub in _SMALL_ORDER_ENCODINGS or sig[:32] in _SMALL_ORDER_ENCODINGS:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
    except Exception:
        return False
    return True


class SealKeyCert(_NamedTuple):
    """A parsed seal-key certificate (seam-runtime ``seal_key::SealKeyCert``)."""

    seal_pk: bytes
    not_before_ms: int
    not_after_ms: int
    issuer_aid: str


def parse_seal_key_cert(cert: bytes) -> SealKeyCert | None:
    """Parse ``framed("seam.seal-key-cert.v1") ‖ framed(seal_pk[32]) ‖ le64(not_before_ms) ‖
    le64(not_after_ms) ‖ framed(issuer_aid)`` (``framed(x) = u32le(len) ‖ x``). ``None`` on a wrong tag, a
    key that is not 32 bytes, truncation, trailing bytes, an issuer AID longer than 62 bytes or not UTF-8,
    an inverted window, a ``not_after`` beyond ``i64::MAX`` ms, or a window wider than
    :data:`SEAL_KEY_MAX_WINDOW_MS`."""
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(cert):
            raise ValueError("truncated")
        b = cert[pos : pos + n]
        pos += n
        return b

    def framed() -> bytes:
        return take(struct.unpack("<I", take(4))[0])

    try:
        if framed() != SEAL_KEY_CERT_DOMAIN:
            return None
        seal_pk = framed()
        if len(seal_pk) != 32:
            return None
        nb = struct.unpack("<Q", take(8))[0]
        na = struct.unpack("<Q", take(8))[0]
        aid = framed()
    except (ValueError, struct.error):
        return None
    if pos != len(cert) or len(aid) > _SEAL_KEY_ISSUER_AID_MAX:
        return None
    if not (nb <= na <= _I64_MAX and na - nb <= SEAL_KEY_MAX_WINDOW_MS):
        return None
    try:
        issuer = aid.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return SealKeyCert(seal_pk, nb, na, issuer)


def verify_seal_key_cert(
    pinned_issuer_aid: str, cert: bytes, sig: bytes
) -> SealKeyCert | None:
    """Verify a seal-key certificate under the **pinned** issuer AID: it must parse, name exactly that AID,
    and carry the issuer's strict Ed25519 signature over ``sha256(cert)``. ``None`` on any failure."""
    fields = parse_seal_key_cert(cert)
    if fields is None or fields.issuer_aid != pinned_issuer_aid:
        return None
    try:
        pub = _aid_to_pubkey(pinned_issuer_aid)
    except Exception:
        return None
    if not _ed25519_verify_strict(pub, sig, hashlib.sha256(cert).digest()):
        return None
    return fields


def _jwk_thumbprint(pub: bytes) -> str:
    """RFC 7638 thumbprint of an Ed25519 key (the AITP ``cnf.jkt``)."""
    jwk = '{"crv":"Ed25519","kty":"OKP","x":"' + _b64url_nopad(pub) + '"}'
    return _b64url_nopad(hashlib.sha256(jwk.encode()).digest())


def _seal_key_cert_member(member: object) -> tuple[bytes, bytes]:
    """The ``{cert, sig}`` member, decoded; exactly those two string members, strict base64url."""
    if not isinstance(member, dict) or set(member) != {"cert", "sig"}:
        raise ValueError("seal-key cert member is not exactly {cert, sig}")
    return _b64url_decode_strict(member["cert"]), _b64url_decode_strict(member["sig"])


def verify_tct(
    issuer_aid: str,
    tct_jws: str,
    commitment: dict,
    now_s: int | None = None,
    *,
    decision: tuple[str, str] | None = None,
) -> bool:
    """Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only.

    The TCT is an RFC-AITP-0005 self-attestation **by a seal key the pinned issuer certifies**
    (seam-runtime #2031, deep-cleanup S-4, runtime 0.123.0; spec ``seam-commitment-digest.v6.md``
    §Seal key). ``ext`` is exactly ``{"com.zer07labs.seam": <statement>,
    "com.zer07labs.seam.seal-key-cert": {"cert", "sig"}}``. The certificate must parse
    (:func:`parse_seal_key_cert`), name exactly ``issuer_aid`` and carry the issuer's strict Ed25519
    signature over ``sha256(cert)`` (:func:`verify_seal_key_cert`). The EdDSA JWS is then verified under
    the certified **seal** key, with ``iss==sub==aud`` its untagged ``aid:pubkey:`` AID, ``cnf.jkt`` its
    thumbprint, and an integer ``iat`` with ``not_before_ms <= iat*1000 <= not_after_ms`` (no grace).
    There is no backward compatibility: a TCT the issuer signed directly (every TCT before runtime
    0.123.0) verifies ``False``. Also checked: `typ`/`alg`, `exp`, and that `grants` is exactly
    `["aitp.attestation"]`. The statement's exact member set picks v5 or v6 (:func:`select_commitment_version`)
    and the digest is recomputed under that version only, over this exact commitment (a v6 one carries
    its raw ``trailers``; :func:`commitment_digest_v6`). A duplicate JSON key anywhere in the header or
    payload, a statement carried in `grants` (the retired v2 shape), or an extra grant verifies
    ``False``. ``commitment`` carries ``committer`` and the ``explanation`` entries and/or the published
    ``explanation_digest``; entries that disagree with the published digest, an unknown kind, or a
    non-canonical confidence verify ``False``.

    When the ``explanation`` entries are given, the sealed voter records are checked too (runtime
    0.87.0, #1687, :func:`verify_commitment_voters`): every vote, ballot and objection must carry a
    ``seam-voter-pop-v1`` record addressed to ``issuer_aid`` that re-verifies offline, all from one
    session, and, with ``decision=(tenant, session_id)``, from that decision's session. With only the
    published ``explanation_digest`` there are no entries to check, so this proves *who* and *what*.

    When ``commitment`` carries a ``selection`` block (runtime 0.90.0, option selection), field 9 is
    framed from it and the winner is recomputed offline (:func:`seam_sdk.selection.verify_selection`):
    the committed action must be the winning option and every vote's signed content must link to it. A
    block with no ``explanation`` entries verifies ``False``. No block is "not a selection decision".
    """
    # Any malformed/forged input must fail closed (return False), never raise.
    try:
        parts = tct_jws.split(".")
        if len(parts) != 3:
            return False
        header_b64, payload_b64, sig_b64 = parts
        # S-4 (1): read the seal-key certificate member from the not-yet-verified payload (parsed with the
        # duplicate-key guard): the token's signer is only known once the certificate names it.
        payload = json.loads(
            _b64url_decode(payload_b64), object_pairs_hook=_no_duplicate_keys
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("ext"), dict):
            return False
        peeked = payload["ext"].get(SEAL_KEY_CERT_EXT_KEY)
        cert_bytes, cert_sig = _seal_key_cert_member(peeked)
        # (2) the certificate, under the PINNED issuer it must name.
        cert = verify_seal_key_cert(issuer_aid, cert_bytes, cert_sig)
        if cert is None:
            return False
        seal_aid = "aid:pubkey:" + _b64url_nopad(cert.seal_pk)
        # (3) the token as a self-attestation by the certified seal key.
        Ed25519PublicKey.from_public_bytes(cert.seal_pk).verify(
            _b64url_decode(sig_b64), f"{header_b64}.{payload_b64}".encode("ascii")
        )
        header = json.loads(
            _b64url_decode(header_b64), object_pairs_hook=_no_duplicate_keys
        )
        if header.get("alg") != "EdDSA" or header.get("typ") != "aitp-tct+jwt":
            return False
        if not (
            payload.get("iss") == payload.get("sub") == payload.get("aud") == seal_aid
        ):
            return False
        cnf = payload.get("cnf")
        if not isinstance(cnf, dict) or cnf.get("jkt") != _jwk_thumbprint(cert.seal_pk):
            return False
        if payload["ext"].get(SEAL_KEY_CERT_EXT_KEY) != peeked:
            return False
        # (4) iat inside the certificate window, no grace. `bool` subclasses `int`: refuse it first.
        iat = payload.get("iat")
        if isinstance(iat, bool) or not isinstance(iat, int):
            return False
        t = iat * 1000
        if not (-(2**63) <= t <= _I64_MAX):
            return False
        if not (cert.not_before_ms <= t <= cert.not_after_ms):
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
        if not isinstance(ext, dict) or set(ext) != {
            COMMITMENT_EXT_KEY,
            SEAL_KEY_CERT_EXT_KEY,
        }:
            return False
        stmt = ext[COMMITMENT_EXT_KEY]
        # v6 statement selection: the exact member set picks v5 or v6 (or refuses, raising), then the
        # digest is recomputed under that version only, with its trailer rules; never both, no fallback.
        version = _select_statement_version(stmt)
        expected = _tct_commitment_digest(version, commitment)
        # Exact string compare: the runtime emits lowercase hex, and an uppercase spelling is a
        # different statement, not a normalization opportunity.
        entries = commitment.get("explanation")
        if entries is not None and not verify_commitment_voters(
            entries, issuer_aid, decision
        ):
            return False
        if stmt["commitment_digest"] != expected:
            return False
        # Option selection (runtime 0.90.0, selection-rule.v1 §5 steps 4, 6-9). No block means "not a
        # selection decision" and nothing more. A block without the entries cannot be checked, so it
        # fails closed rather than passing as if the winner had been recomputed.
        blk = _selection_block(commitment)
        if blk is not None:
            if entries is None:
                return False
            return verify_selection(blk, entries, commitment["action"]).ok
        return True
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


# ── The per-request credential (`seam-request-call-v1`, #508) ──────────────────────────────────────
# A DIFFERENT domain tag from `seam-authorize-call-v3` (below), deliberately, so a captured `Authorize`
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

    Binding the digest, tool_name, agent_id and ticket stops a captured signature being re-pointed at
    another input, tool call, agent or ticket; v3 also stops it being replayed with a different subject,
    session, client request id or feature set while the ticket is live. Every field is keyword-only with
    no default: a defaulted field is a silent mismatch the server reports as a bad ticket.
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


# ── Enrolment proof-of-possession (`seam-enroll-pop-v2`, seam-runtime #1157 / #1164 / #1687, SDK #205) ──
# `EnrollTenantRequest.pop` is the subject AID's own consent to ONE enrolment: an Ed25519 signature, by
# the key the AID embeds, over the tenant, namespace and (for a `voter`) participant it is being bound to. Without it a tenant-scoped
# operator could enrol any AID it has merely seen. Pinned by `conformance/enroll_pop_v2_payload_vector.json`,
# generated by an independent implementation. `EnrollProof` is a NamedTuple, not a dataclass:
# `scripts/` and the import-light tests load this file standalone by path, outside `sys.modules`, and
# `@dataclass` looks its own module up there.

#: v2 (#1687) adds the framed ``participant_id``; v1 is gone (runtime 0.87.0 refuses it).
ENROLL_POP_V2_CONTEXT = b"seam-enroll-pop-v2"
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
    subject_aid: str,
    tenant: str,
    namespace: str,
    issued_at_ms: int,
    nonce: str,
    participant_id: str = "",
) -> bytes:
    """The exact bytes an enrolment proof signs:

    ``frame("seam-enroll-pop-v2") || frame(subject_aid) || frame(tenant) || frame(namespace) ||
    frame(participant_id) || frame(u64le(issued_at_ms)) || frame(nonce)``, with ``frame(x) = u32le(len(x)) || x`` over UTF-8,
    lengths in BYTES. ``issued_at_ms`` is Unix epoch MILLISECONDS as 8 raw little-endian bytes, not
    ASCII decimal. ``participant_id`` is the participant a ``voter`` enrolment binds and ``""`` for
    every other kind. Every argument must be exactly what goes on the wire: the runtime rebuilds this
    payload from the request it received."""
    return b"".join(
        (
            _frame(ENROLL_POP_V2_CONTEXT),
            _frame(subject_aid.encode("utf-8")),
            _frame(tenant.encode("utf-8")),
            _frame(namespace.encode("utf-8")),
            _frame(participant_id.encode("utf-8")),
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
    participant_id: str = "",
) -> EnrollProof:
    """Sign an enrolment proof with the agent's own key. The subject AID is DERIVED from the seed —
    a proof can only ever speak for the key that signs it — and the nonce is validated first, since a
    proof the runtime will refuse is not worth producing. Prefer :meth:`seam_sdk.Agent.enrolment_proof`,
    which defaults ``issued_at_ms`` to now and ``nonce`` to a fresh random one."""
    validate_enroll_pop_nonce(nonce)
    sk = Ed25519PrivateKey.from_private_bytes(agent_seed)
    subject_aid = aid_from_pubkey(sk.public_key().public_bytes_raw())
    payload = enroll_pop_payload(
        subject_aid, tenant, namespace, issued_at_ms, nonce, participant_id
    )
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
    participant_id: str = "",
) -> bool:
    """``True`` iff ``signature`` is ``subject_aid``'s Ed25519 signature over :func:`enroll_pop_payload`
    of these exact fields. Checks the binding only — freshness is the runtime's call, on its clock."""
    try:
        Ed25519PublicKey.from_public_bytes(_aid_to_pubkey(subject_aid)).verify(
            signature,
            enroll_pop_payload(
                subject_aid, tenant, namespace, issued_at_ms, nonce, participant_id
            ),
        )
        return True
    except Exception:
        return False


# ── Voter proof-of-possession (`seam-voter-pop-v1`, seam-runtime #1687) ────────────────────────────
# Every binding vote, ballot and objection carries a proof signed by the voter's OWN enrolled `voter`
# key (never the caller's transport key), over the session's open identity, the decision content and
# the exact entry the runtime will seal. Normative: seam-runtime `docs/specs/voter-verification.v1.md`.
# Pinned by `conformance/voter_pop_v1_payload_vector.json` (generated by an independent implementation).

VOTER_POP_V1_DOMAIN = b"seam-voter-pop-v1"
VOTE_CONTENT_V1_DOMAIN = b"seam-vote-content-v1"
#: The proof lifetime and clock skew the runtime enforces: ``expires_at - issued_at <= 15 min``,
#: ``issued_at <= now + 60 s``, ``now <= expires_at``.
VOTER_POP_MAX_LIFETIME_MS = 15 * 60 * 1000
VOTER_POP_MAX_SKEW_MS = 60 * 1000
#: A sensible default lifetime for a freshly signed proof (5 minutes).
VOTER_POP_DEFAULT_LIFETIME_MS = 5 * 60 * 1000


class VoterPopTarget(_NamedTuple):
    """Where a vote is cast: the runtime (``issuer`` AID from ``GET /v1/trust/issuer-aid`` and
    ``audience``, default ``seam-runtime``) and the session's ``tenant``/``namespace`` and open identity
    (``session_id``, ``opened_at_millis`` = ``SessionStep.opened_at_millis`` from the open; ``0`` on the
    one-shot ``RunDecision`` path)."""

    issuer: str
    tenant: str
    namespace: str
    session_id: str
    opened_at_millis: int = 0
    audience: str = "seam-runtime"


class VoterPop(_NamedTuple):
    """A signed voter proof: the parts of ``VoterProof.pop``. ``signature`` is the raw 64 bytes."""

    voter_aid: str
    issued_at_ms: int
    expires_at_ms: int
    signature: bytes

    def to_pb(self, pb_module: Any):
        """The generated ``VoterProof`` message (``VoterProof{pop: VoterPop{...}}``) of ``pb_module``
        (``seam_sdk._gen.seam.api.v1.seam_pb2``; passed in because this module imports no stubs)."""
        return pb_module.VoterProof(
            pop=pb_module.VoterPop(
                voter_aid=self.voter_aid,
                issued_at_ms=self.issued_at_ms,
                expires_at_ms=self.expires_at_ms,
                signature=self.signature,
            )
        )

    def to_rest(self) -> dict:
        """The REST/JSON ``proof`` object: ``{"pop": {..., "signature": <unpadded base64url>}}``."""
        return {
            "pop": {
                "voter_aid": self.voter_aid,
                "issued_at_ms": self.issued_at_ms,
                "expires_at_ms": self.expires_at_ms,
                "signature": _b64url_nopad(self.signature),
            }
        }


def _ctx_pair(c) -> tuple[str, str]:
    if isinstance(c, (tuple, list)) and len(c) == 2:
        return c[0], c[1] or ""
    return c["ctx_ref"], c.get("content_hash") or ""


def _count_frame(n: int) -> bytes:
    return _frame(struct.pack("<I", _uint_slot("count", n, 32)))


def vote_content_digest(
    mode: str,
    proposal_id: str,
    content: str,
    participants=(),
    on_behalf_of=(),
    context=(),
    features=(),
    policy=None,
) -> bytes:
    """``seam-vote-content-v1``: what the vote is about (32 raw bytes). The runtime derives this from its
    own session state and never accepts it from a client; this is the same function, so a voter can
    compute what it signs.

    ``mode`` is the session's canonical mode id (``macp.mode.decision.v1`` / ``macp.mode.quorum.v1``;
    always decision on the one-shot path). ``proposal_id`` is the vote's/objection's proposal, or the
    ballot's ``request_id`` (``"p1"`` one-shot). ``content`` is the accepted proposal's ``option`` (vote,
    objection), the approval request's ``action`` (ballot), or ``votes[0].value`` (one-shot).
    ``participants`` and ``on_behalf_of`` are as opened, in request order. ``context`` is the sealed
    context provenance in sealed order: ``(ctx_ref, content_hash)`` pairs or mappings with those keys,
    ``content_hash`` ``""`` when the binding carries none.

    ``features`` is the one-shot ``RunDecisionRequest.features`` (a mapping or ``(key, value)`` pairs;
    framed sorted by UTF-8 key bytes, a repeated key refused, never deduplicated); a session vote has
    none. ``policy`` is the session's ``SessionStep.vote_policy`` from open (a generated ``VotePolicyRef``,
    a mapping with ``policy_version`` and ``rules_digest`` / ``rules_digest_hex``, or a pair), framed
    ``0x01‖F(policy_version)‖F(rules_digest)``; ``None`` frames ``0x00`` (the one-shot: server-resolved)."""
    participants = list(participants)
    on_behalf_of = list(on_behalf_of)
    ctx = [_ctx_pair(c) for c in context]
    out = [
        _frame(VOTE_CONTENT_V1_DOMAIN),
        _frame(mode.encode()),
        _frame(proposal_id.encode()),
        _frame(content.encode()),
        _count_frame(len(participants)),
        *(_frame(p.encode()) for p in participants),
        _count_frame(len(on_behalf_of)),
        *(_frame(o.encode()) for o in on_behalf_of),
        _count_frame(len(ctx)),
    ]
    for ref, h in ctx:
        out += [_frame(ref.encode()), _frame(h.encode())]
    feats = _canonical_features(features)
    out.append(_count_frame(len(feats)))
    for k, v in feats:
        out += [_frame(k), _frame(v)]
    out.append(_vote_policy_slot(policy))
    return hashlib.sha256(b"".join(out)).digest()


def _canonical_features(features) -> list[tuple[bytes, bytes]]:
    pairs = list(features.items()) if hasattr(features, "items") else list(features)
    out: list[tuple[bytes, bytes]] = []
    for pair in pairs:
        k, v = pair
        if not isinstance(k, str) or not isinstance(v, str):
            raise TypeError(f"a feature is a (str, str) pair, not {pair!r}")
        out.append((k.encode(), v.encode()))
    out.sort(key=lambda kv: kv[0])
    for a, b in zip(out, out[1:]):
        if a[0] == b[0]:
            raise ValueError(
                f"feature key {a[0].decode()!r} is given twice (refused, never deduplicated)"
            )
    return out


def _vote_policy_slot(policy) -> bytes:
    if policy is None:
        return b"\x00"
    if hasattr(policy, "policy_version") and hasattr(policy, "rules_digest"):
        version, digest = policy.policy_version, bytes(policy.rules_digest)
    elif hasattr(policy, "get"):
        version = policy["policy_version"]
        digest = (
            bytes.fromhex(policy["rules_digest_hex"])
            if "rules_digest_hex" in policy
            else bytes(policy["rules_digest"])
        )
    else:
        version, digest = policy
        digest = bytes(digest)
    if not isinstance(version, str):
        raise TypeError("policy_version must be a str")
    if len(digest) != 32:
        raise ValueError(f"rules_digest must be 32 bytes, got {len(digest)}")
    return b"\x01" + _frame(version.encode()) + _frame(digest)


def vote_entry_bytes(
    kind: str,
    participant: str,
    proposal_id: str,
    value: str,
    reason: str = "",
    *,
    confidence: float | None = None,
    rationale_ref: str | None = None,
) -> bytes:
    """The frozen ``entry_bytes`` a voter signs: the entry the runtime will seal, framed on its own
    (``F(x) = be64(len) || x``). ``kind`` is ``vote``, ``ballot`` or ``objection``; ``participant`` is the
    voter (objector); ``proposal_id`` is the ballot's ``request_id`` for a ballot; ``value`` is the vote
    value, ballot choice, or objection severity (``""`` when omitted); ``reason`` as sealed. A stated
    ``-0.0`` confidence folds to ``+0.0``. Frozen: an explanation-digest bump never changes it."""
    import math

    if kind not in EXPLANATION_KINDS:
        raise ValueError(f"unknown explanation kind {kind!r}")
    out = [
        _be64_frame(kind.encode()),
        _be64_frame(participant.encode()),
        _be64_frame(proposal_id.encode()),
        _be64_frame(value.encode()),
        _be64_frame(reason.encode()),
    ]
    if confidence is None:
        out.append(b"\x00")
    else:
        c = float(confidence)
        if not math.isfinite(c):
            raise ValueError(f"non-finite confidence {confidence!r}")
        out.append(b"\x01" + struct.pack(">d", c + 0.0))  # -0.0 + 0.0 == +0.0
    out.append(
        b"\x00"
        if rationale_ref is None
        else b"\x01" + _be64_frame(rationale_ref.encode())
    )
    return b"".join(out)


def _entry_bytes_of(entry) -> bytes:
    """:func:`vote_entry_bytes` of an explanation-entry mapping, or the bytes themselves."""
    if isinstance(entry, (bytes, bytearray)):
        return bytes(entry)
    return vote_entry_bytes(
        entry["kind"],
        entry["participant"],
        entry["proposal_id"],
        entry["value"],
        entry.get("reason", ""),
        confidence=entry.get("confidence"),
        rationale_ref=entry.get("rationale_ref"),
    )


def voter_pop_payload(
    target: VoterPopTarget,
    voter_aid: str,
    content_digest: bytes,
    issued_at_ms: int,
    expires_at_ms: int,
    entry_bytes: bytes,
) -> bytes:
    """The exact bytes a voter proof signs (``framed(x) = u32le(len) || x``)::

    framed("seam-voter-pop-v1") || framed(issuer) || framed(audience) || framed(tenant)
    || framed(namespace) || framed(session_id) || framed(u64le(opened_at_millis)) || framed(voter_aid)
    || framed(content_digest[32]) || framed(u64le(issued_at_ms)) || framed(u64le(expires_at_ms))
    || framed(entry_bytes)
    """
    if len(content_digest) != 32:
        raise ValueError(f"content_digest must be 32 bytes, got {len(content_digest)}")
    u64 = lambda name, v: _frame(struct.pack("<Q", _uint_slot(name, v, 64)))  # noqa: E731
    return b"".join(
        (
            _frame(VOTER_POP_V1_DOMAIN),
            _frame(target.issuer.encode()),
            _frame(target.audience.encode()),
            _frame(target.tenant.encode()),
            _frame(target.namespace.encode()),
            _frame(target.session_id.encode()),
            u64("opened_at_millis", target.opened_at_millis),
            _frame(voter_aid.encode()),
            _frame(bytes(content_digest)),
            u64("issued_at_ms", issued_at_ms),
            u64("expires_at_ms", expires_at_ms),
            _frame(bytes(entry_bytes)),
        )
    )


def sign_voter_pop(
    voter_seed: bytes,
    target: VoterPopTarget,
    content_digest: bytes,
    entry,
    *,
    issued_at_ms: int | None = None,
    expires_at_ms: int | None = None,
) -> VoterPop:
    """Sign a ``seam-voter-pop-v1`` proof with the voter's OWN enrolled ``voter`` key (Ed25519 seed).

    ``entry`` is the entry the runtime will seal: a mapping (``kind``, ``participant``, ``proposal_id``,
    ``value``, ``reason``, optional ``confidence``/``rationale_ref``) or :func:`vote_entry_bytes` output.
    ``issued_at_ms`` defaults to now and ``expires_at_ms`` to five minutes later. The window is checked
    here against the runtime's rule (``issued <= expires``, ``expires - issued <= 15 min``) so a proof the
    runtime must refuse is never produced. The voter AID is DERIVED from the seed."""
    issued = int(time.time() * 1000) if issued_at_ms is None else issued_at_ms
    expires = (
        issued + VOTER_POP_DEFAULT_LIFETIME_MS
        if expires_at_ms is None
        else expires_at_ms
    )
    if not issued <= expires or expires - issued > VOTER_POP_MAX_LIFETIME_MS:
        raise ValueError(
            "voter proof window must satisfy issued_at_ms <= expires_at_ms <= issued_at_ms + 15 min"
        )
    sk = Ed25519PrivateKey.from_private_bytes(voter_seed)
    voter_aid = aid_from_pubkey(sk.public_key().public_bytes_raw())
    payload = voter_pop_payload(
        target, voter_aid, content_digest, issued, expires, _entry_bytes_of(entry)
    )
    return VoterPop(voter_aid, issued, expires, sk.sign(payload))


def verify_voter_pop(
    target: VoterPopTarget,
    voter_aid: str,
    content_digest: bytes,
    issued_at_ms: int,
    expires_at_ms: int,
    entry,
    signature: bytes,
) -> bool:
    """``True`` iff ``signature`` is ``voter_aid``'s Ed25519 signature over :func:`voter_pop_payload`.
    The binding only; the window is the caller's to check (see :func:`verify_voter_record`)."""
    try:
        Ed25519PublicKey.from_public_bytes(_aid_to_pubkey(voter_aid)).verify(
            bytes(signature),
            voter_pop_payload(
                target,
                voter_aid,
                content_digest,
                issued_at_ms,
                expires_at_ms,
                _entry_bytes_of(entry),
            ),
        )
        return True
    except Exception:
        return False


def verify_voter_record(entry) -> bool:
    """Re-check one sealed entry's ``voter_verification`` offline, from the record alone: rebuild the
    signed input from the record's own addressing fields and the entry's frozen ``entry_bytes``, check
    the window at ``accepted_at_ms``, and verify the signature with the key ``principal`` embeds.
    ``False`` for a missing record, a non-``pop`` method, or anything that does not verify."""
    vv = entry.get("voter_verification")
    if vv is None or vv.get("method") != "pop":
        return False
    try:
        issued, expires = int(vv["issued_at_ms"]), int(vv["expires_at_ms"])
        accepted = int(vv["accepted_at_ms"])
        if not (
            issued <= expires
            and expires - issued <= VOTER_POP_MAX_LIFETIME_MS
            and issued <= accepted + VOTER_POP_MAX_SKEW_MS
            and accepted <= expires
        ):
            return False
        if _vv_bytes(vv, "signer_certificate"):
            return False
        target = VoterPopTarget(
            issuer=vv["issuer"],
            tenant=vv["tenant"],
            namespace=vv["namespace"],
            session_id=vv["session_id"],
            opened_at_millis=int(vv["opened_at_millis"]),
            audience=vv["audience"],
        )
        return verify_voter_pop(
            target,
            vv["principal"],
            _vv_bytes(vv, "content_digest"),
            issued,
            expires,
            entry,
            _vv_bytes(vv, "signature"),
        )
    except Exception:
        return False


def verify_commitment_voters(
    entries, issuer: str, decision: tuple[str, str] | None = None
) -> bool:
    """The commitment-level voter check every verifier runs (``voter-verification.v1.md`` §The sealed
    record). ``True`` iff: every ``vote``, ``ballot`` and ``objection`` carries a record and no
    ``evaluation`` does; every record's ``issuer`` is ``issuer`` (the one the verifier pinned); all records
    share one ``(tenant, namespace, session_id, opened_at_millis, audience)``; when ``decision`` =
    ``(tenant, session_id)`` is known, that is the records' own; and each record re-checks
    (:func:`verify_voter_record`). An explanation with no voter-kind entries passes. ``content_digest``
    is not re-derived: what it covers is not in the commitment."""
    addressing = None
    for e in entries:
        vv = e.get("voter_verification")
        if e["kind"] not in VOTER_VERIFIED_KINDS:
            if vv is not None:
                return False
            continue
        if vv is None or vv.get("issuer") != issuer:
            return False
        a = (
            vv.get("tenant"),
            vv.get("namespace"),
            vv.get("session_id"),
            vv.get("opened_at_millis"),
            vv.get("audience"),
        )
        if addressing is None:
            addressing = a
        elif a != addressing:
            return False
        if decision is not None and (a[0], a[2]) != tuple(decision):
            return False
        if not verify_voter_record(e):
            return False
    return True


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


# ── option selection (`seam.selection.weighted_plurality` v1, runtime 0.90.0) ───────────────────────
#
# Written from seam-runtime ``docs/specs/selection-rule.v1.md`` and pinned by
# ``conformance/selection_rule_v1_vectors.json``. Kept in this file (re-exported by
# :mod:`seam_sdk.selection`) because ``verify_tct`` needs it and this module must stay loadable as a single
# file (``tests/test_errors_is_import_light.py``).

#: The domain tag of v5 field 9.
SELECTION_DIGEST_DOMAIN = b"seam-selection-digest:v1"
#: The one rule v1 defines, and its parameters' only v1 values.
SELECTION_RULE = "seam.selection.weighted_plurality"
SELECTION_RULE_VERSION = 1
SELECTION_TIE = "no_winner"
SELECTION_ABSTENTION = "excluded_counts_for_quorum"
#: Selection is admitted only on the decision mode, so the vote-content mode is this constant (§4.2).
SELECTION_MODE = "macp.mode.decision.v1"
#: The ``0x04`` trailer marker and its body version byte (§4.3).
SELECTION_TRAILER_MARKER = 0x04
SELECTION_BODY_V1 = 0x01
VOTE_VALUES = ("APPROVE", "REJECT", "ABSTAIN")

_U32_MAX = 2**32 - 1


class SelectionDecodeError(ValueError):
    """A selection block (or ``0x04`` trailer) that does not strictly decode. ``reason`` is the spec's
    name: ``truncated``, ``u32_overflow``, ``weights_not_canonical``, ``rules_digest_not_32``,
    ``invalid_utf8``, ``empty_winner``, ``trailing_bytes``, and for the trailer ``zero_length_body``,
    ``unknown_version``, ``wrong_marker``. The whole commitment is refused."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"selection block refused: {reason}")
        self.reason = reason


class SelectionResult(_NamedTuple):
    """The outcome of :func:`verify_selection`. ``result`` is ``"verified"`` or one of the spec's verifier
    result names (``selection_malformed``, ``selection_no_winner_sealed``, ``selection_winner_mismatch``,
    ``selection_action_mismatch``, ``selection_vote_unverified``, ``selection_content_link_mismatch``,
    ``selection_principal_not_one_to_one``). ``at`` is the entry index where the check failed, when the
    spec names one; ``reason`` is ``decide()``'s reason for a malformed or no-winner record;
    ``recomputed`` is the winner this verifier computed when it disagrees with the sealed one."""

    result: str
    winner_proposal_id: Optional[str] = None
    votes_linked: int = 0
    at: Optional[int] = None
    reason: Optional[str] = None
    recomputed: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.result == "verified"


# ── the canonical body (§4.2) ────────────────────────────────────────────────────────────────────────


def _F(b: bytes) -> bytes:
    return struct.pack(">Q", len(b)) + b


def _U(n: int) -> bytes:
    if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n < 2**64:
        raise ValueError(f"not an unsigned integer: {n!r}")
    return struct.pack(">Q", n)


def _u32(name: str, n) -> int:
    if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= _U32_MAX:
        raise ValueError(f"selection {name} must be a u32, got {n!r}")
    return n


def _rules_digest(v) -> bytes:
    if isinstance(v, str):
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError(
                "selection rules_digest must be 64 lowercase hex characters"
            )
        return bytes.fromhex(v)
    b = bytes(v)
    if len(b) != 32:
        raise ValueError(f"selection rules_digest must be 32 bytes, got {len(b)}")
    return b


def _pair(item, a: str, b: str) -> tuple:
    if isinstance(item, dict):
        return item[a], item[b]
    if isinstance(item, (tuple, list)):
        x, y = item
        return x, y
    return getattr(item, a), getattr(item, b)


def selection_block_of(record) -> dict:
    """A selection block as a plain dict (the vector's ``block`` shape, ``rules_digest`` as 32 raw bytes),
    from a generated ``SelectionRecord`` or a mapping with the same field names."""
    get = record.get if isinstance(record, dict) else (lambda k: getattr(record, k))
    return {
        "rule": get("rule"),
        "rule_version": _u32("rule_version", get("rule_version")),
        "default_weight": _u32("default_weight", get("default_weight")),
        "weights": [
            {"participant": p, "weight": _u32("weight", w)}
            for p, w in (_pair(x, "participant", "weight") for x in get("weights"))
        ],
        "tie": get("tie"),
        "abstention": get("abstention"),
        "min_ballots": _u32("min_ballots", get("min_ballots")),
        "policy_version": get("policy_version"),
        "rules_digest": _rules_digest(get("rules_digest")),
        "participants": list(get("participants")),
        "on_behalf_of": list(get("on_behalf_of")),
        "context": [
            {"ctx_ref": r, "content_hash": h or ""}
            for r, h in (_pair(x, "ctx_ref", "content_hash") for x in get("context"))
        ],
        "winner_proposal_id": get("winner_proposal_id"),
    }


def selection_body(record) -> bytes:
    """The canonical selection block body (§4.2) of a ``SelectionRecord`` or mapping.

    Refuses (``ValueError``) a block the runtime could not have sealed rather than hashing it: weights not
    strictly ascending by the participant's UTF-8 bytes, a ``rules_digest`` that is not 32 bytes, an empty
    winner. The result always round-trips through :func:`decode_selection_body`."""
    blk = selection_block_of(record)
    out = [
        _F(blk["rule"].encode()),
        _U(blk["rule_version"]),
        _U(blk["default_weight"]),
        _U(len(blk["weights"])),
    ]
    for w in blk["weights"]:
        out += [_F(w["participant"].encode()), _U(w["weight"])]
    out += [
        _F(blk["tie"].encode()),
        _F(blk["abstention"].encode()),
        _U(blk["min_ballots"]),
        _F(blk["policy_version"].encode()),
        _F(blk["rules_digest"]),
        _U(len(blk["participants"])),
        *(_F(p.encode()) for p in blk["participants"]),
        _U(len(blk["on_behalf_of"])),
        *(_F(o.encode()) for o in blk["on_behalf_of"]),
        _U(len(blk["context"])),
    ]
    for c in blk["context"]:
        out += [_F(c["ctx_ref"].encode()), _F(c["content_hash"].encode())]
    out.append(_F(blk["winner_proposal_id"].encode()))
    body = b"".join(out)
    decode_selection_body(
        body
    )  # the strict decode is the one definition of "could have been sealed"
    return body


def selection_digest(body: bytes) -> bytes:
    """v5 field 9's 32 bytes: ``SHA-256(F("seam-selection-digest:v1") ‖ body)``. The trailer's version byte
    is not hashed."""
    return hashlib.sha256(_F(SELECTION_DIGEST_DOMAIN) + bytes(body)).digest()


class _Reader:
    def __init__(self, b: bytes) -> None:
        self.b, self.i = b, 0

    def take(self, n: int) -> bytes:
        if n > len(self.b) - self.i:
            raise SelectionDecodeError("truncated")
        out = self.b[self.i : self.i + n]
        self.i += n
        return out

    def u(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def u32(self) -> int:
        n = self.u()
        if n > _U32_MAX:
            raise SelectionDecodeError("u32_overflow")
        return n

    def count(self, min_item: int) -> int:
        n = self.u()
        if n * min_item > len(self.b) - self.i:
            raise SelectionDecodeError("truncated")
        return n

    def raw(self) -> bytes:
        return self.take(self.u())

    def text(self) -> str:
        try:
            return self.raw().decode("utf-8")
        except UnicodeDecodeError:
            raise SelectionDecodeError("invalid_utf8") from None


def decode_selection_body(body: bytes) -> dict:
    """Strictly decode a selection block body (§4.2) to a block dict (``rules_digest`` as 32 raw bytes).

    Raises :class:`SelectionDecodeError` on anything the runtime could not have sealed. Semantic checks
    (rule name, version, electorate, …) are :func:`decide`'s, not the decoder's."""
    r = _Reader(bytes(body))
    blk: dict = {
        "rule": r.text(),
        "rule_version": r.u32(),
        "default_weight": r.u32(),
        "weights": [],
    }
    for _ in range(r.count(16)):
        blk["weights"].append({"participant": r.text(), "weight": r.u32()})
    keys = [w["participant"].encode() for w in blk["weights"]]
    if any(a >= b for a, b in zip(keys, keys[1:])):
        raise SelectionDecodeError("weights_not_canonical")
    blk["tie"] = r.text()
    blk["abstention"] = r.text()
    blk["min_ballots"] = r.u32()
    blk["policy_version"] = r.text()
    rd = r.raw()
    if len(rd) != 32:
        raise SelectionDecodeError("rules_digest_not_32")
    blk["rules_digest"] = rd
    blk["participants"] = [r.text() for _ in range(r.count(8))]
    blk["on_behalf_of"] = [r.text() for _ in range(r.count(8))]
    blk["context"] = [
        {"ctx_ref": r.text(), "content_hash": r.text()} for _ in range(r.count(16))
    ]
    blk["winner_proposal_id"] = r.text()
    if blk["winner_proposal_id"] == "":
        raise SelectionDecodeError("empty_winner")
    if r.i != len(r.b):
        raise SelectionDecodeError("trailing_bytes")
    return blk


def decode_selection_trailer(trailer: bytes) -> dict:
    """Strictly decode a whole ``0x04`` trailer (``0x04 ‖ u32_LE(1 + len(body)) ‖ 0x01 ‖ body``, §4.3)."""
    t = bytes(trailer)
    if len(t) < 5:
        raise SelectionDecodeError("truncated")
    if t[0] != SELECTION_TRAILER_MARKER:
        raise SelectionDecodeError("wrong_marker")
    n = struct.unpack("<I", t[1:5])[0]
    if n == 0:
        raise SelectionDecodeError("zero_length_body")
    if len(t) - 5 < n:
        raise SelectionDecodeError("truncated")
    if len(t) - 5 > n:
        raise SelectionDecodeError("trailing_bytes")
    if t[5] != SELECTION_BODY_V1:
        raise SelectionDecodeError("unknown_version")
    return decode_selection_body(t[6:])


# ── decide() (§3) ────────────────────────────────────────────────────────────────────────────────────


def _record_malformed(blk: dict) -> Optional[str]:
    if blk["rule"] != SELECTION_RULE:
        return "unknown_rule"
    if blk["rule_version"] != SELECTION_RULE_VERSION:
        return "unknown_rule_version"
    if blk["tie"] != SELECTION_TIE:
        return "unknown_tie"
    if blk["abstention"] != SELECTION_ABSTENTION:
        return "unknown_abstention"
    keys = [w["participant"].encode() for w in blk["weights"]]
    if any(a >= b for a, b in zip(keys, keys[1:])):
        return "weights_not_canonical"
    if blk["default_weight"] == 0 and all(w["weight"] == 0 for w in blk["weights"]):
        return "zero_electorate"
    if blk["min_ballots"] == 0:
        return "min_ballots_zero"
    if not blk["participants"]:
        return "no_participants"
    if len(set(blk["participants"])) != len(blk["participants"]):
        return "duplicate_participant"
    return None


def decide(record, entries) -> dict:
    """``decide(record, entries)`` (§3): a pure function of the selection record (its winner is ignored)
    and the sealed explanation entries (``kind`` as the lowercase digest word).

    Returns ``{"result": "winner", "winner_proposal_id", "option", "scores", "ballots"}``,
    ``{"result": "no_winner", "reason", "scores", "ballots"}`` or ``{"result": "malformed", "reason",
    "at"}`` (``at`` is the entry index, ``None`` for a record-level check). ``scores`` lists every
    proposal in sealed order. Options compare by UTF-8 bytes, never normalised."""
    blk = (
        record
        if isinstance(record, dict) and "weights" in record
        else selection_block_of(record)
    )
    bad = _record_malformed(blk)
    if bad:
        return {"result": "malformed", "reason": bad, "at": None}
    weights = {w["participant"]: w["weight"] for w in blk["weights"]}
    participants = set(blk["participants"])
    proposals: dict[str, str] = {}
    options: set[bytes] = set()
    voted: set[tuple[str, str]] = set()
    approvers: set[str] = set()
    voters: list[str] = []
    approvals: list[tuple[str, str]] = []
    seen_vote = False
    for i, e in enumerate(entries):
        kind = e["kind"]

        def mal(reason: str, i: int = i) -> dict:
            return {"result": "malformed", "reason": reason, "at": i}

        if kind == "proposal":
            if seen_vote:
                return mal("proposal_after_vote")
            if e.get("voter_verification") is not None:
                return mal("proposal_has_voter_record")
            if (
                e.get("reason", "") != ""
                or e.get("confidence") is not None
                or e.get("rationale_ref") is not None
            ):
                return mal("proposal_has_extra_fields")
            if e["proposal_id"] == "":
                return mal("empty_proposal_id")
            if e["value"] == "":
                return mal("empty_option")
            if e["proposal_id"] in proposals:
                return mal("duplicate_proposal_id")
            if e["value"].encode() in options:
                return mal("duplicate_option")
            proposals[e["proposal_id"]] = e["value"]
            options.add(e["value"].encode())
        elif kind == "vote":
            seen_vote = True
            who, pid = e["participant"], e["proposal_id"]
            if pid not in proposals:
                return mal("vote_unknown_proposal")
            if e["value"] not in VOTE_VALUES:
                return mal("vote_bad_value")
            if who not in participants:
                return mal("vote_not_participant")
            if (who, pid) in voted:
                return mal("duplicate_vote")
            if e["value"] == "APPROVE":
                if who in approvers:
                    return mal("double_approve")
                approvers.add(who)
                approvals.append((who, pid))
            voted.add((who, pid))
            if who not in voters:
                voters.append(who)
        elif kind in ("evaluation", "objection"):
            continue  # sealed, never scored (v1 admits no objection veto)
        elif kind == "ballot":
            return mal("ballot_in_selection")
        else:
            return mal("unknown_kind")
    if not proposals:
        return {"result": "malformed", "reason": "no_proposals", "at": None}
    scores = dict.fromkeys(proposals, 0)
    for who, pid in approvals:
        scores[pid] += weights.get(who, blk["default_weight"])
    ballots = len(voters)
    top = max(scores.values())
    leaders = [pid for pid, sc in scores.items() if sc == top]
    tally = {
        "scores": [{"proposal_id": p, "score": sc} for p, sc in scores.items()],
        "ballots": ballots,
    }
    if ballots < blk["min_ballots"]:
        return {"result": "no_winner", "reason": "below_min_ballots", **tally}
    if top == 0:
        return {"result": "no_winner", "reason": "no_positive_score", **tally}
    if len(leaders) > 1:
        return {"result": "no_winner", "reason": "tie", **tally}
    return {
        "result": "winner",
        "winner_proposal_id": leaders[0],
        "option": proposals[leaders[0]],
        **tally,
    }


# ── the verifier's selection steps (§5 steps 4, 6-9) ─────────────────────────────────────────────────


def _digest_bytes(v) -> bytes:
    if isinstance(v, str):
        return bytes.fromhex(v)
    return bytes(v)


def verify_selection(record, entries, action: str) -> SelectionResult:
    """§5 steps 6-9 over a decoded selection record, the sealed entries and ``Commitment.action``.

    Step 6 recomputes the winner (:func:`decide`) and checks it is the sealed one; step 7 checks the
    winner's sealed option is ``action`` byte for byte; step 8 re-derives every vote's
    ``seam-vote-content-v1`` digest from sealed inputs alone and checks it is the one the voter signed
    (the record's ``content_digest``); step 9 checks participant ↔ principal is one-to-one across the
    votes. It does not re-check signatures or the TCT: that is :func:`~seam_sdk.crypto.verify_tct`'s
    (steps 1-3 and 5), which calls this when the commitment carries a block."""
    blk = (
        record
        if isinstance(record, dict) and "weights" in record
        else selection_block_of(record)
    )
    entries = list(entries)
    d = decide(blk, entries)
    if d["result"] == "malformed":
        return SelectionResult("selection_malformed", reason=d["reason"], at=d["at"])
    if d["result"] == "no_winner":
        return SelectionResult("selection_no_winner_sealed", reason=d["reason"])
    if d["winner_proposal_id"] != blk["winner_proposal_id"]:
        return SelectionResult(
            "selection_winner_mismatch", recomputed=d["winner_proposal_id"]
        )
    if d["option"].encode() != action.encode():
        return SelectionResult("selection_action_mismatch")
    proposals = {
        e["proposal_id"]: e["value"] for e in entries if e["kind"] == "proposal"
    }
    policy = (blk["policy_version"], _rules_digest(blk["rules_digest"]))
    linked = 0
    for i, e in enumerate(entries):
        if e["kind"] != "vote":
            continue
        vv = e.get("voter_verification")
        if vv is None:
            return SelectionResult("selection_vote_unverified", at=i)
        want = vote_content_digest(
            SELECTION_MODE,
            e["proposal_id"],
            proposals[e["proposal_id"]],
            blk["participants"],
            blk["on_behalf_of"],
            blk["context"],
            (),
            policy,
        )
        if _digest_bytes(vv["content_digest"]) != want:
            return SelectionResult("selection_content_link_mismatch", at=i)
        linked += 1
    by_participant: dict[str, str] = {}
    by_principal: dict[str, str] = {}
    for i, e in enumerate(entries):
        if e["kind"] != "vote":
            continue
        p, a = e["participant"], e["voter_verification"]["principal"]
        if by_participant.setdefault(p, a) != a or by_principal.setdefault(a, p) != p:
            return SelectionResult("selection_principal_not_one_to_one", at=i)
    return SelectionResult(
        "verified", winner_proposal_id=d["winner_proposal_id"], votes_linked=linked
    )


# ── seam-commitment-digest:v6 and the Gate block v1 (Flows W2: readers only) ─────────────────────────
# Specs: seam-runtime `docs/specs/seam-commitment-digest.v6.md` and `docs/specs/seam-gate-block.v1.md`.
# Pinned by `conformance/commitment_digest_v6_vector.json`, `commitment_digest_v6_signed_vector.json`
# and `gate_block_vector.json` (byte-identical to the runtime's, via its `sdk-digest-parity`).
#
# v6 is v5 plus field 12 (the env, `sandbox` or `live`), and it DEFINES field 10 as the Gate digest over
# the `0x05` body. v5 above is unchanged and stays verify-only until W9. Nothing here writes v6.
#
# Every refusal raises :class:`CommitmentRefused` before anything is hashed. Its ``rule`` names the spec
# rule, but rule names are ADVISORY (v6 §Refusal rules): where an input breaks two rules this reader may
# name either. Only the refusal is normative.

#: The v5 and v6 commitment digest domain tags (field 0).
COMMITMENT_DIGEST_V5_DOMAIN = "seam-commitment-digest:v5"
COMMITMENT_DIGEST_V6_DOMAIN = "seam-commitment-digest:v6"
#: The Gate digest's domain tag: ``gate_digest = SHA-256(F("seam-gate-digest:v1") ‖ gate_body)``.
GATE_DIGEST_DOMAIN = b"seam-gate-digest:v1"
#: The Gate trailer (``0x05``) and the governing trailer (``0x06``): ``marker ‖ u32le(len) ‖ body``.
GATE_TRAILER_MARKER = 0x05
GOVERNING_TRAILER_MARKER = 0x06
#: The Gate body's version byte (inside the hashed body, unlike ``0x04``'s).
GATE_BODY_V1 = 0x01
#: The ``0x06`` body versions: v1 ``0x01 ‖ doc`` (v5's), v2 ``0x02 ‖ doc ‖ env slot`` (v6's).
GOVERNING_BODY_V1 = 0x01
GOVERNING_BODY_V2 = 0x02
#: The only env values: exactly these ASCII bytes, case-sensitive, compared byte for byte.
FLOW_ENVS = ("sandbox", "live")

_GATE_STATUS = {1: "answered", 2: "unavailable"}
_GATE_ON_OUTAGE = {1: "refuse_seal", 2: "seal_gate_unavailable"}
# 4 (invalid_response) is reserved and refused: an unverifiable answer is never sealed.
_GATE_REASON = {
    1: "timeout",
    2: "connect",
    3: "http_5xx",
    5: "circuit_open",
    6: "token_mint",
}
_GATE_REASON_RESERVED = 4
_GATE_SIGNATURE_LEN = 64
# Legal trailer markers of a sealed commitment that are NOT part of the `0x05`/`0x06` run this reader
# takes (the selection `0x04` is read by :func:`decode_selection_trailer`, as v5 already does).
_OTHER_TRAILER_MARKERS = frozenset({0x01, 0x02, 0x03, 0x04, 0x07})
_HEX64 = frozenset("0123456789abcdef")
_STATEMENT_TYPE = "seam:commitment"
_V5_MEMBERS = frozenset({"type", "commitment_digest"})
_V6_MEMBERS = frozenset({"type", "commitment_digest", "commitment_digest_domain"})


class CommitmentRefused(ValueError):
    """A v6 / Gate-block refusal. ``rule`` is the spec's rule name, which is advisory: only the
    refusal itself is normative (v6 §Refusal rules)."""

    def __init__(self, rule: str, detail: str = "") -> None:
        super().__init__(f"{rule}: {detail}" if detail else rule)
        self.rule = rule


class _FrameReader:
    """Strict reader over one body: every overrun refuses as ``truncated``, never wraps. A ``be64``
    frame length is a Python int compared with what remains, so ``2**64 - 1`` refuses."""

    def __init__(self, b: bytes, truncated: str) -> None:
        self.b, self.i, self.truncated = b, 0, truncated

    def take(self, n: int) -> bytes:
        if n > len(self.b) - self.i:
            raise CommitmentRefused(self.truncated)
        out = self.b[self.i : self.i + n]
        self.i += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def be64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def framed(self) -> bytes:
        return self.take(self.be64())

    def at_end(self) -> bool:
        return self.i == len(self.b)

    def done(self, rule: str) -> None:
        if not self.at_end():
            raise CommitmentRefused(rule)

    def gate_text(self, *, allow_empty: bool = False) -> str:
        raw = self.framed()
        try:
            out = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise CommitmentRefused("gate_text_not_utf8") from None
        if not out and not allow_empty:
            raise CommitmentRefused("gate_text_empty")
        return out


def _env_of(raw: bytes) -> str:
    """The env rule on raw bytes: exactly ``b"sandbox"`` or ``b"live"``. A byte match, never a text
    decode, so the empty string, another case, padding and non-ASCII / non-UTF-8 bytes all refuse."""
    if raw not in (b"sandbox", b"live"):
        raise CommitmentRefused("env_not_sandbox_or_live", repr(raw))
    return raw.decode("ascii")


def decode_gate_body(body: bytes) -> dict:
    """Strictly decode a Gate body v1 (the ``0x05`` trailer's body, version byte included).

    Returns ``status`` (``"answered"`` / ``"unavailable"``), ``attempt_id``, ``domain``, ``flow_id``,
    ``env``, ``timeout_ms``, ``on_outage`` (``"refuse_seal"`` / ``"seal_gate_unavailable"``) and
    ``requested_at_ms``; then, answered: ``receipt_jcs``, ``key_id``, ``signature`` (64 raw bytes) and
    ``certificate_jcs`` (``None`` iff the frame is empty, a route answer); unavailable: ``reason`` and
    ``given_up_at_ms``. The ``be64`` fields are ints (0..2**64-1). The receipt is framed, never parsed,
    and the policy ranges (``timeout_ms``, VG7) are verifier checks, not decode rules.

    Raises :class:`CommitmentRefused` on every ``gate_*`` rule the body alone can check (seam-gate-block.v1
    §Refusal rules). The binding to the commitment's env is :func:`decode_commitment_trailers`'s."""
    b = bytes(body)
    if not b:
        raise CommitmentRefused("gate_body_empty")
    r = _FrameReader(b, "gate_body_truncated")
    if r.u8() != GATE_BODY_V1:
        raise CommitmentRefused("gate_body_unknown_version")
    status = r.u8()
    if status not in _GATE_STATUS:
        raise CommitmentRefused("gate_status_invalid")
    blk: dict = {"status": _GATE_STATUS[status]}
    blk["attempt_id"] = r.gate_text()
    blk["domain"] = r.gate_text()
    blk["flow_id"] = r.gate_text()
    blk["env"] = _env_of(r.framed())
    blk["timeout_ms"] = r.be64()
    on_outage = r.u8()
    if on_outage not in _GATE_ON_OUTAGE:
        raise CommitmentRefused("gate_on_outage_invalid")
    blk["on_outage"] = _GATE_ON_OUTAGE[on_outage]
    blk["requested_at_ms"] = r.be64()
    if status == 1:
        blk["receipt_jcs"] = r.gate_text()
        blk["key_id"] = r.gate_text()
        sig = r.framed()
        if len(sig) != _GATE_SIGNATURE_LEN:
            raise CommitmentRefused("gate_signature_length")
        blk["signature"] = sig
        blk["certificate_jcs"] = r.gate_text(allow_empty=True) or None
    else:
        # Under refuse_seal an outage is a typed refusal and nothing is sealed: such a body is a forgery.
        if on_outage == 1:
            raise CommitmentRefused("gate_unavailable_under_refuse_seal")
        reason = r.u8()
        if reason == _GATE_REASON_RESERVED:
            raise CommitmentRefused("gate_reason_reserved")
        if reason not in _GATE_REASON:
            raise CommitmentRefused("gate_reason_invalid")
        blk["reason"] = _GATE_REASON[reason]
        blk["given_up_at_ms"] = r.be64()
    r.done("gate_body_trailing_bytes")
    return blk


def gate_digest(body: bytes) -> bytes:
    """``seam-gate-digest:v1`` (32 raw bytes): ``SHA-256(be64(19) ‖ "seam-gate-digest:v1" ‖ gate_body)``,
    the body hashed whole, version byte included. The body is strictly decoded first
    (:func:`decode_gate_body`), so a body the runtime could not have sealed is refused, never hashed."""
    b = bytes(body)
    decode_gate_body(b)
    return hashlib.sha256(_be64_frame(GATE_DIGEST_DOMAIN) + b).digest()


def _read_trailer(t: bytes, pos: int, truncated: str) -> tuple[bytes, int]:
    """``marker ‖ u32le(len) ‖ body`` at ``pos`` -> (body, next position)."""
    if len(t) - pos < 5:
        raise CommitmentRefused(truncated)
    n = struct.unpack("<I", t[pos + 1 : pos + 5])[0]
    if len(t) - pos - 5 < n:
        raise CommitmentRefused(truncated)
    return t[pos + 5 : pos + 5 + n], pos + 5 + n


def _decode_governing_body(
    body: bytes, scheme: Optional[str]
) -> tuple[int, bytes, Optional[str]]:
    """The ``0x06`` body -> (body version, doc_sha256, env). ``scheme=None`` accepts both versions."""
    if not body:
        raise CommitmentRefused("governing_body_empty")
    version = body[0]
    if version not in (GOVERNING_BODY_V1, GOVERNING_BODY_V2):
        raise CommitmentRefused("governing_body_unknown_version")
    if scheme == "v5" and version == GOVERNING_BODY_V2:
        raise CommitmentRefused("v5_refuses_governing_body_v2")
    if scheme == "v6" and version == GOVERNING_BODY_V1:
        raise CommitmentRefused("v6_refuses_governing_body_v1")
    if version == GOVERNING_BODY_V1:
        if len(body) != 33:
            raise CommitmentRefused("governing_body_length")
        return version, body[1:], None
    r = _FrameReader(body[1:], "governing_body_truncated")
    doc = r.take(32)
    if r.at_end():
        raise CommitmentRefused("env_presence_missing")
    presence = r.u8()
    env = None
    if presence == 0x01:
        env = _env_of(r.framed())
    elif presence != 0x00:
        raise CommitmentRefused("env_presence_invalid")
    r.done("governing_body_trailing_bytes")
    return version, doc, env


def _slot32(d: Optional[bytes]) -> bytes:
    """Fields 9/10/11: ``0x00`` absent, else ``0x01 ‖ F(d)`` over exactly 32 bytes."""
    if d is None:
        return b"\x00"
    if len(d) != 32:
        raise CommitmentRefused("slot_length_not_32", f"got {len(d)} bytes")
    return b"\x01" + _be64_frame(d)


def _env_slot(env: Optional[bytes]) -> bytes:
    """Field 12: ``0x00`` absent, else ``0x01 ‖ F(env)`` (the env already checked)."""
    return b"\x00" if env is None else b"\x01" + _be64_frame(env)


class CommitmentTrailers(_NamedTuple):
    """A decoded ``0x05`` / ``0x06`` trailer run (:func:`decode_commitment_trailers`).

    ``field_10`` / ``field_11`` / ``field_12`` are the digest encodings, presence byte included.
    ``field_12`` is ``None`` where the reading has no field 12: under v5, and scheme-free unless a body
    v2 was read. ``governing_body_version`` is the ``0x06`` body version read (``None`` with no ``0x06``).
    """

    field_10: bytes
    field_11: bytes
    field_12: Optional[bytes]
    governing_body_version: Optional[int]
    gate_block: Optional[dict]
    gate_digest: Optional[bytes]
    governing_doc_sha256: Optional[bytes]
    env: Optional[str]


def _bytes_or_hex(v) -> bytes:
    return bytes.fromhex(v) if isinstance(v, str) else bytes(v)


def decode_commitment_trailers(trailers, scheme: Optional[str]) -> CommitmentTrailers:
    """Decode a commitment's ``0x05`` / ``0x06`` trailer run (raw bytes, or hex) under ``scheme``.

    ``scheme`` is ``"v5"``, ``"v6"`` or ``None``. A verifier takes it from statement selection
    (:func:`select_commitment_version`); ``None`` is the scheme-free decode (v6 §Where the scheme comes
    from), which accepts both ``0x06`` body versions, reports which it read, and leaves the scheme rules
    (``v5_refuses_*``, ``v6_refuses_governing_body_v1``) to the caller.

    Rules: markers strictly increase (a repeated or misordered ``0x05`` is ``marker_order``), a marker
    outside ``0x01``-``0x07`` is ``unknown_marker``, nothing follows the last trailer; ``0x05`` is decoded
    strictly (:func:`decode_gate_body`) and frames field 10 from this reader's own
    ``seam-gate-digest:v1`` over it (VG1); ``0x06`` v1/v2 frames fields 11 and 12; and a ``0x05`` is
    legal only beside a ``0x06`` body v2 carrying the same env (``gate_env_binding``). Under v5 any
    ``0x05`` refuses. The other legal markers (``0x01``-``0x04``, ``0x07``) are not part of this input
    and refuse: the selection trailer stays with :func:`decode_selection_trailer`, as in v5.

    Raises :class:`CommitmentRefused`; any refusal refuses the whole commitment."""
    if scheme not in ("v5", "v6", None):
        raise ValueError(f"scheme must be 'v5', 'v6' or None, got {scheme!r}")
    t = _bytes_or_hex(trailers)
    pos, last = 0, 0
    gate_body: Optional[bytes] = None
    version: Optional[int] = None
    doc: Optional[bytes] = None
    env: Optional[str] = None
    while pos < len(t):
        marker = t[pos]
        if marker <= last:
            raise CommitmentRefused("marker_order", f"{marker:#04x} after {last:#04x}")
        last = marker
        if marker == GATE_TRAILER_MARKER:
            if scheme == "v5":
                raise CommitmentRefused("v5_refuses_gate_block")
            gate_body, pos = _read_trailer(t, pos, "gate_trailer_truncated")
            decode_gate_body(gate_body)
        elif marker == GOVERNING_TRAILER_MARKER:
            body, pos = _read_trailer(t, pos, "governing_trailer_truncated")
            version, doc, env = _decode_governing_body(body, scheme)
        elif marker in _OTHER_TRAILER_MARKERS:
            raise CommitmentRefused(
                "marker_not_gate_or_governing",
                f"{marker:#04x} is a legal trailer, but not part of the 0x05/0x06 run",
            )
        else:
            raise CommitmentRefused("unknown_marker", f"{marker:#04x}")
    gate_block = None
    gd = None
    if gate_body is not None:
        gate_block = decode_gate_body(gate_body)
        if doc is None or env is None or env != gate_block["env"]:
            raise CommitmentRefused("gate_env_binding")
        gd = gate_digest(gate_body)
    env_b = None if env is None else env.encode("ascii")
    has_field_12 = scheme == "v6" or (scheme is None and version == GOVERNING_BODY_V2)
    return CommitmentTrailers(
        field_10=_slot32(gd),
        field_11=_slot32(doc),
        field_12=_env_slot(env_b) if has_field_12 else None,
        governing_body_version=version,
        gate_block=gate_block,
        gate_digest=gd,
        governing_doc_sha256=doc,
        env=env,
    )


def _slot_input(commitment: dict, name: str) -> Optional[bytes]:
    v = commitment.get(name)
    return None if v is None else _bytes_or_hex(v)


def _env_input(v) -> Optional[bytes]:
    """A caller-supplied env (str or bytes) as checked bytes, or ``None`` when absent. An empty string
    is a refusal, not absence: absence is ``None``."""
    if v is None:
        return None
    if isinstance(v, str):
        try:
            raw = v.encode("utf-8")
        except UnicodeEncodeError:
            raise CommitmentRefused("env_not_sandbox_or_live") from None
    else:
        raw = bytes(v)
    return _env_of(raw).encode("ascii")


def commitment_digest_v6(commitment: dict) -> str:
    """``seam-commitment-digest:v6`` (hex): v5's fields 0-11 (tag ``:v6``) plus field 12, the env.

    Fields 1-9 are read exactly as v5 reads them (``id`` … ``committer``, the explanation, and field 9
    from ``selection`` or ``selection_digest``). Fields 10-12 come one of two ways:

    * **from ``trailers``** (raw bytes or hex; the ``0x05`` / ``0x06`` run the sealed commitment carries,
      ``""`` when it has neither): decoded under v6 (:func:`decode_commitment_trailers`), so field 10 is
      this reader's own Gate digest and field 12 the ``0x06`` body v2 env. A ``governing_doc_sha256``,
      ``gate_digest`` or ``env`` given beside must agree with the derived value, or it raises;
    * **digest-only** (``trailers`` absent or ``None``): ``gate_digest`` (32 bytes), ``governing_doc_sha256``
      (32 bytes) and ``env`` (``"sandbox"`` / ``"live"``, or absent) are taken as given. This is the
      vectors' ``digest_only`` path; a verifier uses ``trailers`` (VG1, :func:`verify_tct`).

    Refuses before hashing (:class:`CommitmentRefused`): a present slot that is not 32 bytes, an env that
    is not exactly ``sandbox`` / ``live`` (the empty string included), and an env without a governing
    doc. ``certificate_digest`` is v5's field-10 name and raises here: v6 field 10 is the Gate digest.
    """
    if commitment.get("certificate_digest") is not None:
        raise ValueError(
            "certificate_digest is v5's opaque field 10; v6 field 10 is the gate digest"
        )
    trailers = commitment.get("trailers")
    if trailers is None:
        gate = _slot_input(commitment, "gate_digest")
        doc = _slot_input(commitment, "governing_doc_sha256")
        env = _env_input(commitment.get("env"))
    else:
        dec = decode_commitment_trailers(trailers, "v6")
        gate, doc = dec.gate_digest, dec.governing_doc_sha256
        env = None if dec.env is None else dec.env.encode("ascii")
        beside = (
            ("gate_digest", _slot_input(commitment, "gate_digest"), gate),
            (
                "governing_doc_sha256",
                _slot_input(commitment, "governing_doc_sha256"),
                doc,
            ),
            ("env", _env_input(commitment.get("env")), env),
        )
        for name, given, derived in beside:
            if given is not None and given != derived:
                raise ValueError(f"{name} does not match the commitment's trailers")
    field_10, field_11 = _slot32(gate), _slot32(doc)
    if env is not None and doc is None:
        raise CommitmentRefused("env_without_governing_doc")
    if commitment.get("selection") is None:
        field_9 = _slot32(_slot_input(commitment, "selection_digest"))
    else:
        field_9 = _selection_slot(commitment)
    supersedes = commitment.get("supersedes")
    out = [
        _be64_frame(COMMITMENT_DIGEST_V6_DOMAIN.encode()),
        _be64_frame(commitment["id"].encode()),
        _be64_frame(commitment["action"].encode()),
        _be64_frame(commitment["authority"].encode()),
        b"\x00" if supersedes is None else b"\x01" + _be64_frame(supersedes.encode()),
        _be64_frame(commitment["auth_method"].encode()),
        _be64_frame(commitment["trust_basis"].encode()),
        _be64_frame((commitment.get("committer") or "").encode()),
        _be64_frame(_commitment_explanation_digest(commitment)),
        field_9,
        field_10,
        field_11,
        _env_slot(env),
    ]
    return hashlib.sha256(b"".join(out)).hexdigest()


def _refuse_duplicate_members(pairs: list) -> dict:
    """``json.loads`` hook, called for EVERY object at every depth with all its members, before any map
    keeps one of two: a repeated name refuses. Names arrive unescaped, so ``"type"`` and
    ``"\\u0074ype"`` are the same name (AITP's raw-bytes duplicate-key guard, RFC-AITP-0001 §5.4.5)."""
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise CommitmentRefused("statement_duplicate_member", repr(k))
        out[k] = v
    return out


def _refuse_constant(name: str):
    # NaN / Infinity are not JSON; Python's parser accepts them unless told otherwise.
    raise CommitmentRefused("statement_not_json", name)


def _select_statement_version(stmt) -> str:
    """Selection by exact member set over the (strictly parsed) statement object: ``"v5"`` or ``"v6"``."""
    if not isinstance(stmt, dict):
        raise CommitmentRefused("statement_not_object")
    members = set(stmt)
    if members == _V5_MEMBERS:
        version = "v5"
    elif members == _V6_MEMBERS:
        domain = stmt["commitment_digest_domain"]
        if not isinstance(domain, str) or domain != COMMITMENT_DIGEST_V6_DOMAIN:
            raise CommitmentRefused("statement_domain_not_v6", repr(domain))
        version = "v6"
    else:
        raise CommitmentRefused("statement_member_set", repr(sorted(members)))
    if stmt["type"] != _STATEMENT_TYPE:
        raise CommitmentRefused("statement_type")
    d = stmt["commitment_digest"]
    if not isinstance(d, str) or len(d) != 64 or not set(d) <= _HEX64:
        raise CommitmentRefused("statement_digest_not_lowercase_hex")
    return version


def select_commitment_version(ext_raw) -> str:
    """Pick the commitment digest version from a TCT's raw ``ext`` JSON text (str or UTF-8 bytes).

    v6 §Verifiers, by exact member set of the ``com.zer07labs.seam`` statement: ``{type,
    commitment_digest}`` is ``"v5"``; ``{type, commitment_digest, commitment_digest_domain}`` with the
    domain exactly ``"seam-commitment-digest:v6"`` is ``"v6"``. Member order is not significant.
    Everything else raises :class:`CommitmentRefused`: not JSON, not an object, no statement, a
    duplicate member name ANYWHERE in ``ext`` (compared after JSON unescaping, detected before any map
    keeps one of the two), another member set, another domain value (``:v5``, ``:v7``, a non-string),
    another ``type``, or a digest that is not exactly 64 lowercase hex characters.

    The caller then recomputes under the selected version ONLY. It never tries both and never falls
    back: a 2-member statement over a v6 commitment selects v5, the v5 digest differs, and it is refused.
    """
    if isinstance(ext_raw, (bytes, bytearray, memoryview)):
        try:
            ext_raw = bytes(ext_raw).decode("utf-8")
        except UnicodeDecodeError:
            raise CommitmentRefused("statement_not_json") from None
    try:
        ext = json.loads(
            ext_raw,
            object_pairs_hook=_refuse_duplicate_members,
            parse_constant=_refuse_constant,
        )
    except CommitmentRefused:
        raise
    except (ValueError, RecursionError):
        raise CommitmentRefused("statement_not_json") from None
    if not isinstance(ext, dict):
        raise CommitmentRefused("statement_not_object")
    if COMMITMENT_EXT_KEY not in ext:
        raise CommitmentRefused("statement_missing")
    return _select_statement_version(ext[COMMITMENT_EXT_KEY])


def _v5_commitment_input(commitment: dict) -> dict:
    """The commitment as the v5 digest reads it, with v5's scheme rules applied first: no env
    (``v5_refuses_env``), no Gate (``v5_refuses_gate_block``), and, when it carries its raw
    ``trailers``, only a ``0x06`` body v1, which then frames field 11 (a ``governing_doc_sha256`` given
    beside must agree). Without ``trailers`` and without an env or Gate, it is returned unchanged, so
    every pre-v6 v5 input digests byte-for-byte as before."""
    if commitment.get("env") is not None:
        raise CommitmentRefused("v5_refuses_env")
    if commitment.get("gate_digest") is not None:
        raise CommitmentRefused("v5_refuses_gate_block")
    trailers = commitment.get("trailers")
    if trailers is None:
        return commitment
    dec = decode_commitment_trailers(trailers, "v5")
    given = _slot_input(commitment, "governing_doc_sha256")
    if given is not None and given != dec.governing_doc_sha256:
        raise ValueError(
            "governing_doc_sha256 does not match the commitment's trailers"
        )
    return {**commitment, "governing_doc_sha256": dec.governing_doc_sha256}


def served_commitment_trailers(gate_body, governing_doc_sha256, env) -> bytes:
    """The raw v6 ``0x05`` / ``0x06`` trailer run a served ``seam.api.v1.Commitment`` projects (#420).

    ``Commitment`` carries no raw trailers. It carries ``gate = 13`` (``GateRecord.body``, the exact
    ``0x05`` body, byte for byte), ``governing_doc_sha256 = 11`` and ``env = 14``, and that projection is
    lossless under v6: the ``0x06`` body v2 is exactly ``0x02 ‖ doc ‖ env slot``. So this rebuilds the run
    (``""`` when the record has neither trailer) and the verifier then decodes it under every v6 rule
    (:func:`decode_commitment_trailers`): field 10 is still this reader's own ``seam-gate-digest:v1`` over
    the body (VG1), and a Gate block must still match the governing env (``gate_env_binding``). Nothing
    served is trusted: each value is hashed into the digest the TCT signs, so a wrong one fails it.

    v6 only: v5 frames a governed record from ``governing_doc_sha256`` beside the commitment, as before.
    Refuses (:class:`CommitmentRefused`) an env without a governing doc (``env_without_governing_doc``),
    an env that is not exactly ``sandbox`` / ``live``, and a doc that is not 32 bytes."""
    out = b""
    if gate_body is not None:
        body = _bytes_or_hex(gate_body)
        out += bytes([GATE_TRAILER_MARKER]) + struct.pack("<I", len(body)) + body
    env_b = _env_input(env)
    if governing_doc_sha256 is None:
        if env_b is not None:
            raise CommitmentRefused("env_without_governing_doc")
        return out
    doc = _bytes_or_hex(governing_doc_sha256)
    if len(doc) != 32:
        raise CommitmentRefused("slot_length_not_32", f"got {len(doc)} bytes")
    body = bytes([GOVERNING_BODY_V2]) + doc + _env_slot(env_b)
    return out + bytes([GOVERNING_TRAILER_MARKER]) + struct.pack("<I", len(body)) + body


def _tct_commitment_digest(version: str, commitment: dict) -> str:
    """The digest :func:`verify_tct` compares, under the selected ``version`` only. Under v6 fields 10-12
    come from the raw ``trailers`` only, never from values beside them (VG1). A commitment without raw
    ``trailers`` is a served one: its ``gate_body`` / ``governing_doc_sha256`` / ``env`` projection is
    rebuilt into the trailers (:func:`served_commitment_trailers`, #420), so a governed record fetched
    through ``GetCommitmentProof`` verifies. A bare ``gate_digest`` beside is never a source: it must agree
    with the digest recomputed over the Gate body, so with no body it refuses."""
    if version == "v6":
        if commitment.get("trailers") is None:
            served = served_commitment_trailers(
                commitment.get("gate_body"),
                commitment.get("governing_doc_sha256"),
                commitment.get("env"),
            )
            commitment = {
                **commitment,
                "trailers": served,
                "governing_doc_sha256": None,
                "env": None,
            }
        elif (
            commitment.get("gate_body") is not None or commitment.get("env") is not None
        ):
            # The raw trailers are the only source: a served projection beside them is refused, as in
            # every port, never compared.
            raise CommitmentRefused(
                "served_projection_beside_trailers",
                "gate_body / env beside raw trailers",
            )
        return commitment_digest_v6(commitment)
    if commitment.get("gate_body") is not None:
        raise CommitmentRefused("v5_refuses_gate_block")
    return _seam_commitment_digest(_v5_commitment_input(commitment))
