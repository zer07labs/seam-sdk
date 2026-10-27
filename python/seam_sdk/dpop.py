"""Operator DPoP for the management plane: proof of possession for a key-bound operator token.

An operator token minted with ``cnf.jkt`` (the console's "Bind token to a key (DPoP)" mint) is refused as
``Bearer``. Every management call (``SeamAdmin``, ``SeamEvents``, HTTP 9099) must instead carry
``authorization: DPoP <token>`` plus a fresh ``dpop`` proof: a compact JWS, signed by the bound Ed25519
key, over the call's method, target, the token and the request body. The grammar is
``docs/specs/mgmt-dpop.md`` (a pinned copy of seam-runtime's); ``conformance/mgmt_dpop_vector.json`` pins
the exact bytes, and its ``golden`` group is the runtime's own vector.

Most callers never touch this module directly — pass the key to
``SeamAdminClient.connect(target, token=..., dpop_key=...)`` and every call is signed. Use
:func:`mgmt_dpop_http_headers` to call the HTTP management plane with your own HTTP client.

Every value this module puts into a proof is printable ASCII, so the JSON it signs is byte-identical in
all five SDKs (no encoder-specific escaping of non-ASCII, ``<``, ``>`` or ``&`` can differ).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

__all__ = [
    "DEFAULT_OPERATOR_AUD",
    "MGMT_DPOP_MAX_BODY_BYTES",
    "MGMT_DPOP_MAX_IAT",
    "MGMT_DPOP_MAX_JTI_BYTES",
    "MGMT_DPOP_MAX_PROOF_BYTES",
    "DpopError",
    "DpopKeyError",
    "OperatorDpopKey",
    "mgmt_dpop_grpc_htu",
    "mgmt_dpop_http_headers",
    "mgmt_dpop_http_htu",
    "mgmt_dpop_proof",
    "new_mgmt_dpop_jti",
]

#: The runtime's operator audience when ``SEAM_RUNTIME_AUD`` is unset — the authority of every gRPC
#: ``htu`` (``grpc://<aud><full method>``), whatever address the client dialled.
DEFAULT_OPERATOR_AUD = "seam-runtime"
#: The runtime refuses a proof larger than this.
MGMT_DPOP_MAX_PROOF_BYTES = 8 * 1024
#: The runtime buffers at most this much request body (HTTP) or message (gRPC) to bind it.
MGMT_DPOP_MAX_BODY_BYTES = 1024 * 1024
#: The runtime refuses a longer ``jti``.
MGMT_DPOP_MAX_JTI_BYTES = 256
#: The largest ``iat`` every SDK accepts: 2**53 - 1, the largest integer a JavaScript number holds exactly.
MGMT_DPOP_MAX_IAT = 2**53 - 1

_B64URL = re.compile(r"^[A-Za-z0-9_-]*\Z")
# Printable ASCII. A token is a header value, so space is excluded there; jti and htu allow it.
_TOKEN_CHARS = re.compile(r"^[\x21-\x7e]+\Z")
_PRINTABLE = re.compile(r"^[\x20-\x7e]+\Z")
# RFC 9110 `token`: what an HTTP method is allowed to be.
_METHOD = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class DpopError(ValueError):
    """A DPoP input the SDK refuses locally, before any network call: the runtime would refuse it, and
    its refusal is one fixed message that names no reason. Never raised for a wire error."""


class DpopKeyError(DpopError):
    """The key, or the token it is meant to be bound to, cannot work: a malformed JWK, a JWK whose
    ``x`` is not the public half of its ``d``, or a token whose ``cnf.jkt`` names a different key."""


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_32(name: str, value: Any) -> bytes:
    """Strictly decode an unpadded base64url member that must hold exactly 32 bytes."""
    if not isinstance(value, str):
        raise DpopKeyError(f"JWK member {name!r} must be a string")
    # A length of 1 mod 4 is not base64 at all; check it here so the decoder never raises its own type.
    if not _B64URL.match(value) or len(value) % 4 == 1:
        raise DpopKeyError(f"JWK member {name!r} must be unpadded base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != 32:
        raise DpopKeyError(
            f"JWK member {name!r} must decode to 32 bytes, got {len(raw)}"
        )
    # A non-canonical encoding (stray low bits in the last character) decodes to the same bytes but is a
    # different string, so its thumbprint would not be the runtime's.
    if _b64url(raw) != value:
        raise DpopKeyError(f"JWK member {name!r} is not canonical base64url")
    return raw


def _sha256_b64url(data: bytes) -> str:
    return _b64url(hashlib.sha256(data).digest())


def _json(obj: Mapping[str, Any]) -> bytes:
    # Compact, in insertion order. Every string reaching here is printable ASCII (enforced by the
    # callers), so `ensure_ascii` changes nothing and the bytes match every other SDK's.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class OperatorDpopKey:
    """The Ed25519 key an operator token is bound to.

    Load it from the JWK the management console reveals once, next to the token —
    ``{"kty":"OKP","crv":"Ed25519","x":...,"d":...}`` — with :meth:`from_jwk`. Keep that JWK as secret as
    the token: whoever holds both can act as the operator until the token expires.

    The private half never leaves this object: ``repr``/``str`` show only the thumbprint, and the object
    refuses to be pickled or copied into another process by accident.
    """

    __slots__ = ("_sk", "_x", "_jkt")

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, bytes | bytearray) or len(seed) != 32:
            raise DpopKeyError("an Ed25519 seed must be exactly 32 bytes")
        sk = Ed25519PrivateKey.from_private_bytes(bytes(seed))
        x = _b64url(sk.public_key().public_bytes_raw())
        self._sk = sk
        self._x = x
        # RFC 7638 thumbprint: SHA-256 over the required members in lexicographic order, no whitespace.
        self._jkt = _sha256_b64url(
            _json({"crv": "Ed25519", "kty": "OKP", "x": x}),
        )

    @classmethod
    def from_seed(cls, seed: bytes) -> OperatorDpopKey:
        """A key from its raw 32-byte Ed25519 seed (the JWK's ``d``, decoded)."""
        return cls(seed)

    @classmethod
    def from_jwk(cls, jwk: str | Mapping[str, Any]) -> OperatorDpopKey:
        """A key from a private OKP/Ed25519 JWK, as JSON text or an already-parsed mapping.

        ``x`` is checked against the public key derived from ``d``, so a reveal pasted with a typo fails
        here, by name, instead of as an opaque 401 on the first call. ``kid`` and other members that do
        not contradict an Ed25519 signing key are ignored.
        """
        if isinstance(jwk, str):
            try:
                jwk = json.loads(jwk)
            except json.JSONDecodeError as e:
                raise DpopKeyError(f"JWK is not valid JSON: {e.msg}") from None
            except RecursionError:
                raise DpopKeyError("JWK is not valid JSON: nested too deeply") from None
        if not isinstance(jwk, Mapping):
            raise DpopKeyError("JWK must be a JSON object")
        if jwk.get("kty") != "OKP":
            raise DpopKeyError('JWK "kty" must be "OKP"')
        if jwk.get("crv") != "Ed25519":
            raise DpopKeyError('JWK "crv" must be "Ed25519"')
        if "alg" in jwk and jwk["alg"] not in ("EdDSA", "Ed25519"):
            raise DpopKeyError('JWK "alg", when present, must be "EdDSA" or "Ed25519"')
        if "use" in jwk and jwk["use"] != "sig":
            raise DpopKeyError('JWK "use", when present, must be "sig"')
        if "d" not in jwk:
            raise DpopKeyError('JWK has no "d": a public JWK cannot sign proofs')
        if "x" not in jwk:
            raise DpopKeyError('JWK has no "x"')
        seed = _b64url_32("d", jwk["d"])
        _b64url_32("x", jwk["x"])
        key = cls(seed)
        if key._x != jwk["x"]:
            raise DpopKeyError('JWK "x" is not the public key of its "d"')
        return key

    @property
    def x(self) -> str:
        """The public key, unpadded base64url — the JWK's ``x``."""
        return self._x

    @property
    def jkt(self) -> str:
        """The RFC 7638 thumbprint the runtime compares against the token's ``cnf.jkt``."""
        return self._jkt

    def public_jwk(self) -> dict[str, str]:
        """The public JWK, in the member order a proof header carries it."""
        return {"kty": "OKP", "crv": "Ed25519", "x": self._x}

    def _sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)

    def __repr__(self) -> str:
        return f"OperatorDpopKey(jkt={self._jkt!r})"

    __str__ = __repr__

    def __reduce__(self) -> Any:
        raise TypeError("OperatorDpopKey holds a private key and cannot be pickled")


def new_mgmt_dpop_jti() -> str:
    """A fresh proof id: 16 random bytes as unpadded base64url (22 characters)."""
    return _b64url(secrets.token_bytes(16))


def _check_token(token: Any) -> str:
    if not isinstance(token, str) or not token:
        raise DpopError("the operator token must be a non-empty string")
    if not _TOKEN_CHARS.match(token):
        raise DpopError("the operator token must be printable ASCII with no spaces")
    return token


def mgmt_dpop_proof(
    key: OperatorDpopKey,
    token: str,
    *,
    htm: str,
    htu: str,
    body: bytes,
    iat: int | None = None,
    jti: str | None = None,
) -> str:
    """The compact-JWS proof for one management call.

    ``htm`` is the HTTP method (``"POST"`` for every gRPC call); ``htu`` is the call's target as the runtime
    compares it — build it with :func:`mgmt_dpop_grpc_htu` or :func:`mgmt_dpop_http_htu`; ``body`` is the
    exact request body (HTTP) or the protobuf-encoded request message without its frame prefix (gRPC).
    ``iat`` defaults to now and ``jti`` to a fresh random id; pass them only to reproduce a vector.

    Each proof is burned on first use, so never reuse one: sign every attempt, retries included.
    """
    if not isinstance(key, OperatorDpopKey):
        raise DpopError("key must be an OperatorDpopKey")
    _check_token(token)
    if not isinstance(htm, str) or not _METHOD.match(htm):
        raise DpopError("htm must be an HTTP method token")
    if not isinstance(htu, str) or not _PRINTABLE.match(htu):
        raise DpopError("htu must be a non-empty printable-ASCII string")
    if not isinstance(body, bytes | bytearray | memoryview):
        raise DpopError("body must be bytes")
    body = bytes(body)
    if len(body) > MGMT_DPOP_MAX_BODY_BYTES:
        raise DpopError(
            f"the request body is {len(body)} bytes; the runtime binds at most "
            f"{MGMT_DPOP_MAX_BODY_BYTES} and refuses a larger one"
        )
    if iat is None:
        iat = int(time.time())
    if (
        isinstance(iat, bool)
        or not isinstance(iat, int)
        or not 0 <= iat <= MGMT_DPOP_MAX_IAT
    ):
        raise DpopError("iat must be a non-negative integer number of seconds")
    if jti is None:
        jti = new_mgmt_dpop_jti()
    if not isinstance(jti, str) or not _PRINTABLE.match(jti):
        raise DpopError("jti must be a non-empty printable-ASCII string")
    if len(jti) > MGMT_DPOP_MAX_JTI_BYTES:
        raise DpopError(f"jti must be at most {MGMT_DPOP_MAX_JTI_BYTES} bytes")

    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.public_jwk()}
    claims = {
        "jti": jti,
        "htm": htm,
        "htu": htu,
        "iat": iat,
        "ath": _sha256_b64url(token.encode("ascii")),
        "seam_bd": _sha256_b64url(body),
    }
    signing_input = _b64url(_json(header)) + "." + _b64url(_json(claims))
    proof = signing_input + "." + _b64url(key._sign(signing_input.encode("ascii")))
    if len(proof) > MGMT_DPOP_MAX_PROOF_BYTES:
        raise DpopError(
            f"the proof is {len(proof)} bytes; the runtime refuses one over {MGMT_DPOP_MAX_PROOF_BYTES}"
        )
    return proof


def mgmt_dpop_grpc_htu(method: str, aud: str = DEFAULT_OPERATOR_AUD) -> str:
    """``grpc://<aud><full method>`` for a gRPC management call, e.g.
    ``grpc://seam-runtime/seam.api.v1.SeamAdmin/EnrollTenant``. ``method`` is the full method path,
    leading slash included; ``aud`` is the runtime's operator audience, not the dialled address."""
    if (
        not isinstance(method, str)
        or not method.startswith("/")
        or not _PRINTABLE.match(method)
    ):
        raise DpopError(
            'method must be a full gRPC method path such as "/pkg.Service/Method"'
        )
    if not isinstance(aud, str) or not aud or not _TOKEN_CHARS.match(aud) or "/" in aud:
        raise DpopError(
            "aud must be a non-empty printable-ASCII string with no spaces or '/'"
        )
    return f"grpc://{aud}{method}"


def mgmt_dpop_http_htu(url: str) -> str:
    """The ``htu`` the runtime compares an HTTP management call against: ``https://<authority><path>``.

    The scheme becomes ``https`` (the runtime treats ``http`` and ``https`` alike, since TLS may end at an
    edge), the host is lower-cased, a default port (``:443`` for https, ``:80`` for http) is dropped, and
    the query and fragment are dropped. The path is kept exactly; an empty one becomes ``/``. A URL
    carrying userinfo is refused.

    This is an explicit grammar, not a URL library, so that every SDK derives the same ``htu`` from the
    same string (``conformance/mgmt_dpop_vector.json`` ``http_htu``):
    ``scheme "://" authority [path] ["?" query] ["#" fragment]``, where ``authority`` is
    ``host [":" port]``, ``host`` is a reg-name or a bracketed IPv6 literal, and ``port`` is 1-5 digits.

    Send the request to exactly this URL. A client that normalises paths (dot-segments such as ``/a/../b``,
    or percent-encoding) sends a path the ``htu`` does not name, and the runtime refuses the proof.
    """
    if not isinstance(url, str) or not _TOKEN_CHARS.match(url):
        raise DpopError("url must be a non-empty visible-ASCII string (no spaces)")
    scheme, sep, rest = url.partition("://")
    scheme = scheme.lower()
    if not sep or scheme not in ("http", "https"):
        raise DpopError("url must be an absolute http:// or https:// URL")
    cut = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    path = tail[
        : min((i for i in (tail.find(c) for c in "?#") if i >= 0), default=len(tail))
    ]
    if "@" in authority:
        raise DpopError("url must not carry userinfo")
    if authority.startswith("["):
        close = authority.find("]")
        if close < 2:
            raise DpopError("url has a malformed IPv6 literal")
        host, after = authority[: close + 1], authority[close + 1 :]
        if after and not after.startswith(":"):
            raise DpopError("url has a malformed IPv6 literal")
        port_text = after[1:] if after else ""
    else:
        host, colon, port_text = authority.partition(":")
        if ":" in port_text:
            raise DpopError(
                "url has more than one ':' in its authority; bracket an IPv6 literal"
            )
    if not host:
        raise DpopError("url has no host")
    host = host.lower()
    port = None
    if port_text:
        # 1-5 digits first, so `int()` never sees an unbounded string.
        if (
            len(port_text) > 5
            or not port_text.isdigit()
            or not port_text.isascii()
            or int(port_text) > 65535
        ):
            raise DpopError("url has an invalid port")
        port = int(port_text)
    authority = host
    if port is not None and port != (443 if scheme == "https" else 80):
        authority = f"{host}:{port}"
    return f"https://{authority}{path or '/'}"


def mgmt_dpop_http_headers(
    key: OperatorDpopKey,
    token: str,
    method: str,
    url: str,
    body: bytes = b"",
    *,
    iat: int | None = None,
    jti: str | None = None,
) -> dict[str, str]:
    """``{"Authorization": "DPoP <token>", "DPoP": <proof>}`` for one call to the HTTP management plane.

    Add both headers to the request you send, with exactly ``body`` as its body (empty for a GET). Call
    this once per request — never reuse the headers for a retry."""
    proof = mgmt_dpop_proof(
        key, token, htm=method, htu=mgmt_dpop_http_htu(url), body=body, iat=iat, jti=jti
    )
    return {"Authorization": f"DPoP {token}", "DPoP": proof}


def _peek_token_claims(token: str) -> dict[str, Any]:
    """The operator token's claims, decoded WITHOUT verifying its signature.

    Only for local diagnostics (does it carry ``cnf.jkt``, does that match the key, what is its ``aud``):
    the SDK holds no operator public key, and the runtime is the verifier. Raises :class:`DpopKeyError`
    for a token that is not a compact JWS with a JSON-object payload."""
    _check_token(token)
    parts = token.split(".")
    if len(parts) != 3 or not _B64URL.match(parts[1]):
        raise DpopKeyError("the operator token is not a compact JWS")
    try:
        payload = json.loads(
            base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        )
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise DpopKeyError("the operator token's payload is not JSON") from None
    if not isinstance(payload, dict):
        raise DpopKeyError("the operator token's payload is not a JSON object")
    return payload


def _token_cnf_jkt(claims: Mapping[str, Any]) -> str | None:
    cnf = claims.get("cnf")
    if cnf is None:
        return None
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jkt"), str):
        raise DpopKeyError("the operator token's cnf claim is malformed")
    return cnf["jkt"]


# A clock is `() -> int` seconds. Exposed on the interceptor for tests and unusual hosts only.
Clock = Callable[[], int]
