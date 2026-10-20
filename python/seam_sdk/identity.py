"""Identity custody: create and load the bootstrap file (schema v1).

One JSON file plus one env pointer (``SEAM_BOOTSTRAP_FILE``). The SDK owns this schema (seam-sdk#201):
it is the lower layer, so a partner calling the SDK directly and the adapters' ``from_bootstrap`` read
and write the same bytes. Schema v1, as first defined by ``seam_agent_core/identity.py`` and kept
field-for-field compatible with it so existing partner files still load::

    {"version": 1, "seed_hex": "<64 hex>", "agent_id": "...", "tenant": "...", "endpoint": "host:port",
     "aid": "aid:pubkey:ed25519:<43 b64url>"}

``aid`` is optional (seam-sdk#274, D-AID-RECORD): :func:`create_identity_file` records the derived AID
as the last key, and the schema version stays 1. A file without it (every file written before) loads
unchanged. When it is present, :func:`load_identity_file` verifies it against the AID derived from
``seed_hex`` and refuses the file on a wrong shape or a mismatch. Every loader since #201 ignores
unknown keys, so a file that records ``aid`` also loads in older releases.

Unknown extra keys are ignored on load, as before.

The seed leaves this module in exactly one direction: from disk into an :class:`Agent` on load.
:func:`create_identity_file` generates it, writes it, and returns ``(path, aid)`` — never the seed.
:func:`load_identity_facts` (seam-sdk#274) reads the same file's public facts and returns no signing
capability at all. Both loaders run one shared validator, so they refuse the same bad file with the same
message.
"""

from __future__ import annotations

import errno
import json
import os
import re
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .client import Agent
from .crypto import aid_from_pubkey

ENV_POINTER = "SEAM_BOOTSTRAP_FILE"
SCHEMA_VERSION = 1

# The shape of a recorded ``aid``: the Ed25519 AID form (``crypto.py``), 32 bytes as unpadded b64url.
_AID_RE = re.compile(r"aid:pubkey:ed25519:[A-Za-z0-9_-]{43}")
# A seed is exactly 64 ASCII hex digits: no whitespace, no sign, no ``0x`` (``bytes.fromhex`` would
# skip whitespace, so the shape is checked before anything is decoded).
_SEED_HEX_RE = re.compile(r"[0-9a-fA-F]{64}")
_SEED_LEN_MESSAGE = "seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)"

PathLike = Union[str, "os.PathLike[str]"]


class IdentityFileError(ValueError):
    """The bootstrap file is missing, malformed, fails validation, or cannot be created. Always loud."""


@dataclass(frozen=True, repr=False)
class LoadedIdentity:
    """The process identity loaded from a bootstrap file. The seed is held only inside ``agent``."""

    agent: Agent
    agent_id: str  # registry identity for scope lookup (may equal the AID)
    tenant: str
    endpoint: str  # the data-plane endpoint this process talks to

    @property
    def aid(self) -> str:
        return self.agent.aid

    def __repr__(self) -> str:
        return (
            f"LoadedIdentity(aid={self.aid!r}, agent_id={self.agent_id!r}, tenant={self.tenant!r}, "
            f"endpoint={self.endpoint!r})"
        )


@dataclass(frozen=True)
class IdentityFacts:
    """The public facts of a bootstrap file: no seed, no :class:`Agent`, no signing capability.

    Returned by :func:`load_identity_facts`. The four fields are the file's **claims**; the verifier is
    :func:`load_identity_file`. In particular ``aid`` is the file's recorded ``aid`` when it has one,
    unverified against the seed (see :func:`load_identity_facts`).
    """

    agent_id: str  # registry identity for scope lookup (may equal the AID)
    tenant: str
    endpoint: str  # the data-plane endpoint this process talks to
    aid: str


def load_identity_file(path: Optional[PathLike] = None) -> LoadedIdentity:
    """Load the process identity from ``path`` or ``$SEAM_BOOTSTRAP_FILE`` (schema v1).

    A recorded ``aid`` is verified, not trusted: it must have the AID shape (else ``"aid is
    malformed"``) and equal the AID derived from ``seed_hex`` (else ``"recorded aid does not match
    seed_hex"``). A file without ``aid`` loads as before.
    """
    data = _read_and_validate(path)
    agent = Agent(_decode_seed(data["seed_hex"]))
    if "aid" in data and data["aid"] != agent.aid:
        raise IdentityFileError("recorded aid does not match seed_hex")
    return LoadedIdentity(
        agent=agent,
        agent_id=str(data["agent_id"]),
        tenant=str(data["tenant"]),
        endpoint=str(data["endpoint"]),
    )


def load_identity_facts(path: Optional[PathLike] = None) -> IdentityFacts:
    """Read the public facts of the bootstrap file at ``path`` or ``$SEAM_BOOTSTRAP_FILE`` (seam-sdk#274).

    For a consumer that shows who an agent is but never signs as it. It runs the **same checks, in the
    same order, with the same messages** as :func:`load_identity_file` (one shared validator), so a
    file one refuses the other refuses identically. It never constructs an :class:`Agent` and returns
    no seed, no key and no signing capability.

    ``aid`` is always a string:

    - **The file records ``aid``** (every file written since #274): it is returned as the file's
      **claim**, shape-checked but **not** verified against ``seed_hex``, and the seed is never
      hex-decoded. A hand-edited ``aid`` that does not match its seed is returned here, and refused by
      :func:`load_identity_file`, which is the verifier.
    - **A legacy file without ``aid``**: it is derived transiently from the seed. The public key is
      computed and encoded, and the signing key goes out of scope; only the string is returned.

    "Seed-free" therefore means no signing capability returned, and no seed decode on a file that
    records ``aid``. It does not mean the seed is never read: parsing the JSON reads it as text.
    """
    data = _read_and_validate(path)
    aid = data["aid"] if "aid" in data else _derive_aid(data["seed_hex"])
    return IdentityFacts(
        agent_id=str(data["agent_id"]),
        tenant=str(data["tenant"]),
        endpoint=str(data["endpoint"]),
        aid=aid,
    )


def _read_and_validate(path: Optional[PathLike]) -> dict:
    # The one validator both loaders run (D-FACTS-CHECKS): same checks, same order, same messages.
    # ``seed_hex`` comes back as an opaque, shape-checked string; no bytes are produced here.
    resolved = os.fspath(path) if path is not None else os.environ.get(ENV_POINTER, "")
    if not resolved:
        raise IdentityFileError(
            f"no bootstrap file: pass a path or set ${ENV_POINTER} (one JSON + env pointer is "
            "the custody contract)"
        )
    try:
        with open(resolved, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        raise IdentityFileError(f"bootstrap file not found: {resolved}") from e
    except json.JSONDecodeError as e:
        raise IdentityFileError(
            f"bootstrap file is not valid JSON: {resolved}: {e}"
        ) from e
    if not isinstance(data, dict):
        raise IdentityFileError(f"bootstrap file is not a JSON object: {resolved}")

    if data.get("version") != SCHEMA_VERSION:
        raise IdentityFileError(
            f"bootstrap schema version {data.get('version')!r} unsupported (want {SCHEMA_VERSION})"
        )
    seed_hex = data.get("seed_hex", "")
    if not isinstance(seed_hex, str) or len(seed_hex) != 64:
        raise IdentityFileError(_SEED_LEN_MESSAGE)
    if not _SEED_HEX_RE.fullmatch(seed_hex):
        raise IdentityFileError("seed_hex is not valid hex")

    missing = [k for k in ("agent_id", "tenant", "endpoint") if not data.get(k)]
    if missing:
        raise IdentityFileError(
            f"bootstrap file missing required field(s): {', '.join(missing)}"
        )
    recorded_aid = data.get("aid")
    if "aid" in data and (
        not isinstance(recorded_aid, str) or not _AID_RE.fullmatch(recorded_aid)
    ):
        raise IdentityFileError("aid is malformed")
    return data


def _decode_seed(seed_hex: str) -> bytes:
    # The only place a seed is hex-decoded on load. ``seed_hex`` has passed the validator.
    return bytes.fromhex(seed_hex)


def _derive_aid(seed_hex: str) -> str:
    # The AID of a seed, without an Agent: the signing key lives only inside this call.
    pub = (
        Ed25519PrivateKey.from_private_bytes(_decode_seed(seed_hex))
        .public_key()
        .public_bytes_raw()
    )
    return aid_from_pubkey(pub)


def create_identity_file(
    path: PathLike, *, agent_id: str, tenant: str, endpoint: str
) -> Tuple[str, str]:
    """Generate a new agent identity and write it to ``path`` as a schema-v1 bootstrap file.

    Returns ``(path, aid)``. The seed is never returned: load the file with
    :func:`load_identity_file` in the process that will use it. The file also records that ``aid``
    as its last key, so the public identity can be read back without the seed.

    The write is atomic and never clobbers. The bytes go to a sibling temp file opened
    ``O_CREAT|O_EXCL|O_NOFOLLOW`` with mode ``0600`` (re-applied with ``fchmod`` so the umask cannot
    widen it), are ``fsync``-ed, and are then published with a hard link, which fails if anything —
    a file, a directory, a symlink — already exists at ``path``. A reader never sees a partial file,
    and an existing file is left byte-for-byte unchanged. Raises :class:`IdentityFileError` on refusal.
    """
    for name, value in (
        ("agent_id", agent_id),
        ("tenant", tenant),
        ("endpoint", endpoint),
    ):
        if not isinstance(value, str) or not value:
            raise IdentityFileError(f"{name} must be a non-empty string")

    final = os.fspath(path)
    agent = Agent.generate()
    body = _identity_file_body(
        agent, agent_id=agent_id, tenant=tenant, endpoint=endpoint
    )

    directory = os.path.dirname(os.path.abspath(final))
    tmp = os.path.join(
        directory, f".{os.path.basename(final)}.{secrets.token_hex(8)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(tmp, flags, 0o600)
    except OSError as e:
        raise IdentityFileError(
            f"cannot create bootstrap file in {directory}: {e.strerror}"
        ) from e
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            view = memoryview(body)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, final)
        except FileExistsError as e:
            raise IdentityFileError(
                f"refusing to overwrite existing path: {final}"
            ) from e
        except OSError as e:
            if e.errno == errno.EEXIST:
                raise IdentityFileError(
                    f"refusing to overwrite existing path: {final}"
                ) from e
            raise IdentityFileError(
                f"cannot publish bootstrap file {final}: {e.strerror}"
            ) from e
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    _fsync_dir(directory)
    return final, agent.aid


def _identity_file_body(
    agent: Agent, *, agent_id: str, tenant: str, endpoint: str
) -> bytes:
    # Key order is the schema's, ``aid`` last; TS's ``identityFileBody`` pins these exact bytes.
    return (
        json.dumps(
            {
                "version": SCHEMA_VERSION,
                "seed_hex": agent.seed.hex(),
                "agent_id": agent_id,
                "tenant": tenant,
                "endpoint": endpoint,
                "aid": agent.aid,
            },
            indent=2,
        ).encode("utf-8")
        + b"\n"
    )


def _fsync_dir(directory: str) -> None:
    # Makes the new directory entry durable on POSIX. Windows cannot open a directory; skip there.
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
