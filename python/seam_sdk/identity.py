"""Identity custody: create and load the bootstrap file (schema v1).

One JSON file plus one env pointer (``SEAM_BOOTSTRAP_FILE``). The SDK owns this schema (seam-sdk#201):
it is the lower layer, so a partner calling the SDK directly and the adapters' ``from_bootstrap`` read
and write the same bytes. Schema v1, as first defined by ``seam_agent_core/identity.py`` and kept
field-for-field compatible with it so existing partner files still load::

    {"version": 1, "seed_hex": "<64 hex>", "agent_id": "...", "tenant": "...", "endpoint": "host:port"}

Unknown extra keys are ignored on load, as before.

The seed leaves this module in exactly one direction: from disk into an :class:`Agent` on load.
:func:`create_identity_file` generates it, writes it, and returns ``(path, aid)`` — never the seed.
"""

from __future__ import annotations

import errno
import json
import os
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple, Union

from .client import Agent

ENV_POINTER = "SEAM_BOOTSTRAP_FILE"
SCHEMA_VERSION = 1

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


def load_identity_file(path: Optional[PathLike] = None) -> LoadedIdentity:
    """Load the process identity from ``path`` or ``$SEAM_BOOTSTRAP_FILE`` (schema v1)."""
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
        raise IdentityFileError(
            "seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)"
        )
    try:
        seed = bytes.fromhex(seed_hex)
    except ValueError as e:
        raise IdentityFileError("seed_hex is not valid hex") from e
    if len(seed) != 32:
        raise IdentityFileError(
            "seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)"
        )

    missing = [k for k in ("agent_id", "tenant", "endpoint") if not data.get(k)]
    if missing:
        raise IdentityFileError(
            f"bootstrap file missing required field(s): {', '.join(missing)}"
        )
    return LoadedIdentity(
        agent=Agent(seed),
        agent_id=str(data["agent_id"]),
        tenant=str(data["tenant"]),
        endpoint=str(data["endpoint"]),
    )


def create_identity_file(
    path: PathLike, *, agent_id: str, tenant: str, endpoint: str
) -> Tuple[str, str]:
    """Generate a new agent identity and write it to ``path`` as a schema-v1 bootstrap file.

    Returns ``(path, aid)``. The seed is never returned: load the file with
    :func:`load_identity_file` in the process that will use it.

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
    body = (
        json.dumps(
            {
                "version": SCHEMA_VERSION,
                "seed_hex": agent.seed.hex(),
                "agent_id": agent_id,
                "tenant": tenant,
                "endpoint": endpoint,
            },
            indent=2,
        ).encode("utf-8")
        + b"\n"
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


def _fsync_dir(directory: str) -> None:
    # Makes the new directory entry durable on POSIX. Windows cannot open a directory; skip there.
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
