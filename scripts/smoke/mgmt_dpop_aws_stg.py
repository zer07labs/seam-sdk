#!/usr/bin/env python3
"""aws-stg end-to-end smoke for DPoP-bound operator tokens (seam-sdk#290, plan Phase 9).

Proves that a token the management console mints with its DPoP toggle on, paired with the private JWK it
reveals once, can call SeamAdmin on aws-stg's DPoP-required management listener through this SDK, and that
the same token sent as Bearer is refused.

Run it through its handoff wrapper, scripts/handoff/2026-10-27-mgmt-dpop-aws-stg.sh, from a machine whose
identity the mesh admits to seam-server's management port (9100). Dry-run is the default and makes no
network call; --apply runs the three checks.

Inputs come from the environment only. They are never printed, written to disk or echoed, and any output
that might quote them is redacted:

  SEAM_OPERATOR_TOKEN          the bound operator token from the console's one-time reveal   (required)
  SEAM_OPERATOR_DPOP_JWK       the private JWK revealed next to it, exactly as shown         (required)
  SEAM_MGMT_TARGET             host:port of the management listener, e.g. localhost:9100     (required)
  SEAM_MGMT_CA_FILE            PEM CA bundle that signed the listener's certificate          (required)
  SEAM_MGMT_TLS_NAME           the certificate name to verify, when it differs from the target host
                               (the relay dials https://seam-server:9100, so usually "seam-server")
  SEAM_UNBOUND_OPERATOR_TOKEN  optional: an UNBOUND operator token (console mint, DPoP toggle off). Sent as
                               Bearer it must be refused (the required listener's no_cnf rule). Without it,
                               the run reports "required posture: not exercised"
  SEAM_RUNTIME_IMAGE_TAG       optional: the seam-server image tag, quoted in a failure report (a bound
                               token needs runtime >= 0.54.0)

Exit codes: 0 every check passed (dry-run: every local precondition holds); 1 a check failed;
2 a missing or unusable input.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Callable, NoReturn, Optional

# gRPC's C-core traces the authorization header when GRPC_TRACE/GRPC_VERBOSITY=debug are inherited. Set
# before grpc is first imported (seam_sdk imports it), so no call this script makes can be traced.
os.environ.pop("GRPC_TRACE", None)
os.environ["GRPC_VERBOSITY"] = "NONE"

REQUIRED = (
    "SEAM_OPERATOR_TOKEN",
    "SEAM_OPERATOR_DPOP_JWK",
    "SEAM_MGMT_TARGET",
    "SEAM_MGMT_CA_FILE",
)
# Each secret input, and the literal label that replaces it in any output. The label is never built from the
# variable's name or value, so nothing derived from an input reaches the output except through redaction.
REDACTED_ENV = {
    "SEAM_OPERATOR_TOKEN": "<redacted operator token>",
    "SEAM_OPERATOR_DPOP_JWK": "<redacted DPoP JWK>",
    "SEAM_UNBOUND_OPERATOR_TOKEN": "<redacted unbound token>",
}


def _secret_fragments(value: str) -> list[str]:
    """The parts of a secret that are secret on their own: a JWK's private member, a JWS's signature."""
    try:
        parsed = json.loads(value)
    except (ValueError, RecursionError):
        parsed = None
    if isinstance(parsed, dict):
        return (
            [parsed["d"]]
            if isinstance(parsed.get("d"), str) and len(parsed["d"]) >= 16
            else []
        )
    segments = value.split(".")
    return [segments[-1]] if len(segments) == 3 and len(segments[-1]) >= 16 else []


class Redactor:
    """Replaces every secret value (and each of its lines, for a multi-line JWK) with a placeholder."""

    def __init__(self, env: dict[str, str]) -> None:
        parts: list[tuple[str, str]] = []
        for name, label in REDACTED_ENV.items():
            value = env.get(name, "")
            if value:
                parts.append((value, label))
                parts.extend(
                    (line.strip(), label)
                    for line in value.splitlines()
                    if len(line.strip()) >= 8
                )
                parts.extend((frag, label) for frag in _secret_fragments(value))
        # Longest first, so a whole value is replaced before any fragment of it.
        self._parts = sorted(parts, key=lambda p: len(p[0]), reverse=True)

    def __call__(self, text: str) -> str:
        for value, placeholder in self._parts:
            text = text.replace(value, placeholder)
        return text


class Smoke:
    def __init__(self, env: dict[str, str], out: Callable[[str], None]) -> None:
        self.env = env
        self.redact = Redactor(env)
        self._out = out
        self.failed = False

    def say(self, line: str) -> None:
        self._out(self.redact(line))

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.say(f"[{'ok' if ok else 'FAIL'}] {name}{': ' + detail if detail else ''}")
        self.failed |= not ok

    def refuse(self, why: str) -> NoReturn:
        self.say(f"[refused] {why}")
        raise SystemExit(2)

    # ── local preconditions (always run; no network) ───────────────────────────────────────────

    def preconditions(self):
        missing = [n for n in REQUIRED if not self.env.get(n)]
        if missing:
            self.refuse("missing environment: " + ", ".join(missing))
        ca_file = self.env["SEAM_MGMT_CA_FILE"]
        try:
            with open(ca_file, "rb") as f:
                ca = f.read()
        except OSError as e:
            self.refuse(f"SEAM_MGMT_CA_FILE is not readable: {e.strerror}")
        if b"-----BEGIN CERTIFICATE-----" not in ca:
            self.refuse("SEAM_MGMT_CA_FILE holds no PEM certificate")
        try:
            from seam_sdk import OperatorDpopKey  # noqa: PLC0415 — the import itself is a precondition
            from seam_sdk.admin import _management_auth  # noqa: PLC0415
            from seam_sdk.dpop import DpopError  # noqa: PLC0415
        except ImportError as e:
            self.refuse(
                f"seam_sdk is not importable here ({type(e).__name__}); pip install -e ./python"
            )
        try:
            key = OperatorDpopKey.from_jwk(self.env["SEAM_OPERATOR_DPOP_JWK"])
            # The same pairing checks SeamAdminClient.connect runs: bound token, matching cnf.jkt, usable aud.
            _management_auth(self.env["SEAM_OPERATOR_TOKEN"], key, None, None)
        except DpopError as e:
            self.refuse(
                f"the token and JWK cannot work together: {type(e).__name__}: {e}"
            )
        self.check(
            "local preconditions",
            True,
            f"key jkt {key.jkt}, target {self.env['SEAM_MGMT_TARGET']}",
        )
        return key, ca

    # ── the live checks (--apply only) ─────────────────────────────────────────────────────────

    def credentials(self, ca: bytes):
        import grpc  # noqa: PLC0415

        return grpc.ssl_channel_credentials(root_certificates=ca)

    def channel_options(self) -> list[tuple[str, str]]:
        name = self.env.get("SEAM_MGMT_TLS_NAME", "")
        return [("grpc.ssl_target_name_override", name)] if name else []

    def run(self, key, ca: bytes) -> None:
        import grpc  # noqa: PLC0415

        from seam_sdk import SeamAdminClient  # noqa: PLC0415
        from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb  # noqa: PLC0415
        from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc  # noqa: PLC0415

        target = self.env["SEAM_MGMT_TARGET"]
        token = self.env["SEAM_OPERATOR_TOKEN"]
        tag = self.env.get("SEAM_RUNTIME_IMAGE_TAG", "")
        hint = (
            f" (runtime image {tag}; a bound token needs >= 0.54.0)"
            if tag
            else " (a bound token needs runtime >= 0.54.0)"
        )

        # 1. The bound token, signed by this SDK, through the public client.
        try:
            if self.channel_options():
                # connect() has no channel-options hook: the same interceptor over a channel carrying them.
                admin = _connect_with_options(
                    SeamAdminClient,
                    target,
                    token,
                    key,
                    self.credentials(ca),
                    self.channel_options(),
                )
            else:
                admin = SeamAdminClient.connect(
                    target, token=token, dpop_key=key, credentials=self.credentials(ca)
                )
            with admin:
                tenants = admin.list_tenants(timeout=15)
            self.check(
                "bound token + DPoP proof: SeamAdmin/ListTenants",
                True,
                f"{len(tenants)} tenant view(s)",
            )
        except Exception as e:  # noqa: BLE001 — every failure is reported, redacted, and fails the run
            self.check(
                "bound token + DPoP proof: SeamAdmin/ListTenants",
                False,
                f"{type(e).__name__}: {e}{hint}",
            )

        # 2. The same bound token as Bearer: refused on any listener (scheme_mismatch). The public client
        # refuses to send it, so this goes through the raw stub.
        self._expect_refused(
            "bound token as Bearer is refused (scheme_mismatch; proves the binding only)",
            grpc,
            pb,
            rpc,
            target,
            token,
            ca,
        )

        # 3. The required posture: an unbound token as Bearer is refused (no_cnf).
        unbound = self.env.get("SEAM_UNBOUND_OPERATOR_TOKEN", "")
        if unbound:
            self._expect_refused(
                "unbound token as Bearer is refused (required posture, no_cnf)",
                grpc,
                pb,
                rpc,
                target,
                unbound,
                ca,
            )
        else:
            self.say(
                "[skip] required posture: not exercised (set SEAM_UNBOUND_OPERATOR_TOKEN to exercise it)"
            )

    def _expect_refused(self, name, grpc, pb, rpc, target, token, ca) -> None:
        channel = grpc.secure_channel(
            target, self.credentials(ca), options=self.channel_options()
        )
        try:
            rpc.SeamAdminStub(channel).ListTenants(
                pb.Empty(), metadata=[("authorization", f"Bearer {token}")], timeout=15
            )
            self.check(name, False, "the call SUCCEEDED; the listener accepted it")
        except grpc.RpcError as e:
            code = e.code()
            self.check(
                name,
                code == grpc.StatusCode.UNAUTHENTICATED,
                f"{code.name}: {e.details()}",
            )
        finally:
            channel.close()


def _connect_with_options(client_cls, target, token, key, credentials, options):
    """SeamAdminClient.connect with channel options: the same interceptor, over a channel carrying them."""
    import grpc  # noqa: PLC0415

    from seam_sdk.admin import _management_auth  # noqa: PLC0415

    channel = grpc.secure_channel(target, credentials, options=options)
    return client_cls(
        grpc.intercept_channel(channel, _management_auth(token, key, None, None))
    )


def main(argv: Optional[list[str]] = None, env: Optional[dict[str, str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--apply", action="store_true", help="run the live checks (default: dry-run)"
    )
    args = parser.parse_args(argv)
    smoke = Smoke(
        dict(os.environ if env is None else env), lambda line: print(line, flush=True)
    )
    try:
        key, ca = smoke.preconditions()
        if not args.apply:
            smoke.say(
                "[dry-run] no network call made; pass --apply to run the live checks"
            )
            return 0
        smoke.run(key, ca)
    except SystemExit as e:
        return int(e.code or 0)
    return 1 if smoke.failed else 0


if __name__ == "__main__":
    sys.exit(main())
