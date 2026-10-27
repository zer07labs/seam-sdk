"""The aws-stg DPoP smoke (scripts/smoke/mgmt_dpop_aws_stg.py) and its handoff wrapper never reveal the
secrets they are handed (seam-sdk#290, plan Phase 9 AC4).

The token and JWK here are fake but real-shaped: a fresh Ed25519 seed and a token bound to it. The wrapper
runs in its default dry-run; the Python script runs --apply against an in-process TLS management server that
deliberately echoes the authorization header back in its refusal, the worst case a redactor must survive.
"""

from __future__ import annotations

import base64
import datetime
import importlib.util
import json
import os
import subprocess
import sys
from concurrent import futures
from pathlib import Path

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from seam_sdk import OperatorDpopKey
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts" / "handoff" / "2026-10-27-mgmt-dpop-aws-stg.sh"
SMOKE = ROOT / "scripts" / "smoke" / "mgmt_dpop_aws_stg.py"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


_HEADER = _b64(b'{"alg":"EdDSA","typ":"JWT"}')


def _token(claims: dict) -> str:
    return f"{_HEADER}.{_b64(json.dumps(claims).encode())}.{_b64(os.urandom(64))}"


@pytest.fixture
def secrets() -> dict[str, str]:
    seed = os.urandom(32)
    key = OperatorDpopKey.from_seed(seed)
    jwk = json.dumps(
        {"kty": "OKP", "crv": "Ed25519", "x": key.x, "d": _b64(seed)}, indent=2
    )
    return {
        "SEAM_OPERATOR_TOKEN": _token(
            {"aud": "seam-runtime", "sub": "smoke", "cnf": {"jkt": key.jkt}}
        ),
        "SEAM_OPERATOR_DPOP_JWK": jwk,
        "SEAM_UNBOUND_OPERATOR_TOKEN": _token(
            {"aud": "seam-runtime", "sub": "unbound-smoke"}
        ),
        "_seed_b64": _b64(seed),
    }


def _leaks(text: str, secrets: dict[str, str]) -> list[str]:
    found = [name for name, value in secrets.items() if value in text]
    # The JWK's private half on its own, and the token's signature segment, are secrets too.
    for name in ("SEAM_OPERATOR_TOKEN", "SEAM_UNBOUND_OPERATOR_TOKEN"):
        if secrets[name].rsplit(".", 1)[1] in text:
            found.append(f"{name} signature")
    return found


def _self_signed(tmp_path: Path) -> tuple[bytes, bytes, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "seam-server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("seam-server")]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    ca = tmp_path / "ca.pem"
    ca.write_bytes(cert_pem)
    return cert_pem, key_pem, ca


@pytest.fixture
def management_server(tmp_path: Path):
    """A TLS SeamAdmin that accepts DPoP and refuses Bearer — echoing the header it refused."""
    cert_pem, key_pem, ca = _self_signed(tmp_path)
    seen: list[dict[str, str]] = []

    def list_tenants(request, context):
        md = dict(context.invocation_metadata())
        seen.append(md)
        auth = md.get("authorization", "")
        if auth.startswith("DPoP ") and md.get("dpop"):
            return pb.ListTenantsResponse()
        context.abort(grpc.StatusCode.UNAUTHENTICATED, f"refused: {auth}")

    handler = grpc.method_handlers_generic_handler(
        "seam.api.v1.SeamAdmin",
        {
            "ListTenants": grpc.unary_unary_rpc_method_handler(
                list_tenants,
                request_deserializer=pb.Empty.FromString,
                response_serializer=pb.ListTenantsResponse.SerializeToString,
            )
        },
    )
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    server.add_generic_rpc_handlers((handler,))
    port = server.add_secure_port(
        "127.0.0.1:0", grpc.ssl_server_credentials([(key_pem, cert_pem)])
    )
    server.start()
    try:
        yield f"127.0.0.1:{port}", ca, seen
    finally:
        server.stop(None)


def _load_smoke():
    spec = importlib.util.spec_from_file_location("mgmt_dpop_aws_stg", SMOKE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _env(secrets: dict[str, str], target: str, ca: Path) -> dict[str, str]:
    env = {k: v for k, v in secrets.items() if not k.startswith("_")}
    env.update(
        SEAM_MGMT_TARGET=target,
        SEAM_MGMT_CA_FILE=str(ca),
        SEAM_MGMT_TLS_NAME="seam-server",
    )
    return env


def test_the_wrapper_dry_run_makes_no_call_and_reveals_nothing(
    tmp_path, secrets
) -> None:
    _, _, ca = _self_signed(tmp_path)
    logs = tmp_path / "logs"
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "SEAM_SMOKE_PYTHON": sys.executable,
        "SEAM_HANDOFF_LOG_DIR": str(logs),
        # Port 1 on loopback: a dry run that dialled it would fail, so success proves no call was made.
        **_env(secrets, "127.0.0.1:1", ca),
    }
    r = subprocess.run(
        ["bash", str(WRAPPER)], env=env, capture_output=True, text=True, timeout=120
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "DRY-RUN" in r.stdout and "(dry-run: skipped)" in r.stdout
    assert "[dry-run] no network call made" in r.stdout
    assert "input SEAM_OPERATOR_TOKEN: set" in r.stdout
    log = "".join(p.read_text() for p in logs.iterdir())
    for stream in (r.stdout, r.stderr, log):
        assert _leaks(stream, secrets) == []


def test_the_wrapper_refuses_argv_inputs_without_echoing_them(tmp_path) -> None:
    r = subprocess.run(
        ["bash", str(WRAPPER), "--token=eyJsecret.value.sig"],
        env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 2 and "never argv" in r.stderr
    assert "eyJsecret" not in r.stdout + r.stderr


def test_tracing_the_wrapper_reveals_nothing(tmp_path, secrets) -> None:
    """`bash -x` and an inherited gRPC trace are the two ways a shell run prints its environment."""
    _, _, ca = _self_signed(tmp_path)
    logs = tmp_path / "logs"
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "SEAM_SMOKE_PYTHON": sys.executable,
        "SEAM_HANDOFF_LOG_DIR": str(logs),
        "GRPC_TRACE": "all",
        "GRPC_VERBOSITY": "debug",
        **_env(secrets, "127.0.0.1:1", ca),
    }
    r = subprocess.run(
        ["bash", "-x", str(WRAPPER)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    log = "".join(p.read_text() for p in logs.iterdir())
    for stream in (r.stdout, r.stderr, log):
        assert _leaks(stream, secrets) == []


def test_the_script_silences_grpc_tracing_before_grpc_loads() -> None:
    source = SMOKE.read_text()
    assert source.index('os.environ["GRPC_VERBOSITY"] = "NONE"') < source.index(
        "import grpc"
    )
    assert 'os.environ.pop("GRPC_TRACE", None)' in source


def test_apply_against_a_hostile_echo_passes_and_reveals_nothing(
    secrets, management_server, capsys
) -> None:
    target, ca, seen = management_server
    rc = _load_smoke().main(["--apply"], env=_env(secrets, target, ca))
    out = capsys.readouterr()
    assert rc == 0, out.out
    assert (
        "[ok] bound token + DPoP proof: SeamAdmin/ListTenants: 0 tenant view(s)"
        in out.out
    )
    assert "[ok] bound token as Bearer is refused" in out.out
    assert "[ok] unbound token as Bearer is refused" in out.out
    # The server really echoed the headers back, so the redactor did work rather than nothing leaking.
    assert "refused: Bearer <SEAM_OPERATOR_TOKEN>" in out.out
    assert "refused: Bearer <SEAM_UNBOUND_OPERATOR_TOKEN>" in out.out
    assert _leaks(out.out + out.err, secrets) == []
    assert [m["authorization"].split(" ")[0] for m in seen] == [
        "DPoP",
        "Bearer",
        "Bearer",
    ]


def test_apply_without_the_unbound_token_says_not_exercised(
    secrets, management_server, capsys
) -> None:
    target, ca, _ = management_server
    env = _env(secrets, target, ca)
    del env["SEAM_UNBOUND_OPERATOR_TOKEN"]
    assert _load_smoke().main(["--apply"], env=env) == 0
    assert "required posture: not exercised" in capsys.readouterr().out


def test_a_failing_live_check_fails_the_run_and_reveals_nothing(
    secrets, tmp_path, capsys
) -> None:
    _, _, ca = _self_signed(tmp_path)
    env = {**_env(secrets, "127.0.0.1:1", ca), "SEAM_RUNTIME_IMAGE_TAG": "0.53.0"}
    assert _load_smoke().main(["--apply"], env=env) == 1
    out = capsys.readouterr()
    assert (
        "[FAIL] bound token + DPoP proof" in out.out
        and "runtime image 0.53.0" in out.out
    )
    assert _leaks(out.out + out.err, secrets) == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"SEAM_OPERATOR_TOKEN": ""}, "missing environment: SEAM_OPERATOR_TOKEN"),
        (
            {"SEAM_MGMT_CA_FILE": "/nonexistent/ca.pem"},
            "SEAM_MGMT_CA_FILE is not readable",
        ),
        (
            {"SEAM_OPERATOR_DPOP_JWK": '{"kty":"OKP"}'},
            "the token and JWK cannot work together",
        ),
        ({"_unbound_as_bound": ""}, "the token and JWK cannot work together"),
    ],
)
def test_unusable_inputs_are_refused_by_name(
    secrets, tmp_path, capsys, change, message
) -> None:
    _, _, ca = _self_signed(tmp_path)
    env = _env(secrets, "127.0.0.1:1", ca)
    if "_unbound_as_bound" in change:
        env["SEAM_OPERATOR_TOKEN"] = secrets["SEAM_UNBOUND_OPERATOR_TOKEN"]
    else:
        env.update(change)
    assert _load_smoke().main([], env=env) == 2
    out = capsys.readouterr()
    assert message in out.out
    assert _leaks(out.out + out.err, secrets) == []


def test_the_redactor_covers_each_line_of_a_multi_line_jwk(secrets) -> None:
    redact = _load_smoke().Redactor(secrets)
    d_line = next(
        line for line in secrets["SEAM_OPERATOR_DPOP_JWK"].splitlines() if '"d"' in line
    )
    assert secrets["_seed_b64"] not in redact(f"oops {d_line.strip()} leaked")
    # The private half alone, and a token's signature alone, are redacted too.
    assert redact(f"d={secrets['_seed_b64']}") == "d=<SEAM_OPERATOR_DPOP_JWK>"
    sig = secrets["SEAM_OPERATOR_TOKEN"].rsplit(".", 1)[1]
    assert redact(f"sig={sig}") == "sig=<SEAM_OPERATOR_TOKEN>"
