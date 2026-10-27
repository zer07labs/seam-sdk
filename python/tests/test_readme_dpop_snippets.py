"""The README's "Bound (DPoP) operator tokens" snippets run as written (seam-sdk#290, plan Phase 10 AC1).

The Python snippet is executed here against an in-process TLS SeamAdmin. The other four live verbatim between
`README:dpop:begin` / `README:dpop:end` markers in test sources that their own suites compile and run:
ts/tests/readme_dpop.test.ts, go/mgmtdpop/readme_test.go, and both MgmtDpopTest files. This test checks each
README block still quotes exactly those lines, so a README edit that is not also a code edit fails here.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import textwrap
from concurrent import futures
from pathlib import Path

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

ROOT = Path(__file__).resolve().parents[2]
SECTION = "### Bound (DPoP) operator tokens"
COMPILED = {
    "ts": ROOT / "ts" / "tests" / "readme_dpop.test.ts",
    "go": ROOT / "go" / "mgmtdpop" / "readme_test.go",
    "java": ROOT
    / "java"
    / "src"
    / "test"
    / "java"
    / "com"
    / "zer07labs"
    / "seam"
    / "MgmtDpopTest.java",
    "kotlin": ROOT
    / "kotlin"
    / "src"
    / "test"
    / "kotlin"
    / "com"
    / "zer07labs"
    / "seam"
    / "MgmtDpopTest.kt",
}
GOLDEN = json.loads((ROOT / "conformance" / "mgmt_dpop_vector.json").read_text())[
    "golden"
]


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _section(readme: Path, heading: str) -> str:
    text = readme.read_text()
    start = text.index(heading)
    end = text.find("\n## ", start)
    return text[start : end if end >= 0 else len(text)]


def _blocks(text: str) -> dict[str, list[str]]:
    blocks: dict[str, list[str]] = {}
    for lang, body in re.findall(r"^```(\w+)\n(.*?)^```$", text, flags=re.S | re.M):
        assert lang not in blocks, f"two {lang} blocks in the section"
        blocks[lang] = body
    return blocks


def _code_lines(body: str) -> list[str]:
    """The block's lines, dedented, without comment-only lines (a README may annotate; code may not differ)."""
    lines = textwrap.dedent(body).splitlines()
    return [
        ln.rstrip() for ln in lines if ln.strip() and not ln.strip().startswith("//")
    ]


def _marked_region(path: Path) -> list[str]:
    text = path.read_text()
    m = re.search(
        r"//\s*README:dpop:begin\n(.*?)\n\s*//\s*README:dpop:end", text, flags=re.S
    )
    assert m, f"{path} has no README:dpop region"
    return _code_lines(m.group(1))


def test_the_section_has_all_five_languages_and_only_the_test_key() -> None:
    section = _section(ROOT / "README.md", SECTION)
    blocks = _blocks(section)
    assert set(blocks) == {"json", "python", "ts", "go", "java", "kotlin"}
    # The only JWK shown is the public test vector's, and it is labelled as such.
    assert json.loads(blocks["json"]) == GOLDEN["jwk"]
    assert "public test vector's key" in section and "Never use it" in section
    assert re.findall(r'"d":"([A-Za-z0-9_-]+)"', section) == [GOLDEN["jwk"]["d"]]


@pytest.mark.parametrize("lang", sorted(COMPILED))
def test_each_snippet_is_the_compiled_code(lang: str) -> None:
    readme = _code_lines(_blocks(_section(ROOT / "README.md", SECTION))[lang])
    assert readme == _marked_region(COMPILED[lang])


def test_the_go_readme_quotes_the_same_code() -> None:
    go_readme = _blocks(
        _section(ROOT / "go" / "README.md", "## Management-plane DPoP")
    )["go"]
    assert _code_lines(go_readme) == _marked_region(COMPILED["go"])


@pytest.fixture
def tls_admin(tmp_path: Path):
    """A TLS SeamAdmin on localhost that records each ListTenants call's headers and raw request bytes."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
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
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
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
    seen: list[tuple[dict[str, str], bytes]] = []

    def list_tenants(request: bytes, context):
        seen.append((dict(context.invocation_metadata()), request))
        return pb.ListTenantsResponse().SerializeToString()

    handler = grpc.method_handlers_generic_handler(
        "seam.api.v1.SeamAdmin",
        {
            "ListTenants": grpc.unary_unary_rpc_method_handler(list_tenants)
        },  # raw bytes in and out
    )
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers((handler,))
    port = server.add_secure_port(
        "localhost:0", grpc.ssl_server_credentials([(key_pem, cert_pem)])
    )
    server.start()
    try:
        yield f"localhost:{port}", cert_pem, seen
    finally:
        server.stop(None)


def test_the_python_snippet_runs_as_written(tls_admin, monkeypatch) -> None:
    target, ca, seen = tls_admin
    token = ".".join(
        [
            _b64(b'{"alg":"EdDSA","typ":"JWT"}'),
            _b64(
                json.dumps(
                    {"aud": "seam-runtime", "cnf": {"jkt": GOLDEN["jkt"]}}
                ).encode()
            ),
            "c2ln",
        ]
    )
    monkeypatch.setenv("SEAM_OPERATOR_DPOP_JWK", json.dumps(GOLDEN["jwk"]))
    monkeypatch.setenv("SEAM_OPERATOR_TOKEN", token)
    monkeypatch.setenv("SEAM_MGMT_TARGET", target)
    # The snippet's grpc.ssl_channel_credentials() trusts the system roots; this one server's CA is added the
    # only way a test can, by injecting it. Nothing else about the snippet changes.
    real = grpc.ssl_channel_credentials
    monkeypatch.setattr(
        grpc, "ssl_channel_credentials", lambda *a, **k: real(root_certificates=ca)
    )

    snippet = _blocks(_section(ROOT / "README.md", SECTION))["python"]
    scope: dict = {}
    exec(compile(snippet, "README.md#python", "exec"), scope)  # noqa: S102 — the snippet IS the test
    scope["admin"].close()

    assert list(scope["tenants"]) == []
    ((headers, body),) = seen
    assert headers["authorization"] == f"DPoP {token}"
    proof = headers["dpop"]
    signing_input, _, sig = proof.rpartition(".")
    Ed25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(GOLDEN["x"] + "=")
    ).verify(base64.urlsafe_b64decode(sig + "=="), signing_input.encode())
    claims = json.loads(base64.urlsafe_b64decode(proof.split(".")[1] + "=="))
    assert claims["htu"] == "grpc://seam-runtime/seam.api.v1.SeamAdmin/ListTenants"
    assert claims["seam_bd"] == _b64(hashlib.sha256(body).digest())
