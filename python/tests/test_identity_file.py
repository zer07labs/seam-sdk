"""seam-sdk#201: Agent.generate() and the schema-v1 bootstrap file (create/load)."""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

import seam_sdk
from seam_sdk import (
    Agent,
    IdentityFacts,
    IdentityFileError,
    create_identity_file,
    load_identity_facts,
    load_identity_file,
)
from seam_sdk import identity as identity_mod
from seam_sdk.identity import ENV_POINTER

posix_only = pytest.mark.skipif(
    os.name != "posix", reason="POSIX file modes and symlinks"
)

FIELDS = dict(agent_id="ap-clerk", tenant="acme", endpoint="seam.example:443")

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "ts" / "tests" / "fixtures"
#: Written by this module's writer (seam-sdk#274); TS pins the same bytes.
AID_FIXTURE = FIXTURES / "identity_v1_aid_python.json"
#: The pre-#274 layout (no ``aid``): the legacy case.
LEGACY_FIXTURE = FIXTURES / "identity_v1_python.json"
FIXTURE_SEED_HEX = "ddc1524b29efe5bc1b9e9ea141b2a4740ba3e4d52f781afa3c1ffb3a3970580c"
FIXTURE_AID = "aid:pubkey:ed25519:9x_uM2PCzXE8pt6di2RwwKCkod7W5kctdLdoIVtKep4"
FIXTURE_FIELDS = dict(
    agent_id="ap-clerk", tenant="acm\u00e9", endpoint="seam.example:443"
)
#: The loader at f1d112d (0.48.1, before the ``aid`` key), vendored byte-exact, and its git blob id.
PRE_AID_LOADER = (
    Path(__file__).resolve().parent / "fixtures" / "identity_f1d112d.py.txt"
)
PRE_AID_LOADER_BLOB = "37998824140deb805190a8e4328876b7cc0f9eac"


def test_generate_is_32_fresh_csprng_bytes():
    a, b = Agent.generate(), Agent.generate()
    assert len(a.seed) == 32 and a.seed != b.seed and a.aid != b.aid


def test_round_trip_aid_equality(tmp_path):
    path, aid = create_identity_file(tmp_path / "id.json", **FIELDS)
    loaded = load_identity_file(path)
    assert loaded.aid == aid == loaded.agent.aid
    assert (loaded.agent_id, loaded.tenant, loaded.endpoint) == (
        "ap-clerk",
        "acme",
        "seam.example:443",
    )


def test_create_never_returns_the_seed(tmp_path):
    result = create_identity_file(tmp_path / "id.json", **FIELDS)
    assert isinstance(result, tuple) and len(result) == 2
    assert all(isinstance(x, str) for x in result)
    seed_hex = json.loads(open(result[0]).read())["seed_hex"]
    assert all(seed_hex not in x for x in result)
    assert not any(hasattr(x, "seed") for x in result)


def test_repr_of_a_loaded_identity_does_not_print_the_seed(tmp_path):
    path, _ = create_identity_file(tmp_path / "id.json", **FIELDS)
    loaded = load_identity_file(path)
    assert loaded.agent.seed.hex() not in repr(loaded)


def test_file_is_schema_v1_with_the_adapters_field_names(tmp_path):
    path, _ = create_identity_file(tmp_path / "id.json", **FIELDS)
    data = json.loads(open(path).read())
    assert list(data) == [
        "version",
        "seed_hex",
        "agent_id",
        "tenant",
        "endpoint",
        "aid",
    ]
    assert data["version"] == 1 and len(data["seed_hex"]) == 64


def test_created_file_records_the_returned_aid(tmp_path):
    path, aid = create_identity_file(tmp_path / "id.json", **FIELDS)
    data = json.loads(open(path).read())
    assert data["aid"] == aid == Agent(bytes.fromhex(data["seed_hex"])).aid


def test_the_writer_lays_out_the_aid_fixture_byte_for_byte(tmp_path, monkeypatch):
    # The real writer, with the seed pinned: the bytes TS's identityFileBody also reproduces.
    seed = bytes.fromhex(FIXTURE_SEED_HEX)
    monkeypatch.setattr(
        identity_mod.Agent, "generate", classmethod(lambda cls: cls(seed))
    )
    path, aid = create_identity_file(tmp_path / "id.json", **FIXTURE_FIELDS)
    assert aid == FIXTURE_AID
    assert open(path, "rb").read() == AID_FIXTURE.read_bytes()


def test_the_aid_fixture_loads_with_its_recorded_aid():
    loaded = load_identity_file(AID_FIXTURE)
    assert loaded.aid == FIXTURE_AID == json.loads(AID_FIXTURE.read_text())["aid"]
    assert loaded.agent.seed.hex() == FIXTURE_SEED_HEX


def test_a_legacy_file_without_aid_loads_unchanged():
    assert "aid" not in json.loads(LEGACY_FIXTURE.read_text())
    loaded = load_identity_file(LEGACY_FIXTURE)
    assert loaded.aid == FIXTURE_AID
    assert (loaded.agent_id, loaded.tenant, loaded.endpoint) == (
        "ap-clerk",
        "acm\u00e9",
        "seam.example:443",
    )


def _with_aid(aid: object) -> dict:
    return {
        "version": 1,
        "seed_hex": FIXTURE_SEED_HEX,
        "agent_id": "a",
        "tenant": "t",
        "endpoint": "e:1",
        "aid": aid,
    }


@pytest.mark.parametrize(
    "aid, message",
    [
        (Agent(bytes(range(32))).aid, "recorded aid does not match seed_hex"),
        (FIXTURE_AID[:-1], "aid is malformed"),
        (FIXTURE_AID + "A", "aid is malformed"),
        (FIXTURE_AID.replace("ed25519", "ed448"), "aid is malformed"),
        (FIXTURE_AID[:-1] + "=", "aid is malformed"),
        ("", "aid is malformed"),
        (None, "aid is malformed"),
        (42, "aid is malformed"),
        ([FIXTURE_AID], "aid is malformed"),
    ],
    ids=[
        "mismatch",
        "short",
        "long",
        "wrong-alg",
        "non-b64url",
        "empty",
        "null",
        "number",
        "list",
    ],
)
def test_a_bad_recorded_aid_is_refused(tmp_path, aid, message):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(_with_aid(aid)))
    with pytest.raises(IdentityFileError) as e:
        load_identity_file(p)
    assert str(e.value) == message


def test_a_matching_recorded_aid_loads(tmp_path):
    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_with_aid(FIXTURE_AID)))
    assert load_identity_file(p).aid == FIXTURE_AID


@pytest.fixture
def pre_aid_loader(tmp_path):
    """``load_identity_file`` as released before #274 (0.48.1), vendored byte-exact (criterion 4).

    The copy is ``git show f1d112d:python/seam_sdk/identity.py``, pinned by its git blob id so it runs in a
    shallow CI clone and cannot drift. ``.txt`` keeps ruff and pytest off it.
    """
    src = PRE_AID_LOADER.read_bytes()
    blob = hashlib.sha1(b"blob %d\0" % len(src) + src).hexdigest()
    assert blob == PRE_AID_LOADER_BLOB, (
        f"{PRE_AID_LOADER.name} is not the f1d112d loader"
    )
    path = tmp_path / "identity_f1d112d.py"
    path.write_bytes(src)
    # A submodule of the installed package, so its `from .client import Agent` resolves.
    name = "seam_sdk._identity_f1d112d"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(name, None)


def test_a_file_that_records_aid_loads_in_the_pre_aid_release(pre_aid_loader):
    loaded = pre_aid_loader.load_identity_file(AID_FIXTURE)
    assert loaded.agent.aid == json.loads(AID_FIXTURE.read_text())["aid"]
    assert loaded.agent.seed.hex() == FIXTURE_SEED_HEX


@posix_only
def test_mode_is_0600_under_umask_0(tmp_path):
    old = os.umask(0)
    try:
        path, _ = create_identity_file(tmp_path / "id.json", **FIELDS)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600


def test_second_create_refuses_and_leaves_bytes_unchanged(tmp_path):
    path, _ = create_identity_file(tmp_path / "id.json", **FIELDS)
    before = open(path, "rb").read()
    with pytest.raises(IdentityFileError, match="refusing to overwrite"):
        create_identity_file(path, **FIELDS)
    assert open(path, "rb").read() == before


@posix_only
@pytest.mark.parametrize("dangling", [False, True])
def test_symlink_at_the_target_is_refused(tmp_path, dangling):
    target = tmp_path / "elsewhere.json"
    if not dangling:
        target.write_bytes(b"untouched")
    link = tmp_path / "id.json"
    os.symlink(target, link)
    with pytest.raises(IdentityFileError, match="refusing to overwrite"):
        create_identity_file(link, **FIELDS)
    assert os.path.islink(link)
    if dangling:
        assert not target.exists()
    else:
        assert target.read_bytes() == b"untouched"


def test_no_temp_file_is_left_behind(tmp_path):
    path, _ = create_identity_file(tmp_path / "id.json", **FIELDS)
    with pytest.raises(IdentityFileError):
        create_identity_file(path, **FIELDS)
    assert sorted(os.listdir(tmp_path)) == ["id.json"]


@pytest.mark.parametrize("field", ["agent_id", "tenant", "endpoint"])
def test_empty_field_is_refused_before_anything_is_written(tmp_path, field):
    with pytest.raises(IdentityFileError, match=field):
        create_identity_file(tmp_path / "id.json", **{**FIELDS, field: ""})
    assert os.listdir(tmp_path) == []


def test_an_existing_adapters_file_still_loads(tmp_path):
    # The exact shape seam-agent-core's from_bootstrap has always read, extra keys included.
    seed = bytes(range(32))
    p = tmp_path / "partner.json"
    p.write_text(
        json.dumps(
            {
                "version": 1,
                "seed_hex": seed.hex(),
                "agent_id": "qa-confirm",
                "tenant": "t1",
                "endpoint": "localhost:50051",
                "comment": "extra keys are ignored",
            }
        )
    )
    loaded = load_identity_file(str(p))
    assert loaded.agent.seed == seed and loaded.aid == Agent(seed).aid


def test_env_pointer_is_read_when_no_path_is_given(tmp_path, monkeypatch):
    path, aid = create_identity_file(tmp_path / "id.json", **FIELDS)
    monkeypatch.setenv(ENV_POINTER, path)
    assert load_identity_file().aid == aid
    monkeypatch.delenv(ENV_POINTER)
    with pytest.raises(IdentityFileError, match=ENV_POINTER):
        load_identity_file()


@pytest.mark.parametrize(
    "data, match",
    [
        ({"version": 2}, "version"),
        ({"version": 1, "seed_hex": "ab"}, "64 hex"),
        ({"version": 1, "seed_hex": "zz" * 32}, "not valid hex"),
        (
            {"version": 1, "seed_hex": "ab" * 32, "agent_id": "a", "tenant": "t"},
            "endpoint",
        ),
        ([1, 2], "JSON object"),
    ],
)
def test_malformed_files_are_loud(tmp_path, data, match):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(data))
    with pytest.raises(IdentityFileError, match=match):
        load_identity_file(p)


def test_missing_file_is_loud(tmp_path):
    with pytest.raises(IdentityFileError, match="not found"):
        load_identity_file(tmp_path / "nope.json")


# ── seam-sdk#274 (D-FACTS-API, D-LEGACY-AID, D-FACTS-CHECKS): the seed-free facts loader ─────────────

FACT_FIELDS = ("agent_id", "tenant", "endpoint", "aid")
#: The plan's example of a 64-char seed with whitespace. A lone trailing digit, so ``bytes.fromhex``
#: already refused it as "not valid hex" before the shared validator; its message is unchanged.
WS_SEED_PLAN = "00 " * 21 + "0"
#: A 64-char seed with whitespace that ``bytes.fromhex`` accepts (it skips whitespace) as 31 bytes. The
#: pre-#274 loader refused it as "seed_hex must be exactly 64 hex chars…"; the shared validator refuses
#: it earlier as "seed_hex is not valid hex" — the stated message change.
WS_SEED_DECODES = "00" * 31 + "  "


def _facts_of(loaded) -> tuple:
    return tuple(getattr(loaded, f) for f in FACT_FIELDS)


def test_identity_facts_are_exported():
    # Criterion 5.
    assert "load_identity_facts" in seam_sdk.__all__
    assert "IdentityFacts" in seam_sdk.__all__
    assert seam_sdk.load_identity_facts is load_identity_facts
    assert seam_sdk.IdentityFacts is IdentityFacts


def test_identity_facts_carry_no_signing_capability():
    # Criterion 1: exactly the four public fields; nothing that holds or derives a key.
    facts = load_identity_facts(AID_FIXTURE)
    assert isinstance(facts, IdentityFacts)
    assert tuple(f.name for f in dataclasses.fields(IdentityFacts)) == FACT_FIELDS
    for name in (
        "seed",
        "seed_hex",
        "agent",
        "private_key",
        "signing_key",
        "sign",
        "key",
    ):
        assert not hasattr(facts, name), name
    assert not any(isinstance(getattr(facts, f), Agent) for f in FACT_FIELDS)
    assert all(isinstance(getattr(facts, f), str) for f in FACT_FIELDS)
    with pytest.raises(dataclasses.FrozenInstanceError):
        facts.aid = "x"  # type: ignore[misc]


@pytest.mark.parametrize(
    "fixture", [LEGACY_FIXTURE, AID_FIXTURE], ids=["legacy", "aid"]
)
def test_identity_facts_repr_names_only_the_four_fields(fixture):
    rendered = repr(load_identity_facts(fixture))
    assert not re.search(r"[0-9a-fA-F]{64}", rendered), rendered
    assert FIXTURE_SEED_HEX not in rendered
    assert re.fullmatch(
        r"IdentityFacts\(agent_id=.*, tenant=.*, endpoint=.*, aid=.*\)", rendered
    ), rendered


@pytest.mark.parametrize(
    "fixture", [LEGACY_FIXTURE, AID_FIXTURE], ids=["legacy", "aid"]
)
def test_identity_facts_never_construct_an_agent(monkeypatch, fixture):
    # Criterion 1: with Agent unconstructible, the facts loader still succeeds — on a legacy file
    # (transient derivation) and on a file that records aid.
    class _NoAgent:
        def __init__(self, *a, **k):
            raise AssertionError("load_identity_facts constructed an Agent")

    monkeypatch.setattr(identity_mod, "Agent", _NoAgent)
    facts = load_identity_facts(fixture)
    assert facts.aid == FIXTURE_AID
    with pytest.raises(AssertionError, match="constructed an Agent"):
        load_identity_file(fixture)


def test_a_file_that_records_aid_is_served_without_decoding_the_seed(monkeypatch):
    # Criterion 2: on a Phase-3 file the seed is never hex-decoded; the full loader must decode it.
    def _refuse(seed_hex):
        raise AssertionError("seed decoded")

    monkeypatch.setattr(identity_mod, "_decode_seed", _refuse)
    facts = load_identity_facts(AID_FIXTURE)
    assert _facts_of(facts) == (*FIXTURE_FIELDS.values(), FIXTURE_AID)
    with pytest.raises(AssertionError, match="seed decoded"):
        load_identity_file(AID_FIXTURE)
    # A legacy file has no recorded aid, so deriving one necessarily decodes the seed.
    with pytest.raises(AssertionError, match="seed decoded"):
        load_identity_facts(LEGACY_FIXTURE)


def _agreement_files(tmp_path) -> list:
    created, _ = create_identity_file(tmp_path / "created.json", **FIELDS)
    partner = tmp_path / "partner.json"
    partner.write_text(
        json.dumps(
            {
                "version": 1,
                "seed_hex": bytes(range(32)).hex(),
                "agent_id": "qa-confirm",
                "tenant": "t1",
                "endpoint": "localhost:50051",
                "comment": "extra keys are ignored",
            }
        )
    )
    return [LEGACY_FIXTURE, AID_FIXTURE, Path(created), partner]


def test_identity_facts_agree_with_the_full_loader_on_every_field(tmp_path):
    # Criterion 4: legacy, recorded-aid, freshly created and adapters-shaped files.
    for path in _agreement_files(tmp_path):
        assert _facts_of(load_identity_facts(path)) == _facts_of(
            load_identity_file(path)
        ), path
    assert load_identity_facts(LEGACY_FIXTURE).aid == FIXTURE_AID
    assert load_identity_facts(AID_FIXTURE).tenant == "acm\u00e9"


def test_identity_facts_read_the_env_pointer(tmp_path, monkeypatch):
    path, aid = create_identity_file(tmp_path / "id.json", **FIELDS)
    monkeypatch.setenv(ENV_POINTER, path)
    assert load_identity_facts().aid == aid
    monkeypatch.delenv(ENV_POINTER)
    with pytest.raises(IdentityFileError) as facts_err:
        load_identity_facts()
    with pytest.raises(IdentityFileError) as full_err:
        load_identity_file()
    assert str(facts_err.value) == str(full_err.value)
    assert ENV_POINTER in str(facts_err.value)


def test_a_mismatched_recorded_aid_is_a_claim_to_facts_and_a_refusal_to_the_full_loader(
    tmp_path,
):
    other = Agent(bytes(range(32))).aid
    p = tmp_path / "claim.json"
    p.write_text(json.dumps(_with_aid(other)))
    assert load_identity_facts(p).aid == other
    with pytest.raises(IdentityFileError, match="recorded aid does not match seed_hex"):
        load_identity_file(p)


_SEED = "ab" * 32
_REFUSALS = [
    # (id, file body as a JSON value or raw text, exact message or None to check equality only)
    (
        "wrong-version",
        {"version": 2},
        "bootstrap schema version 2 unsupported (want 1)",
    ),
    (
        "no-version",
        {"seed_hex": _SEED},
        "bootstrap schema version None unsupported (want 1)",
    ),
    ("short-seed", {"version": 1, "seed_hex": "ab"}, identity_mod._SEED_LEN_MESSAGE),
    ("absent-seed", {"version": 1}, identity_mod._SEED_LEN_MESSAGE),
    ("number-seed", {"version": 1, "seed_hex": 7}, identity_mod._SEED_LEN_MESSAGE),
    (
        "non-hex-seed",
        {"version": 1, "seed_hex": "zz" * 32},
        "seed_hex is not valid hex",
    ),
    (
        "ws-seed-plan",
        {"version": 1, "seed_hex": WS_SEED_PLAN},
        "seed_hex is not valid hex",
    ),
    (
        "ws-seed-decodes",
        {"version": 1, "seed_hex": WS_SEED_DECODES},
        "seed_hex is not valid hex",
    ),
    (
        "0x-seed",
        {"version": 1, "seed_hex": "0x" + "ab" * 31},
        "seed_hex is not valid hex",
    ),
    (
        "bad-seed-and-missing-fields",
        {"version": 1, "seed_hex": "zz" * 32},
        "seed_hex is not valid hex",
    ),
    (
        "missing-endpoint",
        {"version": 1, "seed_hex": _SEED, "agent_id": "a", "tenant": "t"},
        "bootstrap file missing required field(s): endpoint",
    ),
    (
        "missing-all-fields",
        {"version": 1, "seed_hex": _SEED},
        "bootstrap file missing required field(s): agent_id, tenant, endpoint",
    ),
    ("malformed-aid", _with_aid(FIXTURE_AID[:-1]), "aid is malformed"),
    ("empty-aid", _with_aid(""), "aid is malformed"),
    ("null-aid", _with_aid(None), "aid is malformed"),
    ("number-aid", _with_aid(42), "aid is malformed"),
    ("list", [1, 2], None),
    ("not-json", "{not json", None),
]


@pytest.mark.parametrize(
    "body, message", [r[1:] for r in _REFUSALS], ids=[r[0] for r in _REFUSALS]
)
def test_both_loaders_refuse_a_bad_file_identically(tmp_path, body, message):
    # Criterion 3 (D-FACTS-CHECKS): one validator, so the same refusal with the same message.
    p = tmp_path / "bad.json"
    p.write_text(body if isinstance(body, str) else json.dumps(body))
    with pytest.raises(IdentityFileError) as full_err:
        load_identity_file(p)
    with pytest.raises(IdentityFileError) as facts_err:
        load_identity_facts(p)
    assert str(facts_err.value) == str(full_err.value)
    if message is not None:
        assert str(full_err.value) == message


def test_both_loaders_refuse_a_missing_file_identically(tmp_path):
    p = tmp_path / "nope.json"
    with pytest.raises(IdentityFileError) as full_err:
        load_identity_file(p)
    with pytest.raises(IdentityFileError) as facts_err:
        load_identity_facts(p)
    assert (
        str(facts_err.value) == str(full_err.value) == f"bootstrap file not found: {p}"
    )


def test_a_whitespace_seed_changed_message_and_only_message(tmp_path, pre_aid_loader):
    # The stated change: the pre-#274 loader decoded WS_SEED_DECODES to 31 bytes and refused it on
    # length; the shared validator refuses it on shape. Both are IdentityFileError (a ValueError).
    p = tmp_path / "ws.json"
    p.write_text(json.dumps({"version": 1, "seed_hex": WS_SEED_DECODES, **FIELDS}))
    assert len(WS_SEED_DECODES) == len(WS_SEED_PLAN) == 64
    with pytest.raises(ValueError) as before:
        pre_aid_loader.load_identity_file(p)
    assert str(before.value) == identity_mod._SEED_LEN_MESSAGE
    with pytest.raises(IdentityFileError) as after:
        load_identity_file(p)
    assert str(after.value) == "seed_hex is not valid hex"
