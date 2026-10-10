"""seam-sdk#201: Agent.generate() and the schema-v1 bootstrap file (create/load)."""

from __future__ import annotations

import json
import os
import stat

import pytest

from seam_sdk import (
    Agent,
    IdentityFileError,
    create_identity_file,
    load_identity_file,
)
from seam_sdk.identity import ENV_POINTER

posix_only = pytest.mark.skipif(
    os.name != "posix", reason="POSIX file modes and symlinks"
)

FIELDS = dict(agent_id="ap-clerk", tenant="acme", endpoint="seam.example:443")


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
    assert list(data) == ["version", "seed_hex", "agent_id", "tenant", "endpoint"]
    assert data["version"] == 1 and len(data["seed_hex"]) == 64


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
