"""P4 session ids and P5 decision ids (`seam_sdk.ids`), checked against the runtime's stated rules."""

from __future__ import annotations

import uuid

import pytest

import seam_sdk
from seam_sdk.ids import (
    DecisionId,
    InvalidDecisionIdError,
    InvalidSessionIdError,
    decision_id_for_session,
    is_valid_session_id,
    parse_decision_id,
    validate_session_id,
)

V4 = "8f14e45f-ceea-467a-9575-6c2b2a1f8d3e"
V7 = "01890a5d-ac96-774b-bcce-b302099a8057"

ACCEPTED = [
    V4,
    V7,
    str(uuid.uuid4()),
    "A" * 22,  # the token floor: 16 random bytes in unpadded base64url
    "abc-DEF_0123456789xyzQ",
    "t" * 128,  # the byte cap, exactly
    # 36 characters, hyphenated, but NOT a UUID ('g' is not hex): it never takes the UUID branch, so
    # the token rule judges it, and it passes.
    "gggggggg-gggg-gggg-gggg-gggggggggggg",
]

REFUSED = [
    V4.upper(),  # parses as a UUID, so judged only as one: not canonical lowercase
    "8f14e45f-ceea-167a-9575-6c2b2a1f8d3e",  # a v1 UUID
    "00000000-0000-0000-0000-000000000000",  # nil
    "A" * 21,  # one short of the token floor
    "t" * 129,  # over the byte cap
    "has space in it-------",
    "colon:inside:the:token:",
    "",
    "é" * 22,  # outside the charset (and 44 bytes)
]


@pytest.mark.parametrize("sid", ACCEPTED)
def test_accepted_session_ids(sid):
    assert validate_session_id(sid) == sid
    assert is_valid_session_id(sid)


@pytest.mark.parametrize("sid", REFUSED)
def test_refused_session_ids(sid):
    assert not is_valid_session_id(sid)
    with pytest.raises(InvalidSessionIdError) as excinfo:
        validate_session_id(sid)
    if sid:
        assert sid not in str(excinfo.value), (
            "the id is not echoed, matching the runtime"
        )


def test_a_non_string_session_id_is_refused_not_raised_as_typeerror():
    assert not is_valid_session_id(None)
    with pytest.raises(InvalidSessionIdError):
        validate_session_id(123)  # type: ignore[arg-type]


def test_decision_id_round_trips():
    did = decision_id_for_session("acme", V4)
    assert did == f"dec:acme:{V4}"
    parsed = parse_decision_id(did)
    assert parsed == DecisionId("acme", V4)
    assert str(parsed) == did


@pytest.mark.parametrize(
    "did",
    [
        "acme:" + V4,  # no prefix
        # no ':' after the prefix, so no tenant half (a UUID's hyphens are not separators)
        "dec:" + V4,
        "dec::" + V4,  # empty tenant
        "dec:ac.me:" + V4,  # tenant charset
        "dec:acme:" + V4.upper(),  # session half judged by P4
        # an extra ':' lands in the session half, where P4 refuses it
        "dec:acme:extra:" + V4,
        "dec:acme:short",
    ],
)
def test_malformed_decision_ids_are_refused(did):
    with pytest.raises(InvalidDecisionIdError):
        parse_decision_id(did)


def test_building_refuses_what_parsing_refuses():
    with pytest.raises(InvalidDecisionIdError):
        decision_id_for_session("acme", "short")
    with pytest.raises(InvalidDecisionIdError):
        decision_id_for_session("a" * 129, V4)


def test_the_helpers_are_exported():
    for name in (
        "DecisionId",
        "InvalidDecisionIdError",
        "InvalidSessionIdError",
        "decision_id_for_session",
        "is_valid_session_id",
        "parse_decision_id",
        "validate_session_id",
    ):
        assert hasattr(seam_sdk, name), name
