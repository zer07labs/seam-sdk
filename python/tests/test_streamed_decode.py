"""Phase 6 — the streamed-event authenticity surface.

Server-free unit tests over `verify_streamed_record_digest` and `KNOWN_KINDS`, driven from the runtime's
`record_digest_v4` KATs (real digests over real columns), plus an env-gated live check that a streamed
SESSION_LIFECYCLE carries its payload and a streamed v4 DECISION_SEALED recomputes.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from governing_root import STREAM_ID
from live_server import spawn_server

from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as evpb
from seam_sdk import KNOWN_KINDS, SeamClient, verify_streamed_record_digest  # noqa: E402
from seam_sdk.crypto import (  # noqa: E402
    RecordDigestStripError,
    UnsupportedRecordDigestVersion,
)
from seam_sdk.admin import SeamAdminClient  # noqa: E402

VECTORS = json.loads(
    (pathlib.Path(__file__).parents[2] / "conformance" / "vectors.json").read_text()
)


def _kat_event(vector: str = "record_digest_v4") -> evpb.SeamEvent:
    """A v4 DECISION_SEALED whose payload + wire digest are a committed record_digest_v4 vector."""
    v = VECTORS[vector]
    i = v["inputs"]
    payload = evpb.DecisionSealed(
        decision_id=i["decision_id"],
        tenant=i["tenant"],
        namespace=i["namespace"],
        outcome=i["outcome"],
        sealed_at=i["sealed_at"],
        schema_version=i["schema_version"],
        ciphertext_digest=bytes.fromhex(i["ciphertext_digest_hex"]),
        context_digest=bytes.fromhex(i["context_digest_hex"]),
        participation_digest=bytes.fromhex(i["participation_digest_hex"]),
        classification=i["classification"],
        participants_digest=bytes.fromhex(i["participants_digest_hex"]),
        trust_basis_commitment=i["trust_basis_commitment"],
        auth_method=i["auth_method"],
    )
    if i["mode"] is not None:
        payload.mode = i["mode"]
    if i["policy_version"] is not None:
        payload.policy_version = i["policy_version"]
    if i["supersedes"] is not None:
        payload.supersedes = i["supersedes"]
    if i["policy_rules_digest_hex"] is not None:
        payload.policy_rules_digest = bytes.fromhex(i["policy_rules_digest_hex"])
    return evpb.SeamEvent(
        kind="DECISION_SEALED",
        payload=payload,
        digest=bytes.fromhex(v["digest_hex"]),
    )


def test_known_kinds_includes_the_a14_kinds():
    assert "SESSION_LIFECYCLE" in KNOWN_KINDS
    assert "CHAIN_HEAD_ATTESTATION" in KNOWN_KINDS
    assert (
        "AUTHORIZE_EVALUATED" in KNOWN_KINDS
    )  # tag 23: one row per advisory Authorize evaluation
    assert (
        "POLICY_DENIED" in KNOWN_KINDS
    )  # tag 24: one row per commitment a bound policy refused
    assert len(KNOWN_KINDS) == 10


def test_streamed_record_digest_matches_for_a_genuine_event():
    assert verify_streamed_record_digest(_kat_event()) is True


def test_streamed_record_digest_catches_a_payload_rewrite():
    ev = _kat_event()
    ev.payload.outcome = "Expired"  # rewrite a structural column, keep the wire digest
    assert verify_streamed_record_digest(ev) is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("context_digest", b"\x00" * 32),
        ("participation_digest", b"\x00" * 32),
        ("classification", "Public"),
        ("participants_digest", b"\x00" * 32),
        ("trust_basis_commitment", "rewritten"),
        ("auth_method", "rewritten"),
    ],
)
def test_streamed_record_digest_binds_every_mandatory_field(field, value):
    """Each of tags 11, 12 and 14-17 is in the digest: rewriting one (validly shaped) is a False."""
    ev = _kat_event()
    assert getattr(ev.payload, field) != value
    setattr(ev.payload, field, value)
    assert verify_streamed_record_digest(ev) is False, field


@pytest.mark.parametrize("version", [1, 2, 3, 5])
def test_any_other_schema_version_is_cannot_verify(version):
    """v1-v3 are retired (P7), and v5 is unknown. Either is CANNOT-VERIFY, raised as
    `UnsupportedRecordDigestVersion`, never a False: recomputing a v3 record under the v4 tag would
    fabricate a tamper verdict on a genuine record, and a retained v3 formula no longer exists."""
    ev = _kat_event()
    ev.payload.schema_version = version
    with pytest.raises(UnsupportedRecordDigestVersion):
        verify_streamed_record_digest(ev)


def test_a_non_sealed_event_is_refused():
    with pytest.raises(ValueError):
        verify_streamed_record_digest(evpb.SeamEvent(kind="SESSION_LIFECYCLE"))


MANDATORY = [
    ("context_digest", 11),
    ("participation_digest", 12),
    ("classification", 14),
    ("participants_digest", 15),
    ("trust_basis_commitment", 16),
    ("auth_method", 17),
]

#: The wire key of an explicit zero-length occurrence of each tag (field number << 3 | 2, varint).
_EMPTY_ON_THE_WIRE = {
    "context_digest": b"\x5a\x00",
    "participation_digest": b"\x62\x00",
    "policy_rules_digest": b"\x6a\x00",
    "classification": b"\x72\x00",
    "participants_digest": b"\x7a\x00",
    "trust_basis_commitment": b"\x82\x01\x00",
    "auth_method": b"\x8a\x01\x00",
}


def _splice_empty(ev: evpb.SeamEvent, field: str) -> evpb.SeamEvent:
    # proto3 is last-wins, so appending an explicit empty occurrence overwrites the genuine value
    # on decode. The payload is a nested message, so splice into the payload's own bytes.
    raw = ev.payload.SerializeToString() + _EMPTY_ON_THE_WIRE[field]
    tampered = evpb.SeamEvent()
    tampered.CopyFrom(ev)
    tampered.payload.CopyFrom(evpb.DecisionSealed.FromString(raw))
    assert len(getattr(tampered.payload, field)) == 0  # the splice landed
    return tampered


@pytest.mark.parametrize("field,tag", MANDATORY)
def test_a_stripped_mandatory_field_raises_a_strip(field, tag):
    """Absent tag 11, 12 or 14-17 is a strip attack. It must RAISE — distinctly from the False a
    mismatch returns — so an operator can tell "someone removed a field" from "someone rewrote one"."""
    ev = _kat_event()
    ev.payload.ClearField(field)
    with pytest.raises(RecordDigestStripError) as excinfo:
        verify_streamed_record_digest(ev)
    assert excinfo.value.field == field
    assert excinfo.value.wire_tag == tag


@pytest.mark.parametrize("field,tag", MANDATORY)
def test_an_explicitly_encoded_empty_mandatory_field_is_the_same_strip(field, tag):
    """`len == 0` is absence however the bytes arose. proto3 obliges a decoder to ACCEPT an explicitly
    encoded zero-length field, so a hostile producer can put one on the wire even though a conforming
    one never will — it must land on the same refusal as an omitted field, not slip past it."""
    with pytest.raises(RecordDigestStripError) as excinfo:
        verify_streamed_record_digest(_splice_empty(_kat_event(), field))
    assert excinfo.value.wire_tag == tag


@pytest.mark.parametrize(
    "field", ["context_digest", "participation_digest", "participants_digest"]
)
def test_a_wrong_length_mandatory_digest_is_refused(field):
    """A present-but-31-byte digest is malformed, not a mismatch. Framing it would produce a
    well-formed digest over a value no sealer ever wrote."""
    ev = _kat_event()
    setattr(ev.payload, field, bytes(getattr(ev.payload, field))[:31])
    with pytest.raises(RecordDigestStripError):
        verify_streamed_record_digest(ev)


def test_no_policy_rules_digest_verifies_green():
    """Absent tag 13 is LEGITIMATE — no policy bound — and frames as opt(None). Passing the decoded
    empty bytes straight through would frame opt(Some(b"")) and report a mismatch on a genuine record."""
    assert (
        verify_streamed_record_digest(_kat_event("record_digest_v4_absent_policy"))
        is True
    )


def test_an_explicitly_encoded_empty_policy_rules_digest_verifies_green():
    """The tag-13 counterpart of the strip splice above: `0x6a 0x00` must verify GREEN as opt(None),
    identical to omission, rather than framing opt(Some(b""))."""
    ev = _splice_empty(
        _kat_event("record_digest_v4_absent_policy"), "policy_rules_digest"
    )
    assert verify_streamed_record_digest(ev) is True


def test_absent_and_present_policy_rules_are_different_digests():
    """The guard on the guard: the two vectors must not coincidentally share a digest, or the test
    above would pass under a formula that ignores tag 13 entirely."""
    assert (
        VECTORS["record_digest_v4"]["digest_hex"]
        != VECTORS["record_digest_v4_absent_policy"]["digest_hex"]
    )


def test_a_stripped_ciphertext_digest_is_false_not_a_raise():
    """Tag 10 keeps its older shape. The spec makes a tag-10 strip a REFUSE — a failing verdict, which
    for a boolean helper is False — but attaches the distinct-reporting requirement only to tags 11,
    12 and 14-17. So this must NOT become a strip raise."""
    ev = _kat_event()
    ev.payload.ClearField("ciphertext_digest")
    assert verify_streamed_record_digest(ev) is False


# ── Live: a streamed SESSION_LIFECYCLE carries its payload; a streamed v4 DECISION_SEALED recomputes ──


@pytest.fixture
def dual_plane(tmp_path):
    """Data + management planes on OS-allocated ports (was a fixed 8113/8114 pair before #85)."""
    with spawn_server(mgmt=True, log_dir=tmp_path) as srv:
        yield srv.data_addr, srv.mgmt_addr


def test_streamed_events_carry_a14_payloads_live(dual_plane):
    from seam_sdk import Agent

    data_addr, mgmt_addr = dual_plane
    data = SeamClient.connect(data_addr)
    from operator_token import mint_operator_token

    admin = SeamAdminClient.connect(
        mgmt_addr, token=mint_operator_token(["audit:read"])
    )
    agent = Agent(bytes([42] * 32))

    # An interactive open emits SESSION_LIFECYCLE (CP-09); a one-shot decision seals a v4 DECISION_SEALED.
    data.open_session(agent, "p6-live-sid-0123456789abcdef", ["lead", "peer"])
    dec = data.run_decision(
        agent,
        "p6-sid-0123456789abcdef",
        ["fraud-v3", "risk-v2"],
        [("fraud-v3", "BLOCK"), ("risk-v2", "BLOCK")],
    )
    assert dec.outcome == "Resolved"

    lifecycle = None
    sealed = None
    kinds_seen = set()
    for ev in admin.stream_events(stream_id=STREAM_ID, follow=False, ack=False):
        kinds_seen.add(
            ev.kind
        )  # every kind decodes; an unknown one would still iterate, never error
        if ev.kind == "SESSION_LIFECYCLE":
            lifecycle = ev
        elif ev.kind == "DECISION_SEALED" and ev.payload.decision_id == dec.decision_id:
            sealed = ev

    # Every kind seen is one the SDK knows (no opaque surprises in this stream), and the tolerant loop above
    # never errored on any of them.
    assert kinds_seen <= KNOWN_KINDS, f"unexpected kinds: {kinds_seen - KNOWN_KINDS}"

    # CP-09: the SESSION_LIFECYCLE payload (tag 21) is exposed, not kind-only.
    assert lifecycle is not None, "the interactive open must emit a SESSION_LIFECYCLE"
    assert lifecycle.session_lifecycle.phase == "opened"
    assert lifecycle.session_lifecycle.opened_at_millis > 0

    # §A14: the DECISION_SEALED payload carries ciphertext_digest (tag 10), and it recomputes.
    assert sealed is not None, "the sealed decision must appear on the stream"
    # The protocol pass (P7) retired v1-v3: the runtime seals v4 and nothing else, and this SDK
    # recomputes v4 and nothing else. Against a runtime that predates the pass this assertion is the
    # one that goes red, by design: a v3 record is cannot-verify here, not a guess.
    assert sealed.payload.schema_version == 4, (
        f"record schema_version {sealed.payload.schema_version}; this SDK recomputes only v4"
    )
    assert len(sealed.payload.ciphertext_digest) == 32
    assert verify_streamed_record_digest(sealed) is True
