"""`context_digest_v4` — the `seam.audit.context-provenance.v4` sub-digest (wire tag 11).

The four digests below are the runtime's own pins, not numbers this SDK produced:

* `ONE_CONTEXT` and the empty roster are in `seam-event.v1.md`'s vector table (and reproduced by
  seam-runtime `scripts/v4-digest-reference.py` @ 1ac5de5, a stdlib-only reference that shares no
  code with the Rust);
* `V4_RECEIPT_CONTEXT` is the all-five-slots binding that pins the `.v4` receipt slot (`rcpt-005/B`);
* `D3_POPULATED_CONTEXT` is a remote binding with no receipt — the pairing rule's absent half.

The TypeScript twin (`ts/test/context-digest-v4.test.ts`) asserts the same four, so the two languages
cannot drift apart without one of them going red.
"""

from __future__ import annotations

import pytest

from seam_sdk import RECEIPT_KEY_STATUSES, ContextProvenanceError, context_digest_v4
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

EMPTY_CONTEXT = "f1e62208be1f1dfef0dc474cc655cedc546bcfcd4d4ea25bd7bc98188f6aab8f"
ONE_CONTEXT = "8e87a93fd65b0d756817d2dbe3d9346542a2ad8272cc525f2df23d4b73802f85"
V4_RECEIPT_CONTEXT = "3475464e934ac07ea03e6afbcda58f05446517c7df876b11e1a3260db035bf15"
D3_POPULATED_CONTEXT = (
    "2e8e7cdb4739248e9781080f65acf8108c5359dc8f4ed3373ad61239cadb2f98"
)

ONE = {
    "ctx_ref": "sha256:aa",
    "fidelity": "Digest",
    "classification": "Internal",
    "lineage_id": None,
    "version": 1,
    "derived_from": ["x", "y"],
}
RECEIPT = {
    "ctx_ref": "acdp://reg.example.com/ctx-1",
    "fidelity": "Reference",
    "classification": "Confidential",
    "lineage_id": None,
    "version": 2,
    "derived_from": [],
    "content_hash": "sha256:aa",
    "receipt_hash": "sha256:bb",
    "key_status": "CurrentlyAuthorized",
    "resolved_status": "active",
    "receipt_key_status": "Historical",
}
RETRACTED = {
    "ctx_ref": "acdp://reg.example.com/ctx-1",
    "fidelity": "Digest",
    "classification": "Internal",
    "lineage_id": None,
    "version": 1,
    "derived_from": [],
    "content_hash": "sha256:aa",
    "receipt_hash": None,
    "key_status": "CurrentlyAuthorized",
    "resolved_status": "retracted",
}


@pytest.mark.parametrize(
    ("bindings", "want"),
    [
        ([], EMPTY_CONTEXT),
        ([ONE], ONE_CONTEXT),
        ([RECEIPT], V4_RECEIPT_CONTEXT),
        ([RETRACTED], D3_POPULATED_CONTEXT),
    ],
    ids=["empty", "one-local", "v4-receipt", "d3-populated"],
)
def test_matches_the_runtime_pins(bindings, want):
    assert context_digest_v4(bindings).hex() == want


def _pb(d: dict) -> pb.ContextBinding:
    return pb.ContextBinding(**{k: v for k, v in d.items() if v is not None})


@pytest.mark.parametrize(
    "d", [ONE, RECEIPT, RETRACTED], ids=["one", "receipt", "retracted"]
)
def test_a_generated_binding_digests_like_its_dict(d):
    # An unset `optional` field must read as absent (0x00), not as the proto default "" (present).
    assert context_digest_v4([_pb(d)]) == context_digest_v4([d])


def test_the_resolved_binding_carries_receipt_key_status():
    b = _pb(RECEIPT)
    assert b.HasField("receipt_key_status") and b.receipt_key_status == "Historical"
    assert not _pb(ONE).HasField("receipt_key_status")


def test_the_receipt_slot_is_bound():
    current = dict(RECEIPT, receipt_key_status="Current")
    assert context_digest_v4([current]) != context_digest_v4([RECEIPT])


def test_stored_order_is_hashed_never_sorted():
    assert context_digest_v4([ONE, RECEIPT]) != context_digest_v4([RECEIPT, ONE])


@pytest.mark.parametrize(
    "bad",
    [
        dict(RECEIPT, receipt_key_status=None),  # receipt_hash alone
        dict(RETRACTED, receipt_key_status="Current"),  # receipt_key_status alone
    ],
    ids=["receipt-hash-alone", "key-status-alone"],
)
def test_unpaired_slots_are_refused_before_hashing(bad):
    with pytest.raises(ContextProvenanceError) as e:
        context_digest_v4([ONE, bad])
    assert e.value.index == 1 and e.value.field == "receipt_key_status"


@pytest.mark.parametrize("value", ["historical", "CURRENT", "Revoked", ""])
def test_out_of_vocabulary_receipt_key_status_is_refused(value):
    with pytest.raises(ContextProvenanceError):
        context_digest_v4([dict(RECEIPT, receipt_key_status=value)])


def test_the_vocabulary_is_closed_and_pascal_case():
    assert RECEIPT_KEY_STATUSES == ("Current", "Historical")


def test_refusal_is_a_value_error_and_a_wrong_type_is_a_type_error():
    assert issubclass(ContextProvenanceError, ValueError)
    with pytest.raises(TypeError):
        context_digest_v4([dict(ONE, version="1")])
    with pytest.raises(TypeError):
        context_digest_v4(ONE)
