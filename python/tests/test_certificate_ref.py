"""cert-ref (runtime 0.91.0): ``DecisionSealed.certificate`` (tag 19) and its closed int32 provenance."""

from __future__ import annotations

import pytest

from seam_sdk import (
    CERTIFICATE_PROVENANCE_AGENT_ASSERTED,
    CERTIFICATE_PROVENANCE_UNSPECIFIED,
    WIRE_FEATURE_CERT_REF,
    CertificateRef,
    certificate_provenance,
    certificate_ref_of,
)
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev

ID = "sha256:" + "ab" * 32


def test_an_absent_certificate_reads_as_none():
    assert certificate_ref_of(ev.DecisionSealed()) is None


def test_an_agent_asserted_certificate_round_trips_through_the_wire():
    ds = ev.DecisionSealed(certificate=ev.CertificateRef(id=ID, provenance=1))
    back = ev.DecisionSealed.FromString(ds.SerializeToString())
    assert certificate_ref_of(back) == CertificateRef(
        ID, CERTIFICATE_PROVENANCE_AGENT_ASSERTED
    )


@pytest.mark.parametrize("p", [0, 2, 7, -1, 2**31 - 1])
def test_an_unknown_or_unset_provenance_is_the_least_trusted_reading(p):
    ds = ev.DecisionSealed(certificate=ev.CertificateRef(id=ID, provenance=p))
    assert certificate_ref_of(ds).provenance == CERTIFICATE_PROVENANCE_UNSPECIFIED


@pytest.mark.parametrize("v", [True, 1.0, "1", None])
def test_a_non_int_provenance_reads_as_unspecified(v):
    assert certificate_provenance(v) == CERTIFICATE_PROVENANCE_UNSPECIFIED


def test_the_wire_feature_name_is_the_specs():
    assert WIRE_FEATURE_CERT_REF == "feature_flag.cert_ref"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "sha256:" + "AB" * 32,
        "sha256:" + "ab" * 31,
        "decision-cert:sha256:" + "ab" * 32,
        ID + "\n",
    ],
)
def test_a_malformed_id_reads_exactly_as_absent(bad):
    ds = ev.DecisionSealed(certificate=ev.CertificateRef(id=bad, provenance=1))
    assert certificate_ref_of(ds) is None
