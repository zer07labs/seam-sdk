"""The vendored vector's `golden` group says what the vendored spec's Golden vector table says (seam-sdk#290).

All five SDKs' KATs read conformance/mgmt_dpop_vector.json, and CI's spec-pin job keeps
docs/specs/mgmt-dpop.md byte-equal to the runtime's. Nothing else tied the two together, so a re-vendored spec
with a changed vector would have left every KAT green against the stale JSON. This test is that tie.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = (ROOT / "docs" / "specs" / "mgmt-dpop.md").read_text()
GOLDEN = json.loads((ROOT / "conformance" / "mgmt_dpop_vector.json").read_text())[
    "golden"
]


def _golden_section() -> str:
    start = SPEC.index("\n## Golden vector\n")
    end = SPEC.find("\n## ", start + 1)
    return SPEC[start : end if end >= 0 else len(SPEC)]


def _table_rows(section: str) -> dict[str, str]:
    rows = {}
    for label, value in re.findall(r"^\| (.+?) \| `([^`]+)` \|$", section, flags=re.M):
        rows[label.strip("`")] = value
    return rows


def test_every_golden_input_and_output_matches_the_spec_table() -> None:
    rows = _table_rows(_golden_section())
    expected = {
        "htm": GOLDEN["htm"],
        "htu": GOLDEN["htu"],
        "token": GOLDEN["token"],
        "message bytes": " ".join(
            GOLDEN["message_hex"][i : i + 2]
            for i in range(0, len(GOLDEN["message_hex"]), 2)
        ),
        "iat": str(GOLDEN["iat"]),
        "jti": GOLDEN["jti"],
        "jkt": GOLDEN["jkt"],
        "x": GOLDEN["x"],
        "ath": GOLDEN["ath"],
        "seam_bd": GOLDEN["seam_bd"],
    }
    assert {k: rows.get(k) for k in expected} == expected


def test_the_seed_row_is_32_bytes_of_0x42() -> None:
    section = _golden_section()
    assert "| key seed | 32 × `0x42` |" in section
    assert GOLDEN["seed_hex"] == "42" * 32


def test_the_proof_matches_the_spec_block() -> None:
    block = re.search(r"```\n(eyJ[^`]+?)\n```", _golden_section())
    assert block, "the spec's Golden vector section has no proof block"
    assert "".join(block.group(1).split()) == GOLDEN["proof"]
