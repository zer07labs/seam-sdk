#!/usr/bin/env python3
"""Emit the `record_digest_v3` block of `conformance/vectors.json` by EXECUTING the implementation.

WHY THIS EXISTS RATHER THAN A HAND-WRITTEN BLOCK
-------------------------------------------------
A conformance vector is a claim about what four independent implementations must agree on. If a
human types the `digest_hex`, the vector records what someone *believed* the formula produces, and
every implementation that later matches it is agreeing with a typo-shaped fact. This repo's standing
rule is therefore: **inputs are chosen by hand, outputs are never transcribed by hand.**

So the inputs below are a deliberate design (each case exists to pin a specific trap the spec names),
and every `digest_hex` is produced by calling `record_digest_v3` here and now. A pytest re-runs this
in `--check` mode and byte-compares, which is what turns "we don't hand-edit vectors" from a habit
into something CI enforces.

WHY IT LOADS `crypto.py` AS A SINGLE FILE
------------------------------------------
Not for convenience — to stay honest about the contract. seam-runtime's `sdk-digest-parity` gate
loads `python/seam_sdk/crypto.py` exactly this way (`spec_from_file_location`, no package install, no
`BUF_TOKEN`, no generated `_gen/` tree) and calls `record_digest_v*` by exact name. Emitting the
vectors through the same door means this script fails the moment that cross-repo assumption breaks,
in this repo, rather than in their CI. `python/tests/test_errors_is_import_light.py` guards the same
property from the other side.

THE RENDERING IS PART OF THE CONTRACT, AND ONE CHOICE IN IT COSTS THE RUNTIME SOMETHING
----------------------------------------------------------------------------------------
The gate byte-diffs the WHOLE file against the runtime's own emitter, so how this renders matters as
much as what it computes: `json.dumps(..., indent=2)`, `ensure_ascii=True`, a trailing newline,
lowercase hex, `null` for an absent optional. That round-trips the pre-existing file byte-identically
(verified in `--check`, not assumed), so the untouched blocks stay untouched.

`ensure_ascii=True` is a real decision with a real cost, stated here rather than left to be
discovered. It is **not** inherited from the existing file: that file contains no non-ASCII at all —
its one escape, `\u0000`, is a control character every JSON writer emits, serde_json included. This
block is what first introduces the question, because `non_ascii_nfd` carries combining marks and CJK.
Both settings round-trip the old bytes; they differ only on the new case.

Escaping was chosen anyway, and the reason is that this artifact's BYTES are the contract. ASCII-only
bytes survive editors, terminals, transfer encodings and well-meaning normalization passes unchanged;
a raw combining acute does not, and a tool that silently NFC-normalized this file would corrupt the
one case whose entire job is to detect normalization. The cost lands on the runtime: serde_json has
no `ensure_ascii` equivalent, so their emitter needs a custom `Formatter` to reproduce `\u0301`,
`\u65e5` and friends. That is a genuine ask, it is theirs to weigh, and Phase 5 puts it in front of
them explicitly rather than letting them meet it as a red gate.

Usage:
    scripts/emit_record_digest_v3_vectors.py            # rewrite conformance/vectors.json
    scripts/emit_record_digest_v3_vectors.py --check    # exit 1 if the committed block has drifted
Exit: 0 = in sync (or written) · 1 = drift · 2 = infrastructure problem
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
CRYPTO = REPO / "python" / "seam_sdk" / "crypto.py"
VECTORS = REPO / "conformance" / "vectors.json"
BLOCK = "record_digest_v3"

#: Fixed inputs shared by every case. Chosen, not computed — the point of a vector is that its
#: inputs are stable and its output is derived.
CIPHERTEXT = bytes.fromhex("636f6e666f726d616e63652d76332d63697068657274657874")
CONTEXT_LABEL = b"seam-conformance-context-v3"
PARTICIPATION_LABEL = b"seam-conformance-participation-v3"
POLICY_RULES_LABEL = b"seam-conformance-policy-rules-v3"

#: A combining-acute "café" (NFD). Its NFC form is a different byte string that normalizes to the
#: same text — which is the whole point: the spec requires raw UTF-8 with NO normalization, and a
#: purely-ASCII vector set cannot tell a conforming implementation from a normalizing one.
NFD_TEXT = "café-日本"


def _load_crypto():
    """Load `crypto.py` as a single file, the way seam-runtime's parity gate does."""
    spec = importlib.util.spec_from_file_location("seam_crypto_standalone", CRYPTO)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CRYPTO}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if "seam_sdk" in sys.modules:
        raise RuntimeError(
            "loading crypto.py pulled in the seam_sdk package. seam-runtime's digest-parity gate "
            "loads this file with no package present, so that is a cross-repo break, not a detail."
        )
    return module


def build_cases(crypto: Any) -> list[dict]:
    """The five cases, each pinning something the spec singles out as easy to get wrong.

    The `why` strings below stay HERE and are deliberately not emitted into the JSON. They were, in
    the first draft. But every byte of that file is a cross-repo contract — seam-runtime's gate
    byte-diffs the whole thing against their own emitter — and shipping five paragraphs of English
    into it means their Rust must carry the same prose character-for-character, em-dashes included,
    and any wording tweak on either side reddens the gate. The prose has no machine consumer; it
    belongs where the person changing a case will read it, which is here.
    """
    ciphertext_digest = hashlib.sha256(CIPHERTEXT).digest()
    context = hashlib.sha256(CONTEXT_LABEL).digest()
    participation = hashlib.sha256(PARTICIPATION_LABEL).digest()
    policy_rules = hashlib.sha256(POLICY_RULES_LABEL).digest()

    # context != participation is load-bearing, not incidental: slots 10 and 11 are adjacent and
    # offset by one from their wire tags, so equal values would make a swap undetectable.
    assert context != participation

    # The NFD case earns its keep only while it is actually NFD. This literal is one editor
    # "normalize on save" away from becoming NFC — at which point every test still passes (NFC é is
    # still non-ASCII) while the case silently stops being able to catch a normalizing
    # implementation. Refuse to emit rather than emit something that no longer tests what it says.
    if unicodedata.normalize("NFC", NFD_TEXT) == NFD_TEXT:
        raise RuntimeError(
            "NFD_TEXT is in NFC form, so the `non_ascii_nfd` vector no longer distinguishes a "
            "conforming implementation from a normalizing one — which is its entire purpose. "
            "Something normalized the source literal; restore the combining form (e + U+0301)."
        )

    common = dict(
        decision_id="dec:conformance-v3",
        tenant="acme",
        namespace="fraud",
        sealed_at=1700000000000,
        outcome="Resolved",
        schema_version=3,
    )

    cases = [
        (
            "all_optionals_present",
            "Every `opt` slot present, including tag 13. Exercises the present branch of each.",
            dict(
                common,
                mode="decision.v1",
                policy_version="policy-7",
                supersedes="dec:prior",
                policy_rules_digest=policy_rules,
            ),
        ),
        (
            "policy_rules_absent",
            "Tag 13 absent — no policy was bound, today's common case. Pins the deliberate "
            "asymmetry: slots 10 and 11 stay FRAMED even when slot 12 is a single 0x00.",
            dict(
                common,
                mode="decision.v1",
                policy_version="policy-7",
                supersedes=None,
                policy_rules_digest=None,
            ),
        ),
        (
            "optionals_none",
            "All four optionals absent — four 0x00 presence bytes.",
            dict(
                common,
                mode=None,
                policy_version=None,
                supersedes=None,
                policy_rules_digest=None,
            ),
        ),
        (
            "mode_empty_string",
            "Identical to optionals_none except `mode` is present and empty. opt(None) is one "
            "byte, opt(Some('')) is five — a present-but-empty string is data. Every consumer must "
            "assert this case's digest differs from optionals_none's.",
            dict(
                common,
                mode="",
                policy_version=None,
                supersedes=None,
                policy_rules_digest=None,
            ),
        ),
        (
            "non_ascii_nfd",
            "Strings hash as raw UTF-8 with NO normalization — the spec calls this out because it "
            "is a step three of four implementations would do differently or skip. `decision_id` "
            "and `mode` carry a combining acute (NFD) plus CJK: an implementation that normalizes, "
            "or encodes as UTF-16 or ASCII, cannot reproduce this case and reproduces every other "
            "one. It is the only case that is not pure ASCII, and that is its whole job.",
            dict(
                common,
                decision_id=f"dec:{NFD_TEXT}",
                mode=NFD_TEXT,
                policy_version=None,
                supersedes=None,
                policy_rules_digest=policy_rules,
            ),
        ),
    ]

    out = []
    for name, why, kw in cases:
        digest = crypto.record_digest_v3(
            decision_id=kw["decision_id"],
            tenant=kw["tenant"],
            namespace=kw["namespace"],
            ciphertext_digest=ciphertext_digest,
            sealed_at=kw["sealed_at"],
            outcome=kw["outcome"],
            mode=kw["mode"],
            policy_version=kw["policy_version"],
            supersedes=kw["supersedes"],
            context_digest=context,
            participation_digest=participation,
            policy_rules_digest=kw["policy_rules_digest"],
            schema_version=kw["schema_version"],
        )
        rules = kw["policy_rules_digest"]
        out.append(
            {
                "name": name,
                "inputs": {
                    "domain": "seam.audit.record-digest.v3",
                    "decision_id": kw["decision_id"],
                    "tenant": kw["tenant"],
                    "namespace": kw["namespace"],
                    "ciphertext_hex": CIPHERTEXT.hex(),
                    "ciphertext_digest_hex": ciphertext_digest.hex(),
                    "sealed_at": kw["sealed_at"],
                    "outcome": kw["outcome"],
                    "mode": kw["mode"],
                    "policy_version": kw["policy_version"],
                    "supersedes": kw["supersedes"],
                    "context_digest_hex": context.hex(),
                    "participation_digest_hex": participation.hex(),
                    "policy_rules_digest_hex": None if rules is None else rules.hex(),
                    "schema_version": kw["schema_version"],
                },
                "digest_hex": digest.hex(),
            }
        )
    return out


def render(document: dict) -> str:
    """The one rendering, used for both writing and checking. `ensure_ascii` stays at its default:
    the existing file escapes non-ASCII as `\\uXXXX`, and the gate byte-diffs the whole file."""
    return json.dumps(document, indent=2) + "\n"


def build_document() -> dict:
    crypto = _load_crypto()
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    document[BLOCK] = {"cases": build_cases(crypto)}
    return document


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the committed file differs from what this emits",
    )
    args = ap.parse_args()

    if not VECTORS.exists() or not CRYPTO.exists():
        print(f"::error::missing {VECTORS} or {CRYPTO}", file=sys.stderr)
        return 2

    try:
        current = VECTORS.read_text(encoding="utf-8")
        emitted = render(build_document())
    except Exception as exc:  # noqa: BLE001 — the type is not the point, the exit code is
        # NB: every internal refusal above raises an ordinary Exception, never SystemExit.
        # SystemExit derives from BaseException, so it would sail past this handler and exit 1 —
        # reporting an infrastructure condition as drift, which is what this handler prevents.
        # Exit 2, never 1. A malformed vectors.json, an import error in crypto.py, or a renamed
        # `record_digest_v3` are all INFRASTRUCTURE: we could not establish an answer. Exiting 1
        # would report them as "the committed block has drifted", which is a confident wrong
        # diagnosis — the same never-report-infra-as-a-verdict rule
        # `scripts/probe_framework_coinstall.py` is built around.
        print(
            f"::error::could not emit the {BLOCK} block at all: {type(exc).__name__}: {exc}\n"
            f"::error::Treating as INFRASTRUCTURE, not as drift. Nothing was written.",
            file=sys.stderr,
        )
        return 2

    if args.check:
        if emitted == current:
            print(
                f"{VECTORS.name}: {BLOCK} is byte-identical to what the implementation emits"
            )
            return 0
        print(
            f"::error::{VECTORS.name} has drifted from what `record_digest_v3` actually produces.\n"
            f"::error::Either a digest was edited by hand (never do this — the whole point of the\n"
            f"::error::vector is that its output is derived), or the formula changed and the block\n"
            f"::error::was not regenerated. Run: python3 scripts/{Path(__file__).name}",
            file=sys.stderr,
        )
        return 1

    VECTORS.write_text(emitted, encoding="utf-8")
    print(f"wrote {VECTORS.relative_to(REPO)} ({len(emitted)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
