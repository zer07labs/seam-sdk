#!/usr/bin/env python3
"""Emit `conformance/record_digest_v3_extended.json` by EXECUTING the implementation.

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

WHY THIS IS A SEPARATE FILE FROM `conformance/vectors.json`
------------------------------------------------------------
`conformance/vectors.json` is a CROSS-REPO artifact with a byte-identity contract: seam-runtime's
`sdk-digest-parity` gate runs `diff -u` between that file and what its own emitter produces, so the
two repos must agree on every byte, not merely on every digest. seam-runtime landed the v3 blocks
first (`record_digest_v3` and `record_digest_v3_absent_policy`, one `{inputs, digest_hex}` each,
matching the shape every other block in that file already uses), and this repo takes those bytes
verbatim.

That shape carries two cases. The set below carries five, because a single fixture per block cannot
express `mode: ""` vs `mode: null`, and cannot carry decomposed non-ASCII text. Those are exactly
the traps the spec singles out, so they are kept here rather than dropped — the SDK's own
conformance tests in all three languages load this file alongside `vectors.json` and reproduce both
sets. Merging them into `vectors.json` is proposed upstream (see `verify/DECISIONS.md`); until
seam-runtime's emitter can produce these bytes too, adding them here would turn their gate red for
a reason that is not drift.

THE RENDERING, AND THE `ensure_ascii` COST THIS FILE WOULD PUT ON THE RUNTIME
------------------------------------------------------------------------------
Rendering is pinned the same way `vectors.json` pins it — `json.dumps(..., indent=2)`,
`ensure_ascii=True`, a trailing newline, lowercase hex, `null` for an absent optional — so that
adopting this set upstream is a copy, not a re-render.

`ensure_ascii=True` is a real decision with a real cost, stated here rather than left to be
discovered. `vectors.json` does not settle it: that file contains no non-ASCII at all. The
`non_ascii_nfd` case below is what first introduces the question, because it carries combining marks
and CJK.

Escaping was chosen because this artifact's BYTES are the contract. ASCII-only bytes survive editors,
terminals, transfer encodings and well-meaning normalization passes unchanged; a raw combining acute
does not, and a tool that silently NFC-normalized this file would corrupt the one case whose entire
job is to detect normalization. The cost lands on whoever adopts it: serde_json has no `ensure_ascii`
equivalent, so seam-runtime's emitter would need a custom `Formatter` to reproduce `\u0301`,
`\u65e5` and friends. That is a genuine ask, it is theirs to weigh, and it goes to them as a written
proposal rather than as a red gate.

Usage:
    scripts/emit_record_digest_v3_vectors.py            # rewrite the extended vector file
    scripts/emit_record_digest_v3_vectors.py --check    # exit 1 if the committed file has drifted
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
EXTENDED = REPO / "conformance" / "record_digest_v3_extended.json"
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
    """The one rendering, used for both writing and checking. `ensure_ascii` stays at its default,
    so this file renders exactly the way `conformance/vectors.json` does — see the module docstring
    for why that matters to anyone adopting these cases upstream."""
    return json.dumps(document, indent=2) + "\n"


#: Written into the file itself, so a reader who opens it outside this repo learns where the bytes
#: came from and why they are not in `conformance/vectors.json`.
PROVENANCE = (
    "seam-sdk's EXTENDED record_digest_v3 conformance cases. Machine-emitted by "
    "scripts/emit_record_digest_v3_vectors.py -- no digest here was typed by hand. These are a "
    "SUPERSET of the two record_digest_v3 blocks in conformance/vectors.json, which is a byte-"
    "identity contract with seam-runtime and is not edited here. The extra cases pin traps a "
    "single fixture per block cannot express: empty-string vs absent optionals, and decomposed "
    "non-ASCII text. All three SDK implementations reproduce both files."
)


def build_document() -> dict:
    crypto = _load_crypto()
    return {"$comment": PROVENANCE, "cases": build_cases(crypto)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the committed file differs from what this emits",
    )
    args = ap.parse_args()

    if not CRYPTO.exists():
        print(f"::error::missing {CRYPTO}", file=sys.stderr)
        return 2

    try:
        # A missing file is drift, not an infrastructure problem: `--check` must fail loudly when
        # the committed artifact is gone, rather than exit 2 and be read as "could not tell".
        current = EXTENDED.read_text(encoding="utf-8") if EXTENDED.exists() else ""
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
                f"{EXTENDED.name}: byte-identical to what the implementation emits"
            )
            return 0
        print(
            f"::error::{EXTENDED.name} has drifted from what `record_digest_v3` actually produces.\n"
            f"::error::Either a digest was edited by hand (never do this — the whole point of the\n"
            f"::error::vector is that its output is derived), or the formula changed and the block\n"
            f"::error::was not regenerated. Run: python3 scripts/{Path(__file__).name}",
            file=sys.stderr,
        )
        return 1

    EXTENDED.write_text(emitted, encoding="utf-8")
    print(f"wrote {EXTENDED.relative_to(REPO)} ({len(emitted)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
