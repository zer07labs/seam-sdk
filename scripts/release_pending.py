#!/usr/bin/env python3
"""The ledger behind a refused proto-train release, and the one decision that re-fires it.

Why this exists: 0.88.0 and 0.90.0 were tagged and never published. The runtime's `buf push --label
main` runs at the runtime MERGE; its `seam-release` dispatch fires later, at the release TAG. Between
the two, seam-sdk main still carries a green `ci-ok` computed against the OLD contract. So
release-on-runtime.yml's "main must be green" gate read a stale green, stamped and tagged. The release
commit's own CI regenerated from the moved BSR, the contract gate went red, and publish.yml refused. The
result was a public tag that can never be re-cut.

release-on-runtime.yml now re-runs the contract gate FRESH, against the BSR as it is at dispatch time,
before anything is written. A refusal there (or at the main-is-green gate) writes nothing. It records
the version and wire framing it was asked for in one open `release-pending` issue, via `body`. Once
the catch-up PR merges and main's CI is green, release-refire.yml asks `decide` what to do and
re-dispatches exactly the recorded version and framing.

`decide` is pure and is driven by scripts/test_release_refire_gate.py. Every refusal is a reason
string, never a guess. The rules:

  * Fire only the RECORDED version and framing, never "the latest".
  * If the SDK already carries `v<version>`, the release happened: close the issue.
  * If seam-runtime has a NEWER release tag than the recorded version, refuse. That newer
    release's own dispatch supersedes this one, and re-firing an older version over it would put
    the SDK behind the runtime under a fresh tag.
  * If the SDK already tagged a newer version, refuse for the same reason.
  * A body that does not parse exactly, or a title that disagrees with its marker, is refused.
  * Re-fire at most once per main commit. A refused re-fire records nothing new and needs a new
    green main commit before it may try again.
  * State a refusal once. The same refusal on the next green push is a `skip`, not a new comment.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Iterable, NamedTuple, Optional

LABEL = "release-pending"
_SEMVER = r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
_MARKER = re.compile(
    r"<!-- release-pending version=("
    + _SEMVER
    + r") wire_framing_version=([1-9]\d*) -->"
)
_REFIRED = re.compile(r"<!-- release-refired main=([0-9a-f]{40}) -->")
# Runtime release tags: `seamd-vX.Y.Z` (release-plz umbrella) or a manual `vX.Y.Z`. Anything else
# (pre-releases, crate tags) is not a release this ledger compares against.
_RUNTIME_TAG = re.compile(r"^(?:seamd-)?v(" + _SEMVER + r")$")
_SDK_TAG = re.compile(r"^v(" + _SEMVER + r")$")


def title(version: str) -> str:
    return f"release pending: v{version}"


def body(version: str, wire_framing_version: str, run_url: str, reason: str) -> str:
    """The issue body. The marker on its first line is the ONLY thing `decide` reads."""
    if not re.fullmatch(_SEMVER, version):
        raise ValueError(f"not a release version: {version!r}")
    if not re.fullmatch(r"[1-9]\d*", wire_framing_version):
        raise ValueError(f"not a wire framing version: {wire_framing_version!r}")
    return (
        f"<!-- release-pending version={version} wire_framing_version={wire_framing_version} -->\n"
        f"The runtime asked for seam-sdk **v{version}** (wire framing {wire_framing_version}), and "
        f"release-on-runtime refused it before writing anything: {reason}.\n\n"
        f"No commit and no tag were made, so the version is still free. When main's CI is next "
        f"green, `release-refire.yml` re-dispatches exactly this version and framing, unless a newer "
        f"runtime or SDK release has appeared since, in which case it refuses and says so here.\n\n"
        f"Refused run: {run_url}\n"
    )


def _v(s: str) -> tuple[int, int, int]:
    a, b, c = s.split(".")
    return int(a), int(b), int(c)


class Decision(NamedTuple):
    action: str  # "fire" | "close" | "refuse" | "skip"
    issue: Optional[int]
    version: str = ""
    wire_framing_version: str = ""
    reason: str = ""


def decide(
    issues: list[dict],
    runtime_tags: Iterable[str],
    sdk_tags: Iterable[str],
    main_sha: str,
) -> list[Decision]:
    """One decision per open pending issue. `issues` items carry `number`, `title`, `body` and
    `comments` (a list of comment bodies)."""
    if not re.fullmatch(r"[0-9a-f]{40}", main_sha):
        raise ValueError(f"not a commit sha: {main_sha!r}")
    runtime = [_v(m.group(1)) for t in runtime_tags if (m := _RUNTIME_TAG.match(t))]
    sdk = {_v(m.group(1)) for t in sdk_tags if (m := _SDK_TAG.match(t))}
    out: list[Decision] = []
    for issue in sorted(issues, key=lambda i: i["number"]):
        n = issue["number"]
        found = _MARKER.findall(issue.get("body") or "")
        if len(found) != 1:
            out.append(
                Decision(
                    "refuse",
                    n,
                    reason="the issue body carries no single release-pending marker",
                )
            )
            continue
        ver, wf = found[0][0], found[0][4]
        if issue.get("title") != title(ver):
            out.append(
                Decision(
                    "refuse",
                    n,
                    ver,
                    wf,
                    f"the title does not name v{ver}, the version its marker records",
                )
            )
            continue
        want = _v(ver)
        if want in sdk:
            out.append(
                Decision("close", n, ver, wf, f"v{ver} is already tagged in seam-sdk")
            )
            continue
        newer_rt = sorted(v for v in runtime if v > want)
        if newer_rt:
            nv = ".".join(map(str, newer_rt[-1]))
            out.append(
                Decision(
                    "refuse",
                    n,
                    ver,
                    wf,
                    f"seam-runtime has released {nv} since; its own dispatch supersedes v{ver}",
                )
            )
            continue
        newer_sdk = sorted(v for v in sdk if v > want)
        if newer_sdk:
            nv = ".".join(map(str, newer_sdk[-1]))
            out.append(
                Decision(
                    "refuse",
                    n,
                    ver,
                    wf,
                    f"seam-sdk already tagged v{nv}, newer than v{ver}",
                )
            )
            continue
        if main_sha in {
            m for c in issue.get("comments") or [] for m in _REFIRED.findall(c)
        }:
            out.append(
                Decision(
                    "skip", n, ver, wf, f"already re-fired for main {main_sha[:7]}"
                )
            )
            continue
        out.append(Decision("fire", n, ver, wf, f"main {main_sha[:7]} is green"))
    comments = {i["number"]: i.get("comments") or [] for i in issues}
    out = [
        d._replace(action="skip", reason=f"already refused: {d.reason}")
        if d.action == "refuse"
        and any(refusal_comment(d.reason) in c for c in comments[d.issue])
        else d
        for d in out
    ]
    fires = [d for d in out if d.action == "fire"]
    if len(fires) > 1:
        # Two re-firable versions at once cannot both be right: the newer supersedes the older above,
        # so this means two pendings for the SAME version. Refuse all of them rather than pick.
        out = [
            d._replace(
                action="refuse", reason="more than one pending issue is re-firable"
            )
            if d.action == "fire"
            else d
            for d in out
        ]
    return out


def refusal_comment(reason: str) -> str:
    """The line release-refire.yml posts for a refusal. `decide` reads it back so it is said once."""
    return f"Not re-fired: {reason}."


def refired_marker(main_sha: str) -> str:
    return f"<!-- release-refired main={main_sha} -->"


def _main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser(
        "body", help="print the issue title (line 1) and body for a refused release"
    )
    b.add_argument("--version", required=True)
    b.add_argument("--wire-framing-version", required=True)
    b.add_argument("--run-url", required=True)
    b.add_argument("--reason", required=True)
    sub.add_parser(
        "decide", help="read {issues, runtime_tags, sdk_tags, main_sha} JSON on stdin"
    )
    args = ap.parse_args(argv)
    if args.cmd == "body":
        print(title(args.version))
        print(
            body(args.version, args.wire_framing_version, args.run_url, args.reason),
            end="",
        )
        return 0
    inp = json.load(sys.stdin)
    for dec in decide(
        inp["issues"], inp["runtime_tags"], inp["sdk_tags"], inp["main_sha"]
    ):
        print(json.dumps(dec._asdict()))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
