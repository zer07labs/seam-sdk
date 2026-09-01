# seam — the hub's SDK quickstart tells partners to `pip install seam-sdk` with no co-installability caveat

> **Owner:** `seam` (the docs hub). **Filed by:** `seam-sdk`, 2026-08-31.
> **Issue:** [zer07labs/seam#26](https://github.com/zer07labs/seam/issues/26)
> **Source:** `seam-sdk/plans/post-adoption-hardening-and-acdp-readiness.md` (Phase 2), and
> [seam-sdk#48](https://github.com/zer07labs/seam-sdk/issues/48).
> One plan, one home — if you copy this into `seam`, delete it here and leave a pointer.
> **Anchors were verified on 2026-08-31 against `seam` `main`. Re-verify before editing.**

---

## Context — verified, not assumed

`seam/docs/sdk/` tells a partner to install this SDK in two places:

- `docs/sdk/01-base-concepts-and-quickstart.md:110` — the Python quickstart:
  `pip install seam-sdk   # source differs by audience — see docs 02/03`
- `docs/sdk/04-requesting-access.md:14` — the credentials table row:
  `| Cloudsmith read token | `npm install @zer07labs/seam-sdk` / `pip install seam-sdk` | ... |`

Grepped across the whole of `docs/sdk/` on 2026-08-31 for `protobuf|crewai|co-install|coinstall`:
the only two hits are `01-…:13` and `README.md:4`, both naming `seam.api.v1` as the contract. **No
file in `docs/sdk/` mentions the protobuf co-installability constraint at all.**

`seam-sdk` documents that constraint in detail — `seam-sdk/COMPATIBILITY.md`, section
**"Agent-framework co-installability"** (`:112-210` as of `seam-sdk` `20786dc`; cite the heading, not
the line, since the file moves).

## The consequence, stated plainly

A partner follows the hub quickstart, runs `pip install seam-sdk` into a virtualenv that already
holds an agent framework, and gets a **resolution refusal** from their package manager with nothing
in the hub docs to explain it. The hub is where they started, so the hub is where they look, and it
says nothing.

The mechanism is not exotic and it is not OpenTelemetry's fault. `seam-sdk`'s `protobuf` floor is
**derived, not chosen** — it tracks the gencode of the stubs it ships, and it moves on its own
because `buf.gen.yaml` uses unpinned buf remote plugins. protobuf's runtime-version check then
rejects any runtime older than that gencode. So any framework whose transitive closure caps
`protobuf` below the floor cannot share a virtualenv with the SDK. In practice that means a
framework pinning `opentelemetry-exporter-otlp-proto-http` tightly enough to have missed the release
where `opentelemetry-proto` lifted its own `protobuf<7` cap. A framework depending on a *range*
rides over the change automatically.

CrewAI is the live case — [seam-sdk#48](https://github.com/zer07labs/seam-sdk/issues/48) — and by
extension `seam-crewai`. `langchain`, `strands-agents` and `claude-agent-sdk` are all currently
clean.

## Delivers

A partner who hits the refusal finds an explanation in the document that sent them there, instead of
filing a support request or concluding the SDK is broken.

## Depends on

Nothing. This is documentation of an existing, already-documented constraint.

## Files (all in `seam`)

- `docs/sdk/01-base-concepts-and-quickstart.md` — the caveat, immediately after the Python install block.
- `docs/sdk/04-requesting-access.md` — one clause on the Cloudsmith row pointing at it.

## Approach — proposed text, ready to paste

Deliberately **no version numbers and no framework table.** Both are dated the moment they are
written, both already live in `seam-sdk/COMPATIBILITY.md`, and a second copy in the hub is a second
thing to keep true. The hub's job is to say *that* the constraint exists and where the current answer
lives.

### 1. `docs/sdk/01-base-concepts-and-quickstart.md` — after the `pip install seam-sdk` fence

```markdown
> **Installing beside an agent framework?** `seam-sdk`'s `protobuf` floor is *derived* from the
> gencode of the stubs it ships, not chosen — so a framework whose dependency closure caps
> `protobuf` below that floor cannot share a virtualenv with this SDK, and `pip` will refuse to
> resolve rather than fail at runtime. This is not an OpenTelemetry incompatibility: OTel lifted its
> cap, and the breakage is carried by packages that pinned the exporter too tightly to receive it.
>
> Which frameworks are currently affected is re-derived weekly rather than asserted — see
> **Agent-framework co-installability** in
> [`seam-sdk/COMPATIBILITY.md`](https://github.com/zer07labs/seam-sdk/blob/main/COMPATIBILITY.md),
> and run `make probe-frameworks` in that repo to resolve every row live.
```

### 2. `docs/sdk/04-requesting-access.md` — the Cloudsmith row

Append to the **Grants** cell, so a reader scanning only the table still sees it:

```markdown
| Cloudsmith read token | `npm install @zer07labs/seam-sdk` / `pip install seam-sdk` — see the co-installability caveat in [01](01-base-concepts-and-quickstart.md#quickstart-per-language) before installing beside an agent framework | Cloudsmith `zer07labs/internal` |
```

## Rejected alternatives

- **Restating the framework table in the hub.** It would be stale within a release, and it would
  compete with the probe-generated table that `seam-sdk` regenerates. One source, referenced twice.
- **Naming CrewAI specifically in the hub.** The pin is expected to be fixed upstream; a hub doc
  naming a framework as broken outlives the breakage. The issue link carries the specificity.
- **Saying nothing because `COMPATIBILITY.md` already documents it.** That is the current state, and
  it fails exactly the partner this ask is about: they never reach `COMPATIBILITY.md`, because
  nothing they read points there.

## Acceptance criteria

1. `docs/sdk/01-base-concepts-and-quickstart.md` carries the caveat adjacent to the Python install
   instruction, not in a later section.
2. `docs/sdk/04-requesting-access.md`'s Cloudsmith row points at it.
3. Neither file states a version number or a framework verdict — both defer to
   `seam-sdk/COMPATIBILITY.md`.
4. `grep -riE "protobuf|co-install" docs/sdk/` returns the new text.

## Tests

None — `seam` docs carry no test suite. The claim the caveat rests on is already gated in `seam-sdk`
by `python/tests/test_protobuf_floor.py` and the weekly `probe-frameworks` job.

## Scope note

`seam-sdk` wrote this plan and is **not** editing `seam`. The edit is small enough to be applied by
whoever owns the hub docs; if you would rather `seam-sdk` open the PR, say so on the issue and we
will — the text above is the whole diff.
