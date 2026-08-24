# Build Plan — Agent ingress: the door

> **🔄 REFRESHED 2026-08-14 — PENDING (verified against code; the earlier "delivered" claim was
> wrong).** What actually shipped, all in the sibling `seam-adapters` repo (v0.1.0, six packages,
> private Cloudsmith index):
>
> > **RETRACTION (2026-08-23).** This line previously read *"pins `seam-sdk >=0.7,<0.8`, lock
> > resolves 0.7.9 — **not** '0.7.20'"*, implying a live consumer sits inside the wire-broken band.
> > **The pin half is stale.** `seam-adapters/core/pyproject.toml:22` reads
> > `sdk = ["seam-sdk>=0.7.20,<0.8"]`, with the reason recorded inline at `:15-21`. The floor was
> > raised; this note was not.
> >
> > **The lock half is still literally true and is retracted only as an implication.**
> > `seam-adapters/uv.lock:3921` does resolve `0.7.9` — because
> > `seam-adapters/pyproject.toml:32` overrides the dependency with an unconditional editable path
> > source (`{ path = "../seam-sdk/python", editable = true }`), so the lock records the sibling
> > checkout rather than a resolved release. That is not the consumer ignoring the floor.
> >
> > Retracting the whole line would have been a *second* false claim, which is why this says exactly
> > which half was wrong. See `COMPATIBILITY.md` §2, and
> > `python/tests/test_retracted_claims.py`, which fails if the stale wording returns.
>
> - **§A example — PARTIAL.** `examples/fraud/run.py` (observe→enforce→seal + issuer-pinned
>   `verify_decision` + wrong-pin `IssuerMismatchError` assert) and `examples/fraud_council/run.py`
>   (true open→propose→vote→commit with `chain_verified` assert) are real and self-asserting;
>   `scripts/enroll_dev_identities.py` covers identity provisioning. **Missing: the two scenes the
>   plan called the demo** — (1) a budget breach driving `Suspended` → R9 raise →
>   `SeamAdminClient.resume_session` (nothing in any repo calls it from an example; the shipped
>   "escalate→resume" is LangGraph `interrupt()`, a different mechanism), and (2) a **denied
>   admission** (scope violation at Admit — shipped DENYs are tool-gate denials only).
> - **§B MCP server — MISSING entirely, org-wide.** Recorded as a deliberate deferral in
>   seam-adapters `ASSUMPTIONS.md` ("MCP proof is adapter-SHAPED"). No `seam_*` tool surface, no
>   per-agent key-custody design for a shared server.
> - **§C adapter — OVERSHOT.** Four framework shims + a council harness shipped (plan said one,
>   with an explicit no-second-adapter non-goal). The §C "map tool usage to `StepUsage` so budgets
>   bind" element is absent — no `StepUsage` reference anywhere in seam-adapters.
> - **§D packaging — PARTIAL.** Partner compose + ≤5-min quickstart + nightly quickstart CI exist
>   (`seam-adapters/compose/`), but every path needs partner credentials (private image, private
>   wheels). **The DoD — "a stranger, with no access to any private repo" — is not met.**
>
> **Remaining work (the refreshed scope):** §A's Suspended/resume + denied-admission example
> scenes; §B the MCP server; §C `StepUsage` wiring in the adapters; §D a public evaluation path
> (or an explicit product decision that partner-gated is the intended distribution, recorded and
> the DoD amended). The original plan below stands as written for those items.

> **The finding that produced this plan.** There is **no way for a real agent to get into a Seam session.**
> Not "no good way" — no way. Across the entire org there is:
>
> - **no framework adapter** (LangGraph, CrewAI, AutoGen, LlamaIndex, Claude Agent SDK — nothing);
> - **no MCP server**, no A2A, no standard-protocol ingress of any kind;
> - **no example anywhere of an agent participating in a session.** The only `examples/` directory in the
>   entire organisation is a crypto-vector generator in `seam-runtime/crates/seam-client/examples/`.
>
> LangGraph and CrewAI appear in exactly two places in the codebase: an animated diagram on the marketing
> site, and a `type Framework = 'LangGraph' | 'CrewAI' | ...` union in the console's **mock data**.
>
> A customer's only path in today is: **hand-write a MACP participant against a gRPC SDK, from scratch, with
> no example.** We have built the vault, the vault's audit chain, the vault's crypto-shred, the vault's
> signed erasure certificates, and a 69-row roadmap of future vault features — and **no door**.
>
> **This is the highest-priority build in the company, and it is not an enterprise feature.** That is exactly
> why the enterprise catalog never surfaced it.

---

## §0. The load-bearing correction: this needs **ZERO runtime change**

This was believed to be a Phase-3 runtime project. It is not. The belief traced to
`seam-runtime/plans/runtime/build-coord-bridges.md` ("A2A + MCP adapters — **DEFERRED**") and the presence of
`FrameworkBridge` on the never-recreate deleted-traits list. **Both are irrelevant here**, and the
distinction matters enough to state precisely:

| | |
|---|---|
| **`CoordinationEngine`** (and the deleted `FrameworkBridge`) | Swaps the **runtime's** coordination protocol — MACP → A2A/ACP. A *server-side* concern. Correctly deferred; correctly deleted. |
| **Agent ingress** | A **client** of the data plane. The `MacpEngine` runs **server-side**; a participant is *just a gRPC caller*. |

Verified against the code:

- `SeamClient.open_session` (`python/seam_sdk/client.py:125-128, 163-184`) performs the **pinned-key PoP
  admission handshake internally**. The caller does not touch it.
- After that, `submit_proposal` / `submit_vote` / `submit_commit` / `report_outcome` are **plain gRPC calls
  keyed by session id and participant name** — no per-step crypto, no MACP state machine on the client side.
- `Agent(seed)` → `.aid` is stock Ed25519 with pinned conformance vectors.

**Therefore an adapter is a thin wrapper over an SDK that already works.** No new trait, no runtime PR, no
`build-coord-bridges`. This is a ~2-week SDK/examples project, not a quarter of Rust.

---

## §A. The example — build this first, and time yourself

**One file. One framework. End to end.** An agent that opens a session, is admitted, proposes a decision,
commits, and is sealed — with the resulting chain verified by a script that is not the runtime.

Do **not** start with the adapter framework. Start with the example, because **the example is the
experiment**: if writing it takes more than two days, that is the most valuable product data collected all
year, and it tells you exactly what the adapter must fix. Dogfood the SDK the way a customer would and fix
what bleeds. Every paper cut you hit is a paper cut every customer hits, silently, before they leave.

**Framework choice:** whichever the first design partner actually uses. If there is no design partner yet,
pick **LangGraph** — largest installed base in the target segment, and its node/edge model maps cleanly onto
propose → vote → commit.

**The example must cover the unglamorous parts, because these are where a real integration dies:**
- identity provisioning — enrolling the agent's AID → tenant/namespace via the management plane
  (`admin.py` already covers this);
- the **`Suspended`** state when a session budget is breached, and the R9 escalation/resume path;
- a **denied** admission (a scope violation) — because *the denial is the product*. An agent attempting an
  irreversible action, refused at Admit, with a sealed evidence chain, **is the demo.**

**DoD:** a person who has never seen the codebase runs `docker compose up`, runs the example, and gets a
sealed decision plus a third-party-verified chain. Record it. That recording is the sales asset.

---

## §B. The MCP server — maximum surface per unit of code

One adapter that reaches **every MCP-speaking agent at once**, rather than N adapters chasing N frameworks.
This is the direct answer to *"build less, cover more."*

A Python (or TS) process exposing Seam's session lifecycle as MCP tools over `SeamClient`:

| MCP tool | Maps to |
|---|---|
| `seam_open_session` | `open_session` (PoP handshake handled inside the SDK) |
| `seam_propose` / `seam_vote` / `seam_commit` | `submit_proposal` / `submit_vote` / `submit_commit` |
| `seam_session_status` | `session_status` (including `Suspended` on budget breach) |
| `seam_report_outcome` | `report_outcome` |
| `seam_get_decision` / `seam_verify` | `get_decision` / `verify_commitment` |

**Zero runtime change.** The one design question to settle here — and settle it *here*, at the SDK layer, not
in the runtime — is **key custody: one agent seed per MCP server, or one per connected agent?** Per-server is
simpler and correct for a single-tenant sidecar; per-agent is correct the moment one server fronts several
agents whose decisions must be attributable separately. **Attribution is the product**, so design for
per-agent seeds even if v1 ships with one, and do not let the shortcut become the wire contract.

**DoD:** an off-the-shelf MCP-capable agent (Claude Desktop / Claude Agent SDK / any MCP client) opens a Seam
session and gets a decision sealed, with **no Seam-specific code written by the user.**

---

## §C. The framework adapter — only after §A tells you what it should be

A thin package (`seam-langgraph`, or whatever §A's partner uses):
- open a session at graph start; close it at graph end;
- map decision nodes to propose/vote/commit;
- map tool usage to `StepUsage` so budgets actually bind;
- handle `Suspended` (budget breach) and denial (scope floor) as first-class graph states, not exceptions.

**Do not build the second adapter until a second customer names their framework.** The MCP server (§B) is the
hedge that makes waiting cheap — it covers the long tail without a per-framework build.

---

## §D. Packaging — what an outsider needs to exist at all

Ingress is worthless if nobody can stand up the other end:
- the `seamd` image must be **pullable** (it exists, cosign-signed with SBOM and provenance — and is
  **private**);
- `docker-compose.yml` must be runnable by someone outside the company, with the demo KEK clearly labelled
  as a demo;
- a quickstart: pull → compose up → run the example → verify the chain. Five minutes, one page.

*(This is the pilot install path. Helm is a second-customer problem — customer one runs on compose with an
engineer on a call, and their platform team may well write the chart for you.)*

---

## Dependencies

- **`seam-runtime/plans/runtime/build-make-the-claims-true.md` §A and §D** — the example's payoff is the
  **third-party chain verification**, which is impossible until the two proto tags land and the specs are
  public. Do those in the same week; they are ~a day of work between them.
- Nothing else. Not the control-plane backend, not SSO, not the console, not Helm.

## Non-goals

- **No `FrameworkBridge`, no `CoordinationEngine` adapter, no `build-coord-bridges` work.** §0.
- **No A2A/ACP.** Build when a customer names them; MCP covers the tail meanwhile.
- **No second framework adapter** until a second customer names their framework.
- **No new repo.** This lives in `seam-sdk`, which is already the public, protobuf-first, 5-language home.

## Definition of done

**A stranger, with no access to any private repo, gets an agent into a Seam session and verifies the sealed
chain themselves.** That single sentence is the product's entire thesis executed once — and it has never
happened.
