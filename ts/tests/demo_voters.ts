// Demo voter proofs for the LIVE suites (seam-runtime #1687, runtime 0.87.0). Twin of
// python/tests/demo_voters.py — read that module's docstring for the why.
//
// A runtime since #1687 refuses every vote, ballot and objection without its voter's `seam-voter-pop-v1`
// proof; there is no flag and no dev bypass. Under `SEAM_DEV_INSECURE` it binds the demo agents' PUBLIC,
// deterministic demo voter keys (`seamd::voters::demo_voter_seed`) in the demo namespace — as public as
// the demo identity itself, which is why this lives in tests/ and never in src/.
//
// `demoVoting(client)` makes a `SeamClient` sign every vote it sends WITHOUT a proof with that demo key,
// using only the public API: it records what each session opened with (participants, onBehalfOf, mode,
// and the `SessionStep.openedAtMillis` the runtime returns) and what each proposal proposed, then builds
// the address the spec defines (`docs/specs/voter-verification.v1.md`). A vote that already carries a
// proof is left alone.

import { createHash } from "node:crypto";

import { SeamClient, type RunDecisionVote } from "../src/client.js";
import { signVoterPop, voteContentDigest, type VoterPopTarget } from "../src/crypto.js";

export const DEMO_TENANT = "design-partner";
export const DEMO_NAMESPACE = "design-partner/fraud";
export const DECISION_MODE = "macp.mode.decision.v1";

/** `seamd::voters::demo_voter_seed`: SHA-256 over u32-LE length-framed parts. */
export function demoVoterSeed(participant: string, tenant = DEMO_TENANT, namespace = DEMO_NAMESPACE): Uint8Array {
  const h = createHash("sha256");
  for (const part of ["seam-demo-voter-seed-v1", tenant, namespace, participant]) {
    const b = Buffer.from(part, "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32LE(b.length);
    h.update(len);
    h.update(b);
  }
  return new Uint8Array(h.digest());
}

interface SessionAddress {
  participants: string[];
  onBehalfOf: string[];
  mode: string;
  openedAtMillis: bigint;
  policy: { policyVersion: string; rulesDigest: Uint8Array } | null;
  proposals: Map<string, string>;
}

/** Make `client` sign its unsigned votes with the demo voter keys. Returns the same instance. */
export function demoVoting<C extends SeamClient>(client: C): C {
  const sessions = new Map<string, SessionAddress>();
  const proofs = new Map<string, ReturnType<typeof signVoterPop>>();
  let issuer: Promise<string> | undefined;
  const target = async (sessionId: string, openedAtMillis: bigint): Promise<VoterPopTarget> => ({
    issuer: await (issuer ??= client.issuerAid()),
    tenant: DEMO_TENANT,
    namespace: DEMO_NAMESPACE,
    sessionId,
    openedAtMillis,
  });

  const runDecision = client.runDecision.bind(client);
  client.runDecision = (async (agent, sessionId, participants, votes, features, onBehalfOf, opts) => {
    let signed: readonly RunDecisionVote[] = votes;
    if (votes.length > 0 && votes.every((v) => v.length === 2 || v.length === 3)) {
      // Spec: a one-shot opens and seals in one call, so it is addressed `(sessionId, 0)`; content is
      // `votes[0].value`, proposal `p1`, mode the decision mode.
      const t = await target(sessionId, 0n);
      // One-shot: the request features, canonical; policy 0x00 (server-resolved).
      const content = voteContentDigest(DECISION_MODE, "p1", votes[0]![1], participants, onBehalfOf ?? [], [], { features: features ?? {} });
      signed = votes.map((v) => {
        const [agentId, value] = v;
        const reason = v.length === 3 ? v[2] : "";
        const pop = signVoterPop(demoVoterSeed(agentId), t, content, { kind: "vote", participant: agentId, proposalId: "p1", value, reason });
        return [agentId, value, reason, pop] as const;
      });
    }
    return runDecision(agent, sessionId, participants, signed, features, onBehalfOf, opts);
  }) as C["runDecision"];

  const openSession = client.openSession.bind(client);
  client.openSession = (async (agent, opts) => {
    const step = await openSession(agent, opts);
    sessions.set(opts.sessionId, {
      participants: [...opts.participants],
      onBehalfOf: [...(opts.onBehalfOf ?? [])],
      mode: opts.mode || DECISION_MODE,
      openedAtMillis: step.openedAtMillis ?? 0n,
      // Session path: the policy the session bound at open, exactly as the open step reports it.
      policy: step.votePolicy ? { policyVersion: step.votePolicy.policyVersion, rulesDigest: step.votePolicy.rulesDigest } : null,
      proposals: new Map(),
    });
    return step;
  }) as C["openSession"];

  const submitProposal = client.submitProposal.bind(client);
  client.submitProposal = (async (sessionId, proposer, proposalId, option, usage, opts) => {
    const step = await submitProposal(sessionId, proposer, proposalId, option, usage, opts);
    sessions.get(sessionId)?.proposals.set(proposalId, option);
    return step;
  }) as C["submitProposal"];

  const submitVote = client.submitVote.bind(client);
  client.submitVote = (async (sessionId, voter, proposalId, value, usage, opts) => {
    const s = sessions.get(sessionId);
    const option = s?.proposals.get(proposalId);
    if (opts?.proof === undefined && s !== undefined && option !== undefined) {
      // One proof per vote: a resend of the same vote must stay byte-identical (the runtime dedupes it).
      const key = JSON.stringify([sessionId, voter, proposalId, value, opts?.reason ?? ""]);
      const cached = proofs.get(key);
      if (cached !== undefined) return submitVote(sessionId, voter, proposalId, value, usage, { ...opts, proof: cached });
      const content = voteContentDigest(s.mode, proposalId, option, s.participants, s.onBehalfOf, [], { policy: s.policy });
      const proof = signVoterPop(demoVoterSeed(voter), await target(sessionId, s.openedAtMillis), content, {
        kind: "vote",
        participant: voter,
        proposalId,
        value,
        reason: opts?.reason ?? "",
      });
      proofs.set(key, proof);
      opts = { ...opts, proof };
    }
    return submitVote(sessionId, voter, proposalId, value, usage, opts);
  }) as C["submitVote"];

  return client;
}
