package com.zer07labs.seam;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Attaches the {@code seam-request-call-v1} credential to subject-scoped calls, defaulting to a bound
 * agent (seam-sdk#202).
 *
 * <p>The Java SDK is a crypto shim with no client and no verb methods (COMPATIBILITY.md §4), so the
 * bound-agent default lives here, transport-agnostic, rather than on a client. It is the same rule as
 * Python's {@code SeamClient(channel, agent=...)._credential_md} and TS's {@code credential ??=
 * this.agent}: an explicit credential wins; otherwise the bound agent; with neither, nothing is sent.
 * A caller building its own client over the generated stubs holds one instance and calls {@link
 * #metadata} for each subject-scoped verb.
 */
public final class RequestCredentials {
  /** gRPC metadata key for the raw admission ticket. */
  public static final String TICKET_KEY = "x-seam-ticket-bin";

  /** gRPC metadata key for the raw 64-byte request signature. */
  public static final String CALL_SIG_KEY = "x-seam-call-sig-bin";

  /**
   * Returns a live admission ticket for {@code agent}. The Java SDK carries no transport, so the
   * caller's own client admits ({@link SeamCrypto#buildPresentation} → Admit) and caches.
   */
  @FunctionalInterface
  public interface TicketSource {
    byte[] ticketFor(Agent agent);
  }

  private final Agent agent;
  private final TicketSource tickets;

  /**
   * @param agent the bound agent, or {@code null} to keep the credential opt-in per call
   * @param tickets supplies the admission ticket for whichever agent signs
   */
  public RequestCredentials(Agent agent, TicketSource tickets) {
    if (tickets == null) throw new IllegalArgumentException("tickets must not be null");
    this.agent = agent;
    this.tickets = tickets;
  }

  /** The bound agent, or {@code null}. */
  public Agent agent() {
    return agent;
  }

  /**
   * The gRPC metadata for one subject-scoped call: {@link #TICKET_KEY} and {@link #CALL_SIG_KEY}, or an
   * empty map when there is neither an explicit {@code credential} nor a bound agent.
   *
   * @param credential an explicit credential for this call, or {@code null} for the bound agent
   * @param rpcFullName the gRPC full method path, e.g. {@code /seam.api.v1.SeamCoordination/GetDecision}
   * @param resourceId the verb's id for a bodyless read; {@code ""} for a bodied verb
   * @param body the request message's exact serialized bytes for a bodied verb, or {@code null}
   */
  public Map<String, byte[]> metadata(
      Agent credential, String rpcFullName, String resourceId, byte[] body) {
    Agent signer = credential != null ? credential : agent;
    if (signer == null) return Map.of();
    byte[] ticket = tickets.ticketFor(signer);
    String digest = body == null ? "" : SeamCrypto.bodyDigest(body);
    byte[] sig = SeamCrypto.requestSig(signer.seed(), ticket, rpcFullName, resourceId, digest);
    Map<String, byte[]> md = new LinkedHashMap<>();
    md.put(TICKET_KEY, ticket);
    md.put(CALL_SIG_KEY, sig);
    return md;
  }
}
