package com.zer07labs.seam

/**
 * Returns a live admission ticket for an agent. The Kotlin SDK carries no transport, so the caller's own
 * client admits ([SeamCrypto.buildPresentation] → Admit) and caches.
 */
fun interface TicketSource {
    fun ticketFor(agent: Agent): ByteArray
}

/**
 * Attaches the `seam-request-call-v1` credential to subject-scoped calls, defaulting to a bound [agent]
 * (seam-sdk#202).
 *
 * The Kotlin SDK is a crypto shim with no client and no verb methods (COMPATIBILITY.md §4), so the
 * bound-agent default lives here, transport-agnostic, rather than on a client. It is the same rule as
 * Python's `SeamClient(channel, agent=...)._credential_md` and TS's `credential ??= this.agent`: an
 * explicit credential wins; otherwise the bound agent; with neither, nothing is sent. A caller building
 * its own client over the generated stubs holds one instance and calls [metadata] per subject-scoped verb.
 *
 * @property agent the bound agent, or `null` to keep the credential opt-in per call
 * @property tickets supplies the admission ticket for whichever agent signs
 */
class RequestCredentials(val agent: Agent? = null, private val tickets: TicketSource) {
    /**
     * The gRPC metadata for one subject-scoped call — [TICKET_KEY] and [CALL_SIG_KEY] — or an empty map
     * when there is neither an explicit [credential] nor a bound [agent].
     *
     * @param rpcFullName the gRPC full method path, e.g. `/seam.api.v1.SeamCoordination/GetDecision`
     * @param resourceId the verb's id for a bodyless read; `""` for a bodied verb
     * @param body the request message's exact serialized bytes for a bodied verb, or `null`
     */
    fun metadata(
        credential: Agent?,
        rpcFullName: String,
        resourceId: String,
        body: ByteArray? = null,
    ): Map<String, ByteArray> {
        val signer = credential ?: agent ?: return emptyMap()
        val ticket = tickets.ticketFor(signer)
        val digest = if (body == null) "" else SeamCrypto.bodyDigest(body)
        val sig = SeamCrypto.requestSig(signer.seed(), ticket, rpcFullName, resourceId, digest)
        return linkedMapOf(TICKET_KEY to ticket, CALL_SIG_KEY to sig)
    }

    companion object {
        /** gRPC metadata key for the raw admission ticket. */
        const val TICKET_KEY = "x-seam-ticket-bin"

        /** gRPC metadata key for the raw 64-byte request signature. */
        const val CALL_SIG_KEY = "x-seam-call-sig-bin"
    }
}
