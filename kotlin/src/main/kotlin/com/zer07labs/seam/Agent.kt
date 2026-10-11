package com.zer07labs.seam

import java.security.SecureRandom
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters

/**
 * An agent identity — a 32-byte Ed25519 seed that derives the pinned AID and signs the admission PoP,
 * the `Authorize` call_sig and the per-request credential. Mirrors Python's `Agent`.
 *
 * Deliberately not a data class: a generated `toString` would print the seed. [toString] renders the
 * AID only; [seed] hands out a copy for the seed-taking functions on [SeamCrypto].
 */
class Agent(seed: ByteArray) {
    private val seedBytes: ByteArray

    /** The agent's `aid:pubkey:ed25519:` identity. */
    val aid: String

    init {
        require(seed.size == 32) { "agent seed must be 32 bytes" }
        seedBytes = seed.copyOf()
        aid = SeamCrypto.aidFromPubkey(Ed25519PrivateKeyParameters(seedBytes, 0).generatePublicKey().encoded)
    }

    /** A copy of the 32-byte seed. Never log it. */
    fun seed(): ByteArray = seedBytes.copyOf()

    /** The AID only — never the seed. */
    override fun toString(): String = "Agent(aid=$aid)"

    companion object {
        private val rng = SecureRandom()

        /**
         * A new agent identity from 32 CSPRNG bytes ([SecureRandom]) — Python's `Agent.generate()`. To
         * persist one, use [IdentityFile.create], which generates and writes in one step and never
         * returns the seed.
         */
        fun generate(): Agent = Agent(ByteArray(32).also { rng.nextBytes(it) })
    }
}
