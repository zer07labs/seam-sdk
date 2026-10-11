package com.zer07labs.seam;

import java.security.SecureRandom;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

/**
 * An agent identity — a 32-byte Ed25519 seed that derives the pinned AID and signs the admission PoP,
 * the {@code Authorize} call_sig and the per-request credential. Mirrors Python's {@code Agent}.
 *
 * <p>The seed is never printed: {@link #toString} renders the AID only. {@link #seed} hands out a copy
 * for the seed-taking functions on {@link SeamCrypto}.
 */
public final class Agent {
  private static final SecureRandom RNG = new SecureRandom();

  private final byte[] seed;
  private final String aid;

  /** Wrap an existing 32-byte seed. The array is copied; the caller's is theirs. */
  public Agent(byte[] seed) {
    if (seed == null || seed.length != 32) {
      throw new IllegalArgumentException("agent seed must be 32 bytes");
    }
    this.seed = seed.clone();
    this.aid =
        SeamCrypto.aidFromPubkey(
            new Ed25519PrivateKeyParameters(this.seed, 0).generatePublicKey().getEncoded());
  }

  /**
   * A new agent identity from 32 CSPRNG bytes ({@link SecureRandom}) — Python's {@code
   * Agent.generate()}. To persist one, use {@link IdentityFile#create}, which generates and writes in
   * one step and never returns the seed.
   */
  public static Agent generate() {
    byte[] s = new byte[32];
    RNG.nextBytes(s);
    return new Agent(s);
  }

  /** The agent's {@code aid:pubkey:ed25519:} identity. */
  public String aid() {
    return aid;
  }

  /** A copy of the 32-byte seed. Never log it. */
  public byte[] seed() {
    return seed.clone();
  }

  /** The AID only — never the seed. */
  @Override
  public String toString() {
    return "Agent(aid=" + aid + ")";
  }
}
