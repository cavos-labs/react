/**
 * NonceManager - Computes nonces for OAuth wallet sessions
 *
 * The nonce ties a session key to a JWT, preventing replay attacks.
 * nonce = Poseidon(session_key, valid_until, randomness)
 */

import { hash, num } from 'starknet';

export interface NonceParams {
  sessionPubKey: string;
  validAfter: bigint;       // timestamp - session not valid before
  validUntil: bigint;       // timestamp - session expires at
  renewalDeadline: bigint;  // timestamp - can renew until
  randomness: bigint;
}

export class NonceManager {
  /**
   * Compute the nonce for a session
   * MUST match Cairo: PoseidonTrait::new().update(session_key).update(valid_until).update(randomness).finalize()
   */
  static computeNonce(params: NonceParams): string {
    const { sessionPubKey, validUntil, randomness } = params;

    return hash.computePoseidonHashOnElements([
      sessionPubKey,
      num.toHex(validUntil),
      num.toHex(randomness)
    ]);
  }

  /**
   * Generate random nonce parameters
   * @param sessionPubKey The session public key
   * @param currentTimestamp Current block timestamp (seconds)
   * @param sessionDurationSeconds How many seconds the session should last (default: 24 hours)
   * @param renewalGraceSeconds How many seconds after expiry the session can still renew (default: 48 hours)
   */
  static generateNonceParams(
    sessionPubKey: string,
    currentTimestamp: bigint,
    sessionDurationSeconds: bigint = 86400n,
    renewalGraceSeconds: bigint = 172800n
  ): NonceParams {
    // Generate random 252-bit randomness
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);
    const randomness = BigInt('0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('')) % (2n ** 251n);

    const validAfter = currentTimestamp;
    const validUntil = currentTimestamp + sessionDurationSeconds;
    const renewalDeadline = currentTimestamp + renewalGraceSeconds;

    return {
      sessionPubKey,
      validAfter,
      validUntil,
      renewalDeadline,
      randomness,
    };
  }

  /**
   * Verify that a nonce matches expected parameters
   */
  static verifyNonce(
    nonce: string,
    sessionPubKey: string,
    validUntil: bigint,
    renewalDeadline: bigint,
    randomness: bigint
  ): boolean {
    const expected = this.computeNonce({ sessionPubKey, validAfter: 0n, validUntil, renewalDeadline, randomness });
    return nonce === expected;
  }
}
