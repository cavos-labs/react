/**
 * NonceManager - Computes nonces for OAuth wallet sessions
 *
 * The nonce ties an ephemeral key to a JWT, preventing replay attacks.
 * nonce = Poseidon(eph_pubkey, max_block, randomness)
 */

import { hash, num } from 'starknet';

export interface NonceParams {
  ephemeralPubKey: string;
  maxBlock: bigint;
  renewalDeadline: bigint;  // Grace period end - can renew until this block
  randomness: bigint;
}

export class NonceManager {
  /**
   * Compute the nonce for a session
   * MUST match Cairo: PoseidonTrait::new().update(eph_pubkey).update(max_block).update(randomness).finalize()
   */
  static computeNonce(params: NonceParams): string {
    const { ephemeralPubKey, maxBlock, randomness } = params;

    // Poseidon hash of (eph_pubkey, max_block, randomness) - matches Cairo implementation
    return hash.computePoseidonHashOnElements([
      ephemeralPubKey,
      num.toHex(maxBlock),
      num.toHex(randomness)
    ]);
  }

  /**
   * Generate random nonce parameters
   * @param ephemeralPubKey The ephemeral public key
   * @param currentBlock Current block number
   * @param sessionDurationBlocks How many blocks the session should last (default: ~1 hour = 120 blocks)
   * @param renewalGraceBlocks How many blocks after expiry the session can still renew (default: ~24 hours = 2880 blocks)
   */
  static generateNonceParams(
    ephemeralPubKey: string,
    currentBlock: bigint,
    sessionDurationBlocks: bigint = 120n,
    renewalGraceBlocks: bigint = 2880n
  ): NonceParams {
    // Generate random 252-bit randomness
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);
    const randomness = BigInt('0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('')) % (2n ** 251n);

    const maxBlock = currentBlock + sessionDurationBlocks;
    const renewalDeadline = maxBlock + renewalGraceBlocks;

    return {
      ephemeralPubKey,
      maxBlock,
      renewalDeadline,
      randomness,
    };
  }

  /**
   * Verify that a nonce matches expected parameters
   */
  static verifyNonce(
    nonce: string,
    ephemeralPubKey: string,
    maxBlock: bigint,
    renewalDeadline: bigint,
    randomness: bigint
  ): boolean {
    const expected = this.computeNonce({ ephemeralPubKey, maxBlock, renewalDeadline, randomness });
    return nonce === expected;
  }
}
