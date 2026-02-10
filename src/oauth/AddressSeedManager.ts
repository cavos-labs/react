/**
 * AddressSeedManager - Computes deterministic wallet addresses from OAuth identity
 *
 * address_seed = Poseidon(sub, salt)
 *
 * The address_seed uniquely identifies a wallet owner based on their
 * OAuth `sub` claim and a salt value. Same Google account = same wallet.
 */

import { hash, num } from 'starknet';

export class AddressSeedManager {
  private salt: string;

  constructor(salt: string = '0') {
    this.salt = salt;
  }

  /**
   * Compute the address seed from a user's OAuth `sub` claim
   * MUST match Cairo: PoseidonTrait::new().update(sub).update(salt).update(name).finalize()
   * @param sub The OAuth `sub` claim (user ID)
   * @param name Optional wallet name suffix for deterministic derivation
   */
  computeAddressSeed(sub: string, name?: string): string {
    // Convert sub to felt252 (hash if too long)
    const subFelt = this.subToFelt(sub);
    const saltFelt = num.toHex(this.salt);

    const elements = [subFelt, saltFelt];
    if (name) {
      elements.push(this.stringToFelt(name));
    }

    // Poseidon([sub, salt, name?]) - matches Cairo's .update().update().update().finalize()
    return hash.computePoseidonHashOnElements(elements);
  }

  /**
   * Convert a sub claim to a felt252
   * If sub is numeric and fits in felt252, use directly
   * Otherwise, hash it
   */
  private subToFelt(sub: string): string {
    // Try to parse as BigInt directly
    try {
      const subBigInt = BigInt(sub);
      // Check if it fits in felt252 (< 2^251)
      if (subBigInt < 2n ** 251n) {
        return num.toHex(subBigInt);
      }
    } catch {
      // Not a pure number (e.g. Apple sub), use raw string bytes
    }

    return this.stringToFelt(sub);
  }

  private stringToFelt(str: string): string {
    const bytes = new TextEncoder().encode(str);
    let result = 0n;
    for (let i = 0; i < bytes.length && i < 31; i++) {
      result = result * 256n + BigInt(bytes[i]);
    }
    return num.toHex(result);
  }

  /**
   * Compute the contract address for an OAuth wallet
   * @param sub The OAuth `sub` claim
   * @param classHash The OAuth account contract class hash
   * @param jwksRegistryAddress The JWKS registry contract address
   */
  computeContractAddress(
    sub: string,
    classHash: string,
    jwksRegistryAddress: string,
    name?: string,
  ): string {
    const addressSeed = this.computeAddressSeed(sub, name);

    // Constructor calldata: [address_seed, jwks_registry]
    const constructorCalldata = [addressSeed, jwksRegistryAddress];

    const contractAddress = hash.calculateContractAddressFromHash(
      addressSeed, // salt
      classHash,
      constructorCalldata,
      0
    );

    return contractAddress;
  }
}
