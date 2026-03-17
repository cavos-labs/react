/**
 * OAuthWalletManager - Manages OAuth-based wallet authentication
 *
 * Handles:
 * - Session key generation and management
 * - OAuth redirect flow with nonce
 * - JWT parsing and storage
 * - Session persistence across page reloads
 */

import { ec, num, hash, byteArray, CallData, RpcProvider, typedData, type TypedData, type Signature, Contract } from 'starknet';
import { NonceManager, NonceParams } from './NonceManager';
import { AddressSeedManager } from './AddressSeedManager';
import { OAuthWalletConfig } from '../types/config';
import { SessionKeyPolicy } from '../types/session';

export interface OAuthSession {
  /** Session private key (hex) */
  sessionPrivateKey: string;
  /** Session public key (hex) */
  sessionPubKey: string;
  /** Nonce parameters */
  nonceParams: NonceParams;
  /** Computed nonce (for verification) */
  nonce: string;
  /** JWT token (after OAuth callback) */
  jwt?: string;
  /** Parsed JWT claims */
  jwtClaims?: JWTClaims;
  /** Computed wallet address */
  walletAddress?: string;
  /** Address seed */
  addressSeed?: string;
  /** Session key policy */
  sessionPolicy?: SessionKeyPolicy;
  /** Wallet name suffix */
  walletName?: string;
}

export interface JWTClaims {
  sub: string;
  nonce: string;
  exp: number;
  iss: string;
  aud: string;
  email?: string;
  name?: string;
  picture?: string;
}

export interface ClaimOffsets {
  sub_offset: number;
  sub_len: number;
  nonce_offset: number;
  nonce_len: number;
  kid_offset: number;
  kid_len: number;
  exp_offset: number;
  exp_len: number;
  iss_offset: number;
  iss_len: number;
  aud_offset: number;
  aud_len: number;
}

const SESSION_STORAGE_KEY = 'cavos_oauth_session';
const PRE_AUTH_STORAGE_KEY = 'cavos_oauth_pre_auth';

// ── Garaga RSA-2048 calldata builder ──────────────────────────────────────────
// Builds calldata for garaga::signatures::rsa::is_valid_rsa2048_sha256_signature.
// Layout: [sig_24, expected_msg_24, 17×(quotient_24 + remainder_24)]
// Total: 24 + 24 + 17×48 = 864 felt252 values.

const U96_MASK = (1n << 96n) - 1n;

function bigIntTo96Chunks(n: bigint): string[] {
  const limbs: string[] = [];
  for (let i = 0; i < 24; i++) {
    limbs.push('0x' + ((n >> (BigInt(i) * 96n)) & U96_MASK).toString(16));
  }
  return limbs;
}

async function computeSha256(data: Uint8Array): Promise<Uint8Array> {
  if (typeof globalThis.crypto?.subtle !== 'undefined') {
    const hashBuf = await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(data));
    return new Uint8Array(hashBuf);
  }
  // Node.js fallback
  const { createHash } = await import('crypto');
  return new Uint8Array(createHash('sha256').update(data).digest());
}

function pkcs1V15Sha256Encode(sha256Hash: Uint8Array): bigint {
  // PKCS#1 v1.5 encoding for SHA-256:
  // 0x00 || 0x01 || PS (0xFF × 202) || 0x00 || DigestInfo (19 bytes) || Hash (32 bytes)
  // DigestInfo = 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
  const digestInfo = new Uint8Array([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
  ]);
  const encoded = new Uint8Array(256);
  encoded[0] = 0x00;
  encoded[1] = 0x01;
  for (let i = 2; i < 204; i++) encoded[i] = 0xff;
  encoded[204] = 0x00;
  encoded.set(digestInfo, 205);
  encoded.set(sha256Hash, 224);
  // Convert big-endian bytes to bigint
  let result = 0n;
  for (let i = 0; i < 256; i++) {
    result = (result << 8n) | BigInt(encoded[i]);
  }
  return result;
}

async function rsa2048Sha256CalldataBuilder(
  sig: bigint,
  modulus: bigint,
  message: Uint8Array,
): Promise<string[]> {
  // 1. Compute SHA-256 of message and PKCS#1 v1.5 encode
  const sha256Hash = await computeSha256(message);
  const expectedMessage = pkcs1V15Sha256Encode(sha256Hash);

  // 2. Serialize signature and expected_message as 24 × u96 chunks
  const sigChunks = bigIntTo96Chunks(sig);
  const msgChunks = bigIntTo96Chunks(expectedMessage);

  // 3. Compute 17 modular reduction witnesses:
  //    16 squarings: r_i = (prev^2) mod n
  //    1 final multiply: r_16 = (r_15 * sig) mod n
  //    For each step, store quotient and remainder as 24 × u96 chunks
  const reductions: string[] = [];

  let current = sig;
  for (let i = 0; i < 16; i++) {
    const product = current * current;
    const q = product / modulus;
    const r = product % modulus;
    reductions.push(...bigIntTo96Chunks(q), ...bigIntTo96Chunks(r));
    current = r;
  }
  // Final multiply: current (= sig^65536) * sig = sig^65537
  const finalProduct = current * sig;
  const finalQ = finalProduct / modulus;
  const finalR = finalProduct % modulus;
  reductions.push(...bigIntTo96Chunks(finalQ), ...bigIntTo96Chunks(finalR));

  return [...sigChunks, ...msgChunks, ...reductions];
}


export class OAuthWalletManager {
  private config: OAuthWalletConfig;
  private backendUrl: string;
  private appId: string;
  private provider: RpcProvider;
  private session: OAuthSession | null = null;
  private addressSeedManager: AddressSeedManager;
  private sessionDuration: number;
  private renewalGracePeriod: number;
  private defaultPolicy?: SessionKeyPolicy;

  constructor(
    config: OAuthWalletConfig,
    backendUrl: string,
    appId: string,
    rpcUrl: string,
    sessionConfig?: { sessionDuration?: number; renewalGracePeriod?: number; defaultPolicy?: SessionKeyPolicy }
  ) {
    this.config = config;
    this.backendUrl = backendUrl;
    this.appId = appId;
    this.provider = new RpcProvider({ nodeUrl: rpcUrl });
    this.addressSeedManager = new AddressSeedManager(config.salt || '0');
    this.sessionDuration = sessionConfig?.sessionDuration || 86400; // 24 hours in seconds
    this.renewalGracePeriod = sessionConfig?.renewalGracePeriod || 172800; // 48 hours in seconds
    this.defaultPolicy = sessionConfig?.defaultPolicy;
  }

  /**
   * Set the per-app salt for wallet address derivation.
   * Called by CavosSDK after fetching app_salt from backend.
   * Re-computes wallet address if session exists with different salt.
   */
  setAppSalt(salt: string): void {
    this.config.salt = salt;
    this.addressSeedManager = new AddressSeedManager(salt);

    // If session exists and has issuer/sub claims, re-compute the wallet address
    if (this.session?.jwtClaims?.sub && this.session.jwtClaims.iss) {
      const issuer = this.session.jwtClaims.iss;
      const sub = this.session.jwtClaims.sub;

      // Re-compute with new salt and current name
      const newAddressSeed = this.addressSeedManager.computeAddressSeed(
        issuer,
        sub,
        this.session.walletName,
      );
      const newWalletAddress = this.addressSeedManager.computeContractAddress(
        issuer,
        sub,
        this.config.cavosAccountClassHash,
        this.config.jwksRegistryAddress,
        this.session.walletName,
      );

      // Update session with new values
      this.session = {
        ...this.session,
        addressSeed: newAddressSeed,
        walletAddress: newWalletAddress,
      };

      // Persist updated session
      this.persistSession();
    }
  }


  /**
   * Generate a new session with fresh session key (for renewal).
   * Returns a complete OAuthSession that can be used for renewal.
   */
  async generateNewSession(): Promise<OAuthSession> {
    const currentSession = this.getSession();
    if (!currentSession?.walletAddress || !currentSession.jwtClaims?.sub) {
      throw new Error('No current session to renew from');
    }

    // Generate session key pair
    const STARK_CURVE_ORDER = BigInt('0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f');

    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    let privateKeyBigInt = BigInt('0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join(''));

    privateKeyBigInt = (privateKeyBigInt % (STARK_CURVE_ORDER - 1n)) + 1n;

    const sessionPrivateKey = '0x' + privateKeyBigInt.toString(16);
    const sessionPubKey = ec.starkCurve.getStarkKey(sessionPrivateKey);

    // Get current block timestamp
    const block = await this.provider.getBlock('latest');
    const currentTimestamp = BigInt(block.timestamp);

    // Generate nonce params (timestamp-based)
    const nonceParams = NonceManager.generateNonceParams(
      sessionPubKey,
      currentTimestamp,
      BigInt(this.sessionDuration),
      BigInt(this.renewalGracePeriod)
    );

    const nonce = NonceManager.computeNonce(nonceParams);

    // Create new session object reusing current session data
    const newSession: OAuthSession = {
      ...currentSession,
      sessionPrivateKey,
      sessionPubKey,
      nonceParams,
      nonce,
      sessionPolicy: currentSession.sessionPolicy,
      walletName: currentSession.walletName || 'default', // Ensure walletName is set
    };

    return newSession;
  }

  /**
   * Switch active wallet by name.
   * Re-computes address and seed while keeping JWT.
   */
  switchWallet(name?: string): void {
    if (!this.session?.jwtClaims?.sub) {
      // Just update local name for next login if not authenticated
      this.session = { ...this.session as any, walletName: name };
      return;
    }

    const issuer = this.session.jwtClaims.iss;
    const sub = this.session.jwtClaims.sub;
    const addressSeed = this.addressSeedManager.computeAddressSeed(issuer, sub, name);
    const walletAddress = this.addressSeedManager.computeContractAddress(
      issuer,
      sub,
      this.config.cavosAccountClassHash,
      this.config.jwksRegistryAddress,
      name,
    );

    this.session = {
      ...this.session,
      walletName: name,
      addressSeed,
      walletAddress,
    };

    this.persistSession();
  }

  /**
   * Initialize a new OAuth session before redirecting to OAuth provider.
   * Generates session key and computes nonce.
   */
  async initializeSession(policy?: SessionKeyPolicy): Promise<{ nonce: string }> {
    // Generate session key pair
    const STARK_CURVE_ORDER = BigInt('0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f');

    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    let privateKeyBigInt = BigInt('0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join(''));

    privateKeyBigInt = (privateKeyBigInt % (STARK_CURVE_ORDER - 1n)) + 1n;

    const sessionPrivateKey = '0x' + privateKeyBigInt.toString(16);
    const sessionPubKey = ec.starkCurve.getStarkKey(sessionPrivateKey);

    // Get current block timestamp
    const block = await this.provider.getBlock('latest');
    const currentTimestamp = BigInt(block.timestamp);

    // Generate nonce params with configured duration (timestamp-based)
    const nonceParams = NonceManager.generateNonceParams(
      sessionPubKey,
      currentTimestamp,
      BigInt(this.sessionDuration),
      BigInt(this.renewalGracePeriod)
    );

    // Compute nonce
    const nonce = NonceManager.computeNonce(nonceParams);

    // Set default wallet name if not already set
    const walletName = this.session?.walletName || 'default';

    // Create session object (use explicit policy, fall back to config default)
    this.session = {
      sessionPrivateKey,
      sessionPubKey,
      nonceParams,
      nonce,
      sessionPolicy: policy ?? this.defaultPolicy,
      walletName, // Ensure walletName is always set
    };

    // Persist pre-auth session to sessionStorage (survives OAuth redirect)
    if (typeof window !== 'undefined') {
      this.persistPreAuthSession();
    }

    return { nonce };
  }

  /**
   * Get Google OAuth URL with computed nonce
   */
  async getGoogleOAuthUrl(redirectUri?: string): Promise<string> {
    if (typeof window === 'undefined') {
      throw new Error('OAuth not supported in SSR');
    }

    if (!this.session) {
      await this.initializeSession();
    }

    // Build URL with query parameters (backend expects GET)
    const params = new URLSearchParams({
      nonce: this.session!.nonce,
      redirect_uri: redirectUri || window.location.href,
    });

    const response = await fetch(`${this.backendUrl}/api/oauth/google?${params}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
      throw new Error(`OAuth init failed: ${await response.text()}`);
    }

    const { url } = await response.json();
    return url;
  }

  /**
   * Get Apple OAuth URL with computed nonce
   */
  async getAppleOAuthUrl(redirectUri?: string): Promise<string> {
    if (typeof window === 'undefined') {
      throw new Error('OAuth not supported in SSR');
    }

    if (!this.session) {
      await this.initializeSession();
    }

    // Build URL with query parameters (backend expects GET)
    const params = new URLSearchParams({
      nonce: this.session!.nonce,
      redirect_uri: redirectUri || window.location.href,
    });

    const response = await fetch(`${this.backendUrl}/api/oauth/apple?${params}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
      throw new Error(`OAuth init failed: ${await response.text()}`);
    }

    const { url } = await response.json();
    return url;
  }

  /**
   * Handle OAuth callback - extract and validate JWT
   * @param authData The auth data string from callback (contains JWT)
   */
  async handleOAuthCallback(authData: string): Promise<OAuthSession> {
    // Restore pre-auth session (session key + nonce)
    this.restorePreAuthSession();

    if (!this.session) {
      throw new Error('No pre-auth session found. OAuth flow was not initialized properly.');
    }

    // Parse auth data (could be JSON or direct JWT depending on backend)
    let jwt: string;
    try {
      const parsed = JSON.parse(authData);
      jwt = parsed.id_token || parsed.jwt || parsed.token;
    } catch {
      jwt = authData;
    }

    // Parse JWT to extract claims
    const jwtClaims = this.parseJWT(jwt);

    // Verify nonce matches
    if (jwtClaims.nonce !== this.session.nonce) {
      throw new Error('JWT nonce does not match session nonce. Possible replay attack.');
    }

    // Compute address seed and wallet address
    const addressSeed = this.addressSeedManager.computeAddressSeed(
      jwtClaims.iss,
      jwtClaims.sub,
      this.session.walletName,
    );

    const walletAddress = this.addressSeedManager.computeContractAddress(
      jwtClaims.iss,
      jwtClaims.sub,
      this.config.cavosAccountClassHash,
      this.config.jwksRegistryAddress,
      this.session.walletName,
    );
    // Update session with JWT data
    this.session = {
      ...this.session,
      jwt,
      jwtClaims,
      addressSeed,
      walletAddress,
      walletName: this.session.walletName,
    };

    // Persist full session
    this.persistSession();

    // Clear pre-auth sessions (both storage locations)
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem(PRE_AUTH_STORAGE_KEY);
      localStorage.removeItem('cavos_magic_link_pre_auth');
    }

    return this.session;
  }

  /**
   * Build a lightweight session signature for transactions (SESSION_V1).
   * Only includes session key signature - much cheaper for paymaster transactions.
   * Requires the session to be registered first (via deployment with full JWT).
   *
   * Merkle proofs for allowed contracts are appended after the session key.
   * Format: [SESSION_V1, r, s, session_key, proof_len_1, proof_1..., proof_len_2, proof_2..., ...]
   */
  buildSessionSignature(transactionHash: string, calls?: { contractAddress: string }[]): string[] {
    if (!this.session?.sessionPrivateKey || !this.session.sessionPubKey) {
      throw new Error('No session key in session');
    }

    const { sessionPrivateKey, sessionPubKey } = this.session;

    // Sign the transaction hash with the session key
    const signature = ec.starkCurve.sign(transactionHash, sessionPrivateKey);

    // Build lightweight session signature
    const sig: string[] = [
      '0x53455353494f4e5f5631', // SESSION_V1 magic
      num.toHex(signature.r),
      num.toHex(signature.s),
      sessionPubKey,
    ];

    // Append Merkle proofs for each call's target contract
    if (calls && this.session.sessionPolicy?.allowedContracts?.length) {
      const allowedContracts = this.session.sessionPolicy.allowedContracts;
      for (const call of calls) {
        const proof = OAuthWalletManager.computeMerkleProof(allowedContracts, call.contractAddress);
        sig.push(num.toHex(proof.length));
        sig.push(...proof);
      }
    }

    return sig;
  }

  /**
   * Sign typed data with the session key.
   * The signature is a standard ECDSA signature from the session key.
   *
   * @param typedDataInput - The typed data to sign (SNIP-12 format)
   * @returns Signature array [r, s]
   */
  signMessage(typedDataInput: TypedData): string[] {
    if (!this.session?.sessionPrivateKey || !this.session.walletAddress) {
      throw new Error('No active session. Please login first.');
    }

    // Compute the SNIP-12 message hash and build the full session signature
    // that is_valid_signature on the contract expects: [SESSION_V1, r, s, session_key]
    const messageHash = typedData.getMessageHash(typedDataInput, this.session.walletAddress);
    return this.buildSessionSignature(messageHash);
  }

  /**
   * Build the full JWT signature data for on-chain JWT verification (OAUTH_JWT_V1).
   * This performs RSA verification via Garaga and registers the session.
   * Only use during deployment - subsequent transactions should use buildSessionSignature().
   *
   * Signature format (Garaga RSA-2048):
   * [0]      = OAUTH_JWT_V1 magic
   * [1-3]    = session key (r, s, pubkey)
   * [4-5]    = valid_until, randomness
   * [6-12]   = jwt_sub, jwt_nonce, jwt_exp, jwt_kid, jwt_iss, salt, wallet_name
   * [13-24]  = claim offsets and lengths:
   *            sub_offset, sub_len, nonce_offset, nonce_len, kid_offset, kid_len,
   *            exp_offset, exp_len, iss_offset, iss_len, aud_offset, aud_len
   * [25]     = garaga_rsa_len (864)
   * [26-889] = Garaga RSA calldata (sig_24 + expected_msg_24 + 17×48 reductions)
   * [890]    = jwt_bytes_len
   * [891+]   = packed JWT bytes (31-byte chunks)
   * [after JWT] = valid_after, allowed_contracts_root, max_calls_per_tx,
   *               spending_policies_count, spending_policies...
   */
  async buildJWTSignatureData(transactionHash: string, externalSession?: OAuthSession): Promise<string[]> {
    const session = externalSession || this.session;
    if (!session?.jwt || !session.jwtClaims) {
      throw new Error('No JWT in session');
    }
    const { jwt, sessionPrivateKey, sessionPubKey } = session;
    const jwtClaims = session.jwtClaims;
    const nonceParams = session.nonceParams;

    // Sign the transaction hash with the session key
    const signature = ec.starkCurve.sign(transactionHash, sessionPrivateKey);

    // Extract RSA signature from JWT
    const jwtParts = jwt.split('.');
    const rsaSignature = this.base64UrlToBytes(jwtParts[2]);
    const rsaLimbs = this.bytesTo96Limbs(rsaSignature);

    // Convert RSA sig limbs to bigint (little-endian: limb[0] is LSB)
    const sigBigInt = rsaLimbs.reduce(
      (acc: bigint, limb: string, i: number) => acc + BigInt(limb) * (1n << (BigInt(i) * 96n)),
      0n,
    );

    // Fetch the RSA modulus n from the on-chain registry in 17 x 123-bit proof limbs
    // and reconstruct the integer modulus.
    const kid = this.extractKidFromJwt(jwt);
    const nLimbHexes = await this.fetchNFromRegistry(kid);
    const nBigInt = nLimbHexes.reduce(
      (acc: bigint, limb: string, i: number) => acc + BigInt(limb) * (1n << (BigInt(i) * 96n)),
      0n,
    );

    if (nBigInt === 0n) {
      throw new Error(
        `JWKS key not found or invalid: kid="${kid}" is not registered in the on-chain JWKS registry. ` +
        `Make sure the JWKS registry has been populated for this network.`
      );
    }

    // Get signed data (header.payload)
    const signedData = `${jwtParts[0]}.${jwtParts[1]}`;
    const signedDataBytes = new TextEncoder().encode(signedData);

    // Generate Garaga RSA-2048 witnesses (calldata)
    const garagaCalldata = await rsa2048Sha256CalldataBuilder(
      sigBigInt,
      nBigInt,
      signedDataBytes
    );

    // Find claim offsets for on-chain verification
    const offsets = this.findClaimOffsets(jwt);

    // Build signature array matching contract format
    const jwt_sub_felt = this.subToFelt(jwtClaims.sub);
    const salt_hex = num.toHex(this.config.salt || '0x0');

    // Pack signedDataBytes into 31-byte chunks (u248 words)
    const packedBytes: string[] = [];
    const PACK_SIZE = 31;
    for (let i = 0; i < signedDataBytes.length; i += PACK_SIZE) {
      let chunk = 0n;
      const end = Math.min(i + PACK_SIZE, signedDataBytes.length);
      for (let j = i; j < end; j++) {
        chunk = chunk * 256n + BigInt(signedDataBytes[j]);
      }
      packedBytes.push(num.toHex(chunk));
    }

    const sig: string[] = [
      '0x4f415554485f4a57545f5631',               // OAUTH_JWT_V1 magic [0]
      num.toHex(signature.r),                       // session_r [1]
      num.toHex(signature.s),                       // session_s [2]
      sessionPubKey,                                // session_key [3]
      num.toHex(nonceParams.validUntil),            // valid_until [4]
      num.toHex(nonceParams.randomness),            // randomness [5]
      jwt_sub_felt,                                 // jwt_sub [6]
      session.nonce,                                // jwt_nonce [7]
      num.toHex(jwtClaims.exp),                    // jwt_exp [8]
      this.kidToFelt(kid),                          // jwt_kid [9]
      this.stringToFelt(jwtClaims.iss),            // jwt_iss [10]
      salt_hex,                                     // salt [11]
      this.stringToFelt(session.walletName || ''), // wallet_name [12]
      num.toHex(offsets.sub_offset),               // sub_offset [13]
      num.toHex(offsets.sub_len),                  // sub_len [14]
      num.toHex(offsets.nonce_offset),             // nonce_offset [15]
      num.toHex(offsets.nonce_len),                // nonce_len [16]
      num.toHex(offsets.kid_offset),               // kid_offset [17]
      num.toHex(offsets.kid_len),                  // kid_len [18]
      num.toHex(offsets.exp_offset),               // exp_offset [19]
      num.toHex(offsets.exp_len),                  // exp_len [20]
      num.toHex(offsets.iss_offset),               // iss_offset [21]
      num.toHex(offsets.iss_len),                  // iss_len [22]
      num.toHex(offsets.aud_offset),               // aud_offset [23]
      num.toHex(offsets.aud_len),                  // aud_len [24]
      num.toHex(864),                              // garaga_rsa_len [25]
      ...garagaCalldata,                           // Garaga RSA calldata [26-889]
      num.toHex(signedDataBytes.length),           // jwt_bytes_len [890]
      ...packedBytes,                              // packed JWT bytes [891+]
    ];

    // Append policy fields after JWT data
    const policy = session.sessionPolicy;
    sig.push(num.toHex(nonceParams.validAfter)); // valid_after

    if (policy) {
      const merkleRoot = policy.allowedContracts.length > 0
        ? OAuthWalletManager.computeMerkleRoot(policy.allowedContracts)
        : '0x0';
      sig.push(merkleRoot); // allowed_contracts_root
      sig.push(num.toHex(policy.maxCallsPerTx)); // max_calls_per_tx
      sig.push(num.toHex(policy.spendingLimits.length)); // spending_policies_count
      for (const limit of policy.spendingLimits) {
        sig.push(num.toHex(limit.token)); // token address
        const limitBig = BigInt(limit.limit);
        sig.push(num.toHex(limitBig & ((1n << 128n) - 1n))); // limit_low
        sig.push(num.toHex(limitBig >> 128n)); // limit_high
      }
    } else {
      sig.push('0x0'); // allowed_contracts_root (no restriction)
      sig.push(num.toHex(10)); // max_calls_per_tx (default)
      sig.push(num.toHex(0)); // spending_policies_count (none)
    }

    return sig;
  }



  /**
   * Get the current session
   */
  getSession(): OAuthSession | null {
    return this.session;
  }

  /**
   * Get the wallet address
   */
  getWalletAddress(): string | null {
    return this.session?.walletAddress || null;
  }

  /**
   * Get session private key for signing
   */
  getSessionPrivateKey(): string | null {
    return this.session?.sessionPrivateKey || null;
  }

  /**
   * Clear session
   */
  clearSession(): void {
    this.session = null;
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
      sessionStorage.removeItem(PRE_AUTH_STORAGE_KEY);
    }
  }

  /**
   * Update the session policy on the active session.
   * Call this before registerCurrentSession() to ensure the latest policy
   * is embedded in the JWT signature and stored on-chain.
   */
  updateSessionPolicy(policy: SessionKeyPolicy): void {
    if (this.session) {
      this.session.sessionPolicy = policy;
      this.persistSession();
    }
    // Also update defaultPolicy so future sessions pick it up
    this.defaultPolicy = policy;
  }

  /**
   * Update the default policy used for new sessions.
   * Does NOT update the current session — call updateSessionPolicy() for that.
   */
  updateDefaultPolicy(policy: SessionKeyPolicy): void {
    this.defaultPolicy = policy;
  }

  /**
   * Get the address seed manager.
   */
  getAddressSeedManager(): AddressSeedManager {
    return this.addressSeedManager;
  }

  /**
   * Check if session exists and is valid
   */
  hasValidSession(): boolean {
    if (!this.session?.jwt || !this.session.jwtClaims) {
      return false;
    }

    // Check JWT expiration
    const now = Math.floor(Date.now() / 1000);
    if (this.session.jwtClaims.exp < now) {
      return false;
    }

    return true;
  }

  /**
   * Try to restore session from storage
   */
  restoreSession(): boolean {
    if (typeof window === 'undefined') return false;
    try {
      const stored = sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (stored) {
        this.session = JSON.parse(stored);
        // Convert bigints back
        if (this.session?.nonceParams) {
          this.session.nonceParams.validAfter = BigInt(this.session.nonceParams.validAfter);
          this.session.nonceParams.validUntil = BigInt(this.session.nonceParams.validUntil);
          this.session.nonceParams.renewalDeadline = BigInt(this.session.nonceParams.renewalDeadline);
          this.session.nonceParams.randomness = BigInt(this.session.nonceParams.randomness);
        }
        if (this.session) {
          this.session.sessionPolicy = this.deserializePolicy((this.session as any).sessionPolicy) ?? this.defaultPolicy;

          // Migration: ensure walletName is set (fix old sessions)
          if (!this.session.walletName || this.session.walletName === '') {
            this.session.walletName = 'default';
            this.persistSession();
          }
        }
        return this.hasValidSession();
      }
    } catch {
      // Ignore parse errors
    }
    return false;
  }

  // ============== Private helpers ==============

  private serializePolicy(policy?: SessionKeyPolicy): any {
    if (!policy) return undefined;
    return {
      ...policy,
      spendingLimits: policy.spendingLimits.map(sl => ({
        ...sl,
        limit: sl.limit.toString(),
      })),
    };
  }

  private deserializePolicy(raw: any): SessionKeyPolicy | undefined {
    if (!raw) return undefined;
    return {
      ...raw,
      spendingLimits: (raw.spendingLimits || []).map((sl: any) => ({
        ...sl,
        limit: BigInt(sl.limit),
      })),
    };
  }

  private persistPreAuthSession(): void {
    if (typeof window === 'undefined') return;
    if (this.session) {
      const toStore = {
        ...this.session,
        nonceParams: {
          ...this.session.nonceParams,
          validAfter: this.session.nonceParams.validAfter.toString(),
          validUntil: this.session.nonceParams.validUntil.toString(),
          renewalDeadline: this.session.nonceParams.renewalDeadline.toString(),
          randomness: this.session.nonceParams.randomness.toString(),
        },
        sessionPolicy: this.serializePolicy(this.session.sessionPolicy),
      };
      sessionStorage.setItem(PRE_AUTH_STORAGE_KEY, JSON.stringify(toStore));
    }
  }

  /**
   * Freshen the session by generating a new session key pair.
   * This is used for auto-renewal when an existing session expires.
   * It preserves the JWT and wallet address but generates a new nonce and keys.
   */
  async freshenSession(): Promise<OAuthSession> {
    if (!this.session?.jwt) {
      throw new Error('No active session to freshen');
    }

    const oldSession = { ...this.session };

    // Generate NEW session key pair
    const STARK_CURVE_ORDER = BigInt('0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f');
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    let privateKeyBigInt = BigInt('0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    privateKeyBigInt = (privateKeyBigInt % (STARK_CURVE_ORDER - 1n)) + 1n;

    const sessionPrivateKey = '0x' + privateKeyBigInt.toString(16);
    const sessionPubKey = ec.starkCurve.getStarkKey(sessionPrivateKey);

    // Get current block timestamp
    const block = await this.provider.getBlock('latest');
    const currentTimestamp = BigInt(block.timestamp);
    // New nonce params with configured duration (timestamp-based)
    const nonceParams = NonceManager.generateNonceParams(
      sessionPubKey,
      currentTimestamp,
      BigInt(this.sessionDuration),
      BigInt(this.renewalGracePeriod)
    );

    const nonce = NonceManager.computeNonce(nonceParams);
    // Update session
    this.session = {
      ...this.session,
      sessionPrivateKey,
      sessionPubKey,
      nonceParams,
      nonce,
    };

    // Persist freshened session
    this.persistSession();

    return oldSession;
  }

  private restorePreAuthSession(): void {
    if (typeof window === 'undefined') return;
    try {
      // Try sessionStorage first (same-tab popup flow), then localStorage fallback (magic link redirect)
      const stored =
        sessionStorage.getItem(PRE_AUTH_STORAGE_KEY) ||
        localStorage.getItem('cavos_magic_link_pre_auth');
      if (stored) {
        const parsed = JSON.parse(stored);
        this.session = {
          ...parsed,
          nonceParams: {
            ...parsed.nonceParams,
            validAfter: BigInt(parsed.nonceParams.validAfter),
            validUntil: BigInt(parsed.nonceParams.validUntil),
            renewalDeadline: BigInt(parsed.nonceParams.renewalDeadline),
            randomness: BigInt(parsed.nonceParams.randomness),
          },
          sessionPolicy: this.deserializePolicy(parsed.sessionPolicy) ?? this.defaultPolicy,
        };
        // Clean up magic link pre-auth after restoring
        localStorage.removeItem('cavos_magic_link_pre_auth');
      }
    } catch {
      // Ignore
    }
  }

  private persistSession(): void {
    if (typeof window === 'undefined') return;
    if (this.session) {
      const toStore = {
        ...this.session,
        nonceParams: {
          ...this.session.nonceParams,
          validAfter: this.session.nonceParams.validAfter.toString(),
          validUntil: this.session.nonceParams.validUntil.toString(),
          renewalDeadline: this.session.nonceParams.renewalDeadline.toString(),
          randomness: this.session.nonceParams.randomness.toString(),
        },
        sessionPolicy: this.serializePolicy(this.session.sessionPolicy),
      };
      sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(toStore));
    }
  }

  private parseJWT(jwt: string): JWTClaims {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const payload = JSON.parse(atob(this.base64UrlToBase64(parts[1])));

    return {
      sub: payload.sub,
      nonce: payload.nonce,
      exp: payload.exp,
      iss: payload.iss,
      aud: Array.isArray(payload.aud) ? payload.aud[0] : payload.aud,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
    };
  }

  /**
   * Fetch the RSA modulus n of a JWKS key from the on-chain registry.
   * Returns the 24 limbs as an array of hex strings (little-endian, limb 0 = LSB).
   */
  private async fetchNFromRegistry(kid: string): Promise<string[]> {
    const kidFelt = this.kidToFelt(kid);
    const result = await this.provider.callContract({
      contractAddress: this.config.jwksRegistryAddress,
      entrypoint: 'get_key',
      calldata: [kidFelt],
    });
    // Slim JWKSKey: [n0..n23 (24 felt252), provider (felt252), valid_until (u64), is_active (bool)]
    // We only need the 24 n limbs (indices 0..23).
    return (result as string[]).slice(0, 24);
  }

  private extractKidFromJwt(jwt: string): string {
    const parts = jwt.split('.');
    const header = JSON.parse(atob(this.base64UrlToBase64(parts[0])));
    return header.kid || '';
  }

  private base64UrlToBase64(base64url: string): string {
    return base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .padEnd(base64url.length + (4 - (base64url.length % 4)) % 4, '=');
  }

  private base64UrlToBytes(base64url: string): Uint8Array {
    const base64 = this.base64UrlToBase64(base64url);
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  private bytesTo96Limbs(bytes: Uint8Array): string[] {
    // RSA-2048 signature/modulus is 256 bytes (Big-Endian).
    // We want 24 x 96-bit limbs in Little-Endian order (limb 0 = LSB).

    const limbs: string[] = [];
    const totalBits = bytes.length * 8;
    const limbBits = 96;
    const limbCount = 24;

    for (let i = 0; i < limbCount; i++) {
      let limb = 0n;
      const startBit = i * limbBits;
      for (let bit = 0; bit < limbBits; bit++) {
        const absoluteBit = startBit + bit;
        if (absoluteBit < totalBits) {
          const byteIdx = bytes.length - 1 - Math.floor(absoluteBit / 8);
          const bitIdxInByte = absoluteBit % 8;
          const bitValue = (BigInt(bytes[byteIdx]) >> BigInt(bitIdxInByte)) & 1n;
          limb |= (bitValue << BigInt(bit));
        }
      }
      limbs.push(num.toHex(limb));
    }
    return limbs;
  }

  private subToFelt(sub: string): string {
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

  // Must match Cairo's hash_utf8_bytes: poseidon_hash_span over ByteArray serialization.
  // Used for kid lookup/verification (registry key + assert_hashed_claim_match).
  private kidToFelt(kid: string): string {
    return hash.computePoseidonHashOnElements(
      CallData.compile(byteArray.byteArrayFromString(kid))
    );
  }

  private findClaimOffsets(jwt: string): ClaimOffsets {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const header = parts[0];
    const payload = parts[1];

    // Decode header and payload JSON to get claim values
    const headerJson = JSON.parse(atob(this.base64UrlToBase64(header)));
    const payloadJson = JSON.parse(atob(this.base64UrlToBase64(payload)));

    // Get claim values
    const subValue = payloadJson.sub || '';
    const nonceValue = payloadJson.nonce || '';
    const kidValue = headerJson.kid || '';
    const expValue = String(payloadJson.exp || '');
    const issValue = payloadJson.iss || '';
    const audValue = Array.isArray(payloadJson.aud) ? payloadJson.aud[0] : payloadJson.aud || '';

    // Get decoded strings to find positions
    const decodedPayload = atob(this.base64UrlToBase64(payload));
    const decodedHeader = atob(this.base64UrlToBase64(header));

    // Find offsets in the DECODED JSON strings
    // The contract will decode the base64 segment and look for claims at these offsets
    // Offsets are relative to each decoded segment, NOT to the full signedData

    const findStringClaimValueOffset = (decoded: string, key: string, value: string): number => {
      // Try exact pattern first (no space after colon)
      const exactPattern = `"${key}":"${value}"`;
      let idx = decoded.indexOf(exactPattern);
      if (idx >= 0) {
        // Offset is after "key":"
        return idx + key.length + 4; // 4 = `":"` + opening quote of value
      }

      // Try pattern with space after colon
      const spacedPattern = `"${key}": "${value}"`;
      idx = decoded.indexOf(spacedPattern);
      if (idx >= 0) {
        // Offset is after "key": "
        return idx + key.length + 5; // 5 = `": "` + opening quote of value
      }

      // Fallback: search for just the key and find the value
      const keyPattern = `"${key}"`;
      idx = decoded.indexOf(keyPattern);
      if (idx >= 0) {
        // Find the colon after the key
        const colonIdx = decoded.indexOf(':', idx + key.length + 2);
        if (colonIdx >= 0) {
          // Find the opening quote of the value
          const valueQuoteIdx = decoded.indexOf('"', colonIdx + 1);
          if (valueQuoteIdx >= 0) {
            return valueQuoteIdx + 1; // After the opening quote
          }
        }
      }

      return -1;
    };

    const findNumericClaimValueOffset = (decoded: string, key: string, value: string): number => {
      const exactPattern = `"${key}":${value}`;
      let idx = decoded.indexOf(exactPattern);
      if (idx >= 0) {
        return idx + key.length + 3; // 3 = `":`
      }

      const spacedPattern = `"${key}": ${value}`;
      idx = decoded.indexOf(spacedPattern);
      if (idx >= 0) {
        return idx + key.length + 4; // 4 = `": `
      }

      const keyPattern = `"${key}"`;
      idx = decoded.indexOf(keyPattern);
      if (idx >= 0) {
        const colonIdx = decoded.indexOf(':', idx + key.length + 2);
        if (colonIdx >= 0) {
          let valueIdx = colonIdx + 1;
          while (valueIdx < decoded.length && decoded[valueIdx] === ' ') {
            valueIdx += 1;
          }
          return valueIdx;
        }
      }

      return -1;
    };

    // Find offsets in the DECODED JSON strings
    // The contract will decode the base64 segment and look for claims at these offsets
    // Offsets are relative to each decoded segment, NOT to the full signedData

    // sub is in payload (decoded)
    const subValueStart = findStringClaimValueOffset(decodedPayload, 'sub', subValue);
    if (subValueStart < 0) {
      throw new Error(`Failed to find sub claim in JWT payload`);
    }

    // nonce is in payload (decoded)
    const nonceValueStart = findStringClaimValueOffset(decodedPayload, 'nonce', nonceValue);
    if (nonceValueStart < 0) {
      throw new Error(`Failed to find nonce claim in JWT payload`);
    }

    // kid is in header (decoded)
    const kidValueStart = findStringClaimValueOffset(decodedHeader, 'kid', kidValue);
    if (kidValueStart < 0) {
      throw new Error(`Failed to find kid claim in JWT header`);
    }

    const expValueStart = findNumericClaimValueOffset(decodedPayload, 'exp', expValue);
    if (expValueStart < 0) {
      throw new Error(`Failed to find exp claim in JWT payload`);
    }

    const issValueStart = findStringClaimValueOffset(decodedPayload, 'iss', issValue);
    if (issValueStart < 0) {
      throw new Error(`Failed to find iss claim in JWT payload`);
    }

    let audValueStart = findStringClaimValueOffset(decodedPayload, 'aud', audValue);
    if (audValueStart < 0 && Array.isArray(payloadJson.aud)) {
      const exactArrayPattern = `"aud":["${audValue}"`;
      let idx = decodedPayload.indexOf(exactArrayPattern);
      if (idx >= 0) {
        audValueStart = idx + exactArrayPattern.indexOf(audValue);
      } else {
        const spacedArrayPattern = `"aud": ["${audValue}"`;
        idx = decodedPayload.indexOf(spacedArrayPattern);
        if (idx >= 0) {
          audValueStart = idx + spacedArrayPattern.indexOf(audValue);
        }
      }
    }
    if (audValueStart < 0) {
      throw new Error(`Failed to find aud claim in JWT payload`);
    }

    return {
      sub_offset: subValueStart,
      sub_len: subValue.length,
      nonce_offset: nonceValueStart,
      nonce_len: nonceValue.length,
      kid_offset: kidValueStart,
      kid_len: kidValue.length,
      exp_offset: expValueStart,
      exp_len: expValue.length,
      iss_offset: issValueStart,
      iss_len: issValue.length,
      aud_offset: audValueStart,
      aud_len: audValue.length,
    };
  }

  /**
   * Register new user with email+password (Firebase)
   */
  async registerWithFirebase(email: string, password: string): Promise<OAuthSession> {
    if (!this.session) {
      await this.initializeSession();
    }

    const response = await fetch(`${this.backendUrl}/api/oauth/firebase/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password,
        nonce: this.session!.nonce,
        app_id: this.appId,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Registration failed');
    }

    const data = await response.json();

    // Handle verification required response
    if (data.status === 'verification_required') {
      // Store pending verification state
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('cavos_pending_verification', JSON.stringify({
          email,
          app_id: this.appId,
          timestamp: Date.now(),
        }));
      }

      // Import dynamically to avoid circular dependencies
      const { EmailVerificationRequiredError } = await import('./errors');
      throw new EmailVerificationRequiredError(
        data.message || 'Please check your email to verify your account before logging in',
        email
      );
    }

    const { jwt } = data;

    // Process JWT same as Google/Apple
    return this.processFirebaseJWT(jwt);
  }

  /**
   * Login existing user with email+password (Firebase)
   */
  async loginWithFirebase(email: string, password: string): Promise<OAuthSession> {
    if (!this.session) {
      await this.initializeSession();
    }

    const response = await fetch(`${this.backendUrl}/api/oauth/firebase/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password,
        nonce: this.session!.nonce,
        app_id: this.appId,
      }),
    });

    if (!response.ok) {
      const error = await response.json();

      // Handle email not verified error
      if (error.error === 'email_not_verified') {
        // Import dynamically to avoid circular dependencies
        const { EmailNotVerifiedError } = await import('./errors');
        throw new EmailNotVerifiedError(
          error.message || 'Please verify your email before logging in',
          email
        );
      }

      throw new Error(error.error || 'Login failed');
    }

    const { jwt } = await response.json();

    return this.processFirebaseJWT(jwt);
  }

  /**
   * Check if email is verified for the app
   */
  async checkEmailVerification(email: string): Promise<boolean> {
    try {
      const response = await fetch(
        `${this.backendUrl}/api/oauth/firebase/check-verification?app_id=${this.appId}&email=${encodeURIComponent(email)}`
      );

      if (!response.ok) {
        return false;
      }

      const { verified } = await response.json();
      return verified;
    } catch (error) {
      return false;
    }
  }

  /**
   * Resend verification email
   */
  async resendVerificationEmail(email: string): Promise<void> {
    const response = await fetch(`${this.backendUrl}/api/oauth/firebase/resend-verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, app_id: this.appId }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to resend verification email');
    }

  }

  /**
   * Send a magic link email (passwordless sign-in)
   * Initializes a fresh session key+nonce, persists pre-auth session to
   * sessionStorage, then asks the backend to send the branded email.
   */
  async sendMagicLink(email: string): Promise<void> {
    if (!this.session) {
      await this.initializeSession();
    }

    // Persist pre-auth to localStorage so it survives a mobile redirect (cross-tab)
    if (typeof window !== 'undefined' && this.session) {
      try {
        const toStore = {
          ...this.session,
          nonceParams: {
            ...this.session.nonceParams,
            validAfter: this.session.nonceParams.validAfter.toString(),
            validUntil: this.session.nonceParams.validUntil.toString(),
            renewalDeadline: this.session.nonceParams.renewalDeadline.toString(),
            randomness: this.session.nonceParams.randomness.toString(),
          },
          sessionPolicy: this.serializePolicy(this.session.sessionPolicy),
        };
        localStorage.setItem('cavos_magic_link_pre_auth', JSON.stringify(toStore));
      } catch { /* ignore */ }
    }

    const redirect_uri = typeof window !== 'undefined' ? window.location.href : undefined;
    const response = await fetch(`${this.backendUrl}/api/oauth/firebase/magic-link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, nonce: this.session!.nonce, app_id: this.appId, redirect_uri }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to send magic link');
    }
  }

  /**
   * Process Firebase JWT (same as Google/Apple)
   */
  private async processFirebaseJWT(jwt: string): Promise<OAuthSession> {
    if (!this.session) {
      throw new Error('No session initialized');
    }

    // Parse JWT
    const jwtClaims = this.parseJWT(jwt);

    // Verify nonce matches
    if (jwtClaims.nonce !== this.session.nonce) {
      throw new Error('JWT nonce does not match session nonce. Possible replay attack.');
    }

    // Compute address seed and wallet address
    const addressSeed = this.addressSeedManager.computeAddressSeed(
      jwtClaims.iss,
      jwtClaims.sub,
    );

    const walletAddress = this.addressSeedManager.computeContractAddress(
      jwtClaims.iss,
      jwtClaims.sub,
      this.config.cavosAccountClassHash,
      this.config.jwksRegistryAddress,
    );

    // Update session with JWT data
    this.session = {
      ...this.session,
      jwt,
      jwtClaims,
      addressSeed,
      walletAddress,
    };

    // Persist full session
    this.persistSession();

    return this.session;
  }

  // ============== Merkle Tree Utilities ==============

  /**
   * Compute Merkle root from a list of allowed contract addresses.
   * Uses Poseidon hash, matching the on-chain verification.
   * Leaves are sorted for deterministic tree construction.
   */
  static computeMerkleRoot(contracts: string[]): string {
    if (contracts.length === 0) return '0x0';

    // Hash each contract address to get leaves
    // Uses computePoseidonHashOnElements([c]) which matches Cairo's
    // PoseidonTrait::new().update(contract).finalize()
    let leaves = contracts.map(c =>
      hash.computePoseidonHashOnElements([num.toHex(c)])
    );

    // Sort leaves for deterministic ordering
    leaves.sort((a, b) => {
      const aBig = BigInt(a);
      const bBig = BigInt(b);
      if (aBig < bBig) return -1;
      if (aBig > bBig) return 1;
      return 0;
    });

    // Build tree bottom-up
    while (leaves.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < leaves.length; i += 2) {
        if (i + 1 < leaves.length) {
          const left = leaves[i];
          const right = leaves[i + 1];
          // Sorted pair hashing (matches contract's PoseidonTrait)
          const leftBig = BigInt(left);
          const rightBig = BigInt(right);
          if (leftBig < rightBig) {
            nextLevel.push(hash.computePoseidonHashOnElements([left, right]));
          } else {
            nextLevel.push(hash.computePoseidonHashOnElements([right, left]));
          }
        } else {
          nextLevel.push(leaves[i]);
        }
      }
      leaves = nextLevel;
    }

    return leaves[0];
  }

  /**
   * Compute Merkle proof for a given contract address.
   * Returns the sibling hashes needed to verify the leaf.
   */
  static computeMerkleProof(contracts: string[], targetContract: string): string[] {
    if (contracts.length === 0) return [];

    // Hash each contract address to get leaves (must match computeMerkleRoot)
    let leaves = contracts.map(c =>
      hash.computePoseidonHashOnElements([num.toHex(c)])
    );

    // Sort leaves for deterministic ordering
    leaves.sort((a, b) => {
      const aBig = BigInt(a);
      const bBig = BigInt(b);
      if (aBig < bBig) return -1;
      if (aBig > bBig) return 1;
      return 0;
    });

    // Find target leaf
    const targetLeaf = hash.computePoseidonHashOnElements([num.toHex(targetContract)]);
    let targetIdx = leaves.indexOf(targetLeaf);
    if (targetIdx === -1) return [];

    const proof: string[] = [];
    let currentLevel = [...leaves];

    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      let nextTargetIdx = -1;

      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          const left = currentLevel[i];
          const right = currentLevel[i + 1];

          // Add sibling to proof if target is in this pair
          if (i === targetIdx || i + 1 === targetIdx) {
            proof.push(i === targetIdx ? right : left);
            nextTargetIdx = Math.floor(i / 2);
          }

          const leftBig = BigInt(left);
          const rightBig = BigInt(right);
          if (leftBig < rightBig) {
            nextLevel.push(hash.computePoseidonHashOnElements([left, right]));
          } else {
            nextLevel.push(hash.computePoseidonHashOnElements([right, left]));
          }
        } else {
          // Odd leaf, promoted
          if (i === targetIdx) {
            nextTargetIdx = Math.floor(i / 2);
          }
          nextLevel.push(currentLevel[i]);
        }
      }

      currentLevel = nextLevel;
      targetIdx = nextTargetIdx;
    }

    return proof;
  }
}
