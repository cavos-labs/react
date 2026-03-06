/**
 * OAuthWalletManager - Manages OAuth-based wallet authentication
 *
 * Handles:
 * - Session key generation and management
 * - OAuth redirect flow with nonce
 * - JWT parsing and storage
 * - Session persistence across page reloads
 */

import {
  CallData,
  byteArray,
  ec,
  num,
  hash,
  RpcProvider,
  typedData,
  type TypedData,
  type Signature,
} from 'starknet';
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
}

const SESSION_STORAGE_KEY = 'cavos_oauth_session';
const PRE_AUTH_STORAGE_KEY = 'cavos_oauth_pre_auth';

// ── Schwartz-Zippel RSA witness generation (Tier 5) ────────────────────────────
// With carry polynomial (BigT) for correct polynomial identity verification.
//
// Integer: a² = q·n + r
// Polynomial: A(X)² - Q(X)·N(X) - R(X) = (X - B) · T(X)  where B = 2^123
// Batched: BigT = Σ αⁱ · Tᵢ  (32 coefficients, degree 31)

/** The Stark prime p = 2^251 + 17·2^192 + 1 */
const STARK_PRIME = 3618502788666131213697322783095070105623107215331596699973092056135872020481n;

/** Safe proof base for the Schwartz-Zippel construction: B = 2^123 */
const PROOF_LIMB_BASE = 1n << 123n;
const PROOF_LIMB_COUNT = 17;
const RAW_RSA_LIMB_BASE = 1n << 128n;

/** Modular reduction: returns x mod p in [0, p). Handles negative values. */
function modp(x: bigint): bigint {
  const r = x % STARK_PRIME;
  return r < 0n ? r + STARK_PRIME : r;
}

interface RSAWitnesses {
  /** x1..x16: 16 squarings of sig (each as 17 proof limbs, little-endian) */
  intermediates: bigint[][];
  /** sig^65537 mod n (17 proof limbs, little-endian) */
  result: bigint[];
  /** q1..q17: quotients for squarings and final mul (each 17 proof limbs) */
  quotients: bigint[][];
  /** BigT carry polynomial — 32 felt252 coefficients (degree 31) */
  carryCoeffs: bigint[];
}

/** Convert a bigint to 17 × 123-bit proof limbs in little-endian order. */
function bigIntToProofLimbs(n: bigint): bigint[] {
  const limbs: bigint[] = [];
  const MASK = PROOF_LIMB_BASE - 1n;
  for (let i = 0; i < PROOF_LIMB_COUNT; i++) {
    limbs.push((n >> (BigInt(i) * 123n)) & MASK);
  }
  return limbs;
}

/**
 * Polynomial convolution: compute coefficients of P(X) = A(X) · B(X) mod p.
 * Both inputs have 17 coefficients (degree 16); output has 33 (degree 32).
 */
function polyConv(a: bigint[], b: bigint[]): bigint[] {
  const result: bigint[] = new Array(a.length + b.length - 1).fill(0n);
  for (let i = 0; i < a.length; i++) {
    for (let j = 0; j < b.length; j++) {
      result[i + j] = modp(result[i + j] + modp(a[i] * b[j]));
    }
  }
  return result;
}

/**
 * Synthetic division of polynomial P(X) by (X - B) in F_p.
 * P must satisfy P(B) ≡ 0 (mod p).
 * Input: coefficients [c0, c1, ..., c_n] of degree n polynomial.
 * Output: coefficients of degree (n-1) quotient polynomial.
 */
function syntheticDivByXMinusB(coeffs: bigint[], B: bigint): bigint[] {
  const n = coeffs.length - 1; // degree of input
  const t: bigint[] = new Array(n).fill(0n);
  // Start from highest degree: t[n-1] = c[n]
  t[n - 1] = modp(coeffs[n]);
  // Work downward: t[k] = c[k+1] + B · t[k+1]
  for (let k = n - 2; k >= 0; k--) {
    t[k] = modp(coeffs[k + 1] + modp(B * t[k + 1]));
  }
  // Verify: remainder = c[0] + B · t[0] should be 0 mod p
  // (Skip assertion in production — the on-chain check will catch errors)
  return t;
}

/**
 * Compute Poseidon hash matching Cairo's poseidon_hash_span.
 * Uses the already-imported starknet.js `hash` module.
 */
function poseidonHashMany(values: bigint[]): bigint {
  const hexValues = values.map((v) => '0x' + v.toString(16));
  const result = hash.computePoseidonHashOnElements(hexValues);
  return BigInt(result);
}

/**
 * Precompute RSA witnesses for sig^65537 mod n via 16 squarings + 1 final mul.
 * Includes the carry polynomial BigT for correct Schwartz-Zippel verification.
 *
 * Witness layout:
 *   x0  = sig
 *   x_i = x_{i-1}^2 mod n     (i = 1..16)
 *   result = x16 * sig mod n   (= sig^65537 mod n)
 *   q_i s.t. x_{i-1}^2 = q_i * n + x_i     (i = 1..16)
 *   q_17 s.t. x16 * sig = q_17 * n + result
 *   BigT: carry polynomial s.t. Σ αⁱ · Cᵢ(X) = (X - B) · BigT(X)
 */
function generateRSAWitnesses(sig: bigint, n: bigint): RSAWitnesses {
  const steps: bigint[] = [sig];
  const quotients: bigint[][] = [];
  let curr = sig;

  for (let i = 0; i < 16; i++) {
    const sq = curr * curr;
    const q = sq / n;
    quotients.push(bigIntToProofLimbs(q));
    curr = sq % n;
    steps.push(curr);
  }

  // Final: result = x16 * sig mod n  (sig^{65536} * sig = sig^{65537})
  const finalProd = curr * sig;
  const finalQ = finalProd / n;
  quotients.push(bigIntToProofLimbs(finalQ));
  const result = finalProd % n;

  const intermediateLimbs = steps.slice(1).map(bigIntToProofLimbs);
  const resultLimbs = bigIntToProofLimbs(result);
  const nLimbs = bigIntToProofLimbs(n).map(modp);
  const sigLimbs = bigIntToProofLimbs(sig).map(modp);

  // ── Compute carry polynomials for each step ──────────────────────────────────
  // For each step i: C_i(X) = A_i(X)² - Q_i(X)·N(X) - R_i(X)
  // where A_0 = sig, A_i = intermediates[i-1] for squaring steps
  // T_i(X) = C_i(X) / (X - B)    (in F_p)
  const carryPolys: bigint[][] = [];
  const B = modp(PROOF_LIMB_BASE);

  // Squaring steps (i = 0..15)
  for (let i = 0; i < 16; i++) {
    const aLimbs = (i === 0 ? sigLimbs : intermediateLimbs[i - 1]).map(modp);
    const qLimbs = quotients[i].map(modp);
    const rLimbs = intermediateLimbs[i].map(modp);

    // C = A·A - Q·N - R (polynomial coefficients mod p)
    const aa = polyConv(aLimbs, aLimbs);
    const qn = polyConv(qLimbs, nLimbs);

    const C: bigint[] = new Array(33).fill(0n);
    for (let k = 0; k < 33; k++) {
      let val = aa[k] ?? 0n;
      val = modp(val - (qn[k] ?? 0n));
      if (k < PROOF_LIMB_COUNT) val = modp(val - rLimbs[k]);
      C[k] = val;
    }

    const T = syntheticDivByXMinusB(C, B);
    carryPolys.push(T); // 32 coefficients each
  }

  // Final multiplication step: C_17 = prev·sig - Q_17·N - result
  {
    const prevLimbs = intermediateLimbs[15].map(modp); // x_16
    const qLimbs = quotients[16].map(modp);
    const rLimbs = resultLimbs.map(modp);

    const ps = polyConv(prevLimbs, sigLimbs);
    const qn = polyConv(qLimbs, nLimbs);

    const C: bigint[] = new Array(33).fill(0n);
    for (let k = 0; k < 33; k++) {
      let val = ps[k] ?? 0n;
      val = modp(val - (qn[k] ?? 0n));
      if (k < PROOF_LIMB_COUNT) val = modp(val - rLimbs[k]);
      C[k] = val;
    }

    const T = syntheticDivByXMinusB(C, B);
    carryPolys.push(T);
  }

  // ── Derive α and compute BigT = Σ αⁱ · Tᵢ ─────────────────────────────────
  // Phase I hash: Poseidon(sig_limbs, n_limbs, intermediate_limbs, result_limbs, quotient_limbs)
  const phase1Values: bigint[] = [];
  // sig (17 proof limbs)
  phase1Values.push(...sigLimbs);
  // n (17 proof limbs)
  phase1Values.push(...nLimbs);
  // intermediates x1..x16 (16 × 17 = 272 limbs)
  for (const inter of intermediateLimbs) {
    phase1Values.push(...inter.map(modp));
  }
  // result (17 proof limbs)
  phase1Values.push(...resultLimbs.map(modp));
  // quotients q1..q17 (17 × 17 = 289 limbs)
  for (const q of quotients) {
    phase1Values.push(...q.map(modp));
  }

  const alpha = poseidonHashMany(phase1Values);

  // BigT[k] = Σ αⁱ · Tᵢ[k]  for k = 0..31
  const bigT: bigint[] = new Array(32).fill(0n);
  let alphaPow = 1n;
  for (let i = 0; i < 17; i++) {
    for (let k = 0; k < 32; k++) {
      bigT[k] = modp(bigT[k] + modp(alphaPow * carryPolys[i][k]));
    }
    alphaPow = modp(alphaPow * alpha);
  }

  return {
    intermediates: intermediateLimbs,
    result: resultLimbs,
    quotients,
    carryCoeffs: bigT,
  };
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

    // If session exists and has a sub claim, re-compute the wallet address
    if (this.session?.jwtClaims?.sub) {
      const sub = this.session.jwtClaims.sub;

      // Re-compute with new salt and current name
      const newAddressSeed = this.addressSeedManager.computeAddressSeed(sub, this.session.walletName);
      const newWalletAddress = this.addressSeedManager.computeContractAddress(
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

    const sub = this.session.jwtClaims.sub;
    const addressSeed = this.addressSeedManager.computeAddressSeed(sub, name);
    const walletAddress = this.addressSeedManager.computeContractAddress(
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
    const addressSeed = this.addressSeedManager.computeAddressSeed(jwtClaims.sub, this.session.walletName);

    const walletAddress = this.addressSeedManager.computeContractAddress(
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

    // Clear pre-auth session
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem(PRE_AUTH_STORAGE_KEY);
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
  signMessage(typedDataInput: TypedData): Signature {
    if (!this.session?.sessionPrivateKey || !this.session.walletAddress) {
      throw new Error('No active session. Please login first.');
    }

    // Compute the message hash from typed data
    const messageHash = typedData.getMessageHash(typedDataInput, this.session.walletAddress);

    // Sign with session key
    const signature = ec.starkCurve.sign(messageHash, this.session.sessionPrivateKey);

    return [num.toHex(signature.r), num.toHex(signature.s)];
  }

  /**
   * Build the full JWT signature data for on-chain JWT verification (OAUTH_JWT_V1).
   * This performs expensive RSA verification and registers the session.
   * Only use during deployment - subsequent transactions should use buildSessionSignature().
   *
   * Signature format with claim offsets, witnesses, and policy fields (Tier 5):
   * [0]      = OAUTH_JWT_V1 magic
   * [1-3]    = session key (r, s, pubkey)
   * [4-5]    = valid_until, randomness
   * [6-13]   = jwt_sub, jwt_nonce, jwt_exp, jwt_kid, jwt_iss, jwt_aud, salt, wallet_name
   * [14-19]  = claim offsets (sub_offset, sub_len, nonce_offset, nonce_len, kid_offset, kid_len)
   * [20]     = RSA sig length (16)
   * [21-36]  = RSA signature (16 u128 limbs)
   * [37]     = witnesses_len (610)
   * [38-309] = intermediates x1..x16 (16×17 proof limbs)
   * [310-326]= result (17 proof limbs, sig^65537 mod n)
   * [327-615]= quotients q1..q17 (17×17 proof limbs)
   * [616-647]= BigT carry polynomial (32 felt252 coefficients)
   * [648]    = jwt_bytes_len
   * [649+]   = packed JWT bytes (31-byte chunks)
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
    const rsaLimbs = this.bytesToU128Limbs(rsaSignature);

    // Convert RSA sig limbs to bigint (little-endian: limb[0] is LSB)
    const sigBigInt = rsaLimbs.reduce(
      (acc: bigint, limb: string, i: number) => acc + BigInt(limb) * (RAW_RSA_LIMB_BASE ** BigInt(i)),
      0n,
    );

    // Fetch the RSA modulus n from the on-chain registry in 17 x 123-bit proof limbs
    // and reconstruct the integer modulus.
    const kid = this.extractKidFromJwt(jwt);
    const nLimbHexes = await this.fetchNFromRegistry(kid);
    const nBigInt = nLimbHexes.reduce(
      (acc: bigint, limb: string, i: number) => acc + BigInt(limb) * (PROOF_LIMB_BASE ** BigInt(i)),
      0n,
    );

    if (nBigInt === 0n) {
      throw new Error(
        `JWKS key not found or invalid: kid="${kid}" is not registered in the on-chain JWKS registry. ` +
        `Make sure the JWKS registry has been populated for this network.`
      );
    }

    // Generate Schwartz-Zippel witnesses for sig^65537 mod n (with carry polynomial)
    const witnesses = generateRSAWitnesses(sigBigInt, nBigInt);
    const h = (v: bigint) => num.toHex(v);

    // Get signed data (header.payload)
    const signedData = `${jwtParts[0]}.${jwtParts[1]}`;
    const signedDataBytes = new TextEncoder().encode(signedData);

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
      this.hashStringToFelt(kid),                   // jwt_kid [9]
      this.stringToFelt(jwtClaims.iss),            // jwt_iss [10]
      this.stringToFelt(jwtClaims.aud),            // jwt_aud [11]
      salt_hex,                                     // salt [12]
      this.stringToFelt(session.walletName || ''), // wallet_name [13]
      num.toHex(offsets.sub_offset),               // sub_offset [14]
      num.toHex(offsets.sub_len),                  // sub_len [15]
      num.toHex(offsets.nonce_offset),             // nonce_offset [16]
      num.toHex(offsets.nonce_len),                // nonce_len [17]
      num.toHex(offsets.kid_offset),               // kid_offset [18]
      num.toHex(offsets.kid_len),                  // kid_len [19]
      num.toHex(16),                               // rsa_sig_len [20]
      ...rsaLimbs,                                 // RSA sig (16 u128 limbs) [21-36]
      num.toHex(610),                              // witnesses_len [37]
      // intermediates x1..x16: 16 × 17 = 272 felts [38-309]
      ...witnesses.intermediates.flatMap((limbs) => limbs.map(h)),
      // result (17 felts) [310-326]
      ...witnesses.result.map(h),
      // quotients q1..q17: 17 × 17 = 289 felts [327-615]
      ...witnesses.quotients.flatMap((limbs) => limbs.map(h)),
      // BigT carry polynomial: 32 felt252 coefficients [616-647]
      ...witnesses.carryCoeffs.map(h),
      num.toHex(signedDataBytes.length),           // jwt_bytes_len [648]
      ...packedBytes,                              // packed JWT bytes [649+]
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
      const stored = sessionStorage.getItem(PRE_AUTH_STORAGE_KEY);
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
   * Returns the 17 proof limbs as an array of hex strings (little-endian, limb 0 = LSB).
   */
  private async fetchNFromRegistry(kid: string): Promise<string[]> {
    const kidFelt = this.hashStringToFelt(kid);
    const result = await this.provider.callContract({
      contractAddress: this.config.jwksRegistryAddress,
      entrypoint: 'get_key',
      calldata: [kidFelt],
    });
    // Slim JWKSKey: [n0..n16 (17 x 123-bit limbs), provider, valid_until, is_active]
    return (result as string[]).slice(0, 17);
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

  private bytesToU128Limbs(bytes: Uint8Array): string[] {
    // RSA-2048 signature/modulus is 256 bytes (Big-Endian).
    // We want 16 x 128-bit limbs in Little-Endian order (limb 0 = LSB).

    const limbs: string[] = [];

    // Process 16-byte chunks.
    // i=15 corresponds to the last 16 bytes (LSB of the number).
    // so we iterate i from 15 down to 0 to get limbs for index 0 to 15?
    // Wait, if we want limbs[0] to be LSB, we should push the LSB limb first.
    // The LSB limb comes from the END of the byte array (bytes 240-255).
    // So if loop i=15 (bytes 240-255), we make that limb and push it.

    for (let i = 15; i >= 0; i--) {
      // Construct 128-bit limb from 16 bytes.
      // Bytes are Big-Endian within the chunk.
      // byte[i*16] is the MSB of this chunk.
      // byte[i*16 + 15] is the LSB of this chunk.

      let limb = 0n;
      for (let j = 0; j < 16; j++) {
        const byteIdx = i * 16 + j;
        if (byteIdx < bytes.length) {
          limb = (limb * 256n) + BigInt(bytes[byteIdx]);
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

  private hashStringToFelt(str: string): string {
    const value = byteArray.byteArrayFromString(str);
    return hash.computePoseidonHashOnElements(CallData.compile(value));
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

    // Get decoded strings to find positions
    const decodedPayload = atob(this.base64UrlToBase64(payload));
    const decodedHeader = atob(this.base64UrlToBase64(header));

    // Find offsets in the DECODED JSON strings
    // The contract will decode the base64 segment and look for claims at these offsets
    // Offsets are relative to each decoded segment, NOT to the full signedData

    // Helper to find claim value start offset in decoded JSON
    // Searches for the pattern "key":"value" or "key": "value" (with optional space)
    const findClaimValueOffset = (decoded: string, key: string, value: string): number => {
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

    // Find offsets in the DECODED JSON strings
    // The contract will decode the base64 segment and look for claims at these offsets
    // Offsets are relative to each decoded segment, NOT to the full signedData

    // sub is in payload (decoded)
    const subValueStart = findClaimValueOffset(decodedPayload, 'sub', subValue);
    if (subValueStart < 0) {
      throw new Error(`Failed to find sub claim in JWT payload`);
    }

    // nonce is in payload (decoded)
    const nonceValueStart = findClaimValueOffset(decodedPayload, 'nonce', nonceValue);
    if (nonceValueStart < 0) {
      throw new Error(`Failed to find nonce claim in JWT payload`);
    }

    // kid is in header (decoded)
    const kidValueStart = findClaimValueOffset(decodedHeader, 'kid', kidValue);
    if (kidValueStart < 0) {
      throw new Error(`Failed to find kid claim in JWT header`);
    }

    return {
      sub_offset: subValueStart,
      sub_len: subValue.length,
      nonce_offset: nonceValueStart,
      nonce_len: nonceValue.length,
      kid_offset: kidValueStart,
      kid_len: kidValue.length,
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
    const addressSeed = this.addressSeedManager.computeAddressSeed(jwtClaims.sub);

    const walletAddress = this.addressSeedManager.computeContractAddress(
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
