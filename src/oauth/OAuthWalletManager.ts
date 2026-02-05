/**
 * OAuthWalletManager - Manages OAuth-based wallet authentication
 *
 * Handles:
 * - Ephemeral key generation and management
 * - OAuth redirect flow with nonce
 * - JWT parsing and storage
 * - Session persistence across page reloads
 */

import { ec, encode, num, hash, RpcProvider } from 'starknet';
import { NonceManager, NonceParams } from './NonceManager';
import { AddressSeedManager } from './AddressSeedManager';
import { OAuthWalletConfig } from '../types/config';

export interface OAuthSession {
  /** Ephemeral private key (hex) */
  ephemeralPrivateKey: string;
  /** Ephemeral public key (hex) */
  ephemeralPubKey: string;
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
}

export interface JWTClaims {
  sub: string;
  nonce: string;
  exp: number;
  iss: string;
  aud: string;
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

export class OAuthWalletManager {
  private config: OAuthWalletConfig;
  private backendUrl: string;
  private appId: string;
  private provider: RpcProvider;
  private session: OAuthSession | null = null;
  private addressSeedManager: AddressSeedManager;
  private sessionDuration: number;
  private renewalGracePeriod: number;

  constructor(
    config: OAuthWalletConfig,
    backendUrl: string,
    appId: string,
    rpcUrl: string,
    sessionConfig?: { sessionDuration?: number; renewalGracePeriod?: number }
  ) {
    this.config = config;
    this.backendUrl = backendUrl;
    this.appId = appId;
    this.provider = new RpcProvider({ nodeUrl: rpcUrl });
    this.addressSeedManager = new AddressSeedManager(config.salt || '0');
    this.sessionDuration = sessionConfig?.sessionDuration || 2880; // ~24 hours at 30s/block
    this.renewalGracePeriod = sessionConfig?.renewalGracePeriod || 2880; // ~24 hours
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
      const deployerAddress = this.config.deployerContractAddress || '0x0';

      // Re-compute with new salt
      const newAddressSeed = this.addressSeedManager.computeAddressSeed(sub);
      const newWalletAddress = this.addressSeedManager.computeContractAddress(
        sub,
        this.config.cavosAccountClassHash,
        this.config.jwksRegistryAddress,
        deployerAddress
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
   * Generate a new session with fresh ephemeral key (for renewal).
   * Returns a complete OAuthSession that can be used for renewal.
   */
  async generateNewSession(): Promise<OAuthSession> {
    const currentSession = this.getSession();
    if (!currentSession?.walletAddress || !currentSession.jwtClaims?.sub) {
      throw new Error('No current session to renew from');
    }

    // Generate ephemeral key pair
    const STARK_CURVE_ORDER = BigInt('0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f');

    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    let privateKeyBigInt = BigInt('0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join(''));

    privateKeyBigInt = (privateKeyBigInt % (STARK_CURVE_ORDER - 1n)) + 1n;

    const ephemeralPrivateKey = '0x' + privateKeyBigInt.toString(16);
    const ephemeralPubKey = ec.starkCurve.getStarkKey(ephemeralPrivateKey);

    // Get current block number
    const block = await this.provider.getBlockNumber();
    const currentBlock = BigInt(block);

    // Generate nonce params
    const nonceParams = NonceManager.generateNonceParams(
      ephemeralPubKey,
      currentBlock,
      BigInt(this.sessionDuration),
      BigInt(this.renewalGracePeriod)
    );

    const nonce = NonceManager.computeNonce(nonceParams);

    // Create new session object reusing current session data
    const newSession: OAuthSession = {
      ...currentSession,
      ephemeralPrivateKey,
      ephemeralPubKey,
      nonceParams,
      nonce,
    };

    return newSession;
  }

  /**
   * Initialize a new OAuth session before redirecting to OAuth provider
   * Generates ephemeral key and computes nonce
   */
  async initializeSession(): Promise<{ nonce: string }> {
    // Generate ephemeral key pair
    // Stark curve order is approximately 2^251, so we generate random bytes and reduce mod order
    const STARK_CURVE_ORDER = BigInt('0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f');

    // Generate 32 random bytes and convert to BigInt
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    let privateKeyBigInt = BigInt('0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join(''));

    // Reduce modulo curve order and ensure it's >= 1
    privateKeyBigInt = (privateKeyBigInt % (STARK_CURVE_ORDER - 1n)) + 1n;

    const ephemeralPrivateKey = '0x' + privateKeyBigInt.toString(16);
    const ephemeralPubKey = ec.starkCurve.getStarkKey(ephemeralPrivateKey);

    // Get current block number for max_block calculation
    const block = await this.provider.getBlockNumber();
    const currentBlock = BigInt(block);

    // Generate nonce params with configured duration
    const nonceParams = NonceManager.generateNonceParams(
      ephemeralPubKey,
      currentBlock,
      BigInt(this.sessionDuration),
      BigInt(this.renewalGracePeriod)
    );

    // Compute nonce
    const nonce = NonceManager.computeNonce(nonceParams);

    // Create session object
    this.session = {
      ephemeralPrivateKey,
      ephemeralPubKey,
      nonceParams,
      nonce,
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
    // Restore pre-auth session (ephemeral key + nonce)
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
    const addressSeed = this.addressSeedManager.computeAddressSeed(jwtClaims.sub);
    const deployerAddress = this.config.deployerContractAddress || '0x0';

    const walletAddress = this.addressSeedManager.computeContractAddress(
      jwtClaims.sub,
      this.config.cavosAccountClassHash,
      this.config.jwksRegistryAddress,
      deployerAddress
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

    // Clear pre-auth session
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem(PRE_AUTH_STORAGE_KEY);
    }

    return this.session;
  }

  /**
   * Build a lightweight session signature for transactions (SESSION_V1).
   * Only includes ephemeral key signature - much cheaper for paymaster transactions.
   * Requires the session to be registered first (via deployment with full JWT).
   */
  buildSessionSignature(transactionHash: string): string[] {
    if (!this.session?.ephemeralPrivateKey || !this.session.ephemeralPubKey) {
      throw new Error('No ephemeral key in session');
    }

    const { ephemeralPrivateKey, ephemeralPubKey } = this.session;

    // Sign the transaction hash with the ephemeral key
    const signature = ec.starkCurve.sign(transactionHash, ephemeralPrivateKey);

    // Build lightweight session signature
    const sig: string[] = [
      '0x53455353494f4e5f5631', // SESSION_V1 magic
      num.toHex(signature.r),    // eph_r
      num.toHex(signature.s),    // eph_s
      ephemeralPubKey,           // eph_pubkey
    ];

    return sig;
  }

  /**
   * Build the full JWT signature data for on-chain JWT verification (OAUTH_JWT_V1).
   * This performs expensive RSA verification and registers the session.
   * Only use during deployment - subsequent transactions should use buildSessionSignature().
   *
   * New signature format with claim offsets:
   * [0]  = OAUTH_JWT_V1 magic
   * [1-3] = ephemeral key (r, s, pubkey)
   * [4-5] = max_block, randomness
   * [6-12] = jwt_sub, jwt_nonce, jwt_exp, jwt_kid, jwt_iss, jwt_aud, salt
   * [13-14] = sub_offset, sub_len (NEW)
   * [15-16] = nonce_offset, nonce_len (NEW)
   * [17-18] = kid_offset, kid_len (NEW)
   * [19] = RSA sig length (16)
   * [20-35] = RSA signature (16 u128 limbs)
   * [36] = JWT data length
   * [37+] = JWT bytes
   */
  async buildJWTSignatureData(transactionHash: string): Promise<string[]> {
    if (!this.session?.jwt || !this.session.jwtClaims) {
      throw new Error('No JWT in session');
    }
    const { jwt, ephemeralPrivateKey, ephemeralPubKey, addressSeed } = this.session;
    const jwtClaims = this.session.jwtClaims;
    const nonceParams = this.session.nonceParams;

    // Sign the transaction hash with the ephemeral key
    const signature = ec.starkCurve.sign(transactionHash, ephemeralPrivateKey);

    // Extract RSA signature from JWT
    const jwtParts = jwt.split('.');
    const rsaSignature = this.base64UrlToBytes(jwtParts[2]);
    const rsaLimbs = this.bytesToU128Limbs(rsaSignature);

    // Get signed data (header.payload)
    const signedData = `${jwtParts[0]}.${jwtParts[1]}`;
    const signedDataBytes = new TextEncoder().encode(signedData);

    // Find claim offsets for on-chain verification (NEW)
    const offsets = this.findClaimOffsets(jwt);

    // Build signature array matching contract format
    const jwt_sub_felt = this.subToFelt(jwtClaims.sub);
    const salt_hex = num.toHex(this.config.salt || '0x0');

    // Optimization: Pack signedDataBytes into 31-byte chunks (u248 words)
    // This significantly reduces calldata size and processing steps on-chain.
    const packedBytes: string[] = [];
    const PACK_SIZE = 31;
    for (let i = 0; i < signedDataBytes.length; i += PACK_SIZE) {
      let chunk = 0n;
      const end = Math.min(i + PACK_SIZE, signedDataBytes.length);
      for (let j = i; j < end; j++) {
        chunk = (chunk * 256n) + BigInt(signedDataBytes[j]);
      }
      packedBytes.push(num.toHex(chunk));
    }

    // Validates a full OAuth JWT signature (OAUTH_JWT_V1).
    // Performs complete RSA verification and registers the session.
    // Expensive - only used during deployment or explicit session registration.

    // Calculate Montgomery constants
    // We need to fetch the RSA key for the kid to get the modulus n
    const kid = this.extractKidFromJwt(jwt);
    const iss = jwtClaims.iss;
    const modulusLimbs = await this.fetchModulusForKid(kid, iss);

    // Calculate n_prime and R^2
    const { n_prime, r_sq } = this.calculateMontgomeryConstants(modulusLimbs);

    const jwt_kid_value = this.extractKidFromJwt(jwt);
    const jwt_kid_felt = this.stringToFelt(jwt_kid_value);

    const sig: string[] = [
      '0x4f415554485f4a57545f5631', // OAUTH_JWT_V1 magic
      num.toHex(signature.r),      // eph_r [1]
      num.toHex(signature.s),      // eph_s [2]
      ephemeralPubKey,              // eph_pubkey [3]
      num.toHex(nonceParams.maxBlock), // max_block [4]
      num.toHex(nonceParams.randomness), // randomness [5]
      jwt_sub_felt,                 // jwt_sub [6]
      this.session.nonce,           // jwt_nonce [7]
      num.toHex(jwtClaims.exp),    // jwt_exp [8]
      this.stringToFelt(this.extractKidFromJwt(jwt)), // jwt_kid [9]
      this.stringToFelt(jwtClaims.iss), // jwt_iss [10]
      this.stringToFelt(jwtClaims.aud), // jwt_aud [11]
      salt_hex,                     // salt [12]
      num.toHex(offsets.sub_offset),    // sub_offset [13] NEW
      num.toHex(offsets.sub_len),       // sub_len [14] NEW
      num.toHex(offsets.nonce_offset),  // nonce_offset [15] NEW
      num.toHex(offsets.nonce_len),     // nonce_len [16] NEW
      num.toHex(offsets.kid_offset),    // kid_offset [17] NEW
      num.toHex(offsets.kid_len),       // kid_len [18] NEW
      num.toHex(16),                // rsa_sig_len [19]
      ...rsaLimbs,                  // RSA signature as 16 u128 limbs [20-35]
      num.toHex(16),                // n_prime len [36]
      ...n_prime,                   // n_prime limbs [37-52]
      num.toHex(16),                // r_sq len [53]
      ...r_sq,                      // r_sq limbs [54-69]
      num.toHex(signedDataBytes.length), // jwt_bytes_len (TOTAL BYTES as per protocol) [70]
      ...packedBytes,               // packed JWT bytes [71+]
    ];

    return sig;
  }

  // Fetch RSA modulus (n) for the given Key ID (kid) from issuer's JWKS
  private async fetchModulusForKid(kid: string, issuer?: string): Promise<bigint[]> {
    try {
      let jwksUrl = 'https://www.googleapis.com/oauth2/v3/certs'; // Default to Google

      if (issuer === 'https://appleid.apple.com') {
        jwksUrl = 'https://appleid.apple.com/auth/keys';
      } else if (issuer === 'https://cavos.app/firebase') {
        jwksUrl = `${this.backendUrl}/api/jwks/firebase`;
      }

      const response = await fetch(jwksUrl);
      const data = await response.json();

      // Firebase endpoint returns { jwks: { keys: [...] }, contract: {...} }
      // Google/Apple return { keys: [...] }
      const jwks = data.jwks || data;

      if (!jwks.keys || !Array.isArray(jwks.keys)) {
        throw new Error(`Invalid JWKS response from ${jwksUrl}: ${JSON.stringify(data)}`);
      }

      const key = jwks.keys.find((k: any) => k.kid === kid);

      if (!key || !key.n) {
        throw new Error(`Key not found for kid: ${kid} from issuer: ${issuer || 'Google'}`);
      }

      // key.n is base64url encoded modulus
      const modulusBytes = this.base64UrlToBytes(key.n);
      // Convert to 16 u128 limbs
      const limbs = this.bytesToU128Limbs(modulusBytes);
      // specific implementation returns hex strings, convert to bigints for calculation
      return limbs.map(l => BigInt(l));
    } catch (error) {
      throw error;
    }
  }

  private calculateMontgomeryConstants(n_limbs: bigint[]): { n_prime: string[], r_sq: string[] } {
    // Reconstruct n from limbs
    let n = 0n;
    for (let i = 0; i < n_limbs.length; i++) {
      n += n_limbs[i] * (1n << (BigInt(i) * 128n));
    }

    const R = 1n << 2048n;

    // Calculate n_prime = -n^-1 mod R
    function modInverse(n: bigint, mod: bigint): bigint {
      let t = 0n;
      let newt = 1n;
      let r = mod;
      let newr = n;

      while (newr !== 0n) {
        let quotient = r / newr;
        [t, newt] = [newt, t - quotient * newt];
        [r, newr] = [newr, r - quotient * newr];
      }

      if (r > 1n) throw new Error("n is not invertible");
      if (t < 0n) t = t + mod;
      return t;
    }

    const n_inv = modInverse(n, R);
    const n_prime_val = (R - n_inv) % R;
    const r_sq_val = (R * R) % n;

    // Convert back to limbs
    const toLimbs = (val: bigint): string[] => {
      const limbs: string[] = [];
      for (let i = 0; i < 16; i++) {
        const limb = (val >> (BigInt(i) * 128n)) & ((1n << 128n) - 1n);
        limbs.push(num.toHex(limb));
      }
      return limbs;
    }

    return {
      n_prime: toLimbs(n_prime_val),
      r_sq: toLimbs(r_sq_val)
    };
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
   * Get ephemeral private key for signing
   */
  getEphemeralPrivateKey(): string | null {
    return this.session?.ephemeralPrivateKey || null;
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
          this.session.nonceParams.maxBlock = BigInt(this.session.nonceParams.maxBlock);
          this.session.nonceParams.renewalDeadline = BigInt(this.session.nonceParams.renewalDeadline);
          this.session.nonceParams.randomness = BigInt(this.session.nonceParams.randomness);
        }
        return this.hasValidSession();
      }
    } catch {
      // Ignore parse errors
    }
    return false;
  }

  // ============== Private helpers ==============

  private persistPreAuthSession(): void {
    if (typeof window === 'undefined') return;
    if (this.session) {
      const toStore = {
        ...this.session,
        nonceParams: {
          ...this.session.nonceParams,
          maxBlock: this.session.nonceParams.maxBlock.toString(),
          renewalDeadline: this.session.nonceParams.renewalDeadline.toString(),
          randomness: this.session.nonceParams.randomness.toString(),
        },
      };
      sessionStorage.setItem(PRE_AUTH_STORAGE_KEY, JSON.stringify(toStore));
    }
  }

  /**
   * Freshen the session by generating a new ephemeral key pair.
   * This is used for auto-renewal when an existing session expires.
   * It preserves the JWT and wallet address but generates a new nonce and keys.
   */
  async freshenSession(): Promise<OAuthSession> {
    if (!this.session?.jwt) {
      throw new Error('No active session to freshen');
    }

    const oldSession = { ...this.session };

    // Generate NEW ephemeral key pair
    const STARK_CURVE_ORDER = BigInt('0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f');
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    let privateKeyBigInt = BigInt('0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    privateKeyBigInt = (privateKeyBigInt % (STARK_CURVE_ORDER - 1n)) + 1n;

    const ephemeralPrivateKey = '0x' + privateKeyBigInt.toString(16);
    const ephemeralPubKey = ec.starkCurve.getStarkKey(ephemeralPrivateKey);

    // Get current block number
    const block = await this.provider.getBlockNumber();
    const currentBlock = BigInt(block);
    // New nonce params with configured duration
    const nonceParams = NonceManager.generateNonceParams(
      ephemeralPubKey,
      currentBlock,
      BigInt(this.sessionDuration),
      BigInt(this.renewalGracePeriod)
    );

    const nonce = NonceManager.computeNonce(nonceParams);
    // Update session
    this.session = {
      ...this.session,
      ephemeralPrivateKey,
      ephemeralPubKey,
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
            maxBlock: BigInt(parsed.nonceParams.maxBlock),
            renewalDeadline: BigInt(parsed.nonceParams.renewalDeadline),
            randomness: BigInt(parsed.nonceParams.randomness),
          },
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
          maxBlock: this.session.nonceParams.maxBlock.toString(),
          renewalDeadline: this.session.nonceParams.renewalDeadline.toString(),
          randomness: this.session.nonceParams.randomness.toString(),
        },
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
    };
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
    const deployerAddress = this.config.deployerContractAddress || '0x0';

    const walletAddress = this.addressSeedManager.computeContractAddress(
      jwtClaims.sub,
      this.config.cavosAccountClassHash,
      this.config.jwksRegistryAddress,
      deployerAddress
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
}
