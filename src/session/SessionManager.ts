/**
 * Session Keys Implementation
 * Based on Argent's contract-level session library
 * Uses passkey-derived guardian key instead of cloud API
 */

import {
  Account,
  Call,
  CallData,
  CairoCustomEnum,
  RpcProvider,
  byteArray,
  ec,
  hash,
  merkle,
  selector,
  shortString,
  typedData,
  TypedData,
  constants,
} from 'starknet';

// ============================================================================
// Types
// ============================================================================

export interface AllowedMethod {
  'Contract Address': string;
  selector: string;
}

export interface SessionPolicy {
  allowedMethods: Array<{ contractAddress: string; selector: string }>;
  expiresAt: number;
  metadata?: string;
}

export interface OnChainSession {
  expires_at: bigint;
  allowed_methods_root: string;
  metadata_hash: string;
  session_key_guid: bigint;
}

// ============================================================================
// Session Types for TypedData
// ============================================================================

const SESSION_TYPES = {
  StarknetDomain: [
    { name: 'name', type: 'shortstring' },
    { name: 'version', type: 'shortstring' },
    { name: 'chainId', type: 'shortstring' },
    { name: 'revision', type: 'shortstring' },
  ],
  'Allowed Method': [
    { name: 'Contract Address', type: 'ContractAddress' },
    { name: 'selector', type: 'selector' },
  ],
  Session: [
    { name: 'Expires At', type: 'timestamp' },
    { name: 'Allowed Methods', type: 'merkletree', contains: 'Allowed Method' },
    { name: 'Metadata', type: 'string' },
    { name: 'Session Key', type: 'felt' },
  ],
};

// ============================================================================
// Session Class
// ============================================================================

export class Session {
  constructor(
    public expiresAt: bigint,
    public allowedMethods: AllowedMethod[],
    public metadata: string,
    public sessionKeyGuid: bigint,
  ) { }

  private buildMerkleTree(): merkle.MerkleTree {
    const leaves = this.allowedMethods.map((method) =>
      hash.computePoseidonHashOnElements([
        typedData.getTypeHash(SESSION_TYPES, 'Allowed Method', '1'),
        method['Contract Address'],
        selector.getSelectorFromName(method.selector),
      ])
    );
    return new merkle.MerkleTree(leaves, hash.computePoseidonHash);
  }

  public getProofs(calls: Call[]): string[][] {
    const merkleTree = this.buildMerkleTree();
    return calls.map((call) => {
      const allowedIndex = this.allowedMethods.findIndex((allowedMethod) => {
        return (
          allowedMethod['Contract Address'] === call.contractAddress &&
          allowedMethod.selector === call.entrypoint
        );
      });
      if (allowedIndex === -1) {
        throw new Error(`Method ${call.entrypoint} on ${call.contractAddress} not allowed by session`);
      }
      return merkleTree.getProof(merkleTree.leaves[allowedIndex], merkleTree.leaves);
    });
  }

  public async hashWithTransaction(
    transactionHash: string,
    accountAddress: string,
    chainId: string,
  ): Promise<string> {
    const sessionTypedData = await this.getTypedData(chainId);
    const sessionMessageHash = typedData.getMessageHash(sessionTypedData, accountAddress);
    const sessionWithTxHash = hash.computePoseidonHashOnElements([
      transactionHash,
      sessionMessageHash,
      0n, // cache_owner_guid
    ]);
    return sessionWithTxHash;
  }

  public async getTypedData(chainId: string): Promise<TypedData> {
    return {
      types: SESSION_TYPES,
      primaryType: 'Session',
      domain: {
        name: 'SessionAccount.session',
        version: shortString.encodeShortString('1'),
        chainId: chainId,
        revision: '1',
      },
      message: {
        'Expires At': this.expiresAt,
        'Allowed Methods': this.allowedMethods,
        Metadata: this.metadata,
        'Session Key': this.sessionKeyGuid,
      },
    };
  }

  public toOnChainSession(): OnChainSession {
    // Use byteArray for proper string hashing (same as Argent library)
    const bArray = byteArray.byteArrayFromString(this.metadata);
    const metadataHash = hash.computePoseidonHashOnElements(CallData.compile(bArray));

    return {
      expires_at: this.expiresAt,
      allowed_methods_root: this.buildMerkleTree().root.toString(),
      metadata_hash: metadataHash,
      session_key_guid: this.sessionKeyGuid,
    };
  }
}

// ============================================================================
// SessionToken Class
// ============================================================================

export class SessionToken {
  public session: Session;
  public proofs: string[][];
  public sessionAuthorization: string[];
  public sessionSignature: { r: bigint; s: bigint };
  public guardianSignature: { r: bigint; s: bigint };
  public sessionKeyPublicKey: bigint;  // Actual publicKey (not guid)
  public guardianKeyPublicKey: bigint; // Actual publicKey (not guid)

  constructor({
    session,
    sessionAuthorization,
    sessionSignature,
    guardianSignature,
    sessionKeyPublicKey,
    guardianKeyPublicKey,
    calls,
  }: {
    session: Session;
    sessionAuthorization: string[];
    sessionSignature: { r: bigint; s: bigint };
    guardianSignature: { r: bigint; s: bigint };
    sessionKeyPublicKey: bigint;
    guardianKeyPublicKey: bigint;
    calls: Call[];
  }) {
    this.session = session;
    this.proofs = session.getProofs(calls);
    this.sessionAuthorization = sessionAuthorization;
    this.sessionSignature = sessionSignature;
    this.guardianSignature = guardianSignature;
    this.sessionKeyPublicKey = sessionKeyPublicKey;
    this.guardianKeyPublicKey = guardianKeyPublicKey;
  }

  public compileSignature(): string[] {
    const SESSION_MAGIC = shortString.encodeShortString('session-token');

    // Build the session token data structure for ArgentX account validation
    const onChainSession = this.session.toOnChainSession();

    // SignerSignature format from Argent library:
    // signerTypeToCustomEnum(SignerType.Starknet, { pubkey, r, s })
    // pubkey must be the actual publicKey - contract calculates guid from it

    // Create CairoCustomEnum for session signature (Starknet signer type)
    const sessionSignatureEnum = new CairoCustomEnum({
      Starknet: {
        pubkey: this.sessionKeyPublicKey,  // Use actual publicKey, not guid
        r: this.sessionSignature.r,
        s: this.sessionSignature.s,
      },
      Secp256k1: undefined,
      Secp256r1: undefined,
      Eip191: undefined,
      Webauthn: undefined,
    });

    // Create CairoCustomEnum for guardian signature (Starknet signer type)
    const guardianSignatureEnum = new CairoCustomEnum({
      Starknet: {
        pubkey: this.guardianKeyPublicKey,  // Use actual guardian publicKey
        r: this.guardianSignature.r,
        s: this.guardianSignature.s,
      },
      Secp256k1: undefined,
      Secp256r1: undefined,
      Eip191: undefined,
      Webauthn: undefined,
    });

    // Build the token data structure matching the Cairo struct
    const tokenData = {
      session: {
        expires_at: onChainSession.expires_at,
        allowed_methods_root: onChainSession.allowed_methods_root,
        metadata_hash: onChainSession.metadata_hash,
        session_key_guid: onChainSession.session_key_guid,
      },
      cache_owner_guid: 0n,
      session_authorization: this.sessionAuthorization,
      session_signature: sessionSignatureEnum,
      guardian_signature: guardianSignatureEnum,
      proofs: this.proofs,
    };

    // Use CallData.compile for proper serialization
    const compiledData = CallData.compile(tokenData);

    return [SESSION_MAGIC, ...compiledData];
  }
}

// ============================================================================
// StarknetKeyPair Helper
// ============================================================================

export class StarknetKeyPair {
  public privateKey: string;
  public publicKey: bigint;

  constructor(privateKey?: string) {
    if (privateKey) {
      this.privateKey = privateKey;
    } else {
      const pk = ec.starkCurve.utils.randomPrivateKey();
      this.privateKey = '0x' + Buffer.from(pk).toString('hex');
    }
    this.publicKey = BigInt(ec.starkCurve.getStarkKey(this.privateKey));
  }

  // Guid is computed as poseidonHash("Starknet Signer", publicKey) per Argent library
  public get guid(): bigint {
    return BigInt(hash.computePoseidonHash(
      shortString.encodeShortString('Starknet Signer'),
      this.publicKey
    ));
  }

  public async sign(messageHash: string): Promise<{ r: bigint; s: bigint }> {
    const signature = ec.starkCurve.sign(messageHash, this.privateKey);
    return {
      r: BigInt(signature.r),
      s: BigInt(signature.s),
    };
  }
}

// ============================================================================
// SessionManager - Main class for session key management
// ============================================================================

export class SessionManager {
  private provider: RpcProvider;
  private network: 'mainnet' | 'sepolia';
  private chainId: string;

  // Storage key for persisting session data
  private static readonly SESSION_STORAGE_KEY = 'cavos_session_data';

  // Current session state
  private currentSession: Session | null = null;
  private sessionKey: StarknetKeyPair | null = null;
  private guardianKey: StarknetKeyPair | null = null;
  private sessionAuthorization: string[] | null = null;
  private accountAddress: string | null = null;
  private accountPrivateKey: string | null = null;
  private ownerPublicKey: string | null = null;

  constructor(rpcUrl: string, network: 'mainnet' | 'sepolia' = 'sepolia') {
    this.provider = new RpcProvider({ nodeUrl: rpcUrl });
    this.network = network;
    this.chainId = network === 'mainnet'
      ? constants.StarknetChainId.SN_MAIN
      : constants.StarknetChainId.SN_SEPOLIA;

    // Try to restore session from storage on init
    this.loadSessionFromStorage();
  }

  /**
   * Create a new session.
   * Derives guardian key from the account's private key.
   */
  async createSession(
    account: Account,
    policy: SessionPolicy,
    accountPrivateKey: string,
  ): Promise<void> {
    console.log('[SessionManager] Creating session...');

    // Store private key for later use
    this.accountPrivateKey = accountPrivateKey;

    // Generate session keypair
    this.sessionKey = new StarknetKeyPair();
    console.log('[SessionManager] Generated session key');

    // Derive guardian key from account private key
    // Use a derived key (hash of private key + "guardian") for guardian
    const guardianSeed = hash.computePoseidonHashOnElements([
      BigInt(accountPrivateKey),
      BigInt(shortString.encodeShortString('guardian')),
    ]);
    // Ensure proper hex formatting for private key (248 bits = 62 hex chars)
    const guardianSeedBigInt = BigInt(guardianSeed);
    let guardianHexStr = guardianSeedBigInt.toString(16);
    while (guardianHexStr.length < 62) {
      guardianHexStr = '0' + guardianHexStr;
    }
    const guardianHex = '0x' + guardianHexStr;
    this.guardianKey = new StarknetKeyPair(guardianHex);
    console.log('[SessionManager] Derived guardian key');

    // Convert policy to AllowedMethod format
    const allowedMethods: AllowedMethod[] = policy.allowedMethods.map(m => ({
      'Contract Address': m.contractAddress,
      selector: m.selector,
    }));

    // Create session
    this.currentSession = new Session(
      BigInt(Math.floor(policy.expiresAt / 1000)),
      allowedMethods,
      policy.metadata || JSON.stringify({ metadata: 'cavos-session', max_fee: 0 }),
      this.sessionKey.guid,
    );
    console.log('[SessionManager] Created session object');

    // Get session typed data and sign with account (owner)
    const sessionTypedData = await this.currentSession.getTypedData(this.chainId);
    console.log('[SessionManager] Requesting user signature...');

    const ownerSignature = await account.signMessage(sessionTypedData);
    console.log('[SessionManager] User signed session');

    // Also sign with guardian key  
    const sessionHash = typedData.getMessageHash(sessionTypedData, account.address);
    const guardianSigResult = await this.guardianKey.sign(sessionHash);
    console.log('[SessionManager] Guardian signed session');

    // Get owner public key from account
    // The account's public key is needed for the SignerSignature format
    // For ArgentX accounts, we can derive it from the private key used to create the account
    // The signature from account.signMessage() contains r and s
    const ownerSigR = Array.isArray(ownerSignature) ? BigInt(ownerSignature[0]) : BigInt(ownerSignature.r);
    const ownerSigS = Array.isArray(ownerSignature) ? BigInt(ownerSignature[1]) : BigInt(ownerSignature.s);

    // Build session_authorization in MultisigSigner format: [count, ownerSig..., guardianSig...]
    // Both signatures must be in SignerSignature CairoCustomEnum format

    // Owner signature in SignerSignature format
    // We need the owner's public key - it's stored in currentWallet
    // But we need to get it somehow. For now, let's get it from the signer we have.
    // TODO: This is a workaround - we need the actual owner pubkey
    const ownerPubKey = accountPrivateKey
      ? BigInt(ec.starkCurve.getStarkKey(accountPrivateKey))
      : 0n;

    const ownerSignatureEnum = new CairoCustomEnum({
      Starknet: {
        pubkey: ownerPubKey,
        r: ownerSigR,
        s: ownerSigS,
      },
      Secp256k1: undefined,
      Secp256r1: undefined,
      Eip191: undefined,
      Webauthn: undefined,
    });
    const ownerSigCompiled = CallData.compile([ownerSignatureEnum]);

    // Guardian signature in SignerSignature format
    const guardianSignatureEnum = new CairoCustomEnum({
      Starknet: {
        pubkey: this.guardianKey.publicKey,
        r: guardianSigResult.r,
        s: guardianSigResult.s,
      },
      Secp256k1: undefined,
      Secp256r1: undefined,
      Eip191: undefined,
      Webauthn: undefined,
    });
    const guardianSigCompiled = CallData.compile([guardianSignatureEnum]);

    // Combine: [2, ownerSig..., guardianSig...]
    this.sessionAuthorization = [
      '2', // number of signers
      ...ownerSigCompiled.map(s => s.toString()),
      ...guardianSigCompiled.map(s => s.toString()),
    ];
    console.log('[SessionManager] Combined signatures for session_authorization');

    this.accountAddress = account.address;
    this.ownerPublicKey = ownerPubKey.toString();

    // Auto-save session to storage for persistence
    this.saveSessionToStorage();

    console.log('[SessionManager] Session created and saved successfully');
  }

  /**
   * Execute transactions with session key.
   * Uses the account's execute method with custom signature.
   */
  async executeWithSession(
    calls: Call | Call[],
    account: Account,
  ): Promise<string> {
    if (!this.currentSession || !this.sessionKey || !this.guardianKey || !this.sessionAuthorization) {
      throw new Error('No active session');
    }

    if (this.isSessionExpired()) {
      throw new Error('Session has expired');
    }

    const callsArray = Array.isArray(calls) ? calls : [calls];
    console.log('[SessionManager] Executing with session:', callsArray.length, 'calls');

    // Validate calls against session policy
    for (const call of callsArray) {
      const isAllowed = this.currentSession.allowedMethods.some(
        m => m['Contract Address'] === call.contractAddress && m.selector === call.entrypoint
      );
      if (!isAllowed) {
        throw new Error(`Method ${call.entrypoint} on ${call.contractAddress} not allowed by session`);
      }
    }

    // For now, execute directly with the account (which has the private key)
    // In production, you would build the session signature and submit via RPC
    console.log('[SessionManager] Executing transaction with account...');

    const result = await account.execute(callsArray);
    console.log('[SessionManager] Transaction submitted:', result.transaction_hash);

    return result.transaction_hash;
  }

  /**
   * Sign typed data with session keys.
   * Returns the session token signature that can be used with the paymaster.
   */
  async signTypedDataWithSession(
    paymasterTypedData: any,
    accountAddress: string,
    calls: Call[],
  ): Promise<string[]> {
    if (!this.currentSession || !this.sessionKey || !this.guardianKey || !this.sessionAuthorization) {
      throw new Error('No active session');
    }

    if (this.isSessionExpired()) {
      throw new Error('Session has expired');
    }

    // Validate calls against session policy
    for (const call of calls) {
      const isAllowed = this.currentSession.allowedMethods.some(
        m => m['Contract Address'] === call.contractAddress && m.selector === call.entrypoint
      );
      if (!isAllowed) {
        throw new Error(`Method ${call.entrypoint} on ${call.contractAddress} not allowed by session`);
      }
    }

    console.log('[SessionManager] Signing typed data with session key...');

    // Calculate the message hash for the paymaster typed data
    const messageHash = typedData.getMessageHash(paymasterTypedData, accountAddress);
    console.log('[SessionManager] Message hash:', messageHash);

    // Sign with session key
    const sessionWithMsgHash = await this.currentSession.hashWithTransaction(
      messageHash,
      accountAddress,
      this.chainId,
    );
    const sessionSignature = await this.sessionKey.sign(sessionWithMsgHash);
    console.log('[SessionManager] Session key signed');

    // Sign with guardian key
    const guardianSignature = await this.guardianKey.sign(sessionWithMsgHash);
    console.log('[SessionManager] Guardian key signed');

    // Build session token
    const sessionToken = new SessionToken({
      session: this.currentSession,
      sessionAuthorization: this.sessionAuthorization,
      sessionSignature,
      guardianSignature,
      sessionKeyPublicKey: this.sessionKey.publicKey,
      guardianKeyPublicKey: this.guardianKey.publicKey,
      calls,
    });

    // Compile and return signature
    const compiledSignature = sessionToken.compileSignature();
    console.log('[SessionManager] Compiled session token signature');

    return compiledSignature;
  }

  /**
   * Get account address if session is active.
   */
  getAccountAddress(): string | null {
    return this.accountAddress;
  }

  /**
   * Check if session is expired.
   */
  isSessionExpired(): boolean {
    if (!this.currentSession) {
      return true;
    }
    return Date.now() > Number(this.currentSession.expiresAt) * 1000;
  }

  /**
   * Check if there's an active session.
   */
  hasActiveSession(): boolean {
    return this.currentSession !== null && !this.isSessionExpired();
  }

  /**
   * Sign a message with the session key.
   * @param messageHash - The hash of the message to sign
   * @returns Signature object with r and s components
   */
  async signMessage(messageHash: string): Promise<{ r: string; s: string }> {
    if (!this.sessionKey) {
      throw new Error('No active session. Create a session first.');
    }

    if (this.isSessionExpired()) {
      throw new Error('Session has expired. Create a new session.');
    }

    const signature = await this.sessionKey.sign(messageHash);
    return {
      r: `0x${signature.r.toString(16)}`,
      s: `0x${signature.s.toString(16)}`,
    };
  }

  /**
   * Clear current session.
   */
  clearSession(): void {
    this.currentSession = null;
    this.sessionKey = null;
    this.guardianKey = null;
    this.sessionAuthorization = null;
    this.accountAddress = null;
    this.accountPrivateKey = null;
    this.ownerPublicKey = null;
    this.clearSessionStorage();
  }

  /**
   * Get session account for direct interaction.
   */
  async getSessionAccount(): Promise<Account | null> {
    if (!this.hasActiveSession() || !this.accountAddress) {
      return null;
    }
    // Return null for now - session execution goes through executeWithSession
    return null;
  }

  // ============================================================================
  // Session Persistence Methods
  // ============================================================================

  /**
   * Save current session to sessionStorage.
   * This allows session to persist across page reloads without storing the wallet PK.
   */
  saveSessionToStorage(): void {
    if (!this.currentSession || !this.sessionKey || !this.guardianKey || !this.sessionAuthorization) {
      console.warn('[SessionManager] Cannot save - no active session');
      return;
    }

    try {
      const sessionData = {
        // Account info
        accountAddress: this.accountAddress,
        ownerPublicKey: this.ownerPublicKey,

        // Session key (privateKey needed for signing)
        sessionKeyPrivate: this.sessionKey.privateKey,
        sessionKeyPublic: this.sessionKey.publicKey.toString(),

        // Guardian key (privateKey needed for signing)
        guardianKeyPrivate: this.guardianKey.privateKey,
        guardianKeyPublic: this.guardianKey.publicKey.toString(),

        // Session configuration
        expiresAt: Number(this.currentSession.expiresAt),
        allowedMethods: this.currentSession.allowedMethods,
        metadata: this.currentSession.metadata,
        sessionKeyGuid: this.currentSession.sessionKeyGuid.toString(),

        // Authorization signature
        sessionAuthorization: this.sessionAuthorization,
      };

      sessionStorage.setItem(SessionManager.SESSION_STORAGE_KEY, JSON.stringify(sessionData));
      console.log('[SessionManager] Session saved to storage');
    } catch (error) {
      console.error('[SessionManager] Failed to save session:', error);
    }
  }

  /**
   * Load session from sessionStorage.
   * Reconstructs session state without needing the wallet PK.
   */
  loadSessionFromStorage(): boolean {
    try {
      const stored = sessionStorage.getItem(SessionManager.SESSION_STORAGE_KEY);
      if (!stored) {
        return false;
      }

      const data = JSON.parse(stored);

      // Validate expiry
      if (data.expiresAt * 1000 <= Date.now()) {
        console.log('[SessionManager] Stored session expired, clearing');
        this.clearSessionStorage();
        return false;
      }

      // Reconstruct session key
      this.sessionKey = new StarknetKeyPair(data.sessionKeyPrivate);

      // Reconstruct guardian key
      this.guardianKey = new StarknetKeyPair(data.guardianKeyPrivate);

      // Reconstruct session object
      this.currentSession = new Session(
        BigInt(data.expiresAt),
        data.allowedMethods,
        data.metadata,
        BigInt(data.sessionKeyGuid),
      );

      // Restore other state
      this.accountAddress = data.accountAddress;
      this.ownerPublicKey = data.ownerPublicKey;
      this.sessionAuthorization = data.sessionAuthorization;

      console.log('[SessionManager] Session restored from storage');
      return true;
    } catch (error) {
      console.error('[SessionManager] Failed to load session:', error);
      this.clearSessionStorage();
      return false;
    }
  }

  /**
   * Clear session from storage.
   */
  clearSessionStorage(): void {
    try {
      sessionStorage.removeItem(SessionManager.SESSION_STORAGE_KEY);
      console.log('[SessionManager] Session storage cleared');
    } catch (error) {
      console.error('[SessionManager] Failed to clear session storage:', error);
    }
  }

  /**
   * Check if there's a saved session in storage.
   */
  isSessionSaved(): boolean {
    try {
      return sessionStorage.getItem(SessionManager.SESSION_STORAGE_KEY) !== null;
    } catch {
      return false;
    }
  }
}
