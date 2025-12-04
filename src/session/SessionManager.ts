import { Account, Call, CallData, ec, Provider, RpcProvider } from 'starknet';
import { SessionKey, SessionPolicy, SessionData } from '../types';

const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

export class SessionManager {
  private sessionKey: SessionKey | null = null;
  private sessionAccount: Account | null = null;
  private provider: Provider;
  private accountAddress: string | null = null;

  constructor(rpcUrl?: string) {
    this.provider = new RpcProvider({
      // Use Alchemy v0_8 RPC for Sepolia
      nodeUrl: rpcUrl || 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_8/dql5pMT88iueZWl7L0yzT56uVk0EBU4L',
    });
  }

  /**
   * Create a new session key with policy (ON-CHAIN)
   */
  async createSession(
    masterAccount: Account,
    policy: Partial<SessionPolicy> = {}
  ): Promise<SessionKey> {
    // Generate new session keypair
    const sessionKeyPair = ec.starkCurve.utils.randomPrivateKey();
    const sessionPublicKey = ec.starkCurve.getStarkKey(sessionKeyPair);

    // Default policy: 24 hours validity
    const fullPolicy: SessionPolicy = {
      expiresAt: Date.now() + SESSION_DURATION,
      allowedMethods: policy.allowedMethods || [],
      spendingLimits: policy.spendingLimits,
      whitelistedAddresses: policy.whitelistedAddresses,
    };

    // Prepare policy parameters for SessionWallet contract
    const maxAmountPerTx = policy.spendingLimits?.maxAmount || '1000000000000000000'; // 1 ETH default
    const maxAmountPerDay = policy.spendingLimits?.maxAmount || '10000000000000000000'; // 10 ETH default
    const durationSeconds = Math.floor((fullPolicy.expiresAt - Date.now()) / 1000);

    // Register session key ON-CHAIN
    try {
      const result = await masterAccount.execute({
        contractAddress: masterAccount.address,
        entrypoint: 'create_session',
        calldata: CallData.compile({
          session_public_key: '0x' + sessionPublicKey,
          max_amount_per_tx: maxAmountPerTx,
          max_amount_per_day: maxAmountPerDay,
          duration_seconds: durationSeconds,
        }),
      });


      // Add allowed contracts if specified
      if (policy.whitelistedAddresses && policy.whitelistedAddresses.length > 0) {
        // Get session_id from transaction result (for now, use hash of public key)
        const sessionId = '0x' + sessionPublicKey; // Simplified - actual ID comes from contract

        for (const contractAddress of policy.whitelistedAddresses) {
          await masterAccount.execute({
            contractAddress: masterAccount.address,
            entrypoint: 'add_allowed_contract',
            calldata: CallData.compile({
              session_id: sessionId,
              contract_address: contractAddress,
            }),
          });
        }
      }
    } catch (error: any) {
      console.error('[SessionManager] Failed to register session on-chain:', error);
      throw new Error(`Failed to register session: ${error.message}`);
    }

    this.sessionKey = {
      publicKey: '0x' + sessionPublicKey,
      privateKey: '0x' + Buffer.from(sessionKeyPair).toString('hex'),
      policy: fullPolicy,
      createdAt: Date.now(),
    };

    // Create session account
    this.sessionAccount = new Account(
      this.provider,
      masterAccount.address,
      this.sessionKey.privateKey
    );

    this.accountAddress = masterAccount.address;

    return this.sessionKey;
  }

  /**
   * Load existing session
   */
  async loadSession(sessionData: SessionData): Promise<void> {
    this.sessionKey = sessionData.sessionKey;
    this.accountAddress = sessionData.accountAddress;

    // Validate session hasn't expired
    if (this.isSessionExpired()) {
      throw new Error('Session has expired');
    }

    this.sessionAccount = new Account(
      this.provider,
      sessionData.accountAddress,
      sessionData.sessionKey.privateKey
    );
  }

  /**
   * Execute transaction with session key (ON-CHAIN)
   */
  async executeWithSession(calls: Call | Call[]): Promise<string> {
    if (!this.sessionAccount || !this.sessionKey) {
      throw new Error('No active session');
    }

    if (this.isSessionExpired()) {
      throw new Error('Session has expired');
    }

    const callsArray = Array.isArray(calls) ? calls : [calls];

    // Validate calls against policy (client-side check)
    this.validateCalls(callsArray);

    // Use session_id (simplified as public key for now)
    const sessionId = this.sessionKey.publicKey;

    // Execute through SessionWallet contract using execute_with_session
    // The contract will validate the session signature and policy
    const result = await this.sessionAccount.execute(
      callsArray.map(call => ({
        contractAddress: this.accountAddress!,
        entrypoint: 'execute_with_session',
        calldata: CallData.compile({
          session_id: sessionId,
          call: {
            to: call.contractAddress,
            selector: call.entrypoint,
            calldata: call.calldata || [],
          },
        }),
      }))
    );

    return result.transaction_hash;
  }

  /**
   * Get current session data for storage
   */
  getSessionData(): SessionData | null {
    if (!this.sessionKey || !this.accountAddress) {
      return null;
    }

    return {
      sessionKey: this.sessionKey,
      accountAddress: this.accountAddress,
      chainId: 'SN_SEPOLIA', // Or determine from provider
    };
  }

  /**
   * Check if session is expired
   */
  isSessionExpired(): boolean {
    if (!this.sessionKey) {
      return true;
    }

    return Date.now() > this.sessionKey.policy.expiresAt;
  }

  /**
   * Get session account
   */
  getSessionAccount(): Account | null {
    return this.sessionAccount;
  }

  /**
   * Clear session
   */
  clearSession(): void {
    this.sessionKey = null;
    this.sessionAccount = null;
    this.accountAddress = null;
  }

  /**
   * Validate calls against session policy
   */
  private validateCalls(calls: Call[]): void {
    if (!this.sessionKey) {
      throw new Error('No active session');
    }

    const policy = this.sessionKey.policy;

    // Check whitelist
    if (policy.whitelistedAddresses && policy.whitelistedAddresses.length > 0) {
      for (const call of calls) {
        if (!policy.whitelistedAddresses.includes(call.contractAddress)) {
          throw new Error(`Contract ${call.contractAddress} not in whitelist`);
        }
      }
    }

    // Check allowed methods
    if (policy.allowedMethods && policy.allowedMethods.length > 0) {
      for (const call of calls) {
        if (!policy.allowedMethods.includes(call.entrypoint)) {
          throw new Error(`Method ${call.entrypoint} not allowed`);
        }
      }
    }

    // TODO: Implement spending limits check
    // This would require tracking transaction amounts and comparing against limits
  }
}
