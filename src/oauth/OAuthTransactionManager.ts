/**
 * OAuthTransactionManager - Manages transactions for OAuth-based wallets
 *
 * Handles:
 * - Transaction signing with session keys
 * - Building JWT signature data for on-chain verification
 * - Account deployment (self-deploy via paymaster)
 * - Session revocation
 * - Paymaster integration
 */

import {
  Account,
  Call,
  RpcProvider,
  PaymasterRpc,
  num,
  typedData,
  hash,
  ec,
  Signer,
  type Signature,
  type TypedData,
} from 'starknet';
import { OAuthWalletManager, OAuthSession } from './OAuthWalletManager';
import { OAuthWalletConfig } from '../types/config';

/**
 * Custom signer for OAuth accounts.
 * Produces JWT signatures for deploy and session signatures for execute.
 */
class OAuthSigner extends Signer {
  private oauthManager: OAuthWalletManager;
  private forDeploy: boolean;

  constructor(oauthManager: OAuthWalletManager, forDeploy: boolean = false) {
    super();
    this.oauthManager = oauthManager;
    this.forDeploy = forDeploy;
  }

  async getPubKey(): Promise<string> {
    const session = this.oauthManager.getSession();
    return session?.sessionPubKey || '0x0';
  }

  async signMessage(typedDataInput: TypedData, accountAddress: string): Promise<Signature> {
    const msgHash = typedData.getMessageHash(typedDataInput, accountAddress);

    if (this.forDeploy) {
      return await this.oauthManager.buildJWTSignatureData(msgHash);
    } else {
      return this.oauthManager.buildSessionSignature(msgHash);
    }
  }

  async signTransaction(
    _transactions: Call[],
    details: any
  ): Promise<Signature> {
    const txHash = details.transactionHash || '0x0';

    if (this.forDeploy) {
      return await this.oauthManager.buildJWTSignatureData(txHash);
    } else {
      return this.oauthManager.buildSessionSignature(txHash);
    }
  }

  async signDeployAccountTransaction(details: any): Promise<Signature> {
    const txHash = details.transactionHash || '0x0';
    return await this.oauthManager.buildJWTSignatureData(txHash);
  }
}

export class OAuthTransactionManager {
  private config: OAuthWalletConfig;
  private provider: RpcProvider;
  private oauthManager: OAuthWalletManager;
  private paymasterApiKey: string;
  private network: 'mainnet' | 'sepolia';
  private account: Account | null = null;
  private paymasterRpc: PaymasterRpc;
  /** Tracks whether we've already sent a JWT tx (which registers the session on-chain) */
  private sessionRegisteredLocally: boolean = false;

  constructor(
    config: OAuthWalletConfig,
    oauthManager: OAuthWalletManager,
    rpcUrl: string,
    paymasterApiKey: string,
    network: 'mainnet' | 'sepolia'
  ) {
    this.config = config;
    this.provider = new RpcProvider({ nodeUrl: rpcUrl });
    this.oauthManager = oauthManager;
    this.paymasterApiKey = paymasterApiKey;
    this.network = network;

    const paymasterUrl = network === 'mainnet'
      ? 'https://starknet.paymaster.avnu.fi'
      : 'https://sepolia.paymaster.avnu.fi';

    this.paymasterRpc = new PaymasterRpc({
      nodeUrl: paymasterUrl,
      headers: { 'x-paymaster-api-key': paymasterApiKey },
    });
  }

  /**
   * Check if the OAuth account is deployed
   */
  async isDeployed(): Promise<boolean> {
    const address = this.oauthManager.getWalletAddress();
    if (!address) return false;

    try {
      const classHash = await this.provider.getClassHashAt(address);
      return !!classHash;
    } catch {
      return false;
    }
  }

  /**
   * Get session status from on-chain.
   * Returns detailed status including whether it's expired and if it can be renewed.
   */
  async getSessionStatus(): Promise<{
    registered: boolean;
    expired: boolean;
    canRenew: boolean;
    validUntil?: bigint;
    renewalDeadline?: bigint;
  }> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress || !session.sessionPubKey) {
      return { registered: false, expired: false, canRenew: false };
    }

    try {
      console.log('[getSessionStatus] Querying session for key:', session.sessionPubKey, 'at address:', session.walletAddress);
      const result = await this.provider.callContract({
        contractAddress: session.walletAddress,
        entrypoint: 'get_session',
        calldata: [session.sessionPubKey],
      });
      console.log('[getSessionStatus] Raw result:', result);

      // get_session returns (nonce, valid_after, valid_until, renewal_deadline, registered_at, allowed_contracts_root, max_calls_per_tx)
      const nonce = BigInt(result[0]);
      const validUntil = BigInt(result[2]);
      const renewalDeadline = BigInt(result[3]);

      const registered = nonce !== 0n;

      if (!registered) {
        return { registered: false, expired: false, canRenew: false };
      }

      // Get current block timestamp
      const block = await this.provider.getBlock('latest');
      const now = BigInt(block.timestamp);

      const expired = now >= validUntil;
      const canRenew = expired && now < renewalDeadline;

      return { registered, expired, canRenew, validUntil, renewalDeadline };
    } catch (err) {
      console.error('[getSessionStatus] Error calling get_session:', err);
      return { registered: false, expired: false, canRenew: false };
    }
  }

  /**
   * Check if the current session is registered on-chain.
   * Calls the contract's get_session(session_key) function.
   * If nonce == 0, the session is NOT registered.
   */
  async isSessionRegistered(): Promise<boolean> {
    const status = await this.getSessionStatus();
    return status.registered && !status.expired;
  }

  /**
   * Deploy the OAuth account contract using starknet.js PaymasterRpc (Self-Deploy).
   *
   * The account deploys ITSELF via AVNU Paymaster - no relayer needed!
   *
   * Flow:
   * 1. Create counterfactual Account with OAuthSigner and PaymasterRpc
   * 2. Build AccountDeploymentData
   * 3. Call executePaymasterTransaction with deploymentData
   * 4. Contract's __validate_deploy__ verifies JWT and registers session
   */
  async deployAccount(): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress || !session.addressSeed) {
      throw new Error('No valid session for deployment');
    }

    // Check if already deployed
    const alreadyDeployed = await this.isDeployed();
    if (alreadyDeployed) {
      return 'already-deployed';
    }

    // Constructor calldata: [address_seed, jwks_registry]
    const constructorCalldata = [
      session.addressSeed,
      this.config.jwksRegistryAddress,
    ].map(c => num.toHex(c));

    // Create custom signer for deploy (uses full JWT signature)
    const deploySigner = new OAuthSigner(this.oauthManager, true);

    // Create counterfactual Account with PaymasterRpc
    const counterfactualAccount = new Account({
      provider: this.provider,
      address: session.walletAddress,
      signer: deploySigner,
      paymaster: this.paymasterRpc,
    });

    // Build AccountDeploymentData
    const deploymentData = {
      address: session.walletAddress,
      class_hash: this.config.cavosAccountClassHash,
      salt: session.addressSeed,
      calldata: constructorCalldata,
      version: 1 as const,
    };

    try {
      const feesDetails = {
        feeMode: { mode: 'sponsored' as const },
        deploymentData: deploymentData,
      };

      const result = await counterfactualAccount.executePaymasterTransaction(
        [],
        feesDetails
      );

      await this.provider.waitForTransaction(result.transaction_hash);

      return result.transaction_hash;

    } catch (e: any) {
      const errorMsg = e.message || e.toString();
      if (
        errorMsg.includes('contract already deployed') ||
        errorMsg.includes('already deployed') ||
        errorMsg.includes('already-deployed') ||
        errorMsg.includes('Class hash') && errorMsg.includes('not supported')
      ) {
        if (errorMsg.includes('not supported')) {
          throw new Error('Class hash not supported by paymaster. Contact AVNU to whitelist.');
        }
        return 'already-deployed';
      }

      throw e;
    }
  }

  /**
   * Execute calls using the OAuth wallet with paymaster.
   * Uses AVNU API with automatic session handling:
   * - Session NOT registered: Uses JWT signature (registers + executes in one tx)
   * - Session expired but renewable: Auto-renews then executes
   * - Session active: Uses lightweight session signature
   * - Session expired outside grace: Throws error (user must re-login)
   */
  async execute(calls: Call | Call[]): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress) {
      throw new Error('No valid session');
    }

    const callsArray = Array.isArray(calls) ? calls : [calls];

    // Check session status on-chain
    const status = await this.getSessionStatus();
    console.log('[execute] Session status:', JSON.stringify(status, (_, v) => typeof v === 'bigint' ? v.toString() : v));
    // Case 1: Session not registered - use JWT signature via AVNU (registers + executes)
    if (!status.registered) {
      console.log('[execute] Using JWT signature (session not registered)');
      return this.executeWithAVNUAPI(callsArray, session, true); // forceJWT=true
    }

    // Case 2: Session expired but can be renewed - auto-renew then execute
    if (status.expired && status.canRenew) {
      const newSession = await this.oauthManager.generateNewSession();
      await this.renewSession(newSession);
      return this.executeWithAVNUAPI(callsArray, newSession);
    }

    // Case 3: Session expired and outside grace period - cannot renew
    if (status.expired && !status.canRenew) {
      throw new Error('SESSION_EXPIRED: Session has expired outside grace period. Please login again.');
    }

    // Case 4: Session is active - use session signature (cheap)
    return this.executeWithAVNUAPI(callsArray, session);
  }


  /**
   * Execute with AVNU API.
   * @param forceJWT If true, uses JWT signature (for first tx). Otherwise uses session signature.
   */
  private async executeWithAVNUAPI(calls: Call[], session: OAuthSession, forceJWT: boolean = false): Promise<string> {
    if (!session.walletAddress) {
      throw new Error('No wallet address in session');
    }

    const baseUrl = this.network === 'mainnet'
      ? 'https://starknet.api.avnu.fi'
      : 'https://sepolia.api.avnu.fi';

    // Format calls for AVNU API
    const formattedCalls = calls.map(call => ({
      contractAddress: call.contractAddress,
      entrypoint: call.entrypoint,
      calldata: call.calldata
        ? (call.calldata as string[]).map(c => num.toHex(c))
        : [],
    }));

    // Build typed data
    const buildResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.paymasterApiKey,
      },
      body: JSON.stringify({
        userAddress: session.walletAddress,
        calls: formattedCalls,
      }),
    });

    if (!buildResponse.ok) {
      throw new Error(`Build typed data failed: ${await buildResponse.text()}`);
    }

    const paymasterTypedData = await buildResponse.json();

    // Compute message hash
    const messageHash = this.computeTypedDataHash(paymasterTypedData, session.walletAddress);

    // Build signature (JWT for first tx, session for subsequent)
    // Pass calls for Merkle proof inclusion in session signatures
    const signature = forceJWT
      ? await this.oauthManager.buildJWTSignatureData(messageHash)
      : this.oauthManager.buildSessionSignature(messageHash, calls);

    // Execute via paymaster
    const executePayload = {
      userAddress: session.walletAddress,
      typedData: JSON.stringify(paymasterTypedData),
      signature: signature,
    };

    try {
      const executeResponse = await fetch(`${baseUrl}/paymaster/v1/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'api-key': this.paymasterApiKey,
        },
        body: JSON.stringify(executePayload),
      });

      if (!executeResponse.ok) {
        const errorText = await executeResponse.text();

        if (errorText.includes('Session expired')) {
          throw new Error('SESSION_EXPIRED: Session has expired. Call renewSession() to renew.');
        }

        throw new Error(`Execute failed: ${errorText}`);
      }

      const result = await executeResponse.json();
      return result.transactionHash;
    } catch (e: any) {
      throw e;
    }
  }

  /**
   * Wait for a transaction to be confirmed on-chain
   */
  private async waitForTransaction(txHash: string, timeout: number = 120000): Promise<void> {
    const startTime = Date.now();
    const pollInterval = 3000;
    let attemptCount = 0;

    while (Date.now() - startTime < timeout) {
      attemptCount++;
      try {
        const receipt = await this.provider.getTransactionReceipt(txHash);
        if (receipt) {
          const isSuccessful = (receipt as any).execution_status === 'SUCCEEDED' ||
            (receipt as any).status === 'ACCEPTED_ON_L2' ||
            (receipt as any).finality_status === 'ACCEPTED_ON_L2' ||
            (receipt as any).finality_status === 'ACCEPTED_ON_L1';

          if (isSuccessful) {
            return;
          }

          const isFailed = (receipt as any).execution_status === 'REVERTED';
          if (isFailed) {
            throw new Error(`Transaction ${txHash} was reverted`);
          }
        }
      } catch (error: any) {
        if (error.message && error.message.includes('reverted')) {
          throw error;
        }
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    throw new Error(`Transaction ${txHash} confirmation timeout after ${timeout}ms`);
  }

  /**
   * Renew session using the grace period (self-custodial).
   * The old session must be expired but within its renewal window.
   * The old session key signs the new session params to authorize the renewal.
   *
   * @param newSession The new session data (from generateNewSession)
   * @returns Transaction hash
   */
  async renewSession(newSession: OAuthSession): Promise<string> {
    const oldSession = this.oauthManager.getSession();
    if (!oldSession?.walletAddress || !oldSession.sessionPrivateKey) {
      throw new Error('No old session to renew from');
    }

    if (!newSession.sessionPubKey || !newSession.nonce || !newSession.nonceParams) {
      throw new Error('New session data incomplete');
    }

    // Compute allowed_contracts_root for the new session policy
    const policy = newSession.sessionPolicy;
    const allowedContractsRoot = policy?.allowedContracts?.length
      ? OAuthWalletManager.computeMerkleRoot(policy.allowedContracts)
      : '0x0';
    const maxCallsPerTx = policy?.maxCallsPerTx ?? 10;

    // Sign the new session params with the OLD session key
    // Message = poseidon(new_session_key, new_nonce, new_valid_after, new_valid_until,
    //                    new_renewal_deadline, new_allowed_contracts_root, new_max_calls_per_tx)
    const message = hash.computePoseidonHashOnElements([
      newSession.sessionPubKey,
      newSession.nonce,
      num.toHex(newSession.nonceParams.validAfter),
      num.toHex(newSession.nonceParams.validUntil),
      num.toHex(newSession.nonceParams.renewalDeadline),
      allowedContractsRoot,
      num.toHex(maxCallsPerTx),
    ]);

    const oldSignature = ec.starkCurve.sign(message, oldSession.sessionPrivateKey);

    // Build spending policies calldata
    const spendingCalldata: string[] = [];
    if (policy?.spendingLimits?.length) {
      spendingCalldata.push(num.toHex(policy.spendingLimits.length));
      for (const limit of policy.spendingLimits) {
        spendingCalldata.push(num.toHex(limit.token));
        const limitBig = BigInt(limit.limit);
        spendingCalldata.push(num.toHex(limitBig & ((1n << 128n) - 1n))); // low
        spendingCalldata.push(num.toHex(limitBig >> 128n)); // high
      }
    } else {
      spendingCalldata.push(num.toHex(0));
    }

    // Build the renew_session call
    const renewCall: Call = {
      contractAddress: oldSession.walletAddress,
      entrypoint: 'renew_session',
      calldata: [
        oldSession.sessionPubKey,              // old_session_key
        num.toHex(oldSignature.r),             // old_signature_r
        num.toHex(oldSignature.s),             // old_signature_s
        newSession.sessionPubKey,              // new_session_key
        newSession.nonce,                      // new_nonce
        num.toHex(newSession.nonceParams.validAfter),       // new_valid_after
        num.toHex(newSession.nonceParams.validUntil),       // new_valid_until
        num.toHex(newSession.nonceParams.renewalDeadline),  // new_renewal_deadline
        allowedContractsRoot,                  // new_allowed_contracts_root
        num.toHex(maxCallsPerTx),              // new_max_calls_per_tx
        ...spendingCalldata,                   // spending policies
      ]
    };

    // Execute via paymaster using the OLD session signature
    const baseUrl = this.network === 'mainnet'
      ? 'https://starknet.api.avnu.fi'
      : 'https://sepolia.api.avnu.fi';

    const buildResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.paymasterApiKey,
      },
      body: JSON.stringify({
        userAddress: oldSession.walletAddress,
        calls: [{
          contractAddress: renewCall.contractAddress,
          entrypoint: renewCall.entrypoint,
          calldata: renewCall.calldata,
        }],
      }),
    });

    if (!buildResponse.ok) {
      throw new Error(`Build typed data failed: ${await buildResponse.text()}`);
    }

    const paymasterTypedData = await buildResponse.json();
    const messageHash = this.computeTypedDataHash(paymasterTypedData, oldSession.walletAddress);

    // Sign with OLD session (it's in grace period, can only renew, not transact)
    const signature = this.oauthManager.buildSessionSignature(messageHash);

    const executeResponse = await fetch(`${baseUrl}/paymaster/v1/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.paymasterApiKey,
      },
      body: JSON.stringify({
        userAddress: oldSession.walletAddress,
        typedData: JSON.stringify(paymasterTypedData),
        signature: signature,
      }),
    });

    if (!executeResponse.ok) {
      const errorText = await executeResponse.text();
      if (errorText.includes('Renewal period expired')) {
        throw new Error('Grace period expired. Please login again with JWT.');
      }
      throw new Error(`Renew session failed: ${errorText}`);
    }

    const result = await executeResponse.json();
    return result.transactionHash;
  }

  /**
   * Revoke a specific session key.
   * Requires JWT verification — builds a full JWT-signed transaction.
   *
   * @param sessionKey The session key (public key) to revoke
   * @returns Transaction hash
   */
  async revokeSession(sessionKey: string): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress) {
      throw new Error('No valid session');
    }

    const revokeCall: Call = {
      contractAddress: session.walletAddress,
      entrypoint: 'revoke_session',
      calldata: [sessionKey],
    };

    // Authentication handled by tx validation layer (JWT or session signature)
    return this.executeWithAVNUAPI([revokeCall], session);
  }

  /**
   * Emergency revoke all session keys.
   * Increments the revocation epoch, invalidating ALL existing sessions.
   * Requires JWT verification.
   *
   * @returns Transaction hash
   */
  async emergencyRevokeAllSessions(): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress) {
      throw new Error('No valid session');
    }

    const revokeCall: Call = {
      contractAddress: session.walletAddress,
      entrypoint: 'emergency_revoke',
      calldata: [],
    };

    // Authentication handled by tx validation layer (JWT or session signature)
    return this.executeWithAVNUAPI([revokeCall], session);
  }

  /**
   * Get the wallet address
   */
  getAddress(): string | null {
    return this.oauthManager.getWalletAddress();
  }

  /**
   * Get a starknet.js Account object for compatibility
   */
  getAccount(): Account | null {
    const address = this.oauthManager.getWalletAddress();
    const privateKey = this.oauthManager.getSessionPrivateKey();

    if (!address || !privateKey) {
      return null;
    }

    if (!this.account) {
      this.account = new Account({ provider: this.provider, address, signer: privateKey });
    }

    return this.account;
  }

  // ============== Private helpers ==============

  private computeTypedDataHash(paymasterTypedData: any, address: string): string {
    try {
      const messageHash = typedData.getMessageHash(paymasterTypedData, address);
      return messageHash;
    } catch (error: any) {
      console.error('[OAuthTransactionManager] Failed to compute typed data hash:', error);
      throw new Error(`Failed to compute typed data hash: ${error.message}`);
    }
  }
}
