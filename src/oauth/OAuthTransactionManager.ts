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
  private paymasterApiBaseUrl: string;
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
    network: 'mainnet' | 'sepolia',
    paymasterUrl?: string
  ) {
    this.config = config;
    this.provider = new RpcProvider({ nodeUrl: rpcUrl });
    this.oauthManager = oauthManager;
    this.paymasterApiKey = paymasterApiKey;
    this.network = network;

    const defaultPaymasterUrl = network === 'mainnet'
      ? 'https://paymaster.cavos.xyz'
      : 'https://sepolia-paymaster.cavos.xyz';

    const resolvedPaymasterUrl = paymasterUrl || defaultPaymasterUrl;

    // Both point to the same Cavos JSON-RPC endpoint
    this.paymasterApiBaseUrl = paymasterUrl || defaultPaymasterUrl;

    this.paymasterRpc = new PaymasterRpc({
      nodeUrl: resolvedPaymasterUrl,
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
      const result = await this.provider.callContract({
        contractAddress: session.walletAddress,
        entrypoint: 'get_session',
        calldata: [session.sessionPubKey],
      });

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

      await this.waitForTransaction(result.transaction_hash);

      return result.transaction_hash;

    } catch (e: any) {
      const errorMsg = e.message || e.toString();
      console.error('[deployAccount] Deployment error:', errorMsg, e);
      if (
        errorMsg.includes('contract already deployed') ||
        errorMsg.includes('already deployed') ||
        errorMsg.includes('already-deployed')
      ) {
        return 'already-deployed';
      }
      if (errorMsg.includes('Class hash') && errorMsg.includes('not supported')) {
        throw new Error('Class hash not supported by paymaster. Contact AVNU to whitelist.');
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
    // Case 1: Session not registered - throw error
    if (!status.registered) {
      throw new Error('Session not registered on-chain. Please call registerSession() first to authorize this session.');
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
   * Register the current session key on-chain using the current JWT.
   * Call this explicitly before executing transactions to pre-register the session.
   */
  async registerCurrentSession(): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.jwt || !session.walletAddress) {
      throw new Error('Must be logged in to register session');
    }

    const registrationCall: Call = {
      contractAddress: session.walletAddress,
      entrypoint: 'get_version',
      calldata: [],
    };

    return this.executeWithAVNUAPI([registrationCall], session, true);
  }

  /**
   * Send a JSON-RPC request to the Cavos paymaster.
   */
  private async callPaymasterRpc(method: string, params: any[]): Promise<any> {
    const response = await fetch(this.paymasterApiBaseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-paymaster-api-key': this.paymasterApiKey,
      },
      body: JSON.stringify({ jsonrpc: '2.0', method, id: 1, params }),
    });

    const text = await response.text();
    if (!response.ok) {
      throw new Error(`Paymaster RPC request failed: ${text}`);
    }

    const data = JSON.parse(text);
    if (data.error) {
      const detail = data.error.data
        ? ` | ${typeof data.error.data === 'string' ? data.error.data : JSON.stringify(data.error.data)}`
        : '';
      throw new Error(`Paymaster RPC error [${data.error.code}]: ${data.error.message}${detail}`);
    }

    return data.result;
  }

  /**
   * Execute via Cavos paymaster JSON-RPC (paymaster_buildTransaction + sign + paymaster_executeTransaction).
   * @param forceJWT If true, uses JWT signature (for first tx). Otherwise uses session signature.
   */
  private async executeWithAVNUAPI(calls: Call[], session: OAuthSession, forceJWT: boolean = false): Promise<string> {
    if (!session.walletAddress) {
      throw new Error('No wallet address in session');
    }

    // Format calls for Cavos JSON-RPC: { to, selector, calldata }
    const formattedCalls = calls.map(call => ({
      to: call.contractAddress,
      selector: hash.getSelectorFromName(call.entrypoint),
      calldata: call.calldata
        ? (call.calldata as string[]).map(c => num.toHex(c))
        : [],
    }));

    // Build typed data via paymaster_buildTransaction
    const buildResult = await this.callPaymasterRpc('paymaster_buildTransaction', [{
      transaction: {
        type: 'invoke',
        invoke: {
          user_address: session.walletAddress,
          calls: formattedCalls,
        },
      },
      parameters: {
        version: '0x1',
        fee_mode: { mode: 'sponsored' },
      },
    }]);

    // Response for invoke: { type: 'invoke', typed_data, parameters, fee }
    const paymasterTypedData = buildResult.typed_data;
    if (!paymasterTypedData) {
      throw new Error(`paymaster_buildTransaction returned unexpected format: ${JSON.stringify(buildResult)}`);
    }

    // Compute message hash
    const messageHash = this.computeTypedDataHash(paymasterTypedData, session.walletAddress);

    // Build signature (JWT for first tx, session for subsequent)
    // Pass calls for Merkle proof inclusion in session signatures
    const signature = forceJWT
      ? await this.oauthManager.buildJWTSignatureData(messageHash, session)
      : this.oauthManager.buildSessionSignature(messageHash, calls);

    // Execute via paymaster_executeTransaction
    const result = await this.callPaymasterRpc('paymaster_executeTransaction', [{
      transaction: {
        type: 'invoke',
        invoke: {
          user_address: session.walletAddress,
          typed_data: paymasterTypedData,
          signature: signature,
        },
      },
      parameters: buildResult.parameters,
    }]);

    return result.transaction_hash;
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
            const revertReason = (receipt as any).revert_error || (receipt as any).revert_reason || 'Unknown revert reason';
            throw new Error(`Transaction ${txHash} was reverted: ${revertReason}`);
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

    // Execute via Cavos paymaster JSON-RPC using the OLD session signature
    const buildResult = await this.callPaymasterRpc('paymaster_buildTransaction', [{
      transaction: {
        type: 'invoke',
        invoke: {
          user_address: oldSession.walletAddress,
          calls: [{
            to: renewCall.contractAddress,
            selector: hash.getSelectorFromName(renewCall.entrypoint),
            calldata: (renewCall.calldata as string[] | undefined) ?? [],
          }],
        },
      },
      parameters: {
        version: '0x1',
        fee_mode: { mode: 'sponsored' },
      },
    }]);

    const paymasterTypedData = buildResult.typed_data;
    if (!paymasterTypedData) {
      throw new Error(`paymaster_buildTransaction returned unexpected format: ${JSON.stringify(buildResult)}`);
    }

    const messageHash = this.computeTypedDataHash(paymasterTypedData, oldSession.walletAddress);

    // Sign with OLD session (it's in grace period, can only renew, not transact)
    const signature = this.oauthManager.buildSessionSignature(messageHash);

    let result: any;
    try {
      result = await this.callPaymasterRpc('paymaster_executeTransaction', [{
        transaction: {
          type: 'invoke',
          invoke: {
            user_address: oldSession.walletAddress,
            typed_data: paymasterTypedData,
            signature: signature,
          },
        },
        parameters: buildResult.parameters,
      }]);
    } catch (e: any) {
      if (e.message?.includes('Renewal period expired')) {
        throw new Error('Grace period expired. Please login again with JWT.');
      }
      throw new Error(`Renew session failed: ${e.message}`);
    }

    return result.transaction_hash;
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

    // revoke_session requires JWT verification on-chain
    return this.executeWithAVNUAPI([revokeCall], session, true);
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

    // emergency_revoke requires JWT verification on-chain
    return this.executeWithAVNUAPI([revokeCall], session, true);
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
