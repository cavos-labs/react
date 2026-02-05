/**
 * OAuthTransactionManager - Manages transactions for OAuth-based wallets
 *
 * Handles:
 * - Transaction signing with ephemeral keys
 * - Building JWT signature data for on-chain verification
 * - Account deployment (self-deploy via paymaster)
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
    return session?.ephemeralPubKey || '0x0';
  }

  async signMessage(typedDataInput: TypedData, accountAddress: string): Promise<Signature> {
    // For OutsideExecution (paymaster), compute the typed data hash properly
    const msgHash = typedData.getMessageHash(typedDataInput, accountAddress);

    if (this.forDeploy) {
      // For deploy, use full JWT signature
      return await this.oauthManager.buildJWTSignatureData(msgHash);
    } else {
      // For execute, use lightweight session signature
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

    // Deploy always uses full JWT signature
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

    // Initialize PaymasterRpc
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
    maxBlock?: bigint;
    renewalDeadline?: bigint;
  }> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress || !session.ephemeralPubKey) {
      return { registered: false, expired: false, canRenew: false };
    }

    try {
      const result = await this.provider.callContract({
        contractAddress: session.walletAddress,
        entrypoint: 'get_session',
        calldata: [session.ephemeralPubKey],
      });

      // get_session returns (nonce, max_block, renewal_deadline, registered_at)
      const nonce = BigInt(result[0]);
      const maxBlock = BigInt(result[1]);
      const renewalDeadline = BigInt(result[2]);

      const registered = nonce !== 0n;

      if (!registered) {
        return { registered: false, expired: false, canRenew: false };
      }

      // Get current block number
      const currentBlock = BigInt((await this.provider.getBlockNumber()) || 0);

      const expired = currentBlock >= maxBlock;
      const canRenew = expired && currentBlock < renewalDeadline;

      return { registered, expired, canRenew, maxBlock, renewalDeadline };
    } catch {
      return { registered: false, expired: false, canRenew: false };
    }
  }

  /**
   * Check if the current session is registered on-chain.
   * Calls the contract's get_session(ephemeral_pubkey) function.
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

    // Deployer address is legacy - no longer used but kept for contract constructor compatibility
    const deployerAddress = this.config.deployerContractAddress || '0x0';

    // Check if already deployed
    const alreadyDeployed = await this.isDeployed();
    if (alreadyDeployed) {
      return 'already-deployed';
    }

    // Constructor calldata: [address_seed, jwks_registry, deployer]
    const constructorCalldata = [
      session.addressSeed,
      this.config.jwksRegistryAddress,
      deployerAddress,
    ].map(c => num.toHex(c));

    // Create custom signer for deploy (uses full JWT signature)
    const deploySigner = new OAuthSigner(this.oauthManager, true);

    // Create counterfactual Account with PaymasterRpc (starknet.js v9 syntax)
    const counterfactualAccount = new Account({
      provider: this.provider,
      address: session.walletAddress,
      signer: deploySigner,
      paymaster: this.paymasterRpc,
    });

    // Build AccountDeploymentData per starknet.js spec
    const deploymentData = {
      address: session.walletAddress,
      class_hash: this.config.cavosAccountClassHash,
      salt: session.addressSeed,
      calldata: constructorCalldata,
      version: 1 as const,
    };

    try {
      // Execute deploy with paymaster sponsorship using starknet.js
      const feesDetails = {
        feeMode: { mode: 'sponsored' as const },
        deploymentData: deploymentData,
      };

      // For DEPLOY_ACCOUNT, call executePaymasterTransaction with empty calls
      const result = await counterfactualAccount.executePaymasterTransaction(
        [], // No calls - just deploy
        feesDetails
      );

      // Wait for confirmation
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
        // If class hash not supported, fall back to note
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
    // Case 1: Session not registered - use JWT signature via AVNU (registers + executes)
    if (!status.registered) {
      return this.executeWithAVNUAPI(callsArray, session, true); // forceJWT=true
    }

    // Case 2: Session expired but can be renewed - auto-renew then execute
    if (status.expired && status.canRenew) {
      // Generate new session
      const newSession = await this.oauthManager.generateNewSession();

      // Renew the session
      await this.renewSession(newSession);

      // Now execute with the new session signature
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
    const signature = forceJWT
      ? await this.oauthManager.buildJWTSignatureData(messageHash)
      : this.oauthManager.buildSessionSignature(messageHash);

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

        // Check if session expired - developer must handle renewal
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
    const pollInterval = 3000; // Poll every 3 seconds
    let attemptCount = 0;

    while (Date.now() - startTime < timeout) {
      attemptCount++;
      try {
        const receipt = await this.provider.getTransactionReceipt(txHash);
        if (receipt) {
          // Check if transaction was successful
          const isSuccessful = (receipt as any).execution_status === 'SUCCEEDED' ||
            (receipt as any).status === 'ACCEPTED_ON_L2' ||
            (receipt as any).finality_status === 'ACCEPTED_ON_L2' ||
            (receipt as any).finality_status === 'ACCEPTED_ON_L1';

          if (isSuccessful) {
            return;
          }

          // Check if transaction failed
          const isFailed = (receipt as any).execution_status === 'REVERTED';
          if (isFailed) {
            throw new Error(`Transaction ${txHash} was reverted`);
          }
        }
      } catch (error: any) {
        // Transaction not found yet or other error
        if (error.message && error.message.includes('reverted')) {
          throw error;
        }
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    throw new Error(`Transaction ${txHash} confirmation timeout after ${timeout}ms`);
  }

  /**
   * Internal helper for renewSession using raw session objects
   */
  private async renewSessionInternal(oldSession: OAuthSession, newSession: OAuthSession): Promise<string> {
    if (!oldSession.ephemeralPrivateKey || !oldSession.ephemeralPubKey) {
      throw new Error('Old session key missing for renewal');
    }

    // Build the renew_session call
    const message = hash.computePoseidonHashOnElements([
      newSession.ephemeralPubKey,
      newSession.nonce,
      num.toHex(newSession.nonceParams.maxBlock),
      num.toHex(newSession.nonceParams.renewalDeadline),
    ]);

    const oldCurveSignature = ec.starkCurve.sign(message, oldSession.ephemeralPrivateKey);

    const renewCall: Call = {
      contractAddress: oldSession.walletAddress!,
      entrypoint: 'renew_session',
      calldata: [
        oldSession.ephemeralPubKey,
        num.toHex(oldCurveSignature.r),
        num.toHex(oldCurveSignature.s),
        newSession.ephemeralPubKey,
        newSession.nonce,
        num.toHex(newSession.nonceParams.maxBlock),
        num.toHex(newSession.nonceParams.renewalDeadline),
      ]
    };

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
        calls: [renewCall],
      }),
    });

    if (!buildResponse.ok) {
      throw new Error(`Build renewal failed: ${await buildResponse.text()}`);
    }

    const paymasterTypedData = await buildResponse.json();
    const messageHash = this.computeTypedDataHash(paymasterTypedData, oldSession.walletAddress!);

    // Sign with OLD session key
    const signature = ec.starkCurve.sign(messageHash, oldSession.ephemeralPrivateKey);
    const formattedSignature = [
      '0x53455353494f4e5f5631',
      num.toHex(signature.r),
      num.toHex(signature.s),
      oldSession.ephemeralPubKey,
    ];

    const executeResponse = await fetch(`${baseUrl}/paymaster/v1/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.paymasterApiKey,
      },
      body: JSON.stringify({
        userAddress: oldSession.walletAddress,
        typedData: JSON.stringify(paymasterTypedData),
        signature: formattedSignature,
      }),
    });

    if (!executeResponse.ok) {
      const errorText = await executeResponse.text();
      if (errorText.includes('Renewal period expired')) {
        throw new Error('Renewal period expired');
      }
      throw new Error(`Execution of renewal failed: ${errorText}`);
    }

    const result = await executeResponse.json();
    return result.transactionHash;
  }

  /**
   * Renew session using the grace period (self-custodial).
   * The old session must be expired but within its renewal window.
   * The old ephemeral key signs the new session params to authorize the renewal.
   *
   * @param newSession The new session data (from a fresh OAuth login)
   * @returns Transaction hash
   */
  async renewSession(newSession: OAuthSession): Promise<string> {
    const oldSession = this.oauthManager.getSession();
    if (!oldSession?.walletAddress || !oldSession.ephemeralPrivateKey) {
      throw new Error('No old session to renew from');
    }

    if (!newSession.ephemeralPubKey || !newSession.nonce || !newSession.nonceParams) {
      throw new Error('New session data incomplete');
    }

    // Sign the new session params with the OLD ephemeral key
    // Message = poseidon(new_ephemeral_pubkey, new_nonce, new_max_block, new_renewal_deadline)
    const message = hash.computePoseidonHashOnElements([
      newSession.ephemeralPubKey,
      newSession.nonce,
      num.toHex(newSession.nonceParams.maxBlock),
      num.toHex(newSession.nonceParams.renewalDeadline),
    ]);

    const oldSignature = ec.starkCurve.sign(message, oldSession.ephemeralPrivateKey);

    // Build the renew_session call
    const renewCall: Call = {
      contractAddress: oldSession.walletAddress,
      entrypoint: 'renew_session',
      calldata: [
        oldSession.ephemeralPubKey,           // old_ephemeral_pubkey
        num.toHex(oldSignature.r),            // old_signature_r
        num.toHex(oldSignature.s),            // old_signature_s
        newSession.ephemeralPubKey,           // new_ephemeral_pubkey
        newSession.nonce,                     // new_nonce
        num.toHex(newSession.nonceParams.maxBlock),        // new_max_block
        num.toHex(newSession.nonceParams.renewalDeadline), // new_renewal_deadline
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
      // If grace period expired, caller should use registerSessionViaDeployer
      if (errorText.includes('Renewal period expired')) {
        throw new Error('Grace period expired. Use registerSessionViaDeployer instead.');
      }
      throw new Error(`Renew session failed: ${errorText}`);
    }

    const result = await executeResponse.json();
    return result.transactionHash;
  }

  /**
   * Register a new session via the deployer (fallback when grace period expired).
   * This requires the relayer to verify the JWT off-chain.
   * Less decentralized but always works.
   *
   * @param newSession The new session data (from a fresh OAuth login)
   * @returns Transaction hash
   */
  async registerSessionViaDeployer(newSession: OAuthSession): Promise<string> {
    if (!newSession.walletAddress || !newSession.ephemeralPubKey || !newSession.nonce || !newSession.nonceParams) {
      throw new Error('New session data incomplete');
    }

    if (!this.config.deployerContractAddress) {
      throw new Error('Deployer contract address not configured');
    }

    if (!this.config.relayerAddress || !this.config.relayerPrivateKey) {
      throw new Error('Relayer configuration missing');
    }

    const baseUrl = this.network === 'mainnet'
      ? 'https://starknet.api.avnu.fi'
      : 'https://sepolia.api.avnu.fi';

    // Generate valid JWT signature for on-chain verification
    // Use dummy hash because verify_jwt_and_register_session_internal doesn't check ECDSA
    const dummyTxHash = '0x0';
    const jwtSignature = await this.oauthManager.buildJWTSignatureData(dummyTxHash);

    // Build the register_session call (called by relayer on the deployer)
    // [account_address, ephemeral_pubkey, nonce, max_block, renewal_deadline, signature_len, ...signature]
    const registerCall: Call = {
      contractAddress: this.config.deployerContractAddress,
      entrypoint: 'register_session',
      calldata: [
        newSession.walletAddress,                          // account_address
        newSession.ephemeralPubKey,                        // ephemeral_pubkey
        newSession.nonce,                                  // nonce
        num.toHex(newSession.nonceParams.maxBlock),        // max_block
        num.toHex(newSession.nonceParams.renewalDeadline), // renewal_deadline
        num.toHex(jwtSignature.length),                    // signature_len
        ...jwtSignature,                                   // signature span
      ]
    };

    // Execute via relayer
    const buildResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.paymasterApiKey,
      },
      body: JSON.stringify({
        userAddress: this.config.relayerAddress,
        calls: [{
          contractAddress: registerCall.contractAddress,
          entrypoint: registerCall.entrypoint,
          calldata: registerCall.calldata,
        }],
      }),
    });

    if (!buildResponse.ok) {
      throw new Error(`Build typed data failed: ${await buildResponse.text()}`);
    }

    const paymasterTypedData = await buildResponse.json();

    // Sign with relayer
    const relayerAccount = new Account({
      provider: this.provider,
      address: this.config.relayerAddress,
      signer: this.config.relayerPrivateKey
    });

    const signature = await relayerAccount.signMessage(paymasterTypedData);
    const formattedSignature = Array.isArray(signature)
      ? signature.map(s => num.toHex(s))
      : [num.toHex(signature.r), num.toHex(signature.s)];

    const executeResponse = await fetch(`${baseUrl}/paymaster/v1/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.paymasterApiKey,
      },
      body: JSON.stringify({
        userAddress: this.config.relayerAddress,
        typedData: JSON.stringify(paymasterTypedData),
        signature: formattedSignature,
      }),
    });

    if (!executeResponse.ok) {
      throw new Error(`Register session via deployer failed: ${await executeResponse.text()}`);
    }

    const result = await executeResponse.json();

    // Wait for transaction confirmation
    await this.provider.waitForTransaction(result.transactionHash);

    return result.transactionHash;
  }

  /**
   * Get the wallet address
   */
  getAddress(): string | null {
    return this.oauthManager.getWalletAddress();
  }

  /**
   * Get a starknet.js Account object for compatibility
   * Note: This account uses a custom signer that builds OAuth signatures
   */
  getAccount(): Account | null {
    const address = this.oauthManager.getWalletAddress();
    const privateKey = this.oauthManager.getEphemeralPrivateKey();

    if (!address || !privateKey) {
      return null;
    }

    // Create account with ephemeral key
    // Note: The actual signature will be built by buildJWTSignatureData
    if (!this.account) {
      this.account = new Account({ provider: this.provider, address, signer: privateKey });
    }

    return this.account;
  }

  // ============== Private helpers ==============

  private computeTypedDataHash(paymasterTypedData: any, address: string): string {
    // Use starknet.js typedData utilities to compute the SNIP-12 message hash
    // This handles SNIP-9 OutsideExecution typed data properly
    try {
      const messageHash = typedData.getMessageHash(paymasterTypedData, address);
      return messageHash;
    } catch (error: any) {
      console.error('[OAuthTransactionManager] Failed to compute typed data hash:', error);
      throw new Error(`Failed to compute typed data hash: ${error.message}`);
    }
  }
}
