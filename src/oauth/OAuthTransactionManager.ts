/**
 * OAuthTransactionManager - Manages transactions for OAuth-based wallets
 *
 * Handles:
 * - Transaction signing with ephemeral keys
 * - Building JWT signature data for on-chain verification
 * - Account deployment
 * - Paymaster integration
 */

import {
  Account,
  Call,
  RpcProvider,
  num,
  typedData,
  hash,
  ec,
} from 'starknet';
import { OAuthWalletManager, OAuthSession } from './OAuthWalletManager';
import { OAuthWalletConfig } from '../types/config';

export class OAuthTransactionManager {
  private config: OAuthWalletConfig;
  private provider: RpcProvider;
  private oauthManager: OAuthWalletManager;
  private paymasterApiKey: string;
  private network: 'mainnet' | 'sepolia';
  private account: Account | null = null;

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
   * Deploy the OAuth account contract using paymaster.
   * This uses the new deploy_oauth_account_with_session function that
   * registers the session during deployment, avoiding expensive on-chain RSA verification.
   */
  async deployAccount(): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress || !session.addressSeed) {
      throw new Error('No valid session for deployment');
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

    // Extract session parameters for on-chain registration
    const ephemeralPubkey = session.ephemeralPubKey;
    const nonce = session.nonce;
    const maxBlock = session.nonceParams.maxBlock;
    const renewalDeadline = session.nonceParams.renewalDeadline;

    console.log('[OAuthTransactionManager] Deploying account with session registration...');
    console.log('[OAuthTransactionManager] CLASS HASH BEING USED:', this.config.cavosAccountClassHash);
    console.log('[OAuthTransactionManager] JWKS Registry:', this.config.jwksRegistryAddress);
    console.log('[OAuthTransactionManager] Deployer:', this.config.deployerContractAddress);
    console.log('[OAuthTransactionManager] Ephemeral pubkey:', ephemeralPubkey);
    console.log('[OAuthTransactionManager] Nonce:', nonce);
    console.log('[OAuthTransactionManager] Max block:', maxBlock.toString());
    console.log('[OAuthTransactionManager] Renewal deadline:', renewalDeadline.toString());

    // Calldata for deploy_oauth_account_with_session:
    // [class_hash, salt, address_seed, jwks_registry, ephemeral_pubkey, nonce, max_block, renewal_deadline, signature_len, ...signature]

    // We need to provide a valid JWT signature.
    // The contract's verify_jwt_and_register_session_internal does NOT check the ephemeral signature (r,s)
    // against the transaction hash (because in this Case the Relayer is the transaction sender).
    // So we can sign a dummy hash here.
    const dummyTxHash = '0x0';
    const jwtSignature = await this.oauthManager.buildJWTSignatureData(dummyTxHash);

    const deployCall: Call = {
      contractAddress: this.config.deployerContractAddress,
      entrypoint: 'deploy_oauth_account_with_session',
      calldata: [
        this.config.cavosAccountClassHash,
        session.addressSeed,
        session.addressSeed, // salt matches addressSeed
        this.config.jwksRegistryAddress,
        ephemeralPubkey,
        nonce,
        num.toHex(maxBlock),
        num.toHex(renewalDeadline),
        num.toHex(jwtSignature.length), // signature_len
        ...jwtSignature,                // signature span
      ]
    };

    // Step 1: Build typed data for Relayer
    const buildResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.paymasterApiKey,
      },
      body: JSON.stringify({
        userAddress: this.config.relayerAddress,
        calls: [deployCall],
      }),
    });

    if (!buildResponse.ok) {
      const errorText = await buildResponse.text();
      console.error('[OAuthTransactionManager] Relayer build failed:', errorText);
      throw new Error(`Relayer build failed: ${errorText}`);
    }

    const paymasterTypedData = await buildResponse.json();

    // Step 2: Sign with Relayer Private Key (Standard Starknet Signature)
    // We need a temporary Account instance to sign SNIP-12 data easily, or just use `account.signMessage`
    const relayerAccount = new Account({
      provider: this.provider,
      address: this.config.relayerAddress,
      signer: this.config.relayerPrivateKey
    });

    // Sign the typed data
    const signature = await relayerAccount.signMessage(paymasterTypedData);

    // Format signature for API (ensure hex strings)
    const formattedSignature = Array.isArray(signature)
      ? signature.map(s => num.toHex(s))
      : [num.toHex(signature.r), num.toHex(signature.s)];

    // Step 3: Execute via paymaster
    try {
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
        const errorText = await executeResponse.text();
        // Check for "already deployed" error
        if (errorText.includes('contract already deployed') || errorText.includes('0x48997c5f27f1308e2266befb0693d0df10e6e097a9de9c66f3b8cb542fb032b')) {
          console.log('[OAuthTransactionManager] Account already deployed (caught from Relayer error).');
          return 'already-deployed';
        }
        console.error('[OAuthTransactionManager] Relayer execute failed:', errorText);
        throw new Error(`Relayer execute failed: ${errorText}`);
      }

      const result = await executeResponse.json();
      console.log('[OAuthTransactionManager] Deploy tx hash:', result.transactionHash);
      return result.transactionHash;

    } catch (e: any) {
      if (e.message.includes('contract already deployed') || e.message.includes('already-deployed')) {
        return 'already-deployed';
      }
      throw e;
    }
  }

  /**
   * Execute calls using the OAuth wallet with paymaster.
   * Assumes the session was registered during deployment.
   * Uses lightweight session signatures (no RSA verification).
   */
  async execute(calls: Call | Call[]): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress) {
      throw new Error('No valid session');
    }

    const callsArray = Array.isArray(calls) ? calls : [calls];

    const baseUrl = this.network === 'mainnet'
      ? 'https://starknet.api.avnu.fi'
      : 'https://sepolia.api.avnu.fi';

    // Format calls for AVNU API
    const formattedCalls = callsArray.map(call => ({
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

    // Build lightweight session signature (no RSA verification needed!)
    // The session was registered during deployment, so we can use cheap signatures now
    const signature = this.oauthManager.buildSessionSignature(messageHash);

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

    console.log(`[OAuthTransactionManager] Waiting for tx ${txHash} to confirm...`);

    while (Date.now() - startTime < timeout) {
      attemptCount++;
      try {
        const receipt = await this.provider.getTransactionReceipt(txHash);
        if (receipt) {
          console.log(`[OAuthTransactionManager] Receipt found after ${attemptCount} attempts:`, receipt);

          // Check if transaction was successful
          const isSuccessful = (receipt as any).execution_status === 'SUCCEEDED' ||
                              (receipt as any).status === 'ACCEPTED_ON_L2' ||
                              (receipt as any).finality_status === 'ACCEPTED_ON_L2' ||
                              (receipt as any).finality_status === 'ACCEPTED_ON_L1';

          if (isSuccessful) {
            console.log(`[OAuthTransactionManager] Transaction confirmed successfully!`);
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
        console.log(`[OAuthTransactionManager] Attempt ${attemptCount}: tx not ready yet...`);
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

    console.log('[OAuthTransactionManager] Renewing session via grace period...');

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
    console.log('[OAuthTransactionManager] Session renewed! Tx hash:', result.transactionHash);
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

    console.log('[OAuthTransactionManager] Registering session via deployer (fallback)...');

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
    console.log('[OAuthTransactionManager] Session registered via deployer! Tx hash:', result.transactionHash);
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
