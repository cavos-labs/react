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
  EDAMode,
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
    transactions: Call[],
    details: any
  ): Promise<Signature> {
    const txHash = details.transactionHash || '0x0';

    if (this.forDeploy) {
      return await this.oauthManager.buildJWTSignatureData(txHash);
    } else {
      return this.oauthManager.buildSessionSignature(txHash, transactions);
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
      const [result, block] = await Promise.all([
        this.provider.callContract({
          contractAddress: session.walletAddress,
          entrypoint: 'get_session',
          calldata: [session.sessionPubKey],
        }),
        this.provider.getBlock('latest'),
      ]);

      // get_session returns (nonce, valid_after, valid_until, renewal_deadline, registered_at, allowed_contracts_root, max_calls_per_tx)
      const nonce = BigInt(result[0]);
      const validUntil = BigInt(result[2]);
      const renewalDeadline = BigInt(result[3]);

      const registered = nonce !== 0n;

      if (!registered) {
        return { registered: false, expired: false, canRenew: false };
      }

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
   * Execute calls using the OAuth wallet.
   *
   * @param options.gasless - When true (default), gas is sponsored via AVNU Paymaster.
   *   When false, the wallet pays gas itself (requires STRK balance and a registered session).
   *
   * Session handling:
   * - Session NOT registered: Uses JWT signature (registers + executes in one tx). Requires gasless.
   * - Session expired but renewable: Auto-renews then executes.
   * - Session active + gasless: Uses AVNU Paymaster (sponsored).
   * - Session active + non-gasless: Uses standard Account.execute() (user pays gas).
   * - Session expired outside grace: Throws — user must re-login.
   */
  async execute(calls: Call | Call[], options?: { gasless?: boolean }): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress) {
      throw new Error('No valid session');
    }

    const gasless = options?.gasless !== false; // default true
    const callsArray = Array.isArray(calls) ? calls : [calls];

    // Check session status on-chain
    const status = await this.getSessionStatus();

    // Case 1: Session not registered — use JWT to auto-register + execute in one tx (always sponsored)
    if (!status.registered) {
      if (!gasless) {
        throw new Error(
          'Cannot execute a non-sponsored transaction without a registered session. ' +
          'Execute one sponsored transaction first to register the session on-chain.'
        );
      }
      return this.executeWithAVNUAPI(callsArray, session, true);
    }

    // Case 2: Session expired but can be renewed — auto-renew then execute
    if (status.expired && status.canRenew) {
      const newSession = await this.oauthManager.generateNewSession();
      await this.renewSession(newSession);
      return gasless
        ? this.executeWithAVNUAPI(callsArray, newSession)
        : this.executeWithUserFees(callsArray, newSession);
    }

    // Case 3: Session expired and outside grace period — cannot proceed
    if (status.expired && !status.canRenew) {
      throw new Error('SESSION_EXPIRED: Session has expired outside grace period. Please login again.');
    }

    // Case 4: Session is active
    return gasless
      ? this.executeWithAVNUAPI(callsArray, session)
      : this.executeWithUserFees(callsArray, session);
  }

  /**
   * Execute calls paying gas from the wallet's own balance (no paymaster).
   *
   * Bypasses account.execute() entirely — builds, signs, and submits the
   * v3 INVOKE transaction directly via raw RPC to avoid starknet.js
   * zeroing out resource_bounds or calling fee estimation with empty sigs.
   */
  private async executeWithUserFees(calls: Call[], session: OAuthSession): Promise<string> {
    if (!session.walletAddress) {
      throw new Error('No wallet address in session');
    }

    const rpcUrl = (this.provider as any).channel?.nodeUrl
      || (this.provider as any).nodeUrl
      || '';
    if (!rpcUrl) {
      throw new Error('Cannot resolve RPC URL from provider');
    }

    // 1. Get nonce + chainId in parallel
    const [nonce, chainId] = await Promise.all([
      this.provider.getNonceForAddress(session.walletAddress),
      this.provider.getChainId(),
    ]);

    // 2. Build multicall calldata: [n_calls, to, selector, len, ...data, ...]
    const calldata: string[] = [num.toHex(calls.length)];
    for (const call of calls) {
      calldata.push(num.toHex(call.contractAddress));
      calldata.push(num.toHex(hash.getSelectorFromName(call.entrypoint)));
      const cd = (call.calldata as string[] | undefined) ?? [];
      calldata.push(num.toHex(cd.length));
      calldata.push(...cd.map(c => num.toHex(c)));
    }

    // 3. Estimate resource bounds via raw RPC with dummy SESSION_V1 sig
    const resourceBounds = await this.estimateUserFeeBounds(calls, session, nonce, rpcUrl);

    // 4. Compute the transaction hash — must match EXACTLY what we submit
    const txHash = hash.calculateInvokeTransactionHash({
      senderAddress: session.walletAddress,
      version: '0x3',  // ETransactionVersion3.V3
      compiledCalldata: calldata,
      chainId,
      nonce,
      accountDeploymentData: [],
      nonceDataAvailabilityMode: EDAMode.L1,
      feeDataAvailabilityMode: EDAMode.L1,
      resourceBounds,
      tip: 0n,
      paymasterData: [],
    });

    console.log('[executeWithUserFees] txHash:', txHash);
    console.log('[executeWithUserFees] resourceBounds:', resourceBounds);

    // 5. Sign with session key (SESSION_V1 + Merkle proof per call)
    const signature = this.oauthManager.buildSessionSignature(txHash, calls);

    // 6. Submit directly — no starknet.js Account wrapper involved
    const resp = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'starknet_addInvokeTransaction',
        params: {
          invoke_transaction: {
            type: 'INVOKE',
            version: '0x3',
            sender_address: session.walletAddress,
            calldata,
            signature: (signature as string[]).map(s => num.toHex(s)),
            nonce: num.toHex(nonce),
            resource_bounds: {
              l1_gas: {
                max_amount: num.toHex(resourceBounds.l1_gas.max_amount),
                max_price_per_unit: num.toHex(resourceBounds.l1_gas.max_price_per_unit),
              },
              l2_gas: {
                max_amount: num.toHex(resourceBounds.l2_gas.max_amount),
                max_price_per_unit: num.toHex(resourceBounds.l2_gas.max_price_per_unit),
              },
              l1_data_gas: {
                max_amount: num.toHex(resourceBounds.l1_data_gas.max_amount),
                max_price_per_unit: num.toHex(resourceBounds.l1_data_gas.max_price_per_unit),
              },
            },
            tip: '0x0',
            paymaster_data: [],
            account_deployment_data: [],
            nonce_data_availability_mode: 'L1',
            fee_data_availability_mode: 'L1',
          },
        },
      }),
    });

    const json = await resp.json() as any;
    if (json.error) {
      throw new Error(`starknet_addInvokeTransaction failed: ${JSON.stringify(json.error)}`);
    }

    return json.result.transaction_hash;
  }

  /**
   * Estimate resource bounds for a user-paid transaction.
   * Uses a dummy SESSION_V1 signature (non-empty) so __execute__ can read the
   * magic without going out-of-bounds during SKIP_VALIDATE fee estimation.
   */
  private async estimateUserFeeBounds(
    calls: Call[],
    session: OAuthSession,
    nonce: string | number,
    rpcUrl: string,
  ): Promise<{
    l1_gas: { max_amount: bigint; max_price_per_unit: bigint };
    l2_gas: { max_amount: bigint; max_price_per_unit: bigint };
    l1_data_gas: { max_amount: bigint; max_price_per_unit: bigint };
  }> {
    // SESSION_V1 dummy signature: magic + r + s + pubkey + proof_len=0 per call
    const dummySig = [
      '0x53455353494f4e5f5631', // SESSION_V1 magic
      '0x1',                    // r (dummy)
      '0x1',                    // s (dummy)
      session.sessionPubKey || '0x0',
      ...calls.map(() => '0x0'), // proof_len = 0 for each call
    ];

    // Build calldata in starknet.js multicall format:
    // [n_calls, to_1, selector_1, calldata_len_1, ...calldata_1, ...]
    const calldata: string[] = [num.toHex(calls.length)];
    for (const call of calls) {
      calldata.push(num.toHex(call.contractAddress));
      calldata.push(num.toHex(hash.getSelectorFromName(call.entrypoint)));
      const cd = (call.calldata as string[] | undefined) ?? [];
      calldata.push(num.toHex(cd.length));
      calldata.push(...cd.map(c => num.toHex(c)));
    }

    const estimateReq = {
      jsonrpc: '2.0',
      method: 'starknet_estimateFee',
      id: 1,
      params: {
        request: [
          {
            type: 'INVOKE',
            version: '0x100000000000000000000000000000003',
            sender_address: session.walletAddress,
            calldata,
            signature: dummySig,
            nonce: num.toHex(nonce),
            resource_bounds: {
              l2_gas: { max_amount: '0x0', max_price_per_unit: '0x0' },
              l1_gas: { max_amount: '0x0', max_price_per_unit: '0x0' },
              l1_data_gas: { max_amount: '0x0', max_price_per_unit: '0x0' },
            },
            tip: '0x0',
            paymaster_data: [],
            nonce_data_availability_mode: 'L1',
            fee_data_availability_mode: 'L1',
            account_deployment_data: [],
          },
        ],
        block_id: 'latest',
        simulation_flags: ['SKIP_VALIDATE'],
      },
    };

    const resp = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(estimateReq),
    });

    const json = await resp.json() as any;
    if (json.error) {
      throw new Error(`Fee estimation failed: ${JSON.stringify(json.error)}`);
    }

    const est = Array.isArray(json.result) ? json.result[0] : json.result;

    // SKIP_VALIDATE estimation omits the gas used by __validate__.
    // Our session-key validation (Poseidon hashing + Merkle proof + ECDSA) consumes
    // roughly 3-5M L2 gas.  Add a fixed overhead so the tx isn't rejected with
    // "Out of gas" inside __validate__.
    const VALIDATION_GAS_OVERHEAD = 5_000_000n;

    const l2Exec   = BigInt(est?.l2_gas_consumed      ?? '0x0') * 2n || 500_000n;
    const l2Amount = l2Exec + VALIDATION_GAS_OVERHEAD;
    const l2Price  = BigInt(est?.l2_gas_price          ?? '0x5f5e100') * 2n;
    const ldAmount = BigInt(est?.l1_data_gas_consumed  ?? '0x0') * 2n || 2_000n;
    const ldPrice  = BigInt(est?.l1_data_gas_price     ?? '0x5f5e100') * 2n;
    const l1Price  = BigInt(est?.l1_gas_price          ?? '0x5f5e100') * 2n;

    return {
      l1_gas:      { max_amount: 0n, max_price_per_unit: l1Price },
      l2_gas:      { max_amount: l2Amount, max_price_per_unit: l2Price },
      l1_data_gas: { max_amount: ldAmount, max_price_per_unit: ldPrice },
    };
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

    // A minimal no-op call — the JWT signature in the tx is what registers the session on-chain
    const registrationCall: Call = {
      contractAddress: session.walletAddress,
      entrypoint: 'get_version',
      calldata: [],
    };

    const txHash = await this.executeWithAVNUAPI([registrationCall], session, true);
    // Wait for the tx to be confirmed so callers can rely on the session being live on-chain
    await this.waitForTransaction(txHash);
    return txHash;
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
  private async waitForTransaction(txHash: string, timeout: number = 180_000): Promise<void> {
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
