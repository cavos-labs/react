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
  outsideExecution,
  hash,
  transaction,
  ec,
  Signer,
  EDAMode,
  type Signature,
  type TypedData,
} from 'starknet';
import { OAuthWalletManager, OAuthSession } from './OAuthWalletManager';
import { OAuthWalletConfig } from '../types/config';
import { getLatestCavosAccountClassHash } from '../config/defaults';

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
    // starknet.js v9 does not include transactionHash in InvocationsSignerDetails —
    // compute it the same way the base Signer does.
    let txHash: string = details.transactionHash;
    if (!txHash) {
      const walletAddress = details.walletAddress || this.oauthManager.getWalletAddress();
      if (!walletAddress) {
        throw new Error('No wallet address available for transaction signing');
      }
      const compiledCalldata = transaction.getExecuteCalldata(
        transactions,
        details.cairoVersion ?? '1',
      );
      // Convert data availability mode string → integer (L1=0, L2=1)
      const intDAM = (mode: any) => (mode === 'L1' || mode === 0 ? 0 : 1);
      txHash = hash.calculateInvokeTransactionHash({
        ...details,
        senderAddress: walletAddress,
        compiledCalldata,
        version: details.version,
        nonceDataAvailabilityMode: intDAM(details.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: intDAM(details.feeDataAvailabilityMode),
      });
    }

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
  private chainIdOverride: string | undefined;
  private account: Account | null = null;
  private paymasterRpc: PaymasterRpc;

  constructor(
    config: OAuthWalletConfig,
    oauthManager: OAuthWalletManager,
    rpcUrl: string,
    paymasterApiKey: string,
    network: 'mainnet' | 'sepolia',
    paymasterUrl?: string,
    chainIdOverride?: string
  ) {
    this.config = config;
    this.provider = new RpcProvider({ nodeUrl: rpcUrl });
    this.oauthManager = oauthManager;
    this.paymasterApiKey = paymasterApiKey;
    this.network = network;
    this.chainIdOverride = chainIdOverride;

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

  private async getCurrentChainTimestamp(): Promise<bigint> {
    const block = await this.provider.getBlock('latest');
    return BigInt(block.timestamp);
  }

  private getDerivationClassHash(): string {
    return num.toHex(this.config.cavosAccountClassHash);
  }

  private getUpgradeTargetClassHash(): string {
    return num.toHex(getLatestCavosAccountClassHash(this.network));
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

  async getDeployedClassHash(): Promise<string | null> {
    const address = this.oauthManager.getWalletAddress();
    if (!address) return null;

    try {
      return num.toHex(await this.provider.getClassHashAt(address));
    } catch {
      return null;
    }
  }

  async needsClassHashUpgrade(): Promise<boolean> {
    const deployedClassHash = await this.getDeployedClassHash();
    if (!deployedClassHash) {
      return false;
    }

    const target = this.getUpgradeTargetClassHash();
    const needsUpgrade = num.toHex(deployedClassHash) !== target;
    console.log(
      `[CavosSDK] needsClassHashUpgrade: deployed=${num.toHex(deployedClassHash)} latest=${target} needsUpgrade=${needsUpgrade}`
    );
    return needsUpgrade;
  }

  async upgradeAccountClassHash(targetClassHash?: string): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress) {
      throw new Error('No valid session');
    }

    const deployedClassHash = await this.getDeployedClassHash();
    if (!deployedClassHash) {
      throw new Error('Account is not deployed');
    }

    const nextClassHash = num.toHex(targetClassHash || this.getUpgradeTargetClassHash());
    if (num.toHex(deployedClassHash) === nextClassHash) {
      console.log(`[CavosSDK] upgradeAccountClassHash: already up-to-date (${nextClassHash})`);
      return 'already-up-to-date';
    }

    console.log(
      `[CavosSDK] upgradeAccountClassHash: upgrading ${session.walletAddress} from ${num.toHex(deployedClassHash)} to ${nextClassHash}`
    );

    const upgradeCall: Call = {
      contractAddress: session.walletAddress,
      entrypoint: 'upgrade',
      calldata: [nextClassHash],
    };

    const txHash = await this.executeWithAVNUAPI([upgradeCall], session, true);
    await this.waitForTransaction(txHash);
    console.log(`[CavosSDK] upgradeAccountClassHash: upgrade tx confirmed ${txHash}`);
    return txHash;
  }

  /**
   * Get session status from on-chain.
   * Returns detailed status including whether it's expired and if it can be renewed.
   */
  async getSessionStatus(): Promise<{
    registered: boolean;
    active: boolean;
    expired: boolean;
    canRenew: boolean;
    validAfter?: bigint;
    validUntil?: bigint;
    renewalDeadline?: bigint;
  }> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress || !session.sessionPubKey) {
      return { registered: false, active: false, expired: false, canRenew: false };
    }

    try {
      const result = await this.provider.callContract({
        contractAddress: session.walletAddress,
        entrypoint: 'get_session',
        calldata: [session.sessionPubKey],
      });

      // get_session returns (nonce, valid_after, valid_until, renewal_deadline, registered_at, allowed_contracts_root, max_calls_per_tx)
      const nonce = BigInt(result[0]);
      const validAfter = BigInt(result[1]);
      const validUntil = BigInt(result[2]);
      const renewalDeadline = BigInt(result[3]);

      const registered = nonce !== 0n;

      if (!registered) {
        return { registered: false, active: false, expired: false, canRenew: false };
      }

      // Session state is enforced on-chain against block.timestamp, so status
      // checks need to use chain time to avoid false positives on Slot/Katana.
      const now = await this.getCurrentChainTimestamp();
      const active = now >= validAfter;
      const expired = now >= validUntil;
      const canRenew = expired && now < renewalDeadline;

      return { registered, active, expired, canRenew, validAfter, validUntil, renewalDeadline };
    } catch (err) {
      console.error('[getSessionStatus] Error calling get_session:', err);
      return { registered: false, active: false, expired: false, canRenew: false };
    }
  }

  /**
   * Check if the current session is registered on-chain.
   * Calls the contract's get_session(session_key) function.
   * If nonce == 0, the session is NOT registered.
   */
  async isSessionRegistered(): Promise<boolean> {
    const status = await this.getSessionStatus();
    return status.registered && status.active && !status.expired;
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
      class_hash: this.getDerivationClassHash(),
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
   * Deploy the account using a direct DEPLOY_ACCOUNT transaction (no paymaster).
   * Use this for Slot/Katana chains where no_fee = true.
   */
  async deployAccountDirect(): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress || !session.addressSeed) {
      throw new Error('No valid session for deployment');
    }

    if (await this.isDeployed()) {
      return 'already-deployed';
    }

    const constructorCalldata = [
      session.addressSeed,
      this.config.jwksRegistryAddress,
    ].map(c => num.toHex(c));

    const deploySigner = new OAuthSigner(this.oauthManager, true);
    const account = new Account({
      provider: this.provider,
      address: session.walletAddress,
      signer: deploySigner,
    });

    const result = await account.deployAccount({
      classHash: this.getDerivationClassHash(),
      constructorCalldata,
      addressSalt: session.addressSeed,
      contractAddress: session.walletAddress,
    });

    await this.waitForTransaction(result.transaction_hash);
    return result.transaction_hash;
  }

  /**
   * Deploy the account via UDC (Universal Deployer Contract) using an external relayer.
   *
   * On Slot/Katana, __validate_deploy__ blocks call_contract (same restriction as
   * __validate__), so the standard DEPLOY_ACCOUNT tx fails when the contract needs
   * to verify the JWT via the JWKS registry.
   *
   * This method side-steps the issue: the relayer submits a regular INVOKE to the
   * UDC, which calls the deploy syscall internally. The deployed account's
   * constructor runs in execution context (no call_contract restriction) and the
   * address matches DEPLOY_ACCOUNT when unique=false (deployer_address=0).
   *
   * Session registration must happen separately via execute_from_outside_v2.
   */
  async deployAccountViaRelayer(relayerAccount: Account): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress || !session.addressSeed) {
      throw new Error('No valid session for deployment');
    }

    if (await this.isDeployed()) {
      return 'already-deployed';
    }

    // Starknet mainnet UDC — available on Slot via fork.
    const UDC_ADDRESS = '0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf';

    const constructorCalldata = [
      session.addressSeed,
      this.config.jwksRegistryAddress,
    ].map(c => num.toHex(c));

    // UDC.deployContract(class_hash, salt, unique, calldata)
    // unique = 0 (false) → deployer_address = 0 → same address as DEPLOY_ACCOUNT.
    // Cairo 0 array serialization: calldata_len followed by elements.
    const { transaction_hash } = await relayerAccount.execute(
      {
        contractAddress: UDC_ADDRESS,
        entrypoint: 'deployContract',
        calldata: [
          this.getDerivationClassHash(),
          num.toHex(session.addressSeed),
          '0x0',                                     // unique = false
          num.toHex(constructorCalldata.length),     // calldata_len
          ...constructorCalldata,
        ],
      },
      {
        resourceBounds: {
          l1_gas:      { max_amount: 0n, max_price_per_unit: 0n },
          l2_gas:      { max_amount: 0n, max_price_per_unit: 0n },
          l1_data_gas: { max_amount: 0n, max_price_per_unit: 0n },
        },
      },
    );

    await this.waitForTransaction(transaction_hash);
    return transaction_hash;
  }

  private getNoFeeResourceBounds() {
    return {
      l1_gas: { max_amount: 0n, max_price_per_unit: 0n },
      l2_gas: { max_amount: 0n, max_price_per_unit: 0n },
      l1_data_gas: { max_amount: 0n, max_price_per_unit: 0n },
    };
  }

  private createDirectAccount(useJWTSignature: boolean): Account {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress) {
      throw new Error('No valid session');
    }

    return new Account({
      provider: this.provider,
      address: session.walletAddress,
      signer: new OAuthSigner(this.oauthManager, useJWTSignature),
    });
  }

  private async executeDirectNoFee(calls: Call[], useJWTSignature: boolean): Promise<string> {
    const account = this.createDirectAccount(useJWTSignature);
    const result = await account.execute(calls, {
      resourceBounds: this.getNoFeeResourceBounds(),
    });

    await this.waitForTransaction(result.transaction_hash);
    return result.transaction_hash;
  }

  /**
   * Experimental direct JWT registration on Slot.
   *
   * This mirrors the mainnet/sepolia path as closely as possible by sending a
   * regular invoke signed with OAUTH_JWT_V1. On some Katana/Slot deployments
   * this is expected to revert because JWT verification needs call_contract in
   * __validate__. We still expose it as a diagnostic path so apps can compare
   * the direct and outside-execution behaviors.
   */
  async registerCurrentSessionDirect(): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.jwt || !session.walletAddress) {
      throw new Error('Must be logged in to register session');
    }

    const registrationCall: Call = {
      contractAddress: session.walletAddress,
      entrypoint: 'get_version',
      calldata: [],
    };
    const chainId = this.chainIdOverride ?? await this.provider.getChainId();
    const txHash = await this.executeDirectNoFee([registrationCall], true);
    return txHash;
  }

  /**
   * Execute on a no_fee chain such as Slot using the standard account path.
   *
   * This path only works once the session is already registered on-chain.
   * First-time Slot registration must go through execute_from_outside_v2.
   */
  async executeOnNoFeeChain(calls: Call | Call[]): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.walletAddress) {
      throw new Error('No valid session');
    }

    const callsArray = Array.isArray(calls) ? calls : [calls];
    const status = await this.getSessionStatus();

    if (!status.registered) {
      throw new Error(
        'Session is not registered on Slot yet. ' +
        'Use executeViaOutsideExecution() or CavosSDK.executeOnSlot() for the first transaction.'
      );
    }

    if (status.expired && status.canRenew) {
      throw new Error(
        'SESSION_EXPIRED: Session has expired on Slot and must be renewed from a fresh login before executing again.'
      );
    }

    if (status.expired && !status.canRenew) {
      throw new Error('SESSION_EXPIRED: Session has expired outside grace period. Please login again.');
    }

    if (!status.active) {
      throw new Error(
        `SESSION_NOT_ACTIVE: Session activates at ${status.validAfter?.toString() || 'unknown'}.`
      );
    }

    return this.executeDirectNoFee(callsArray, false);
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

    if (!status.active) {
      throw new Error(
        `SESSION_NOT_ACTIVE: Session activates at ${status.validAfter?.toString() || 'unknown'}.`
      );
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
  /**
   * Register the current session on Slot via execute_from_outside_v2 (SNIP-9).
   *
   * __validate__ blocks call_contract syscalls (needed for JWKS lookup), so JWT
   * validation cannot run there.  execute_from_outside_v2 runs in execution mode
   * where call_contract is allowed — same mechanism the paymaster uses on mainnet.
   *
   * The no-op wallet self-call only exists to carry the JWT signature through the
   * outside-execution path. The account stores the session policy during this step;
   * allowed-contract enforcement starts on subsequent SESSION_V1 transactions.
   *
   * @param relayerAccount Pre-funded Account on the Slot that submits the outer tx.
   */
  async registerCurrentSessionViaOutside(relayerAccount: Account): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.jwt || !session.walletAddress) {
      throw new Error('Must be logged in to register session');
    }
    const noOpCall: Call = {
      contractAddress: session.walletAddress,
      entrypoint: 'get_version',
      calldata: [],
    };
    return this.executeViaOutsideExecution([noOpCall], relayerAccount);
  }

  /**
   * Execute calls on Slot via execute_from_outside_v2 (SNIP-9).
   *
   * Mirrors the normal wallet flow:
   * - Session NOT registered: JWT signature (OAUTH_JWT_V1) — validates on-chain and registers
   *   the session key in the same tx. One-time cost (RSA).
   * - Session registered: lightweight session key signature (SESSION_V1) — only ECDSA, cheap.
   *
   * Hashes the outside-execution payload manually using the account contract's
   * SNIP-12 type hashes. starknet.js does not currently support the u64 fields
   * used by the on-chain OutsideExecution struct.
   */
  async executeViaOutsideExecution(calls: Call[], relayerAccount: Account): Promise<string> {
    const session = this.oauthManager.getSession();
    if (!session?.jwt || !session.walletAddress) throw new Error('Not logged in');

    const walletAddress = session.walletAddress;
    const chainId = this.chainIdOverride ?? await this.provider.getChainId();

    // Match the paymaster/SNIP-9 flow used on mainnet and sepolia as closely as
    // possible: bind the outside execution to the submitter account instead of
    // ANY_CALLER, use a short execution window.
    //
    // IMPORTANT: We use our manual SNIP-12 hash computation instead of starknet.js's
    // outsideExecution.getTypedData / typedData.getMessageHash helpers because
    // starknet.js v9 encodes Execute After/Before as u128, while our Cairo contract
    // uses u64 — this type mismatch produces a different SNIP-12 type hash and
    // message hash, causing "Invalid session key signature" on-chain.
    const caller = relayerAccount.address;
    const currentTimestamp = BigInt((await this.provider.getBlock('latest')).timestamp);
    const executeAfter = 1n;
    const executeBefore = currentTimestamp + 3600n;
    const nonce = this.generateOutsideExecutionNonce();

    // Compute the SNIP-12 rev1 message hash using our manual implementation
    // that matches the contract's u64-based type hashes exactly.
    const messageHash = this.computeOutsideExecutionMessageHash(
      walletAddress,
      caller,
      nonce,
      executeAfter,
      executeBefore,
      calls,
      chainId,
    );

    // Choose signature: JWT for unregistered sessions (registers + executes), session key otherwise.
    const sessionStatus = await this.getSessionStatus();
    let sigArray: string[];
    if (!sessionStatus.registered) {
      const signature = await this.oauthManager.buildJWTSignatureData(messageHash);
      sigArray = Array.isArray(signature) ? signature.map(String) : [String(signature)];
    } else {
      sigArray = this.oauthManager.buildSessionSignature(messageHash, calls);
    }

    // Build the execute_from_outside_v2 calldata manually (matches the contract's
    // expected encoding: caller, nonce, execute_after, execute_before, calls[], signature[]).
    const calldata = this.buildOutsideExecutionCalldata(
      caller,
      nonce,
      executeAfter,
      executeBefore,
      calls,
      sigArray,
    );

    // Relayer submits the outer transaction
    const { transaction_hash } = await relayerAccount.execute(
      {
        contractAddress: walletAddress,
        entrypoint: 'execute_from_outside_v2',
        calldata,
      },
      {
        resourceBounds: {
          l1_gas:      { max_amount: 0n, max_price_per_unit: 0n },
          l2_gas:      { max_amount: 0n, max_price_per_unit: 0n },
          l1_data_gas: { max_amount: 0n, max_price_per_unit: 0n },
        },
      },
    );
    await this.waitForTransaction(transaction_hash);
    return transaction_hash;
  }

  private generateOutsideExecutionNonce(): string {
    const bytes =
      typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function'
        ? crypto.getRandomValues(new Uint8Array(16))
        : ec.starkCurve.utils.randomPrivateKey().slice(0, 16);

    return '0x' + Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // ── SNIP-12 Rev 1 hash for OutsideExecution (mirrors get_outside_execution_message_hash_v2) ──

  private static readonly OUTSIDE_EXECUTION_TYPE_HASH =
    '0x312b56c05a7965066ddbda31c016d8d05afc305071c0ca3cdc2192c3c2f1f0f';
  private static readonly CALL_TYPE_HASH =
    '0x3635c7f2a7ba93844c0d064e18e487f35ab90f7c39d00f186a781fc3f0c2ca9';
  private static readonly DOMAIN_TYPE_HASH =
    '0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210';
  // shortString: 'Account.execute_from_outside'
  private static readonly DOMAIN_NAME =
    '0x4163636f756e742e657865637574655f66726f6d5f6f757473696465';
  // shortString: 'StarkNet Message'
  private static readonly STARKNET_MESSAGE =
    '0x537461726b4e6574204d657373616765';

  private computeOutsideExecutionMessageHash(
    walletAddress: string,
    caller: string,
    nonce: string,
    executeAfter: bigint,
    executeBefore: bigint,
    calls: Call[],
    chainId: string,
  ): string {
    // poseidonMany: takes bigint[], returns hex string
    const poseidonMany = (arr: bigint[]) => hash.computePoseidonHashOnElements(arr);
    // Helper to nest: converts hex string result back to bigint for nesting
    const pm = (arr: bigint[]) => BigInt(poseidonMany(arr));

    // Hash each call
    const callHashes = calls.map(call => {
      const selector = call.entrypoint.startsWith('0x')
        ? call.entrypoint
        : hash.getSelectorFromName(call.entrypoint);
      const cd = (call.calldata as string[] | undefined) ?? [];
      const calldataHash = pm(cd.map(v => BigInt(v)));
      return pm([
        BigInt(OAuthTransactionManager.CALL_TYPE_HASH),
        BigInt(call.contractAddress),
        BigInt(selector),
        calldataHash,
      ]);
    });

    const callsHash = pm(callHashes);

    const structHash = pm([
      BigInt(OAuthTransactionManager.OUTSIDE_EXECUTION_TYPE_HASH),
      BigInt(caller),
      BigInt(nonce),
      executeAfter,
      executeBefore,
      callsHash,
    ]);

    const domainHash = pm([
      BigInt(OAuthTransactionManager.DOMAIN_TYPE_HASH),
      BigInt(OAuthTransactionManager.DOMAIN_NAME),
      2n,
      BigInt(chainId),
      1n,
    ]);

    return poseidonMany([
      BigInt(OAuthTransactionManager.STARKNET_MESSAGE),
      domainHash,
      BigInt(walletAddress),
      structHash,
    ]);
  }

  private buildOutsideExecutionCalldata(
    caller: string,
    nonce: string,
    executeAfter: bigint,
    executeBefore: bigint,
    calls: Call[],
    signature: string[],
  ): string[] {
    const h = (v: string | bigint) => num.toHex(v);
    const calldata: string[] = [
      h(caller),
      h(nonce),
      h(executeAfter),
      h(executeBefore),
      h(BigInt(calls.length)),
    ];

    for (const call of calls) {
      const selector = call.entrypoint.startsWith('0x')
        ? call.entrypoint
        : hash.getSelectorFromName(call.entrypoint);
      const cd = (call.calldata as string[] | undefined) ?? [];
      calldata.push(h(call.contractAddress), h(selector), h(BigInt(cd.length)), ...cd.map(h));
    }

    calldata.push(h(BigInt(signature.length)), ...signature);
    return calldata;
  }

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
          const executionStatus = (receipt as any).execution_status;
          const finalityStatus = (receipt as any).finality_status || (receipt as any).status;

          if (executionStatus === 'REVERTED') {
            const revertReason = (receipt as any).revert_error || (receipt as any).revert_reason || 'Unknown revert reason';
            throw new Error(`Transaction ${txHash} was reverted: ${revertReason}`);
          }

          if (executionStatus === 'SUCCEEDED') {
            return;
          }

          // Some RPCs omit execution_status for older receipts. In that case, fall
          // back to finality only after ruling out explicit reverts above.
          if (!executionStatus && (
            finalityStatus === 'ACCEPTED_ON_L2' ||
            finalityStatus === 'ACCEPTED_ON_L1'
          )) {
            return;
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
