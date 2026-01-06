import { Account, Call } from 'starknet';
import { AuthManager } from './auth/AuthManager';
import { WalletManager } from './wallet/WalletManager';
import { SessionManager } from './session/SessionManager';
import { PaymasterIntegration } from './paymaster/PaymasterIntegration';
import { TransactionManager } from './transaction/TransactionManager';
import { AnalyticsManager } from './analytics/AnalyticsManager';
import { CavosConfig, UserInfo, DecryptedWallet, OnrampProvider, LoginProvider, TypedData, Signature } from './types';
import axios from 'axios';

export class CavosSDK {
  private config: CavosConfig;
  private authManager: AuthManager;
  private walletManager: WalletManager | null = null;
  private sessionManager: SessionManager;
  private paymaster: PaymasterIntegration;
  private transactionManager: TransactionManager | null = null;
  private analyticsManager: AnalyticsManager;
  private isLimitExceeded: boolean = false;

  // Default Cavos shared paymaster API key for Sepolia
  private static readonly DEFAULT_PAYMASTER_KEY = 'c37c52b7-ea5a-4426-8121-329a78354b0b';
  private static readonly DEFAULT_RPC_MAINNET = 'https://starknet-mainnet.g.alchemy.com/starknet/version/rpc/v0_10/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';
  private static readonly DEFAULT_RPC_SEPOLIA = 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';

  constructor(config: CavosConfig) {

    this.config = {
      ...config,
      // Use provided key or default Cavos shared key
      paymasterApiKey: config.paymasterApiKey || CavosSDK.DEFAULT_PAYMASTER_KEY,
      // Use provided RPC URL or default based on network
      starknetRpcUrl: config.starknetRpcUrl || (
        config.network === 'mainnet'
          ? CavosSDK.DEFAULT_RPC_MAINNET
          : CavosSDK.DEFAULT_RPC_SEPOLIA
      ),
    };

    // Initialize auth manager
    this.authManager = new AuthManager({
      backendUrl: 'https://cavos.xyz',
      appId: this.config.appId,
    });

    // Initialize analytics manager
    this.analyticsManager = new AnalyticsManager(this.config);

    // Initialize session manager with network
    this.sessionManager = new SessionManager(
      this.config.starknetRpcUrl!,
      this.config.network || 'sepolia'
    );

    // Initialize paymaster with default key
    this.paymaster = new PaymasterIntegration(this.config.paymasterApiKey!);

    if (this.config.enableLogging) {

    }
  }

  /**
   * Initialize SDK and restore session if available
   */
  async init(): Promise<void> {
    // Validate MAU limits before initialization
    await this.validateAccess();

    // Try to restore session
    if (this.authManager.restoreSession()) {

      try {
        await this.initializeWallet();

      } catch (error) {
        console.error('[CavosSDK] Failed to restore wallet:', error);
        throw error;
      }
    }
  }

  /**
   * Login with Google OAuth
   * @param redirectUri Optional redirect URI (defaults to current page)
   */
  async loginWithGoogle(redirectUri?: string): Promise<void> {
    await this.authManager.loginWithGoogle(redirectUri);
  }

  /**
   * Login with Apple OAuth
   * @param redirectUri Optional redirect URI (defaults to current page)
   */
  async loginWithApple(redirectUri?: string): Promise<void> {
    await this.authManager.loginWithApple(redirectUri);
  }

  /**
   * Login with a specific provider
   * @param provider The login provider ('google' | 'apple')
   * @param redirectUri Optional redirect URI (defaults to current page)
   */
  async login(provider: LoginProvider, redirectUri?: string): Promise<void> {
    switch (provider) {
      case 'google':
        await this.loginWithGoogle(redirectUri);
        break;
      case 'apple':
        await this.loginWithApple(redirectUri);
        break;
      default:
        throw new Error(`Unsupported login provider: ${provider}`);
    }
  }

  /**
   * Handle OAuth callback
   */
  /**
   * Handle OAuth callback
   */
  async handleCallback(authDataString: string): Promise<void> {
    await this.authManager.handleCallback(authDataString);

    // Initialize wallet
    try {
      await this.initializeWallet();
    } catch (error: any) {
      console.error('[CavosSDK] Wallet initialization failed:', error.message);
      throw error;
    }
  }

  /**
   * Initialize wallet manager, load/create wallet, and auto-deploy if needed
   * This ensures the account is ready to use immediately after login
   */
  /**
   * Initialize wallet manager, load/create wallet, and auto-deploy if needed
   * This ensures the account is ready to use immediately after login
   */
  private async initializeWallet(): Promise<void> {
    const user = this.authManager.getUserInfo();
    if (!user) {
      throw new Error('User info not available');
    }

    // Initialize wallet manager with AuthManager and WebAuthn support
    this.walletManager = new WalletManager(
      this.authManager,
      this.config.starknetRpcUrl!,
      this.config.network || 'sepolia',
      this.analyticsManager
    );

    // Try to load existing wallet
    try {
      await this.walletManager.loadWallet(user);
    } catch (error: any) {

      // If load fails, we don't auto-create. The UI should handle this.
      throw error;
    }

    // Auto-deploy account if not already deployed (gasless with AVNU paymaster)
    const isDeployed = await this.walletManager.isDeployed();
    if (!isDeployed) {

      await this.walletManager.deployAccountWithPaymaster(
        this.config.paymasterApiKey!,
        this.config.network || 'sepolia'
      );

    }

    // Initialize transaction manager with account and paymaster API key
    const account = this.walletManager.getAccount();
    if (!account) {
      throw new Error('Failed to get account');
    }

    this.transactionManager = new TransactionManager(
      account,
      this.config.paymasterApiKey!,
      this.config.network || 'sepolia',
      this.analyticsManager
    );
  }

  /**
   * Explicitly create a new wallet.
   * This must be called from a user gesture (e.g. button click) to satisfy WebAuthn requirements.
   */
  async createWallet(): Promise<void> {
    if (this.isLimitExceeded) {
      throw new Error('MAU limit reached. Upgrade your plan to create more wallets.');
    }

    if (!this.walletManager) {
      this.walletManager = new WalletManager(
        this.authManager,
        this.config.starknetRpcUrl!,
        this.config.network || 'sepolia',
        this.analyticsManager
      );
    }

    const user = this.authManager.getUserInfo();

    if (user) {
      // OAuth Flow
      await this.walletManager.createWallet(user);
      await this.walletManager.deployAccountWithPaymaster(
        this.config.paymasterApiKey!,
        this.config.network || 'sepolia'
      );
    } else {
      // Passkey-Only Flow (Smart Auth: Recover -> Create)
      try {
        await this.walletManager.recoverWalletWithPasskey();
      } catch (error) {
        // Fallback to creation
        await this.walletManager.createPasskeyOnlyWallet(this.config.paymasterApiKey!);
      }
    }

    // Initialize transaction manager
    const account = this.walletManager.getAccount();
    if (account) {
      this.transactionManager = new TransactionManager(
        account,
        this.config.paymasterApiKey!,
        this.config.network || 'sepolia',
        this.analyticsManager
      );
    }
  }

  /**
   * Retry wallet unlock after a failed passkey attempt.
   * This is useful when the user cancels the passkey prompt and wants to try again.
   * Only works if the user is authenticated but doesn't have a wallet loaded.
   */
  async retryWalletUnlock(): Promise<void> {
    const user = this.authManager.getUserInfo();
    if (!user) {
      throw new Error('User not authenticated');
    }

    if (this.getAddress()) {
      throw new Error('Wallet is already unlocked');
    }

    // Initialize wallet manager if not already initialized
    if (!this.walletManager) {
      this.walletManager = new WalletManager(
        this.authManager,
        this.config.starknetRpcUrl!,
        this.config.network || 'sepolia',
        this.analyticsManager
      );
    }

    // Try to load the wallet again
    await this.walletManager.loadWallet(user);

    // Initialize transaction manager
    const account = this.walletManager.getAccount();
    if (account) {
      this.transactionManager = new TransactionManager(
        account,
        this.config.paymasterApiKey!,
        this.config.network || 'sepolia',
        this.analyticsManager
      );
    }
  }

  /**
   * Create a session for executing transactions without user signature.
   * User will be prompted to sign the session authorization once.
   */
  async createSession(policy: {
    allowedMethods: Array<{ contractAddress: string; selector: string }>;
    expiresAt?: number;
    maxFees?: Array<{ tokenAddress: string; maxAmount: string }>;
  }): Promise<void> {
    console.log('[CavosSDK] createSession called with:', policy);

    const account = this.walletManager?.getAccount();
    const walletInfo = this.walletManager?.getWalletInfo();
    console.log('[CavosSDK] Account:', account ? account.address : 'null');

    if (!account || !walletInfo) {
      throw new Error('No wallet loaded. Please login first.');
    }

    const fullPolicy = {
      allowedMethods: policy.allowedMethods,
      expiresAt: policy.expiresAt || Date.now() + 24 * 60 * 60 * 1000, // Default 24 hours
    };
    console.log('[CavosSDK] Full policy:', fullPolicy);

    // Pass the wallet's private key for guardian key derivation
    await this.sessionManager.createSession(account, fullPolicy, walletInfo.privateKey);
    console.log('[CavosSDK] Session created successfully');

    // EPHEMERAL PK: Clear private key from memory after session is created
    // The session keys are now stored in sessionStorage and will be used for signing
    this.walletManager?.clearPrivateKey();
    console.log('[CavosSDK] Private key cleared (ephemeral PK architecture)');
  }

  /**
   * Execute transactions with session key (no user signature required).
   * Session must be created first with createSession().
   * Uses gasless execution via paymaster with session key signature.
   */
  async executeWithSession(calls: Call | Call[]): Promise<string> {
    if (!this.sessionManager.hasActiveSession()) {
      throw new Error('No active session. Call createSession() first.');
    }

    const account = this.walletManager?.getAccount();
    if (!account) {
      throw new Error('No wallet loaded');
    }

    const callsArray = Array.isArray(calls) ? calls : [calls];
    console.log('[CavosSDK] Executing with session key:', callsArray.length, 'calls');

    // Get paymaster API configuration
    const baseUrl = this.config.network === 'mainnet'
      ? 'https://starknet.api.avnu.fi'
      : 'https://sepolia.api.avnu.fi';

    // Format calls for AVNU API
    const formattedCalls = callsArray.map(call => ({
      contractAddress: call.contractAddress,
      entrypoint: call.entrypoint,
      calldata: call.calldata ? (call.calldata as string[]).map(c => `0x${BigInt(c).toString(16)}`) : [],
    }));

    // Step 1: Build typed data from paymaster
    console.log('[CavosSDK] Building typed data from paymaster...');
    const buildResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.config.paymasterApiKey!,
      },
      body: JSON.stringify({
        userAddress: account.address,
        calls: formattedCalls,
      }),
    });

    if (!buildResponse.ok) {
      throw new Error(`Build typed data failed: ${await buildResponse.text()}`);
    }

    const paymasterTypedData = await buildResponse.json();
    console.log('[CavosSDK] Received typed data from paymaster');

    // Step 2: Sign with session keys (NOT with account private key!)
    const sessionSignature = await this.sessionManager.signTypedDataWithSession(
      paymasterTypedData,
      account.address,
      callsArray,
    );
    console.log('[CavosSDK] Got session signature:', sessionSignature.length, 'elements');

    // Format signature for API
    const formattedSignature = sessionSignature.map(s =>
      s.startsWith('0x') ? s : `0x${BigInt(s).toString(16)}`
    );

    // Step 3: Execute via paymaster with session signature
    console.log('[CavosSDK] Executing via paymaster with session signature...');
    const executeResponse = await fetch(`${baseUrl}/paymaster/v1/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.config.paymasterApiKey!,
      },
      body: JSON.stringify({
        userAddress: account.address,
        typedData: JSON.stringify(paymasterTypedData),
        signature: formattedSignature,
      }),
    });

    if (!executeResponse.ok) {
      const errorText = await executeResponse.text();
      console.error('[CavosSDK] Paymaster execute failed:', errorText);
      throw new Error(`Execute failed: ${errorText}`);
    }

    const result = await executeResponse.json();
    console.log('[CavosSDK] Transaction submitted with session key:', result.transactionHash);

    return result.transactionHash;
  }

  /**
   * Check if there's an active session.
   */
  hasActiveSession(): boolean {
    return this.sessionManager.hasActiveSession();
  }

  /**
   * Clear current session.
   */
  clearSession(): void {
    this.sessionManager.clearSession();
  }

  /**
   * Execute a transaction.
   * Uses session keys for signing - requires an active session.
   * 
   * @param calls - The call(s) to execute
   * @param _options - Execution options (ignored - gasless is always true with session keys)
   * @returns Transaction hash
   * @throws Error if no active session
   */
  async execute(calls: Call | Call[], _options?: { gasless?: boolean }): Promise<string> {
    // All transactions with session keys are gasless
    return this.executeWithSession(calls);
  }

  /**
   * Sign a message with the session key.
   * Uses session keys for signing - requires an active session.
   * 
   * @param message - The message hash to sign (must be a hex string)
   * @returns Signature with r and s components
   * @throws Error if no active session
   */
  async signMessage(message: string): Promise<Signature> {
    return this.sessionManager.signMessage(message);
  }

  /**
   * Get current wallet address
   */
  getAddress(): string | null {
    return this.walletManager?.getAddress() || null;
  }

  /**
   * Check if user has an existing wallet in the database
   */
  async hasWallet(): Promise<boolean> {
    if (!this.walletManager) return false;
    try {
      return await this.walletManager.hasWallet();
    } catch (error) {
      return false;
    }
  }

  /**
   * Get current user info
   */
  getUserInfo(): UserInfo | null {
    return this.authManager.getUserInfo();
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return this.authManager.isAuthenticated();
  }

  /**
   * Deletes the current user's account.
   * This action is irreversible.
   */
  async deleteAccount(): Promise<void> {
    await this.authManager.deleteAccount(this.config.appId, this.config.network || 'sepolia');
    await this.logout();
  }

  /**
   * Check if account is deployed on-chain
   */
  async isAccountDeployed(): Promise<boolean> {
    if (!this.walletManager) {
      return false;
    }

    return await this.walletManager.isDeployed();
  }

  /**
   * Deploy the account contract on-chain using AVNU Paymaster
   * NOTE: This is handled automatically during login. Only call this manually if needed.
   * NO FUNDING REQUIRED - Gasless deployment using Cavos shared paymaster
   */
  async deployAccount(): Promise<string> {
    if (!this.walletManager) {
      throw new Error('Wallet not initialized. Please login first.');
    }

    const network = this.config.network || 'sepolia';

    return await this.walletManager.deployAccountWithPaymaster(
      this.config.paymasterApiKey!,
      network
    );
  }

  /**
   * Get account balance in ETH
   */
  async getBalance(): Promise<string> {
    if (!this.walletManager) {
      return '0';
    }

    return await this.walletManager.getBalance();
  }

  /**
   * Get funding address for the wallet
   * Send ETH to this address before deploying
   */
  getFundingAddress(): string | null {
    return this.walletManager?.getFundingAddress() || null;
  }

  /**
   * Logout and clear all data
   */
  async logout(): Promise<void> {
    this.authManager.logout();
    this.sessionManager.clearSession();

    // Clear wallet session cache
    if (this.walletManager) {
      this.walletManager.clearWalletSession();
    }

    this.walletManager = null;
    this.transactionManager = null;
  }

  /**
   * Delete wallet from cloud storage
   */
  async deleteWallet(): Promise<void> {
    if (!this.walletManager) {
      throw new Error('Wallet not initialized');
    }

    await this.walletManager.deleteWallet();
  }

  /**
   * Get current account (for advanced usage)
   */
  getAccount(): Account | null {
    return this.walletManager?.getAccount() || null;
  }

  /**
   * Get session account (for advanced usage)
   */
  async getSessionAccount(): Promise<Account | null> {
    return this.sessionManager.getSessionAccount();
  }

  /**
   * Validate app access and MAU limits
   */
  private async validateAccess(): Promise<void> {
    try {
      // Use configured backend URL or default
      const backendUrl = 'https://cavos.xyz';
      const network = this.config.network || 'sepolia';

      const response = await axios.get(
        `${backendUrl}/api/apps/${this.config.appId}/validate`,
        {
          params: { network }
        }
      );

      const result = response.data;

      if (!result.allowed) {
        this.isLimitExceeded = true;
        console.warn('[Cavos SDK] MAU limit exceeded. New wallet creation is blocked.');
        // Do not throw error here, allow existing users to proceed
        return;
      }

      if (result.warning) {
        console.warn('[Cavos SDK]', result.message);
        // We could emit a warning event here if we had an event emitter
      }
    } catch (error: any) {
      // Log but don't block on network errors during validation (fail open for reliability unless explicitly blocked)
      // However, for strict enforcement we might want to block. 
      // Current plan says "Silent fail - don't block user" for tracking, but for validation?
      // "Block initialization" is in the plan for MAULimitExceeded. 
      // For network errors, let's log and proceed to avoid breaking the app if our validation server is down.
      console.warn('[Cavos SDK] Validation check failed:', error.message);
    }
  }

  // ===============================
  // ONRAMP INTEGRATION
  // ===============================

  /**
   * Get an onramp URL for purchasing crypto with fiat
   * @param provider The onramp provider to use (e.g., 'RAMP_NETWORK')
   * @returns Complete onramp URL with pre-filled wallet address
   * @throws {Error} If no account is connected
   * @throws {Error} If network is Sepolia (onramp only available on mainnet)
   * @throws {Error} If address format is invalid
   */
  public getOnramp(provider: OnrampProvider): string {
    const address = this.getAddress();
    if (!address) {
      throw new Error('No account connected. Call deployAccount() or connectAccount() first.');
    }

    // Validate network - onramp not available on Sepolia
    if (this.config.network === 'sepolia') {
      throw new Error('Onramp feature is not available on Sepolia network. Please use mainnet.');
    }

    // Handle different providers
    switch (provider) {
      case 'RAMP_NETWORK':
        return this.getRampNetworkUrl(address);
      default:
        throw new Error(`Unknown onramp provider: ${provider}`);
    }
  }

  /**
   * Generate Ramp Network onramp URL
   * @returns Complete Ramp Network URL
   * @private
   */
  private getRampNetworkUrl(address: string): string {
    const formattedAddress = this.formatAddress(address);
    const url = this.buildRampNetworkUrl(formattedAddress);

    return url;
  }

  /**
   * Format a Starknet address to exactly 66 characters (0x + 64 hex chars)
   * Pads with zeros after the 0x prefix if address is too short
   * @param address The address to format
   * @returns Formatted address with exactly 66 characters
   * @throws {Error} If address format is invalid
   * @private
   */
  private formatAddress(address: string): string {
    // Validate address starts with 0x
    if (!address.startsWith('0x')) {
      throw new Error('Address must start with 0x');
    }

    // Remove 0x prefix for processing
    const hexPart = address.slice(2);

    // Validate hex characters
    if (!/^[0-9a-fA-F]+$/.test(hexPart)) {
      throw new Error('Address contains invalid characters. Only hexadecimal characters are allowed.');
    }

    // Check if address is too long
    if (hexPart.length > 64) {
      throw new Error(`Address is too long. Expected max 64 hex characters, got ${hexPart.length}`);
    }

    // Pad with zeros if needed (pad at the beginning after 0x)
    const paddedHex = hexPart.padStart(64, '0');

    // Return formatted address
    return `0x${paddedHex}`;
  }

  /**
   * Build complete Ramp Network onramp URL with query parameters
   * @param formattedAddress The formatted wallet address (66 chars)
   * @returns Complete Ramp Network URL
   * @private
   */
  private buildRampNetworkUrl(formattedAddress: string): string {
    const baseUrl = 'https://app.rampnetwork.com/exchange';

    // Build query parameters
    const params = new URLSearchParams();

    // Required parameters
    params.append('defaultFlow', 'ONRAMP');
    params.append('enabledFlows', 'ONRAMP');
    params.append('enabledCryptoAssets', 'STARKNET_*');
    params.append('hostApiKey', 'p8skgorascdvryjzeqoah3xxfbpnx79nopzo6pzw');
    params.append('userAddress', formattedAddress);
    params.append('outAsset', 'STARKNET_USDC');
    params.append('inAsset', 'USD');
    params.append('inAssetValue', '10000');

    // Construct final URL
    return `${baseUrl}?${params.toString()}`;
  }

  // ============================================
  // PASSKEY-ONLY METHODS
  // ============================================
  /**
   * Load an existing passkey-only wallet
   */
  async loadPasskeyOnlyWallet(): Promise<void> {
    if (!this.walletManager) {
      this.walletManager = new WalletManager(
        this.authManager,
        this.config.starknetRpcUrl!,
        this.config.network || 'sepolia',
        this.analyticsManager
      );
    }

    await this.walletManager.loadPasskeyOnlyWallet();

    // Initialize transaction manager
    const account = this.walletManager.getAccount();
    if (account) {
      this.transactionManager = new TransactionManager(
        account,
        this.config.paymasterApiKey!,
        this.config.network || 'sepolia',
        this.analyticsManager
      );
    }
  }

  /**
   * Recover wallet from backend using an existing passkey
   */
  async recoverWalletWithPasskey(): Promise<void> {
    if (!this.walletManager) {
      this.walletManager = new WalletManager(
        this.authManager,
        this.config.starknetRpcUrl!,
        this.config.network || 'sepolia',
        this.analyticsManager
      );
    }

    await this.walletManager.recoverWalletWithPasskey();

    // Initialize transaction manager
    const account = this.walletManager.getAccount();
    if (account) {
      this.transactionManager = new TransactionManager(
        account,
        this.config.paymasterApiKey!,
        this.config.network || 'sepolia',
        this.analyticsManager
      );
    }
  }

  /**
   * Check if a passkey-only wallet exists locally
   */
  async hasPasskeyOnlyWallet(): Promise<boolean> {
    if (!this.walletManager) {
      // Create temp manager to check storage
      const tempManager = new WalletManager(
        this.authManager,
        this.config.starknetRpcUrl!,
        this.config.network || 'sepolia'
      );
      return tempManager.hasPasskeyOnlyWallet();
    }
    return this.walletManager.hasPasskeyOnlyWallet();
  }

  /**
   * Clear passkey-only wallet from local storage
   */
  async clearPasskeyOnlyWallet(): Promise<void> {
    if (this.walletManager) {
      await this.walletManager.clearPasskeyOnlyWallet();
    }
    // Also clear generic session if manual calls
    localStorage.removeItem('cavos_passkey_wallet');
  }
}
