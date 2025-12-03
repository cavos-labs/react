import { Account, Call } from 'starknet';
import { AuthManager } from './auth/AuthManager';
import { WalletManager } from './wallet/WalletManager';
import { SessionManager } from './session/SessionManager';
import { PaymasterIntegration } from './paymaster/PaymasterIntegration';
import { TransactionManager } from './transaction/TransactionManager';
import { AnalyticsManager } from './analytics/AnalyticsManager';
import { CavosConfig, UserInfo, SessionPolicy, ExecuteOptions, OnrampProvider, LoginProvider } from './types';

export class CavosSDK {
  private config: CavosConfig;
  private authManager: AuthManager;
  private walletManager: WalletManager | null = null;
  private sessionManager: SessionManager;
  private paymaster: PaymasterIntegration;
  private transactionManager: TransactionManager | null = null;
  private analyticsManager: AnalyticsManager;

  // Default Cavos shared paymaster API key for Sepolia
  private static readonly DEFAULT_PAYMASTER_KEY = 'c37c52b7-ea5a-4426-8121-329a78354b0b';
  private static readonly DEFAULT_RPC_MAINNET = 'https://starknet-mainnet.g.alchemy.com/starknet/version/rpc/v0_8/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';
  private static readonly DEFAULT_RPC_SEPOLIA = 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_8/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';

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

    // Initialize session manager
    this.sessionManager = new SessionManager(this.config.starknetRpcUrl!);

    // Initialize paymaster with default key
    this.paymaster = new PaymasterIntegration(this.config.paymasterApiKey!);

    if (this.config.enableLogging) {
      console.log('[CavosSDK] Initialized with config:', this.config);
    }
  }

  /**
   * Initialize SDK and restore session if available
   */
  async init(): Promise<void> {
    // Try to restore session
    if (this.authManager.restoreSession()) {
      console.log('[CavosSDK] Session restored');
      try {
        await this.initializeWallet();
        console.log('[CavosSDK] Wallet restored');
      } catch (error) {
        console.error('[CavosSDK] Failed to restore wallet:', error);
        // If wallet restoration fails, we might want to clear session
        // this.authManager.logout();
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
      console.warn('[CavosSDK] Wallet initialization failed:', error.message);
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
      console.log('[CavosSDK] Load failed:', error.message);
      // If load fails, we don't auto-create. The UI should handle this.
      throw error;
    }

    // Auto-deploy account if not already deployed (gasless with AVNU paymaster)
    const isDeployed = await this.walletManager.isDeployed();
    if (!isDeployed) {
      console.log('[CavosSDK] Deploying account...');
      await this.walletManager.deployAccountWithPaymaster(
        this.config.paymasterApiKey!,
        this.config.network || 'sepolia'
      );
      console.log('[CavosSDK] Account deployed successfully');
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
    const user = this.authManager.getUserInfo();
    if (!user) {
      throw new Error('User info not available');
    }

    if (!this.walletManager) {
      this.walletManager = new WalletManager(
        this.authManager,
        this.config.starknetRpcUrl!,
        this.config.network || 'sepolia',
        this.analyticsManager
      );
    }

    await this.walletManager.createWallet(user);

    // Auto-deploy account immediately after creation
    console.log('[CavosSDK] Deploying new account...');
    await this.walletManager.deployAccountWithPaymaster(
      this.config.paymasterApiKey!,
      this.config.network || 'sepolia'
    );
    console.log('[CavosSDK] Account deployed successfully');

    // After creation, initialize transaction manager
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
  async createSession(): Promise<void> {
    console.warn('[CavosSDK] Session keys not supported with ArgentX accounts. Use execute() with gasless option instead.');
    // No-op for ArgentX accounts
  }

  /**
   * Execute a transaction
   */
  async execute(calls: Call | Call[], options?: ExecuteOptions): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Transaction manager not initialized. Please login first.');
    }

    return await this.transactionManager.execute(calls, options);
  }

  /**
   * Get current wallet address
   */
  getAddress(): string | null {
    return this.walletManager?.getAddress() || null;
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
   * Check if session is active
   */
  hasActiveSession(): boolean {
    return !this.sessionManager.isSessionExpired();
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
  getSessionAccount(): Account | null {
    return this.sessionManager.getSessionAccount();
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

    if (this.config.enableLogging) {
      console.log('[CavosSDK] Ramp Network onramp URL generated:', {
        address: formattedAddress,
        outAsset: 'STARKNET_USDC',
        inAsset: 'USD'
      });
    }

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
}
