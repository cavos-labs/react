import { Account, Call, RpcProvider, type TypedData } from 'starknet';
import { SessionManager } from './session/SessionManager';
import { PaymasterIntegration } from './paymaster/PaymasterIntegration';
import { AnalyticsManager } from './analytics/AnalyticsManager';
import { OAuthWalletManager, OAuthTransactionManager } from './oauth';
import { CavosConfig, UserInfo, OnrampProvider, LoginProvider, Signature, OAuthWalletConfig, FirebaseCredentials } from './types';
import { DEFAULT_OAUTH_CONFIG_SEPOLIA, DEFAULT_OAUTH_CONFIG_MAINNET } from './config/defaults';
import { Logger } from './utils/logger';
import axios from 'axios';

export interface WalletStatus {
  isDeploying: boolean;
  isDeployed: boolean;
  isRegistering: boolean;
  isSessionActive: boolean;
  isReady: boolean;
}

export type WalletStatusListener = (status: WalletStatus) => void;

export class CavosSDK {
  private config: CavosConfig;
  private logger: Logger;
  private oauthWalletManager: OAuthWalletManager;
  private transactionManager: OAuthTransactionManager | null = null;
  private sessionManager: SessionManager;
  private paymaster: PaymasterIntegration;
  private analyticsManager: AnalyticsManager;
  private isLimitExceeded: boolean = false;
  private appSalt: string | null = null;

  // Wallet status state
  private _walletStatus: WalletStatus = {
    isDeploying: false,
    isDeployed: false,
    isRegistering: false,
    isSessionActive: false,
    isReady: false,
  };
  private walletStatusListeners: Set<WalletStatusListener> = new Set();

  // Default Cavos shared paymaster API key for Sepolia
  public static readonly DEFAULT_PAYMASTER_KEY = 'c37c52b7-ea5a-4426-8121-329a78354b0b';
  private static readonly DEFAULT_RPC_MAINNET = 'https://starknet-mainnet.g.alchemy.com/starknet/version/rpc/v0_10/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';
  private static readonly DEFAULT_RPC_SEPOLIA = 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';

  constructor(config: CavosConfig) {
    const network = config.network || 'sepolia';
    const defaultOAuthConfig = network === 'mainnet' ? DEFAULT_OAUTH_CONFIG_MAINNET : DEFAULT_OAUTH_CONFIG_SEPOLIA;

    this.config = {
      ...config,
      network,
      paymasterApiKey: config.paymasterApiKey || CavosSDK.DEFAULT_PAYMASTER_KEY,
      starknetRpcUrl: config.starknetRpcUrl || (
        network === 'mainnet'
          ? CavosSDK.DEFAULT_RPC_MAINNET
          : CavosSDK.DEFAULT_RPC_SEPOLIA
      ),
      oauthWallet: {
        ...defaultOAuthConfig,
        ...config.oauthWallet
      }
    };

    // Initialize logger
    this.logger = new Logger(config.enableLogging || false);

    const oauthConfig = this.config.oauthWallet as OAuthWalletConfig;
    const sessionConfig = {
      sessionDuration: this.config.session?.sessionDuration || 86400, // 24 hours in seconds
      renewalGracePeriod: this.config.session?.renewalGracePeriod || 172800, // 48 hours in seconds
      defaultPolicy: this.config.session?.defaultPolicy,
    };
    this.oauthWalletManager = new OAuthWalletManager(
      oauthConfig,
      this.config.backendUrl || 'https://cavos.xyz',
      this.config.appId,
      this.config.starknetRpcUrl!,
      sessionConfig
    );

    this.analyticsManager = new AnalyticsManager(this.config);

    this.sessionManager = new SessionManager(
      this.config.starknetRpcUrl!,
      this.config.network || 'sepolia'
    );

    this.paymaster = new PaymasterIntegration(this.config.paymasterApiKey!);
  }

  /**
   * Initialize SDK and restore session if available
   */
  async init(): Promise<void> {
    console.log('[CavosSDK] init() called');

    // CRITICAL: Restore session FIRST so that setAppSalt() can recalculate the address
    const sessionRestored = this.oauthWalletManager.restoreSession();
    console.log('[CavosSDK] restoreSession result:', sessionRestored, 'wallet before salt:', this.oauthWalletManager.getWalletAddress());

    // Now fetch app_salt and apply it (will recalculate wallet if session exists)
    await this.validateAccess();
    console.log('[CavosSDK] after validateAccess, appSalt:', this.appSalt, 'wallet after salt:', this.oauthWalletManager.getWalletAddress());

    if (sessionRestored) {
      this.initializeTransactionManager();
      // Check deployment status and update walletStatus
      this.deployAccountInBackground();
    }
  }

  /**
   * Handle OAuth login redirect or Firebase email/password login
   */
  async login(provider: LoginProvider, credentials?: FirebaseCredentials): Promise<void> {
    // Ensure app_salt is fetched before starting OAuth flow
    if (!this.appSalt) {
      await this.validateAccess();
    }

    if (provider === 'firebase') {
      if (!credentials) {
        throw new Error('Firebase login requires email and password');
      }
      await this.loginWithFirebase(credentials.email, credentials.password);
      return;
    }

    // OAuth providers (google, apple)
    const redirectUri = (typeof window !== 'undefined' ? window.location.href : undefined);

    let url: string;
    if (provider === 'google') {
      url = await this.oauthWalletManager.getGoogleOAuthUrl(redirectUri);
    } else if (provider === 'apple') {
      url = await this.oauthWalletManager.getAppleOAuthUrl(redirectUri);
    } else {
      throw new Error(`Unsupported login provider: ${provider}`);
    }

    if (typeof window !== 'undefined') {
      window.location.href = url;
    }
  }

  /**
   * Register new user with Firebase email/password
   * NOTE: This only creates the user in Firebase and stores the session locally.
   * The account is NOT deployed on-chain. Use login() to deploy.
   */
  async register(provider: LoginProvider, credentials: FirebaseCredentials): Promise<void> {
    if (provider !== 'firebase') {
      throw new Error('Registration is only supported for firebase provider');
    }

    await this.oauthWalletManager.registerWithFirebase(credentials.email, credentials.password);
    this.initializeTransactionManager();

    // Do NOT deploy on registration
    this.logger.log('User registered. Account will be deployed on first login.');
  }

  /**
   * Login with Firebase email/password
   * Deploys account if it doesn't exist yet
   */
  private async loginWithFirebase(email: string, password: string): Promise<void> {
    if (!this.appSalt) {
      await this.validateAccess();
    }

    await this.oauthWalletManager.loginWithFirebase(email, password);
    this.initializeTransactionManager();

    // Deploy or register session in background (only on login)
    this.deployAccountInBackground();
  }

  /**
   * Deploy account in background
   *
   * Note: Session registration is no longer needed here!
   * The first execute() call will automatically register the session using JWT signature.
   * This eliminates the relayer dependency completely.
   */
  private deployAccountInBackground(): void {
    this.isAccountDeployed().then(async (deployed) => {
      if (!deployed) {
        this.logger.log('Account not deployed. Deploying with session...');
        this.updateWalletStatus({ isDeploying: true });
        try {
          await this.deployAccount();
          this.updateWalletStatus({
            isDeploying: false,
            isDeployed: true,
            isSessionActive: false, // Session will be registered on first execute()
            isReady: true
          });
          // Track wallet deployment for MAU
          const address = this.getAddress();
          const email = this.oauthWalletManager.getSession()?.jwtClaims?.sub;
          if (address) {
            this.analyticsManager.trackWalletDeployment(address, email);
          }
        } catch (err) {
          this.updateWalletStatus({ isDeploying: false });
          throw err;
        }
      } else {
        this.logger.log('Account already deployed. Ready to execute.');
        this.updateWalletStatus({
          isDeployed: true,
          isSessionActive: false, // Will be checked/registered on first execute()
          isReady: true
        });
      }
    }).catch(err => {
      this.logger.alwaysError('Background deployment check failed:', err);
    });
  }

  /**
   * Handle OAuth callback
   */
  async handleCallback(authDataString: string): Promise<void> {
    // CRITICAL: Fetch app_salt BEFORE processing callback
    // The callback will compute wallet address using the salt
    if (!this.appSalt) {
      await this.validateAccess();
    }

    await this.oauthWalletManager.handleOAuthCallback(authDataString);
    this.initializeTransactionManager();

    // Ensure session is registered on-chain (background)
    this.deployAccountInBackground();
  }

  private initializeTransactionManager(): void {
    const session = this.oauthWalletManager.getSession();
    if (!session || !session.walletAddress) return;

    this.transactionManager = new OAuthTransactionManager(
      this.config.oauthWallet as OAuthWalletConfig,
      this.oauthWalletManager,
      this.config.starknetRpcUrl!,
      this.config.paymasterApiKey!,
      this.config.network || 'sepolia'
    );
  }

  /**
   * Execute transactions (OAuth Wallet Flow)
   *
   * Automatically handles session registration:
   * - If session NOT registered: Uses JWT signature (self-custodial, no relayer needed)
   * - If session IS registered: Uses lightweight session signature
   *
   * No manual session registration needed - it's all handled transparently!
   */
  async execute(calls: Call | Call[], _options?: { gasless?: boolean }): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Wallet not initialized. Please login first.');
    }

    // The transactionManager.execute() will automatically detect if session is registered
    // and use the appropriate signature type (JWT for first tx, session for subsequent)
    const txHash = await this.transactionManager.execute(calls);

    // Track transaction for MAU
    const address = this.getAddress();
    if (address) {
      this.analyticsManager.trackTransaction(txHash, address, 'confirmed');
    }

    return txHash;
  }

  /**
   * Execute with session (Compatibility Alias for execute)
   */
  async executeWithSession(calls: Call | Call[]): Promise<string> {
    return this.execute(calls);
  }

  /**
   * Create session (Compatibility Alias - Always returns success as OAuth IS a session)
   */
  async createSession(_policy?: any): Promise<void> {
    this.logger.warn('createSession() is deprecated. OAuth flow handles sessions automatically.');
    return;
  }

  /**
   * Check if has active session (Compatibility Alias)
   */
  hasActiveSession(): boolean {
    return this.isAuthenticated();
  }

  /**
   * Clear session (Compatibility Alias for logout)
   */
  async clearSession(): Promise<void> {
    await this.logout();
  }

  /**
   * Get current wallet address
   */
  getAddress(): string | null {
    return this.oauthWalletManager.getWalletAddress();
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return this.oauthWalletManager.hasValidSession();
  }

  /**
   * Check if account is deployed on-chain
   */
  async isAccountDeployed(): Promise<boolean> {
    const address = this.getAddress();
    if (!address) return false;

    try {
      const provider = new RpcProvider({ nodeUrl: this.config.starknetRpcUrl! });
      const classHash = await provider.getClassHashAt(address);
      return !!classHash;
    } catch {
      return false;
    }
  }

  /**
   * Deploy the account contract on-chain
   */
  async deployAccount(): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Wallet not initialized');
    }
    return this.transactionManager.deployAccount();
  }

  /**
   * Renew the current session with a new session key.
   * The current session must be registered on-chain and expired (but within the grace period).
   * If the session is not registered yet, execute a transaction first to register it.
   * If the session is still active, renewal is not needed.
   * @returns Transaction hash of the renewal transaction
   */
  async renewSession(): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Wallet not initialized');
    }

    // Check session status on-chain before attempting renewal
    const status = await this.transactionManager.getSessionStatus();

    if (!status.registered) {
      throw new Error('Session not registered on-chain yet. Execute a transaction first — the session key gets registered automatically on your first tx.');
    }

    if (!status.expired) {
      const remaining = status.validUntil ? Number(status.validUntil - BigInt(Math.floor(Date.now() / 1000))) : 0;
      const hours = Math.floor(remaining / 3600);
      const mins = Math.floor((remaining % 3600) / 60);
      throw new Error(`Session is still active (${hours}h ${mins}m remaining). Renewal is only needed after expiry.`);
    }

    if (!status.canRenew) {
      throw new Error('Session expired outside the grace period. Please login again.');
    }

    // Freshen session (generate new session key while keeping old one in memory)
    await this.oauthWalletManager.freshenSession();
    const newSession = this.oauthWalletManager.getSession();

    if (!newSession) {
      throw new Error('Failed to generate new session');
    }

    const txHash = await this.transactionManager.renewSession(newSession);

    return txHash;
  }

  /**
   * Revoke a specific session key on-chain.
   * Requires JWT verification.
   * @param sessionKey The session key (public key) to revoke
   * @returns Transaction hash
   */
  async revokeSession(sessionKey: string): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Wallet not initialized');
    }

    return this.transactionManager.revokeSession(sessionKey);
  }

  /**
   * Emergency revoke ALL session keys on-chain.
   * Increments the revocation epoch, invalidating all existing sessions.
   * Requires JWT verification.
   * @returns Transaction hash
   */
  async emergencyRevokeAllSessions(): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Wallet not initialized');
    }

    return this.transactionManager.emergencyRevokeAllSessions();
  }

  /**
   * Logout and clear all data
   */
  async logout(): Promise<void> {
    this.oauthWalletManager.clearSession();
    this.transactionManager = null;
    // Reset wallet status
    this._walletStatus = {
      isDeploying: false,
      isDeployed: false,
      isRegistering: false,
      isSessionActive: false,
      isReady: false,
    };
    this.notifyWalletStatusListeners();
  }

  /**
   * Get current wallet status
   */
  getWalletStatus(): WalletStatus {
    return { ...this._walletStatus };
  }

  /**
   * Subscribe to wallet status changes
   */
  onWalletStatusChange(listener: WalletStatusListener): () => void {
    this.walletStatusListeners.add(listener);
    // Immediately call with current status
    listener(this.getWalletStatus());
    // Return unsubscribe function
    return () => {
      this.walletStatusListeners.delete(listener);
    };
  }

  /**
   * Update wallet status and notify listeners
   */
  private updateWalletStatus(updates: Partial<WalletStatus>): void {
    this._walletStatus = { ...this._walletStatus, ...updates };
    this.notifyWalletStatusListeners();
  }

  /**
   * Notify all wallet status listeners
   */
  private notifyWalletStatusListeners(): void {
    const status = this.getWalletStatus();
    this.walletStatusListeners.forEach(listener => listener(status));
  }

  /**
   * Get current user info from JWT claims
   */
  getUserInfo(): UserInfo | null {
    const session = this.oauthWalletManager.getSession();
    if (!session || !session.jwtClaims) return null;

    return {
      id: session.jwtClaims.sub,
      email: '',
      name: '',
      picture: ''
    };
  }

  /**
   * Get funding address
   */
  getFundingAddress(): string | null {
    return this.getAddress();
  }

  /**
   * Get account (Not directly available in OAuth flow without eph PK access)
   */
  getAccount(): Account | null {
    this.logger.warn('getAccount() is not available in OAuth-only mode. Use execute() instead.');
    return null;
  }

  /**
   * Validate app access and MAU limits
   */
  private async validateAccess(): Promise<void> {
    try {
      const backendUrl = this.config.backendUrl || 'https://cavos.xyz';
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
        this.logger.warn('MAU limit exceeded.');
        return;
      }

      // Store app_salt for per-app wallet derivation
      if (result.app_salt) {
        this.appSalt = result.app_salt;
        // Update OAuthWalletManager with the per-app salt
        this.oauthWalletManager.setAppSalt(result.app_salt);
      }

      if (result.warning) {
        this.logger.warn(result.message);
      }
    } catch (error: any) {
      this.logger.warn('Validation check failed:', error.message);
    }
  }

  /**
   * Get an onramp URL for purchasing crypto with fiat
   */
  public getOnramp(provider: OnrampProvider): string {
    const address = this.getAddress();
    if (!address) {
      throw new Error('No account connected.');
    }

    if (this.config.network === 'sepolia') {
      throw new Error('Onramp feature is not available on Sepolia network.');
    }

    switch (provider) {
      case 'RAMP_NETWORK':
        return this.getRampNetworkUrl(address);
      default:
        throw new Error(`Unknown onramp provider: ${provider}`);
    }
  }

  private getRampNetworkUrl(address: string): string {
    const hexPart = address.startsWith('0x') ? address.slice(2) : address;
    const paddedHex = hexPart.padStart(64, '0');
    const formattedAddress = `0x${paddedHex}`;

    const baseUrl = 'https://app.rampnetwork.com/exchange';
    const params = new URLSearchParams();
    params.append('defaultFlow', 'ONRAMP');
    params.append('enabledFlows', 'ONRAMP');
    params.append('enabledCryptoAssets', 'STARKNET_*');
    params.append('hostApiKey', 'p8skgorascdvryjzeqoah3xxfbpnx79nopzo6pzw');
    params.append('userAddress', formattedAddress);
    params.append('outAsset', 'STARKNET_USDC');
    params.append('inAsset', 'USD');
    params.append('inAssetValue', '10000');

    return `${baseUrl}?${params.toString()}`;
  }

  /**
   * Get account balance in ETH
   */
  async getBalance(): Promise<string> {
    const address = this.getAddress();
    if (!address) return '0';

    try {
      const provider = new RpcProvider({ nodeUrl: this.config.starknetRpcUrl! });
      const ethAddress = '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';
      const result = await provider.callContract({
        contractAddress: ethAddress,
        entrypoint: 'balanceOf',
        calldata: [address],
      });
      return BigInt(result[0] || '0').toString();
    } catch (error) {
      return '0';
    }
  }

  /**
   * Check if email is verified for this app
   */
  async isEmailVerified(email: string): Promise<boolean> {
    return this.oauthWalletManager.checkEmailVerification(email);
  }

  /**
   * Resend verification email
   */
  async resendVerificationEmail(email: string): Promise<void> {
    return this.oauthWalletManager.resendVerificationEmail(email);
  }

  // Passkey compatibility methods (deprecated/no-op)
  async createWallet(): Promise<void> {
    this.logger.warn('createWallet() is deprecated. OAuth flow handles account creation automatically.');
  }

  async hasPasskeyOnlyWallet(): Promise<boolean> { return false; }
  async loadPasskeyOnlyWallet(): Promise<void> { }
  async clearPasskeyOnlyWallet(): Promise<void> { }
  async retryWalletUnlock(): Promise<void> { }
  async deleteAccount(): Promise<void> { }
  /**
   * Sign typed data with the session key (OAuth mode).
   *
   * @param typedDataInput - The typed data to sign (SNIP-12 format)
   * @returns Signature object with r and s components
   */
  async signMessage(typedDataInput: TypedData): Promise<Signature> {
    const sig = this.oauthWalletManager.signMessage(typedDataInput);
    // sig is an array [r, s] from starknet.js
    return {
      r: (sig as string[])[0],
      s: (sig as string[])[1],
    };
  }
}
