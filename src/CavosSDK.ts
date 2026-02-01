import { Account, Call, RpcProvider } from 'starknet';
import { SessionManager } from './session/SessionManager';
import { PaymasterIntegration } from './paymaster/PaymasterIntegration';
import { AnalyticsManager } from './analytics/AnalyticsManager';
import { OAuthWalletManager, OAuthTransactionManager } from './oauth';
import { CavosConfig, UserInfo, OnrampProvider, LoginProvider, Signature, OAuthWalletConfig, FirebaseCredentials } from './types';
import { DEFAULT_OAUTH_CONFIG_SEPOLIA, DEFAULT_OAUTH_CONFIG_MAINNET } from './config/defaults';
import axios from 'axios';

export class CavosSDK {
  private config: CavosConfig;
  private oauthWalletManager: OAuthWalletManager;
  private transactionManager: OAuthTransactionManager | null = null;
  private sessionManager: SessionManager;
  private paymaster: PaymasterIntegration;
  private analyticsManager: AnalyticsManager;
  private isLimitExceeded: boolean = false;

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

    const oauthConfig = this.config.oauthWallet as OAuthWalletConfig;
    const sessionConfig = {
      sessionDuration: this.config.session?.sessionDuration || 2880, // ~24 hours
      renewalGracePeriod: this.config.session?.renewalGracePeriod || 2880, // ~24 hours
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
    await this.validateAccess();

    if (this.oauthWalletManager.restoreSession()) {
      this.initializeTransactionManager();
    }
  }

  /**
   * Handle OAuth login redirect or Firebase email/password login
   */
  async login(provider: LoginProvider, credentials?: FirebaseCredentials): Promise<void> {
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
   */
  async register(provider: LoginProvider, credentials: FirebaseCredentials): Promise<void> {
    if (provider !== 'firebase') {
      throw new Error('Registration is only supported for firebase provider');
    }

    await this.oauthWalletManager.registerWithFirebase(credentials.email, credentials.password);
    this.initializeTransactionManager();

    // Deploy account in background
    this.deployAccountInBackground();
  }

  /**
   * Login with Firebase email/password
   */
  private async loginWithFirebase(email: string, password: string): Promise<void> {
    await this.oauthWalletManager.loginWithFirebase(email, password);
    this.initializeTransactionManager();

    // Deploy or register session in background
    this.deployAccountInBackground();
  }

  /**
   * Deploy account or register session in background
   */
  private deployAccountInBackground(): void {
    this.isAccountDeployed().then(async (deployed) => {
      if (!deployed) {
        console.log('[CavosSDK] Account not deployed. Deploying with session...');
        await this.deployAccount();
      } else {
        console.log('[CavosSDK] Account already deployed. Registering new session via deployer...');
        if (this.transactionManager) {
          const session = this.oauthWalletManager.getSession();
          if (session) {
            await this.transactionManager.registerSessionViaDeployer(session);
          }
        }
      }
    }).catch(err => {
      console.error('[CavosSDK] Background session registration/deployment failed:', err);
    });
  }

  /**
   * Handle OAuth callback
   */
  async handleCallback(authDataString: string): Promise<void> {
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
   */
  async execute(calls: Call | Call[], _options?: { gasless?: boolean }): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Wallet not initialized. Please login first.');
    }
    return this.transactionManager.execute(calls);
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
    console.warn('[CavosSDK] createSession() is deprecated. OAuth flow handles sessions automatically.');
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
   * Renew the current session with a new ephemeral key
   * Call this when execute() throws SESSION_EXPIRED error
   * @returns Transaction hash of the renewal transaction
   */
  async renewSession(): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Wallet not initialized');
    }

    // Freshen session (generate new ephemeral key while keeping old one in memory)
    await this.oauthWalletManager.freshenSession();
    const newSession = this.oauthWalletManager.getSession();

    if (!newSession) {
      throw new Error('Failed to generate new session');
    }

    // Register new session on-chain (uses old session internally for signing)
    const txHash = await this.transactionManager.renewSession(newSession);

    return txHash;
  }

  /**
   * Logout and clear all data
   */
  async logout(): Promise<void> {
    this.oauthWalletManager.clearSession();
    this.transactionManager = null;
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
    console.warn('[CavosSDK] getAccount() is not available in OAuth-only mode. Use execute() instead.');
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
        console.warn('[Cavos SDK] MAU limit exceeded.');
        return;
      }

      if (result.warning) {
        console.warn('[Cavos SDK]', result.message);
      }
    } catch (error: any) {
      console.warn('[Cavos SDK] Validation check failed:', error.message);
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

  // Passkey compatibility methods (deprecated/no-op)
  async createWallet(): Promise<void> {
    console.warn('[CavosSDK] createWallet() is deprecated. OAuth flow handles account creation automatically.');
  }

  async hasPasskeyOnlyWallet(): Promise<boolean> { return false; }
  async loadPasskeyOnlyWallet(): Promise<void> { }
  async clearPasskeyOnlyWallet(): Promise<void> { }
  async retryWalletUnlock(): Promise<void> { }
  async deleteAccount(): Promise<void> { }
  async signMessage(_message: string): Promise<Signature> {
    throw new Error('signMessage() not yet implemented for OAuth-only mode.');
  }
}
