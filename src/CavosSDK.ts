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

  private static readonly DEFAULT_RPC_MAINNET = 'https://starknet-mainnet.g.alchemy.com/starknet/version/rpc/v0_10/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';
  private static readonly DEFAULT_RPC_SEPOLIA = 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/dql5pMT88iueZWl7L0yzT56uVk0EBU4L';

  constructor(config: CavosConfig) {
    const network = config.network || 'sepolia';
    const defaultOAuthConfig = network === 'mainnet' ? DEFAULT_OAUTH_CONFIG_MAINNET : DEFAULT_OAUTH_CONFIG_SEPOLIA;

    this.config = {
      ...config,
      network,
      paymasterApiKey: config.paymasterApiKey,
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
   * Login with OAuth (Google/Apple) or Firebase email/password.
   * 
   * For OAuth providers, opens a popup window by default. If the popup is 
   * blocked, falls back to redirect. Your app never loses state.
   * 
   * @example
   * ```ts
   * await cavos.login('google');   // popup opens, user auths, resolves
   * await cavos.login('apple');    // same with Apple
   * await cavos.login('firebase', { email, password }); // no popup needed
   * ```
   */
  async login(provider: LoginProvider, credentials?: FirebaseCredentials): Promise<void> {
    if (provider === 'firebase') {
      if (!credentials) {
        throw new Error('Firebase login requires email and password');
      }
      await this.loginWithFirebase(credentials.email, credentials.password);
      return;
    }

    if (typeof window === 'undefined') {
      throw new Error('OAuth login requires a browser environment');
    }

    console.log('[CavosSDK] Opening popup synchronously...');
    // OPEN POPUP SYNCHRONOUSLY to bypass browser popup blockers
    const width = 500;
    const height = 600;
    const left = window.screenX + (window.innerWidth - width) / 2;
    const top = window.screenY + (window.innerHeight - height) / 2;
    const popup = window.open(
      '',
      'cavos-oauth',
      `width=${width},height=${height},left=${left},top=${top},popup=true`
    );

    if (popup) {
      popup.document.write('<p style="font-family:sans-serif;text-align:center;margin-top:40vh;color:#888;">Preparing authentication...</p>');
    } else {
      console.warn('[CavosSDK] window.open() returned null synchronously. Popup blocked.');
    }

    try {
      // Ensure app_salt is fetched before starting OAuth flow
      if (!this.appSalt) {
        await this.validateAccess();
      }

      const redirectUri = window.location.origin + window.location.pathname;
      let url: string;
      if (provider === 'google') {
        url = await this.oauthWalletManager.getGoogleOAuthUrl(redirectUri);
      } else if (provider === 'apple') {
        url = await this.oauthWalletManager.getAppleOAuthUrl(redirectUri);
      } else {
        throw new Error(`Unsupported login provider: ${provider}`);
      }

      if (!popup || popup.closed) {
        console.warn('[CavosSDK] Popup blocked or closed by user, falling back to redirect');
        sessionStorage.setItem('cavos_fallback_redirect', 'true');
        window.location.href = url;
        return;
      }

      console.log('[CavosSDK] Navigating popup to OAuth URL...');
      popup.location.href = url;
    } catch (e) {
      console.error('[CavosSDK] Error preparing OAuth URL:', e);
      if (popup && !popup.closed) popup.close();
      throw e;
    }

    console.log('[CavosSDK] Waiting for popup message...');
    // Wait for popup to send auth_data back via postMessage
    const authData = await new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(() => {
        cleanup();
        reject(new Error('OAuth login timed out (120s).'));
      }, 120_000);

      const interval = setInterval(() => {
        try {
          if (popup && popup.closed) {
            cleanup();
            reject(new Error('Login popup was closed.'));
          }
        } catch (e) {
          // COOP might block reading popup.closed
        }
      }, 500);

      const onMessage = (event: MessageEvent) => {
        if (event.origin !== window.location.origin) return;
        if (event.data?.type === 'cavos-oauth-callback' && event.data?.auth_data) {
          cleanup();
          resolve(event.data.auth_data);
        } else if (event.data?.type === 'cavos-oauth-close') {
          cleanup();
          reject(new Error('Login popup was closed.'));
        }
      };

      const cleanup = () => {
        clearTimeout(timeout);
        clearInterval(interval);
        window.removeEventListener('message', onMessage);
        try { popup?.close(); } catch { }
      };

      window.addEventListener('message', onMessage);
    });

    // Process the callback
    await this.handleCallback(authData);
  }

  /**
   * Detect and handle OAuth popup callback. Call at app startup.
   * If the page is a popup callback, sends auth_data to opener and closes.
   * 
   * @returns true if this was a popup callback (app should stop initializing)
   */
  static handlePopupCallback(): boolean {
    if (typeof window === 'undefined') return false;

    // Check if we have auth_data in the URL
    const params = new URLSearchParams(window.location.search);
    const authData = params.get('auth_data') || params.get('zk_auth_data');
    if (!authData) return false;

    // Check if this was a redirect fallback we explicitly triggered
    if (sessionStorage.getItem('cavos_fallback_redirect') === 'true') {
      console.log('[CavosSDK] Found auth_data, but this was a redirect fallback. Not closing window.');
      sessionStorage.removeItem('cavos_fallback_redirect');
      return false; // Let handleCallback take over
    }

    let hasOpener = false;
    try {
      hasOpener = !!window.opener && window.opener !== window;
    } catch {
      // COOP might block accessing window.opener, but if we're in a popup we should
      // still try to postMessage back to whoever opened us
      hasOpener = true;
    }

    // We have auth_data. If we are NOT in a popup (no opener), we shouldn't close the window.
    // Instead, we might need to handle it normally (redirect flow).
    if (!hasOpener) {
      console.warn('[CavosSDK] Found auth_data but no window.opener. This looks like a redirect callback, not a popup.');
      return false; // Let handleCallback take over
    }

    console.log('[CavosSDK] Popup callback detected. Sending message to opener...');
    try {
      window.opener.postMessage({
        type: 'cavos-oauth-callback',
        auth_data: authData,
      }, '*'); // Use '*' to avoid strict cross-origin drops if domains differ slightly

      // Safely close the popup. In COOP environments, window.close() might be blocked.
      setTimeout(() => {
        console.log('[CavosSDK] Closing popup window...');
        try { window.close(); } catch { }
        try { window.opener.postMessage({ type: 'cavos-oauth-close' }, '*'); } catch { }
        // If it doesn't close, show a friendly message to the user
        document.body.innerHTML = '<div style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;color:#333;background:#f9f9f9;flex-direction:column;"><h2>Authentication Successful</h2><p>You can safely close this window.</p></div>';
      }, 100);
      return true;
    } catch (e) {
      console.error('[CavosSDK] Error posting message from popup:', e);
      return false;
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

    // Store in seen wallets for discovery
    this.addWalletToSeen(this.oauthWalletManager.getSession()?.jwtClaims?.sub, this.oauthWalletManager.getSession()?.walletName);

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
          const deployHash = await this.deployAccount();
          this.logger.log('Account deployment triggered. TxHash:', deployHash);

          this.updateWalletStatus({
            isDeploying: false,
            isDeployed: true,
            isSessionActive: false,
            isReady: false, // NOT ready yet — session needs registration
          });

          // Track wallet deployment for MAU
          const address = this.getAddress();
          const email = this.oauthWalletManager.getSession()?.jwtClaims?.sub;
          if (address) {
            this.analyticsManager.trackWalletDeployment(address, email);
          }

          // Auto-register session after deploy
          await this.autoRegisterSession();
        } catch (err) {
          this.updateWalletStatus({ isDeploying: false });
          this.logger.alwaysError('Background deployment failed:', err);
        }
      } else {
        this.logger.log('Account already deployed. Checking session status...');
        // Check if current session key is already registered on-chain
        const sessionActive = this.transactionManager
          ? await this.transactionManager.isSessionRegistered()
          : false;

        if (sessionActive) {
          this.updateWalletStatus({
            isDeployed: true,
            isSessionActive: true,
            isReady: true,
          });
        } else {
          this.updateWalletStatus({
            isDeployed: true,
            isSessionActive: false,
            isReady: false,
          });
          // Auto-register session if not active
          await this.autoRegisterSession();
        }
      }
    }).catch(err => {
      this.logger.alwaysError('Background deployment check failed:', err);
    });
  }

  /**
   * Auto-register session after deploy or when session is not active.
   * Updates walletStatus progressively.
   */
  private async autoRegisterSession(): Promise<void> {
    if (!this.transactionManager) return;

    try {
      this.updateWalletStatus({ isRegistering: true });
      this.logger.log('Auto-registering session on-chain...');
      const txHash = await this.transactionManager.registerCurrentSession();
      this.logger.log('Session registered. TxHash:', txHash);
      this.updateWalletStatus({
        isRegistering: false,
        isSessionActive: true,
        isReady: true,
      });
    } catch (err) {
      this.logger.alwaysError('Auto session registration failed:', err);
      this.updateWalletStatus({
        isRegistering: false,
        isReady: true, // Still mark as ready — execute() can try JWT fallback
      });
    }
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

    // Store in seen wallets for discovery
    this.addWalletToSeen(this.oauthWalletManager.getSession()?.jwtClaims?.sub, this.oauthWalletManager.getSession()?.walletName);

    // Ensure session is registered on-chain (background)
    this.deployAccountInBackground();
  }


  /**
   * Initialize TransactionManager
   */
  private initializeTransactionManager(): void {
    const session = this.oauthWalletManager.getSession();
    if (!session || !session.walletAddress) return;

    this.transactionManager = new OAuthTransactionManager(
      this.config.oauthWallet as OAuthWalletConfig,
      this.oauthWalletManager,
      this.config.starknetRpcUrl!,
      this.config.paymasterApiKey!,
      this.config.network || 'sepolia',
      this.config.paymasterUrl
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
   * Get all wallet addresses associated with the current user.
   * Scans for SessionRegistered events and checks ownership.
   */
  async getAssociatedWallets(): Promise<{ address: string; name?: string }[]> {
    const session = this.oauthWalletManager.getSession();
    if (!session?.jwtClaims?.sub) return [];

    const sub = session.jwtClaims.sub;
    const provider = new RpcProvider({ nodeUrl: this.config.starknetRpcUrl! });

    // 1. Start with the "default" (unnamed) wallet
    const defaultAddress = this.oauthWalletManager.getWalletAddress();
    const wallets: { address: string; name?: string }[] = [];
    if (defaultAddress) wallets.push({ address: defaultAddress });

    try {
      const SESSION_REGISTERED_KEY = '0x3b884c3fe0cee93e6453d50e9670be6fb54804e1bbbc159a845d9ab244a5ee6';
      const FROM_BLOCK = this.config.network === 'mainnet' ? 6600000 : 0;
      const isBrowser = typeof window !== 'undefined';
      const seenNamesKey = `cavos_seen_wallets_${this.config.appId}_${sub}`;
      const seenNames = isBrowser ? JSON.parse(localStorage.getItem(seenNamesKey) || '[]') : [];

      for (const name of seenNames) {
        const addr = this.oauthWalletManager.getAddressSeedManager().computeContractAddress(
          sub,
          this.config.oauthWallet!.cavosAccountClassHash!,
          this.config.oauthWallet!.jwksRegistryAddress!,
          name
        );
        if (!wallets.find(w => w.address === addr)) {
          wallets.push({ address: addr, name });
        }
      }

      return wallets;
    } catch (err) {
      this.logger.alwaysError('Discovery failed:', err);
      return wallets;
    }
  }

  /**
   * Switch the active wallet by name.
   */
  async switchWallet(name?: string): Promise<void> {
    this.oauthWalletManager.switchWallet(name);
    this.initializeTransactionManager();

    // Store in seen wallets for discovery
    const session = this.oauthWalletManager.getSession();
    if (session?.jwtClaims?.sub) {
      this.addWalletToSeen(session.jwtClaims.sub, name);
    }

    // Check deployment in background for the newly selected wallet
    this.deployAccountInBackground();
    this.notifyWalletStatusListeners();
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
   * Register the current session key on-chain using the current JWT.
   * Call this explicitly to pre-register the session before executing transactions.
   */
  async registerCurrentSession(): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Wallet not initialized');
    }
    const txHash = await this.transactionManager.registerCurrentSession();
    this.updateWalletStatus({ isSessionActive: true });
    return txHash;
  }

  /**
   * Update the session policy on the active session.
   * Call this before registerCurrentSession() to ensure the latest policy
   * is embedded in the JWT signature and stored on-chain.
   */
  updateSessionPolicy(policy: import('./types/session').SessionKeyPolicy): void {
    this.oauthWalletManager.updateSessionPolicy(policy);
  }

  /**
   * Export the current session as a base64 token for use with the Cavos CLI.
   * Use: cavos session import <token>
   */
  exportSession(): string {
    const session = this.oauthWalletManager.getSession();
    if (!session?.walletAddress || !session.sessionPrivateKey) {
      throw new Error('No active session to export');
    }
    // JWT is intentionally excluded — the CLI uses the session key directly
    // (SESSION_V1 signature). The session must already be registered on-chain.
    const tokenObj = {
      sessionPrivateKey: session.sessionPrivateKey,
      sessionPubKey: session.sessionPubKey,
      nonceParams: {
        sessionPubKey: session.nonceParams.sessionPubKey,
        validAfter: session.nonceParams.validAfter.toString(),
        validUntil: session.nonceParams.validUntil.toString(),
        renewalDeadline: session.nonceParams.renewalDeadline.toString(),
        randomness: session.nonceParams.randomness.toString(),
      },
      nonce: session.nonce,
      walletAddress: session.walletAddress,
      addressSeed: session.addressSeed ?? '',
      appSalt: this.appSalt ?? '0x0',
      walletName: session.walletName,
      sessionPolicy: session.sessionPolicy ? {
        spendingLimits: session.sessionPolicy.spendingLimits.map(sl => ({
          token: sl.token,
          limit: sl.limit.toString(),
        })),
        allowedContracts: session.sessionPolicy.allowedContracts,
        maxCallsPerTx: session.sessionPolicy.maxCallsPerTx,
      } : undefined,
    };
    return btoa(JSON.stringify(tokenObj));
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
   * Get account (Not directly available in OAuth flow without session PK access)
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

      // Store app_salt for per-app wallet derivation
      if (result.app_salt) {
        this.appSalt = result.app_salt;
        // Update OAuthWalletManager with the per-app salt
        this.oauthWalletManager.setAppSalt(result.app_salt);
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

  /**
   * Helper to persist a wallet name for discovery
   */
  private addWalletToSeen(sub: string | undefined, name: string | undefined): void {
    if (!sub || !name || typeof window === 'undefined') return;
    const seenNamesKey = `cavos_seen_wallets_${this.config.appId}_${sub}`;
    const seenNames = JSON.parse(localStorage.getItem(seenNamesKey) || '[]');
    if (!seenNames.includes(name)) {
      seenNames.push(name);
      localStorage.setItem(seenNamesKey, JSON.stringify(seenNames));
    }
  }
}
