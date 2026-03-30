import { Account, Call, RpcProvider, num, type TypedData } from 'starknet';
import { SessionManager } from './session/SessionManager';
import { PaymasterIntegration } from './paymaster/PaymasterIntegration';
import { AnalyticsManager } from './analytics/AnalyticsManager';
import { OAuthWalletManager, OAuthTransactionManager } from './oauth';
import { CavosConfig, UserInfo, OnrampProvider, LoginProvider, Signature, OAuthWalletConfig, FirebaseCredentials } from './types';
import { DEFAULT_OAUTH_CONFIG_SEPOLIA, DEFAULT_OAUTH_CONFIG_MAINNET, DEFAULT_SLOT_RELAYER_ADDRESS, DEFAULT_SLOT_RELAYER_PRIVATE_KEY } from './config/defaults';
import { Logger } from './utils/logger';
import axios from 'axios';

export interface WalletStatus {
  isDeploying: boolean;
  isDeployed: boolean;
  isRegistering: boolean;
  isSessionActive: boolean;
  isReady: boolean;
  /** Tx hash of a pending deploy whose confirmation timed out. Useful to show an explorer link. */
  pendingDeployTxHash?: string;
  /** True while the wallet is being deployed to the Slot chain. */
  isSlotDeploying: boolean;
  /** True once the wallet is confirmed deployed on the Slot chain. */
  isSlotDeployed: boolean;
  /** Tx hash of a pending Slot deploy whose confirmation timed out. */
  pendingSlotDeployTxHash?: string;
}

/** Thrown when the JWT has expired and the user must re-login to continue. */
export class JwtExpiredError extends Error {
  readonly code = 'JWT_EXPIRED';
  constructor(message = 'JWT has expired. Please login again.') {
    super(message);
    this.name = 'JwtExpiredError';
  }
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
  /** Prevents concurrent deployAccountInBackground() runs */
  private _deployingInBackground = false;
  /** Prevents concurrent _deploySlotInBackground() runs */
  private _deployingSlotInBackground = false;
  /** Shared RpcProvider instance to avoid creating one per call */
  private provider: RpcProvider;
  /** RpcProvider for the Slot chain (null if slot not configured) */
  private slotProvider: RpcProvider | null = null;
  /** OAuthTransactionManager pointing at the Slot RPC (null if slot not configured) */
  private slotTransactionManager: OAuthTransactionManager | null = null;
  /** Relayer used for first-time Slot session registration via execute_from_outside_v2. */
  private slotRelayerAccount: Account | null = null;

  private static readonly PENDING_DEPLOY_TX_KEY = 'cavos_pending_deploy_tx';
  private static readonly PENDING_SLOT_DEPLOY_TX_KEY = 'cavos_pending_slot_deploy_tx';

  // Wallet status state
  private _walletStatus: WalletStatus = {
    isDeploying: false,
    isDeployed: false,
    isRegistering: false,
    isSessionActive: false,
    isReady: false,
    isSlotDeploying: false,
    isSlotDeployed: false,
  };
  private walletStatusListeners: Set<WalletStatusListener> = new Set();
  private _authChangeListeners: Set<() => void> = new Set();

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

    this.provider = new RpcProvider({ nodeUrl: this.config.starknetRpcUrl! });

    if (config.slot?.rpcUrl) {
      this.slotProvider = new RpcProvider({ nodeUrl: config.slot.rpcUrl });
      const relayerAddress = DEFAULT_SLOT_RELAYER_ADDRESS;
      const relayerPrivateKey = DEFAULT_SLOT_RELAYER_PRIVATE_KEY;
      this.slotRelayerAccount = new Account({
        provider: this.slotProvider,
        address: relayerAddress,
        signer: relayerPrivateKey,
      });
    }

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
    this.logger.log('init() called');

    // CRITICAL: Restore session FIRST so that setAppSalt() can recalculate the address
    const sessionRestored = this.oauthWalletManager.restoreSession();
    this.logger.log('restoreSession result:', sessionRestored);

    // Now fetch app_salt and apply it (will recalculate wallet if session exists)
    await this.validateAccess();
    this.logger.log('init complete');

    if (sessionRestored) {
      this.initializeTransactionManager();
      this.initializeSlotTransactionManager();
      // Check deployment status and update walletStatus
      this.deployAccountInBackground();
    }
  }

  /** Returns true if the stored JWT is expired (or missing). */
  private isJwtExpired(): boolean {
    const session = this.oauthWalletManager.getSession();
    if (!session?.jwtClaims?.exp) return true;
    return Math.floor(Date.now() / 1000) >= session.jwtClaims.exp;
  }

  /**
   * Login with OAuth (Google/Apple) or Firebase email/password.
   * 
   * For OAuth providers, opens a new window/tab. After authentication,
   * the auth window writes to localStorage and closes. The original tab
   * picks up the auth data via 'storage' events.
   * 
   * @example
   * ```ts
   * await cavos.login('google');   // window opens, user auths, resolves
   * await cavos.login('apple');    // same with Apple
   * await cavos.login('firebase', { email, password }); // no window needed
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

    // Clear any stale auth result
    localStorage.removeItem('cavos_auth_result');

    this.logger.log('Opening auth window...');
    // Open new tab synchronously to avoid popup blockers.
    // '_blank' always opens a new tab; named targets can be reused as popups.
    const authWindow = window.open('', '_blank');

    if (authWindow) {
      authWindow.document.write('<p style="font-family:sans-serif;text-align:center;margin-top:40vh;color:#888;">Preparing authentication...</p>');
    } else {
      this.logger.alwaysError('window.open() returned null. Popup blocked.');
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

      if (!authWindow || authWindow.closed) {
        this.logger.log('Window blocked or closed, falling back to redirect');
        sessionStorage.setItem('cavos_fallback_redirect', 'true');
        window.location.href = url;
        return;
      }

      this.logger.log('Navigating auth window to OAuth URL...');
      authWindow.location.href = url;
    } catch (e) {
      this.logger.alwaysError('Error preparing OAuth URL:', e);
      if (authWindow && !authWindow.closed) authWindow.close();
      throw e;
    }

    this.logger.log('Waiting for auth window to complete...');
    // Wait for auth result via localStorage 'storage' event
    const authData = await new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(() => {
        cleanup();
        reject(new Error('OAuth login timed out (120s).'));
      }, 120_000);

      // Poll: check if the window was closed without auth completing
      const interval = setInterval(() => {
        // Check localStorage directly (storage event doesn't fire in the same tab)
        const result = localStorage.getItem('cavos_auth_result');
        if (result) {
          cleanup();
          localStorage.removeItem('cavos_auth_result');
          resolve(result);
          return;
        }
        try {
          if (authWindow && authWindow.closed) {
            cleanup();
            reject(new Error('Login window was closed without completing authentication.'));
          }
        } catch {
          // COOP might block reading authWindow.closed — ignore
        }
      }, 500);

      // Listen for storage event (fires when another tab writes to localStorage)
      const onStorage = (event: StorageEvent) => {
        if (event.key === 'cavos_auth_result' && event.newValue) {
          cleanup();
          localStorage.removeItem('cavos_auth_result');
          resolve(event.newValue);
        }
      };

      const cleanup = () => {
        clearTimeout(timeout);
        clearInterval(interval);
        window.removeEventListener('storage', onStorage);
        try { authWindow?.close(); } catch { }
      };

      window.addEventListener('storage', onStorage);
    });

    // Process the callback
    await this.handleCallback(authData);
  }

  /**
   * Detect and handle OAuth callback in the auth window. Call at app startup.
   * If auth_data is in the URL, writes it to localStorage so the original tab
   * can pick it up, then closes this window.
   * 
   * @returns true if this was an auth callback (app should stop initializing)
   */
  static handlePopupCallback(): boolean {
    if (typeof window === 'undefined') return false;

    // Check if we have auth_data in the URL
    const params = new URLSearchParams(window.location.search);
    const authData = params.get('auth_data') || params.get('zk_auth_data');
    if (!authData) return false;

    // Check if this was a redirect fallback we explicitly triggered
    if (sessionStorage.getItem('cavos_fallback_redirect') === 'true') {
      sessionStorage.removeItem('cavos_fallback_redirect');
      return false;
    }

    // Only treat as a popup child if this window was opened via window.open().
    // Magic link redirects land in a normal browser tab (opener === null) — never close those.
    if (!window.opener) return false;

    // Auth callback detected — write to localStorage for the original tab and close
    try {
      localStorage.setItem('cavos_auth_result', authData);
      setTimeout(() => {
        try { window.close(); } catch { }
      }, 500);

      return true;
    } catch (e) {
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
    this.initializeSlotTransactionManager();

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
    this.initializeSlotTransactionManager();

    // Store in seen wallets for discovery
    this.addWalletToSeen(
      this.oauthWalletManager.getSession()?.jwtClaims?.iss,
      this.oauthWalletManager.getSession()?.jwtClaims?.sub,
      this.oauthWalletManager.getSession()?.walletName,
    );

    // Deploy or register session in background (only on login)
    this.deployAccountInBackground();
  }

  /**
   * Deploy account in background.
   * Deduplicated — concurrent calls are no-ops.
   * Persists the deploy tx hash to localStorage so a timeout doesn't lose it.
   */
  private deployAccountInBackground(): void {
    if (this._deployingInBackground) {
      this.logger.log('deployAccountInBackground: already running, skipping duplicate call.');
      return;
    }
    this._deployingInBackground = true;

    this._runDeployBackground().finally(() => {
      this._deployingInBackground = false;
    });
  }

  private async _runDeployBackground(): Promise<void> {
    try {
      // ── Step 0: Re-poll a previous deploy tx that timed out ─────────────────
      const pendingTxHash = typeof localStorage !== 'undefined'
        ? localStorage.getItem(CavosSDK.PENDING_DEPLOY_TX_KEY)
        : null;

      if (pendingTxHash) {
        this.logger.log('Found pending deploy tx from previous session, re-polling:', pendingTxHash);
        this.updateWalletStatus({ isDeploying: true, pendingDeployTxHash: pendingTxHash });
        try {
          // Poll up to 3 min — tx is probably already confirmed
          await this._waitForDeployTx(pendingTxHash, 180_000);
          localStorage.removeItem(CavosSDK.PENDING_DEPLOY_TX_KEY);
          this.logger.log('Pending deploy tx confirmed:', pendingTxHash);
          this.updateWalletStatus({
            isDeploying: false,
            isDeployed: true,
            pendingDeployTxHash: undefined,
          });
          await this.autoRegisterSession();
          return;
        } catch (err) {
          // Still not confirmed — leave the hash and let user check explorer
          this.logger.alwaysError('Re-poll of pending deploy tx failed:', err);
          this.updateWalletStatus({ isDeploying: false });
          return;
        }
      }

      // ── Step 1: Check current deploy status ──────────────────────────────────
      const deployed = await this.isAccountDeployed();

      if (!deployed) {
        this.logger.log('Account not deployed. Deploying...');
        this.updateWalletStatus({ isDeploying: true });
        try {
          const deployHash = await this.deployAccount();

          if (deployHash === 'already-deployed') {
            // Race: deployed between the check and now
            this.updateWalletStatus({ isDeploying: false, isDeployed: true });
            await this.autoRegisterSession();
            return;
          }

          this.logger.log('Deploy tx submitted:', deployHash);
          // Persist in case of timeout
          if (typeof localStorage !== 'undefined') {
            localStorage.setItem(CavosSDK.PENDING_DEPLOY_TX_KEY, deployHash);
          }
          this.updateWalletStatus({ pendingDeployTxHash: deployHash });

          // deployAccount() already calls waitForTransaction internally —
          // if it resolved without throwing, the tx is confirmed.
          localStorage.removeItem(CavosSDK.PENDING_DEPLOY_TX_KEY);
          this.updateWalletStatus({
            isDeploying: false,
            isDeployed: true,
            isSessionActive: false,
            isReady: false,
            pendingDeployTxHash: undefined,
          });

          // Track wallet deployment for MAU
          const address = this.getAddress();
          if (address) {
            this.analyticsManager.trackWalletDeployment(address);
          }

          await this.autoRegisterSession();
          this._deploySlotInBackground();
        } catch (err: any) {
          const msg: string = err?.message || String(err);
          if (msg.includes('timeout')) {
            // The tx was submitted but we lost the confirmation — keep the hash for next init()
            this.logger.alwaysError('Deploy confirmation timed out. Hash persisted for recovery.', err);
            this.updateWalletStatus({ isDeploying: false });
          } else {
            localStorage.removeItem(CavosSDK.PENDING_DEPLOY_TX_KEY);
            this.updateWalletStatus({ isDeploying: false, pendingDeployTxHash: undefined });
            this.logger.alwaysError('Background deployment failed:', err);
          }
        }
      } else {
      this.logger.log('Account already deployed. Checking session status...');
        const sessionActive = this.transactionManager
          ? await this.transactionManager.isSessionRegistered()
          : false;

        if (sessionActive) {
          this.updateWalletStatus({ isDeployed: true, isSessionActive: true, isReady: true });
        } else {
          this.updateWalletStatus({ isDeployed: true, isSessionActive: false, isReady: false });
          await this.autoRegisterSession();
        }
        this._deploySlotInBackground();
      }
    } catch (err) {
      this.logger.alwaysError('Background deployment check failed:', err);
    }
  }

  /** Poll a known tx hash until confirmed. Used for deploy tx recovery. */
  private async _waitForDeployTx(txHash: string, timeout: number, provider?: RpcProvider): Promise<void> {
    const rpc = provider ?? this.provider;
    const start = Date.now();
    while (Date.now() - start < timeout) {
      try {
        const receipt = await rpc.getTransactionReceipt(txHash);
        if (receipt) {
          const ok = (receipt as any).execution_status === 'SUCCEEDED' ||
            (receipt as any).finality_status === 'ACCEPTED_ON_L2' ||
            (receipt as any).finality_status === 'ACCEPTED_ON_L1';
          if (ok) return;
          if ((receipt as any).execution_status === 'REVERTED') {
            throw new Error(`Deploy tx reverted: ${(receipt as any).revert_error || 'unknown'}`);
          }
        }
      } catch (e: any) {
        if (e?.message?.includes('reverted')) throw e;
      }
      await new Promise(r => setTimeout(r, 3000));
    }
    throw new Error(`Deploy tx ${txHash} still unconfirmed after ${timeout}ms`);
  }

  /**
   * Auto-register session after deploy or when session is not active.
   * Skips gracefully if JWT is expired — execute() will surface the error to the user
   * clearly via JwtExpiredError instead of failing silently here.
   */
  private async autoRegisterSessionOnSlot(): Promise<void> {
    if (!this.slotTransactionManager) return;

    if (this.isJwtExpired()) {
      this.logger.log('[Slot] Auto-registration skipped: JWT is expired.');
      return;
    }

    const session = this.oauthWalletManager.getSession();
    const allowedContracts = session?.sessionPolicy?.allowedContracts ?? [];
    const walletAddress = session?.walletAddress
      ? num.toHex(session.walletAddress).toLowerCase()
      : null;
    const walletAllowed = walletAddress
      ? allowedContracts.some(contract => num.toHex(contract).toLowerCase() === walletAddress)
      : false;
    if (allowedContracts.length > 0 && !walletAllowed) {
      this.logger.log(
        '[Slot] Auto-registration skipped for restricted policy. ' +
        'The first executeOnSlot() call must register the session using an allowed target contract.'
      );
      return;
    }

    try {
      if (!this.slotRelayerAccount) {
        this.logger.log('[Slot] Auto-registration skipped: no relayer account available.');
        return;
      }

      this.logger.log('[Slot] Auto-registering session on Slot via outside execution...');
      const txHash = await this.slotTransactionManager.registerCurrentSessionViaOutside(
        this.slotRelayerAccount,
      );
      this.logger.log('[Slot] Session registered on Slot. TxHash:', txHash);
    } catch (err) {
      this.logger.alwaysError('[Slot] Auto session registration on Slot failed:', err);
      // Non-blocking — executeOnSlot() will surface a clear error to the user.
    }
  }

  private async autoRegisterSession(): Promise<void> {
    if (!this.transactionManager) return;

    // Don't attempt registration with an expired JWT — it will always fail on-chain.
    if (this.isJwtExpired()) {
      this.logger.log('Auto-registration skipped: JWT is expired. User must re-login.');
      this.updateWalletStatus({ isRegistering: false, isReady: false });
      return;
    }

    try {
      this.updateWalletStatus({ isRegistering: true });
      this.logger.log('Auto-registering session on-chain...');
      const txHash = await this.transactionManager.registerCurrentSession();
      this.logger.log('Session registered on-chain. TxHash:', txHash);
      // Trust the tx submission — on-chain state won't reflect immediately.
      // Mark ready now; the session key is valid from this point.
      this.updateWalletStatus({ isRegistering: false, isSessionActive: true, isReady: true });
    } catch (err) {
      this.logger.alwaysError('Auto session registration failed:', err);
      // Mark isReady: true anyway — the wallet is usable via JWT path in execute().
      // If the JWT is expired, execute() will throw JwtExpiredError clearly to the user.
      this.updateWalletStatus({ isRegistering: false, isSessionActive: false, isReady: true });
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
    this.initializeSlotTransactionManager();

    // Store in seen wallets for discovery
    this.addWalletToSeen(
      this.oauthWalletManager.getSession()?.jwtClaims?.iss,
      this.oauthWalletManager.getSession()?.jwtClaims?.sub,
      this.oauthWalletManager.getSession()?.walletName,
    );

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

  private initializeSlotTransactionManager(): void {
    if (!this.config.slot?.rpcUrl) return;
    const session = this.oauthWalletManager.getSession();
    if (!session || !session.walletAddress) return;

    this.slotTransactionManager = new OAuthTransactionManager(
      this.config.oauthWallet as OAuthWalletConfig,
      this.oauthWalletManager,
      this.config.slot.rpcUrl,
      '', // no paymaster on Slot (no_fee = true)
      this.config.network || 'sepolia',
      undefined, // no custom paymaster URL
      this.config.slot.chainId, // optional chain ID override
    );
  }

  private _deploySlotInBackground(): void {
    if (!this.config.slot?.rpcUrl || this._deployingSlotInBackground) return;
    this._deployingSlotInBackground = true;
    this._runSlotDeployBackground().finally(() => {
      this._deployingSlotInBackground = false;
    });
  }

  private async _runSlotDeployBackground(): Promise<void> {
    try {
      const address = this.getAddress();
      if (!address) return;

      // Re-poll a previous Slot deploy tx that timed out
      const pendingTxHash = typeof localStorage !== 'undefined'
        ? localStorage.getItem(CavosSDK.PENDING_SLOT_DEPLOY_TX_KEY)
        : null;

      if (pendingTxHash) {
        this.logger.log('[Slot] Found pending deploy tx, re-polling:', pendingTxHash);
        this.updateWalletStatus({ isSlotDeploying: true, pendingSlotDeployTxHash: pendingTxHash });
        try {
          await this._waitForDeployTx(pendingTxHash, 180_000, this.slotProvider!);
          localStorage.removeItem(CavosSDK.PENDING_SLOT_DEPLOY_TX_KEY);
          this.updateWalletStatus({ isSlotDeploying: false, isSlotDeployed: true, pendingSlotDeployTxHash: undefined });
          const slotSessionActiveAfterPoll = this.slotTransactionManager
            ? await this.slotTransactionManager.isSessionRegistered()
            : false;
          if (!slotSessionActiveAfterPoll) {
            await this.autoRegisterSessionOnSlot();
          }
          return;
        } catch {
          this.updateWalletStatus({ isSlotDeploying: false });
          return;
        }
      }

      // Check if already deployed on Slot
      let isDeployedOnSlot = false;
      try {
        const classHash = await this.slotProvider!.getClassHashAt(address);
        isDeployedOnSlot = !!classHash;
      } catch {
        isDeployedOnSlot = false;
      }

      if (isDeployedOnSlot) {
        this.logger.log('[Slot] Wallet already deployed on Slot.');
        this.updateWalletStatus({ isSlotDeployed: true });
        // Mirror normal wallet: check session status before registering.
        const slotSessionActive = this.slotTransactionManager
          ? await this.slotTransactionManager.isSessionRegistered()
          : false;
        if (!slotSessionActive) {
          await this.autoRegisterSessionOnSlot();
        } else {
          this.logger.log('[Slot] Session already registered on Slot.');
        }
        return;
      }

      this.logger.log('[Slot] Wallet not deployed on Slot. Deploying...');
      this.updateWalletStatus({ isSlotDeploying: true });

      if (!this.slotTransactionManager) {
        this.initializeSlotTransactionManager();
      }
      if (!this.slotTransactionManager) return;

      try {
        const deployHash = await this.slotTransactionManager.deployAccountDirect();

        if (deployHash === 'already-deployed') {
          this.updateWalletStatus({ isSlotDeploying: false, isSlotDeployed: true });
          await this.autoRegisterSessionOnSlot();
          return;
        }

        this.logger.log('[Slot] Deploy tx submitted:', deployHash);
        if (typeof localStorage !== 'undefined') {
          localStorage.setItem(CavosSDK.PENDING_SLOT_DEPLOY_TX_KEY, deployHash);
        }
        this.updateWalletStatus({ pendingSlotDeployTxHash: deployHash });

        localStorage.removeItem(CavosSDK.PENDING_SLOT_DEPLOY_TX_KEY);
        this.updateWalletStatus({ isSlotDeploying: false, isSlotDeployed: true, pendingSlotDeployTxHash: undefined });
        this.logger.log('[Slot] Wallet deployed on Slot.');
        await this.autoRegisterSessionOnSlot();
      } catch (err: any) {
        const msg: string = err?.message || String(err);
        if (msg.includes('timeout')) {
          this.logger.alwaysError('[Slot] Deploy confirmation timed out. Hash persisted for recovery.', err);
        } else {
          typeof localStorage !== 'undefined' && localStorage.removeItem(CavosSDK.PENDING_SLOT_DEPLOY_TX_KEY);
          this.logger.alwaysError('[Slot] Background deployment failed:', err);
        }
        this.updateWalletStatus({ isSlotDeploying: false });
      }
    } catch (err) {
      this.logger.alwaysError('[Slot] Background deployment check failed:', err);
      this.updateWalletStatus({ isSlotDeploying: false });
    }
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
  async execute(calls: Call | Call[], options?: { gasless?: boolean }): Promise<string> {
    if (!this.transactionManager) {
      throw new Error('Wallet not initialized. Please login first.');
    }

    // Before attempting a JWT-path tx, surface a clear error if JWT is expired.
    const status = await this.transactionManager.getSessionStatus();
    if (!status.registered && this.isJwtExpired()) {
      throw new JwtExpiredError();
    }

    // The transactionManager.execute() will automatically detect if session is registered
    // and use the appropriate signature type (JWT for first tx, session for subsequent)
    const txHash = await this.transactionManager.execute(calls, options);

    // Track transaction for MAU
    const address = this.getAddress();
    if (address) {
      this.analyticsManager.trackTransaction(address);
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
   * Get the public key of the current session key (safe to display).
   * Returns null if not authenticated.
   */
  getSessionPublicKey(): string | null {
    return this.oauthWalletManager.getSession()?.sessionPubKey ?? null;
  }

  /**
   * Get all wallet addresses associated with the current user.
   * Scans for SessionRegistered events and checks ownership.
   */
  async getAssociatedWallets(): Promise<{ address: string; name?: string }[]> {
    const session = this.oauthWalletManager.getSession();
    if (!session?.jwtClaims?.sub) return [];

    const issuer = session.jwtClaims.iss;
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
      const seenNamesKey = this.getSeenWalletsStorageKey(issuer, sub);
      if (!seenNamesKey) {
        return wallets;
      }
      const seenNames = isBrowser ? JSON.parse(localStorage.getItem(seenNamesKey) || '[]') : [];

      for (const name of seenNames) {
        const addr = this.oauthWalletManager.getAddressSeedManager().computeContractAddress(
          issuer,
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
    if (session?.jwtClaims?.iss && session.jwtClaims.sub) {
      this.addWalletToSeen(session.jwtClaims.iss, session.jwtClaims.sub, name);
    }

    // Check deployment in background for the newly selected wallet
    this.initializeSlotTransactionManager();
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
      const classHash = await this.provider.getClassHashAt(address);
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
    this.slotTransactionManager = null;
    // Reset wallet status
    this._walletStatus = {
      isDeploying: false,
      isDeployed: false,
      isRegistering: false,
      isSessionActive: false,
      isReady: false,
      isSlotDeploying: false,
      isSlotDeployed: false,
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
   * Subscribe to auth state changes (e.g. when magic link polling completes)
   */
  onAuthChange(cb: () => void): () => void {
    this._authChangeListeners.add(cb);
    return () => this._authChangeListeners.delete(cb);
  }

  /**
   * Send a magic link email and start polling localStorage for the verify result.
   * Returns immediately after the email is sent. Auth completes in the background
   * when the user clicks the link — onAuthChange listeners are notified.
   */
  async sendMagicLink(email: string): Promise<void> {
    if (!this.appSalt) {
      await this.validateAccess();
    }
    await this.oauthWalletManager.sendMagicLink(email);
    // Fire-and-forget poll — resolves when user clicks the magic link
    this._pollMagicLinkResult();
  }

  private _pollMagicLinkResult(): void {
    if (typeof window === 'undefined') return;
    localStorage.removeItem('cavos_auth_result');

    let done = false;
    const cleanup = () => {
      done = true;
      clearTimeout(timeout);
      clearInterval(interval);
      window.removeEventListener('storage', onStorage);
    };

    const complete = (raw: string) => {
      if (done) return;
      cleanup();
      this._completeMagicLinkAuth(raw);
    };

    const timeout = setTimeout(() => cleanup(), 600_000); // 10 min

    const interval = setInterval(() => {
      const r = localStorage.getItem('cavos_auth_result');
      if (r) complete(r);
    }, 500);

    const onStorage = (e: StorageEvent) => {
      if (e.key === 'cavos_auth_result' && e.newValue) complete(e.newValue);
    };
    window.addEventListener('storage', onStorage);
  }

  private async _completeMagicLinkAuth(authData: string): Promise<void> {
    try {
      localStorage.removeItem('cavos_auth_result');
      if (!this.appSalt) await this.validateAccess();
      await this.handleCallback(authData);
      this._authChangeListeners.forEach(cb => cb());
    } catch (e) {
      this.logger.alwaysError('[MagicLink] Failed to complete auth:', e);
    }
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
      id: `${session.jwtClaims.iss}:${session.jwtClaims.sub}`,
      email: session.jwtClaims.email ?? '',
      name: session.jwtClaims.name ?? '',
      picture: session.jwtClaims.picture ?? '',
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
  async signMessage(typedDataInput: TypedData): Promise<string[]> {
    // Returns [SESSION_V1_magic, r, s, session_key] — ready for on-chain is_valid_signature
    return this.oauthWalletManager.signMessage(typedDataInput);
  }

  /**
   * Helper to persist a wallet name for discovery
   */
  private addWalletToSeen(
    issuer: string | undefined,
    sub: string | undefined,
    name: string | undefined,
  ): void {
    const seenNamesKey = this.getSeenWalletsStorageKey(issuer, sub);
    if (!seenNamesKey || !name || typeof window === 'undefined') return;
    const seenNames = JSON.parse(localStorage.getItem(seenNamesKey) || '[]');
    if (!seenNames.includes(name)) {
      seenNames.push(name);
      localStorage.setItem(seenNamesKey, JSON.stringify(seenNames));
    }
  }

  private getSeenWalletsStorageKey(
    issuer: string | undefined,
    sub: string | undefined,
  ): string | null {
    if (!issuer || !sub) return null;
    return `cavos_seen_wallets_${this.config.appId}_${issuer}:${sub}`;
  }

  /**
   * Execute calls on the Slot chain.
   * Uses execute_from_outside_v2 for first-time session registration, then
   * switches to direct no-fee account execution once the session is active.
   */
  async executeOnSlot(calls: Call | Call[]): Promise<string> {
    if (!this.slotTransactionManager) {
      throw new Error('Slot not configured. Pass slot.rpcUrl in CavosConfig.');
    }
    if (!this._walletStatus.isSlotDeployed) {
      throw new Error('Wallet not deployed on Slot yet. Wait for walletStatus.isSlotDeployed.');
    }

    const callsArray = Array.isArray(calls) ? calls : [calls];
    const status = await this.slotTransactionManager.getSessionStatus();

    if (!status.registered) {
      if (!this.slotRelayerAccount) {
        throw new Error('Slot session is not registered yet and no relayer is available.');
      }
      return this.slotTransactionManager.executeViaOutsideExecution(
        callsArray,
        this.slotRelayerAccount,
      );
    }

    return this.slotTransactionManager.executeOnNoFeeChain(callsArray);
  }

  /**
   * Returns the RpcProvider for the Slot chain.
   * Use for read-only queries (callContract, getEvents) or Dojo SDK integration.
   * Returns null if slot.rpcUrl was not configured.
   */
  getSlotProvider(): RpcProvider | null {
    return this.slotProvider;
  }
}
