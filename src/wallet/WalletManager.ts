import { Account, CallData, ec, hash, RpcProvider, CairoOption, CairoCustomEnum } from 'starknet';
import { UserInfo, DecryptedWallet } from '../types';
import { WebAuthnManager } from '../security/WebAuthnManager';
import { AnalyticsManager } from '../analytics/AnalyticsManager';
import { AuthManager } from '../auth/AuthManager';
import axios from 'axios';

export class WalletManager {
  private provider: RpcProvider;
  private account: Account | null = null;
  private analyticsManager: AnalyticsManager | null = null;
  private authManager: AuthManager;
  private webAuthnManager: WebAuthnManager;
  private appId: string;
  private network: string;

  private currentWallet: DecryptedWallet | null = null;
  private currentAccount: Account | null = null;
  private userEmail: string | null = null;

  // ArgentX account class hash (v0.3.0)
  private static readonly ARGENT_ACCOUNT_CLASS_HASH = '0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f';
  // ArgentX account class hash for passkey signers (no guardian)
  private static readonly ARGENT_ACCOUNT_CLASS_HASH_PASSKEY = '0x01a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003';

  // Session storage key for caching decrypted wallet
  private static readonly SESSION_WALLET_KEY = 'cavos_wallet_session';
  // Local storage key for passkey wallet metadata
  private static readonly PASSKEY_WALLET_KEY = 'cavos_passkey_wallet';

  constructor(
    authManager: AuthManager,
    starknetRpcUrl: string,
    network: string,
    analyticsManager?: AnalyticsManager
  ) {
    this.authManager = authManager;
    this.appId = authManager.getAppId();
    this.network = network;
    this.webAuthnManager = new WebAuthnManager();

    // Use Alchemy v0_10 RPC - configure to use 'latest' block instead of 'pending'
    this.provider = new RpcProvider({
      nodeUrl: starknetRpcUrl,
      default: 'latest' as any, // v0_10 doesn't support 'pending' block
    });

    if (analyticsManager) {
      this.analyticsManager = analyticsManager;
    }
  }

  /**
   * Create a new wallet with WebAuthn encryption
   */
  async createWallet(user: UserInfo): Promise<Account> {
    this.userEmail = user.email;

    // 1. Generate new keypair
    const privateKey = ec.starkCurve.utils.randomPrivateKey();
    const publicKey = ec.starkCurve.getStarkKey(privateKey);

    // 2. Compute wallet address
    const address = await this.computeWalletAddress(publicKey);

    const privateKeyHex = '0x' + Buffer.from(privateKey).toString('hex');
    const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

    // 3. Register Passkey and derive encryption key
    // We use a random challenge for the registration. In a stricter setup, this comes from server.
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));

    const { encryptionKey } = await this.webAuthnManager.register(user.email, challenge);

    // 4. Encrypt private key

    const { ciphertext, iv } = await this.webAuthnManager.encrypt(encryptionKey, privateKeyHex);

    // Combine IV and Ciphertext for storage (e.g., "iv:ciphertext")
    const encryptedBlob = `${iv}:${ciphertext}`;

    // 5. Save to Backend API

    await this.saveWalletToApi(address, encryptedBlob);

    // 6. Create account instance
    this.currentWallet = {
      address,
      publicKey: publicKeyHex,
      privateKey: privateKeyHex,
    };

    // Save to session cache
    this.saveWalletToSession(this.currentWallet);

    this.currentAccount = new Account(this.provider, address, privateKeyHex);

    // Track MAU
    await this.trackUsage(address);

    return this.currentAccount;
  }

  /**
   * Save decrypted wallet to session storage
   */
  private saveWalletToSession(wallet: DecryptedWallet): void {
    try {
      const walletData = JSON.stringify(wallet);
      sessionStorage.setItem(WalletManager.SESSION_WALLET_KEY, walletData);

    } catch (error) {
      console.warn('[WalletManager] Failed to cache wallet:', error);
    }
  }

  /**
   * Load decrypted wallet from session storage
   */
  private loadWalletFromSession(): DecryptedWallet | null {
    try {
      const walletData = sessionStorage.getItem(WalletManager.SESSION_WALLET_KEY);
      if (!walletData) return null;

      const wallet = JSON.parse(walletData) as DecryptedWallet;

      return wallet;
    } catch (error) {
      console.warn('[WalletManager] Failed to load wallet from session:', error);
      return null;
    }
  }

  /**
   * Clear wallet from session storage
   */
  clearWalletSession(): void {
    sessionStorage.removeItem(WalletManager.SESSION_WALLET_KEY);

  }

  /**
   * Load existing wallet using WebAuthn decryption
   */
  async loadWallet(user: UserInfo): Promise<Account> {
    this.userEmail = user.email;

    // Check session cache first
    const cachedWallet = this.loadWalletFromSession();
    if (cachedWallet) {
      this.currentWallet = cachedWallet;
      this.currentAccount = new Account(this.provider, cachedWallet.address, cachedWallet.privateKey);

      // Track MAU even for session restore
      await this.trackUsage(cachedWallet.address);

      return this.currentAccount;
    }

    // 1. Fetch encrypted blob from Backend API

    const walletData = await this.fetchWalletFromApi();

    if (!walletData) {
      throw new Error('No wallet found');
    }

    const { encrypted_pk_blob, address } = walletData;
    const [iv, ciphertext] = encrypted_pk_blob.split(':');

    if (!iv || !ciphertext) {
      throw new Error('Invalid encrypted blob format');
    }

    // 2. Authenticate Passkey and derive encryption key
    // Challenge should ideally match what was used or be server provided, 
    // but for PRF with static salt (in manager), any challenge works for authentication 
    // as long as the RP ID is the same.
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));

    const { encryptionKey } = await this.webAuthnManager.authenticate(challenge);

    // 3. Decrypt private key

    const privateKey = await this.webAuthnManager.decrypt(encryptionKey, ciphertext, iv);

    // 4. Derive public key and verify address (optional sanity check)
    const privateKeyBytes = Buffer.from(privateKey.replace('0x', ''), 'hex');
    const publicKey = ec.starkCurve.getStarkKey(privateKeyBytes);
    const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

    this.currentWallet = {
      address,
      publicKey: publicKeyHex,
      privateKey,
    };

    // Save to session cache
    this.saveWalletToSession(this.currentWallet);

    this.currentAccount = new Account(this.provider, address, privateKey);

    // Track MAU
    await this.trackUsage(address);

    return this.currentAccount;
  }

  /**
   * Get or create wallet
   */
  async getOrCreateWallet(user: UserInfo): Promise<Account> {
    try {
      // Try to load existing wallet
      return await this.loadWallet(user);
    } catch (error: any) {

      // If load fails (e.g. no wallet found or user cancelled WebAuthn), try create
      // Note: If user cancelled WebAuthn during load, they might cancel during create too.
      // But we assume "No wallet found" is the main reason to create.
      if (error.message === 'No wallet found') {
        return await this.createWallet(user);
      }
      throw error;
    }
  }

  /**
   * Save wallet to API
   */
  private async saveWalletToApi(address: string, encryptedBlob: string): Promise<void> {
    const token = this.authManager.getAccessToken();
    if (!token) throw new Error('Not authenticated');

    const user = this.authManager.getUserInfo();
    if (!user) throw new Error('User info not available');

    const backendUrl = (this.authManager as any).backendUrl || 'https://cavos.xyz';

    await axios.post(`${backendUrl}/api/wallets`, {
      address,
      network: this.network,
      encrypted_pk_blob: encryptedBlob,
      app_id: this.appId,
      user_social_id: user.id,
      email: user.email
    });
  }

  /**
   * Fetch wallet from API
   */
  private async fetchWalletFromApi(): Promise<{ encrypted_pk_blob: string, address: string } | null> {
    const token = this.authManager.getAccessToken();
    if (!token) throw new Error('Not authenticated');

    const user = this.authManager.getUserInfo();
    if (!user) throw new Error('User info not available');

    const backendUrl = (this.authManager as any).backendUrl || 'https://cavos.xyz';

    try {
      const params = new URLSearchParams({
        app_id: this.appId,
        user_social_id: user.id,
        network: this.network
      });

      const response = await axios.get(`${backendUrl}/api/wallets?${params.toString()}`);

      if (response.data.found) {
        return {
          encrypted_pk_blob: response.data.encrypted_pk_blob,
          address: response.data.address
        };
      }
      return null;
    } catch (error) {
      console.error('[WalletManager] Failed to fetch wallet:', error);
      return null;
    }
  }

  /**
   * Delete wallet (Not implemented in new flow yet, or via API)
   */
  async deleteWallet(): Promise<void> {
    // TODO: Implement API endpoint for deletion if needed
    this.currentWallet = null;
    this.currentAccount = null;
  }

  /**
   * Get current account
   */
  getAccount(): Account | null {
    return this.currentAccount;
  }

  /**
   * Sign a message with the wallet
   * @param message - The message to sign (string, typed data object, or array of field elements)
   * @returns Signature object with r and s values
   */
  async signMessage(message: string | object | string[]): Promise<{ r: string; s: string }> {
    if (!this.currentAccount) {
      throw new Error('No account available. Please login first.');
    }

    try {
      let typedData: any;

      if (typeof message === 'string') {
        // For long messages, we need to hash them first since Starknet types have length limits
        // shortstring max is 31 chars, felt is even shorter
        const messageToSign = message.length > 31
          ? hash.computeHashOnElements([BigInt('0x' + Buffer.from(message).toString('hex'))])
          : message;

        // Create a simple typed data structure for string messages
        typedData = {
          types: {
            StarkNetDomain: [
              { name: 'name', type: 'shortstring' },
              { name: 'version', type: 'shortstring' },
            ],
            Message: [
              { name: 'content', type: message.length > 31 ? 'felt' : 'shortstring' },
            ],
          },
          primaryType: 'Message',
          domain: {
            name: 'Cavos',
            version: '1',
          },
          message: {
            content: messageToSign,
          },
        };
      } else if (typeof message === 'object' && !Array.isArray(message)) {
        // If it's an object, assume it's already a typed data structure
        typedData = message;
      } else {
        // If it's an array, use it directly
        typedData = message;
      }

      const signature = await this.currentAccount.signMessage(typedData);

      // Return signature in original Starknet format
      // Signature object has r and s properties (BigInt values)
      return {
        r: (signature as any).r,
        s: (signature as any).s,
      };
    } catch (error) {
      console.error('[WalletManager] Error signing message:', error);
      throw error;
    }
  }

  /**
   * Get current wallet address
   */
  getAddress(): string | null {
    return this.currentWallet?.address || null;
  }

  /**
   * Check if wallet exists (via API check)
   */
  async hasWallet(): Promise<boolean> {
    const wallet = await this.fetchWalletFromApi();
    return wallet !== null;
  }

  /**
   * Compute wallet address using ArgentX pattern (AVNU-compatible)
   */
  private async computeWalletAddress(publicKey: string): Promise<string> {
    const starkKeyPub = publicKey;
    const signer = new CairoCustomEnum({ Starknet: { pubkey: starkKeyPub } });
    const guardian = new CairoOption(1);
    const constructorCallData = CallData.compile({ owner: signer, guardian: guardian });

    return hash.calculateContractAddressFromHash(
      WalletManager.ARGENT_ACCOUNT_CLASS_HASH,
      WalletManager.ARGENT_ACCOUNT_CLASS_HASH,
      constructorCallData,
      0
    );
  }

  /**
   * Get deployment data for ArgentX account
   */
  getDeploymentData(): any {
    if (!this.currentWallet) throw new Error('No wallet initialized');

    const privateKey = this.currentWallet.privateKey;
    const starkKeyPub = ec.starkCurve.getStarkKey(privateKey);
    const signer = new CairoCustomEnum({ Starknet: { pubkey: starkKeyPub } });
    const guardian = new CairoOption(1);
    const constructorCallData = CallData.compile({ owner: signer, guardian: guardian });

    return {
      class_hash: WalletManager.ARGENT_ACCOUNT_CLASS_HASH,
      salt: WalletManager.ARGENT_ACCOUNT_CLASS_HASH,
      unique: "0x0",
      calldata: constructorCallData.map((x) => `0x${BigInt(x).toString(16)}`),
    };
  }

  /**
   * Check if account is deployed on-chain
   */
  async isDeployed(): Promise<boolean> {
    if (!this.currentWallet) return false;
    try {
      // Use 'latest' block for v0_10 RPC compatibility
      const classHash = await this.provider.getClassHashAt(this.currentWallet.address, 'latest');
      const deployed = classHash !== '0x0' && classHash !== '0x' && classHash !== '';
      return deployed;
    } catch (error: any) {
      // If we can't get the class hash, assume not deployed
      return false;
    }
  }

  /**
   * Deploy ArgentX account using AVNU Paymaster
   */
  async deployAccountWithPaymaster(apiKey: string, network: 'mainnet' | 'sepolia' = 'sepolia'): Promise<string> {
    if (!this.currentWallet) throw new Error('No wallet initialized');
    if (await this.isDeployed()) {

      return this.currentWallet.address;
    }

    const userAddress = this.currentWallet.address;
    const deploymentData = this.getDeploymentData();

    try {

      const baseUrl = network === 'sepolia' ? 'https://sepolia.api.avnu.fi' : 'https://starknet.api.avnu.fi';

      // Step 1: Build typed data
      const typeDataResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'api-key': apiKey },
        body: JSON.stringify({
          userAddress: userAddress,
          accountClassHash: WalletManager.ARGENT_ACCOUNT_CLASS_HASH,
          deploymentData: deploymentData,
          calls: [],
        }),
      });

      if (!typeDataResponse.ok) throw new Error(await typeDataResponse.text());


      // Step 2: Deploy account
      const deployResponse = await fetch(`${baseUrl}/paymaster/v1/deploy-account`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'api-key': apiKey },
        body: JSON.stringify({ userAddress, deploymentData }),
      });

      if (!deployResponse.ok) throw new Error(await deployResponse.text());
      const deployResult = await deployResponse.json();


      if (deployResult.transactionHash) {
        await this.provider.waitForTransaction(deployResult.transactionHash);
        if (this.analyticsManager) {
          await this.analyticsManager.trackWalletDeployment(this.currentWallet.address, this.userEmail || undefined);
        }
      }

      return deployResult.transactionHash;
    } catch (error: any) {

      // Check if error is because contract is already deployed or tx already sent
      const errorMessage = error.message || error.toString();
      if (errorMessage.includes('already deployed') ||
        errorMessage.includes('CONTRACT_ADDRESS_UNAVAILABLE') ||
        errorMessage.includes('Tx already sent')) {
        return this.currentWallet.address;
      }

      throw new Error(`Failed to deploy account: ${error.message || error}`);
    }
  }

  /**
   * Get account balance (ETH)
   */
  async getBalance(): Promise<string> {
    if (!this.currentWallet) return '0';
    try {
      const ethAddress = '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7';
      const result = await this.provider.callContract({
        contractAddress: ethAddress,
        entrypoint: 'balanceOf',
        calldata: CallData.compile({ account: this.currentWallet.address }),
      });
      return Array.isArray(result) ? result[0] : '0';
    } catch (error) {
      return '0';
    }
  }

  getFundingAddress(): string | null {
    return this.currentWallet?.address || null;
  }

  getWalletInfo(): DecryptedWallet | null {
    return this.currentWallet;
  }

  /**
   * Track MAU usage
   */
  private async trackUsage(walletAddress: string): Promise<void> {
    try {
      const backendUrl = (this.authManager as any).backendUrl || 'https://cavos.xyz';

      await axios.post(`${backendUrl}/api/usage/track`, {
        app_id: this.appId,
        wallet_address: walletAddress,
        network: this.network
      });
    } catch (error) {
      // Silent fail - don't block user flow for metrics
    }
  }

  // ============================================
  // PASSKEY-ONLY WALLET METHODS
  // ============================================

  /**
   * Create a wallet using ONLY a passkey (WebAuthn)
   * No OAuth login required. Wallet is stored locally.
   */
  async createPasskeyOnlyWallet(paymasterApiKey: string): Promise<void> {
    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));

    // 1. Register passkey with anonymous ID
    const { encryptionKey, credentialId } = await this.webAuthnManager.register(userId, challenge);

    // 2. Generate wallet keypair
    const privateKey = ec.starkCurve.utils.randomPrivateKey();
    const privateKeyHex = '0x' + Buffer.from(privateKey).toString('hex');
    const publicKey = ec.starkCurve.getStarkKey(privateKey);
    const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

    // 3. Compute wallet address
    const address = await this.computePasskeyWalletAddress(publicKeyHex);

    // 4. Encrypt private key
    const { ciphertext, iv } = await this.webAuthnManager.encrypt(encryptionKey, privateKeyHex);

    // 5. Store locally using localStorage (persistent)
    localStorage.setItem(
      WalletManager.PASSKEY_WALLET_KEY,
      JSON.stringify({
        credentialId,
        address,
        publicKey: publicKeyHex,
        encryptedBlob: `${iv}:${ciphertext}`,
      })
    );

    // 6. Set wallet state
    this.currentWallet = {
      address,
      publicKey: publicKeyHex,
      privateKey: privateKeyHex,
    };
    this.currentAccount = new Account(this.provider, address, privateKeyHex);

    // 7. Auto-deploy wallet
    await this.deployPasskeyWallet(paymasterApiKey);

    // 8. Save wallet to backend (for recovery with passkey)
    await this.savePasskeyWalletToBackend(credentialId, address, `${iv}:${ciphertext}`);

    // 9. Track usage
    await this.trackUsage(address);
  }

  /**
   * Load an existing passkey-only wallet from local storage
   */
  async loadPasskeyOnlyWallet(): Promise<void> {
    const dataStr = localStorage.getItem(WalletManager.PASSKEY_WALLET_KEY);
    if (!dataStr) {
      throw new Error('No passkey wallet found');
    }

    const data = JSON.parse(dataStr);

    // Authenticate with passkey
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const { encryptionKey } = await this.webAuthnManager.authenticate(challenge);

    // Decrypt private key
    const [iv, ciphertext] = data.encryptedBlob.split(':');
    const privateKeyHex = await this.webAuthnManager.decrypt(encryptionKey, ciphertext, iv);

    // Set wallet state
    this.currentWallet = {
      address: data.address,
      publicKey: data.publicKey,
      privateKey: privateKeyHex,
    };
    this.currentAccount = new Account(this.provider, data.address, privateKeyHex);
  }

  /**
   * Recover wallet from backend using an existing passkey
   */
  async recoverWalletWithPasskey(): Promise<void> {
    // 1. Authenticate with passkey
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const { encryptionKey, credentialId } = await this.webAuthnManager.authenticate(challenge);

    // 2. Try to fetch wallet from backend using credentialId
    const backendWallet = await this.fetchPasskeyWalletFromBackend(credentialId);

    if (!backendWallet) {
      throw new Error('No wallet found in backend for this passkey.');
    }

    // 3. Decrypt private key
    const [iv, ciphertext] = backendWallet.encryptedBlob.split(':');
    const privateKeyHex = await this.webAuthnManager.decrypt(encryptionKey, ciphertext, iv);

    // 4. Derive public key
    const privateKeyBytes = Buffer.from(privateKeyHex.replace('0x', ''), 'hex');
    const publicKey = ec.starkCurve.getStarkKey(privateKeyBytes);
    const publicKeyHex = publicKey.startsWith('0x') ? publicKey : '0x' + publicKey;

    // 5. Save to local storage for future use
    localStorage.setItem(
      WalletManager.PASSKEY_WALLET_KEY,
      JSON.stringify({
        credentialId,
        address: backendWallet.address,
        publicKey: publicKeyHex,
        encryptedBlob: backendWallet.encryptedBlob,
      })
    );

    // 6. Set wallet state
    this.currentWallet = {
      address: backendWallet.address,
      publicKey: publicKeyHex,
      privateKey: privateKeyHex,
    };
    this.currentAccount = new Account(this.provider, backendWallet.address, privateKeyHex);
  }

  /**
   * Check if a passkey-only wallet exists locally
   */
  async hasPasskeyOnlyWallet(): Promise<boolean> {
    return !!localStorage.getItem(WalletManager.PASSKEY_WALLET_KEY);
  }

  /**
   * Compute wallet address for passkey-only wallet
   */
  private async computePasskeyWalletAddress(publicKey: string): Promise<string> {
    const constructorCallData = CallData.compile({
      owner: publicKey,
      guardian: '0x0',
    });

    return hash.calculateContractAddressFromHash(
      publicKey,  // salt is publicKey
      WalletManager.ARGENT_ACCOUNT_CLASS_HASH_PASSKEY,
      constructorCallData,
      0
    );
  }

  /**
   * Deploy passkey-only wallet via AVNU Paymaster
   */
  private async deployPasskeyWallet(paymasterApiKey: string): Promise<string> {
    if (!this.currentWallet) throw new Error('No passkey wallet');

    const starkKeyPub = this.currentWallet.publicKey;
    const constructorCallData = CallData.compile({
      owner: starkKeyPub,
      guardian: '0x0',
    });

    const deploymentData = {
      class_hash: WalletManager.ARGENT_ACCOUNT_CLASS_HASH_PASSKEY,
      salt: starkKeyPub,
      unique: '0x0',
      calldata: constructorCallData.map((x) => `0x${BigInt(x).toString(16)}`),
    };

    const baseUrl = this.network === 'sepolia'
      ? 'https://sepolia.api.avnu.fi'
      : 'https://starknet.api.avnu.fi';

    try {
      await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'api-key': paymasterApiKey },
        body: JSON.stringify({
          userAddress: this.currentWallet.address,
          accountClassHash: WalletManager.ARGENT_ACCOUNT_CLASS_HASH_PASSKEY,
          deploymentData: deploymentData,
          calls: [],
        }),
      });

      const deployResponse = await fetch(`${baseUrl}/paymaster/v1/deploy-account`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'api-key': paymasterApiKey },
        body: JSON.stringify({
          userAddress: this.currentWallet.address,
          deploymentData,
        }),
      });

      if (!deployResponse.ok) throw new Error(await deployResponse.text());
      const deployResult = await deployResponse.json();

      if (deployResult.transactionHash) {
        await this.provider.waitForTransaction(deployResult.transactionHash);
      }

      return deployResult.transactionHash;
    } catch (error: any) {
      const errorMessage = error.message || error.toString();
      if (errorMessage.includes('already deployed') || errorMessage.includes('CONTRACT_ADDRESS_UNAVAILABLE')) {
        return this.currentWallet.address;
      }
      throw error;
    }
  }

  /**
   * Save passkey wallet to backend for recovery
   */
  private async savePasskeyWalletToBackend(
    credentialId: string,
    address: string,
    encryptedBlob: string
  ): Promise<void> {
    const backendUrl = (this.authManager as any).backendUrl || 'https://cavos.xyz';
    try {
      await axios.post(`${backendUrl}/api/wallets`, {
        app_id: this.appId,
        user_social_id: `passkey:${credentialId}`,
        network: this.network,
        address,
        encrypted_pk_blob: encryptedBlob,
      });
    } catch (error) {
      console.warn('[WalletManager] Failed to save passkey wallet to backend:', error);
    }
  }

  /**
   * Fetch passkey wallet from backend for recovery
   */
  private async fetchPasskeyWalletFromBackend(
    credentialId: string
  ): Promise<{ address: string; encryptedBlob: string } | null> {
    const backendUrl = (this.authManager as any).backendUrl || 'https://cavos.xyz';
    try {
      const params = new URLSearchParams({
        app_id: this.appId,
        user_social_id: `passkey:${credentialId}`,
        network: this.network,
      });

      const response = await axios.get(`${backendUrl}/api/wallets?${params.toString()}`);

      if (response.data.found) {
        return {
          address: response.data.address,
          encryptedBlob: response.data.encrypted_pk_blob,
        };
      }
      return null;
    } catch (error) {
      console.warn('[WalletManager] Failed to fetch passkey wallet from backend:', error);
      return null;
    }
  }
  /**
   * Clear passkey-only wallet from local storage
   */
  async clearPasskeyOnlyWallet(): Promise<void> {
    localStorage.removeItem(WalletManager.PASSKEY_WALLET_KEY);
    this.currentWallet = null;
    this.currentAccount = null;
  }
}
