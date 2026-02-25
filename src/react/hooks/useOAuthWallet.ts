/**
 * useOAuthWallet - React hook for OAuth Wallet authentication
 *
 * Provides a simple interface to the OAuthWalletManager and OAuthTransactionManager
 * for on-chain JWT verification without ZK proofs.
 */

import { useState, useCallback, useEffect } from 'react';
import { Call } from 'starknet';
import { OAuthWalletManager, OAuthSession } from '../../oauth/OAuthWalletManager';
import { OAuthTransactionManager } from '../../oauth/OAuthTransactionManager';
import { OAuthWalletConfig } from '../../types/config';

export type { Call } from 'starknet';
import { CavosSDK } from '../../CavosSDK';

export interface UseOAuthWalletConfig {
  config: OAuthWalletConfig;
  backendUrl: string;
  appId: string;
  rpcUrl: string;
  network?: 'mainnet' | 'sepolia';
  paymasterUrl?: string;
  apiKey?: string;
}

export type OAuthWalletStage =
  | 'idle'
  | 'initializing'
  | 'oauth'
  | 'processing'
  | 'deploying'
  | 'ready'
  | 'error';

export interface UseOAuthWalletReturn {
  /** Current stage of authentication */
  stage: OAuthWalletStage;
  /** Wallet address (once authenticated) */
  address: string | null;
  /** User email from JWT (if available) */
  email: string | null;
  /** Whether account is deployed */
  isDeployed: boolean;
  /** Initialize OAuth flow and get redirect URL */
  initializeAndGetOAuthUrl: (provider: 'google' | 'apple', redirectUri?: string) => Promise<string>;
  /** Handle OAuth callback (call after redirect) */
  handleCallback: (authData: string) => Promise<void>;
  /** Execute transaction(s) */
  execute: (calls: Call | Call[]) => Promise<string>;
  /** Deploy account if not deployed */
  deployAccount: () => Promise<string>;
  /** Log out and clear session */
  logout: () => void;
  /** Whether an operation is loading */
  isLoading: boolean;
  /** Current error message */
  error: string | null;
  /** Full session data (for advanced usage) */
  session: OAuthSession | null;
}

export function useOAuthWallet(hookConfig: UseOAuthWalletConfig): UseOAuthWalletReturn {
  const [manager, setManager] = useState<OAuthWalletManager | null>(null);
  const [txManager, setTxManager] = useState<OAuthTransactionManager | null>(null);
  const [stage, setStage] = useState<OAuthWalletStage>('idle');
  const [address, setAddress] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [isDeployed, setIsDeployed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState<OAuthSession | null>(null);

  // Initialize managers on mount
  useEffect(() => {
    const walletManager = new OAuthWalletManager(
      hookConfig.config,
      hookConfig.backendUrl,
      hookConfig.appId,
      hookConfig.rpcUrl
    );

    const transactionManager = new OAuthTransactionManager(
      hookConfig.config,
      walletManager,
      hookConfig.rpcUrl,
      hookConfig.apiKey || '',
      hookConfig.network || 'sepolia',
      hookConfig.paymasterUrl
    );

    setManager(walletManager);
    setTxManager(transactionManager);

    // Try to restore existing session
    if (walletManager.restoreSession()) {
      const restoredSession = walletManager.getSession();
      if (restoredSession?.walletAddress) {
        setSession(restoredSession);
        setAddress(restoredSession.walletAddress);
        setStage('ready');

        // Check if deployed
        transactionManager.isDeployed().then(deployed => {
          setIsDeployed(deployed);
        });
      }
    }
  }, [hookConfig.config, hookConfig.backendUrl, hookConfig.appId, hookConfig.rpcUrl]);

  const initializeAndGetOAuthUrl = useCallback(
    async (provider: 'google' | 'apple', redirectUri?: string): Promise<string> => {
      if (!manager) throw new Error('Manager not initialized');

      setIsLoading(true);
      setError(null);
      setStage('initializing');

      try {
        await manager.initializeSession();
        setStage('oauth');

        const url =
          provider === 'google'
            ? await manager.getGoogleOAuthUrl(redirectUri)
            : await manager.getAppleOAuthUrl(redirectUri);

        return url;
      } catch (e: any) {
        setError(e.message);
        setStage('error');
        throw e;
      } finally {
        setIsLoading(false);
      }
    },
    [manager]
  );

  const handleCallback = useCallback(
    async (authData: string): Promise<void> => {
      if (!manager || !txManager) throw new Error('Manager not initialized');

      setIsLoading(true);
      setError(null);
      setStage('processing');

      try {
        const oauthSession = await manager.handleOAuthCallback(authData);

        setSession(oauthSession);
        setAddress(oauthSession.walletAddress || null);

        // Try to extract email from JWT (Google includes it)
        if (oauthSession.jwt) {
          try {
            const payload = JSON.parse(
              atob(oauthSession.jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))
            );
            setEmail(payload.email || null);
          } catch {
            // Ignore
          }
        }

        // Check deployment status
        const deployed = await txManager.isDeployed();
        setIsDeployed(deployed);

        // If not deployed, deploy automatically
        if (!deployed) {
          setStage('deploying');
          const deployHash = await txManager.deployAccount();

          // Verify the account is actually on-chain — the tx may have reverted
          // or deployAccount() may have returned 'already-deployed' as a false positive.
          const deployConfirmed = await txManager.isDeployed();
          if (!deployConfirmed) {
            throw new Error(
              `Deploy transaction submitted (${deployHash}) but account is not deployed on-chain. ` +
              'The transaction may have reverted.'
            );
          }
          setIsDeployed(true);
        } else {
          setIsDeployed(true);
        }
        setStage('ready');
      } catch (e: any) {
        setError(e.message);
        setStage('error');
        throw e;
      } finally {
        setIsLoading(false);
      }
    },
    [manager, txManager]
  );

  const execute = useCallback(
    async (calls: Call | Call[]): Promise<string> => {
      if (!txManager) throw new Error('Transaction manager not initialized');
      if (stage !== 'ready') throw new Error('Not authenticated');

      setIsLoading(true);
      setError(null);

      try {
        const hash = await txManager.execute(calls);
        return hash;
      } catch (e: any) {
        setError(e.message);
        throw e;
      } finally {
        setIsLoading(false);
      }
    },
    [txManager, stage]
  );

  const deployAccount = useCallback(async (): Promise<string> => {
    if (!txManager) throw new Error('Transaction manager not initialized');

    setIsLoading(true);
    setError(null);
    setStage('deploying');

    try {
      const hash = await txManager.deployAccount();
      setIsDeployed(true);
      setStage('ready');
      return hash;
    } catch (e: any) {
      setError(e.message);
      setStage('error');
      throw e;
    } finally {
      setIsLoading(false);
    }
  }, [txManager]);

  const logout = useCallback(() => {
    if (manager) {
      manager.clearSession();
    }
    setSession(null);
    setAddress(null);
    setEmail(null);
    setIsDeployed(false);
    setStage('idle');
    setError(null);
  }, [manager]);

  return {
    stage,
    address,
    email,
    isDeployed,
    initializeAndGetOAuthUrl,
    handleCallback,
    execute,
    deployAccount,
    logout,
    isLoading,
    error,
    session,
  };
}
