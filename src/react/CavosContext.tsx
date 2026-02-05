'use client';
import React, { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react';
import { CavosSDK, WalletStatus } from '../CavosSDK';
import { CavosConfig, UserInfo, OnrampProvider, LoginProvider, Signature, FirebaseCredentials } from '../types';
import { Call, type TypedData } from 'starknet';

export interface CavosContextValue {
  cavos: CavosSDK;
  isAuthenticated: boolean;
  user: UserInfo | null;
  address: string | null;
  hasActiveSession: boolean;
  login: (provider: LoginProvider, credentials?: FirebaseCredentials) => Promise<void>;
  register: (provider: LoginProvider, credentials: FirebaseCredentials) => Promise<void>;
  execute: (calls: Call | Call[], options?: { gasless?: boolean }) => Promise<string>;
  renewSession: () => Promise<string>;
  signMessage: (typedData: TypedData) => Promise<Signature>;
  getOnramp: (provider: OnrampProvider) => string;
  logout: () => Promise<void>;
  isLoading: boolean;
  isAccountDeployed: () => Promise<boolean>;
  deployAccount: () => Promise<string>;
  getBalance: () => Promise<string>;
  resendVerificationEmail: (email: string) => Promise<void>;
  /** Wallet status for tracking deploy/session registration state */
  walletStatus: WalletStatus;
}

const CavosContext = createContext<CavosContextValue | null>(null);

export interface CavosProviderProps {
  config: CavosConfig;
  children: ReactNode;
}

const DEFAULT_WALLET_STATUS: WalletStatus = {
  isDeploying: false,
  isDeployed: false,
  isRegistering: false,
  isSessionActive: false,
  isReady: false,
};

export function CavosProvider({ config, children }: CavosProviderProps) {
  const [cavos] = useState(() => new CavosSDK(config));
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<UserInfo | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [hasActiveSession, setHasActiveSession] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [walletStatus, setWalletStatus] = useState<WalletStatus>(DEFAULT_WALLET_STATUS);

  const updateState = useCallback(() => {
    setIsAuthenticated(cavos.isAuthenticated());
    setUser(cavos.getUserInfo());
    setAddress(cavos.getAddress());
    setHasActiveSession(cavos.isAuthenticated());
  }, [cavos]);

  // Subscribe to wallet status changes
  useEffect(() => {
    const unsubscribe = cavos.onWalletStatusChange(setWalletStatus);
    return unsubscribe;
  }, [cavos]);

  useEffect(() => {
    const initialize = async () => {
      if (typeof window === 'undefined') return;
      console.log('[CavosContext] initialize() starting');

      const urlParams = new URLSearchParams(window.location.search);
      const authData = urlParams.get('auth_data') || urlParams.get('zk_auth_data');
      console.log('[CavosContext] authData:', authData ? 'present' : 'null');

      try {
        if (authData) {
          // Handle OAuth callback
          console.log('[CavosContext] calling handleCallback()');
          await cavos.handleCallback(authData);
          // Clean up URL
          window.history.replaceState({}, document.title, window.location.pathname);
        } else {
          // Initialize and restore session
          console.log('[CavosContext] calling init()');
          await cavos.init();
        }
        console.log('[CavosContext] after init/callback, address:', cavos.getAddress());
        updateState();
      } catch (error) {
        console.error('[CavosProvider] Initialization error:', error);
      } finally {
        setIsLoading(false);
      }
    };

    initialize();
  }, [cavos, updateState]);

  const login = useCallback(async (provider: LoginProvider, credentials?: FirebaseCredentials) => {
    setIsLoading(true);
    try {
      await cavos.login(provider, credentials);
      updateState();
    } catch (error) {
      console.error(`[CavosProvider] ${provider} login error:`, error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [cavos, updateState]);

  const register = useCallback(async (provider: LoginProvider, credentials: FirebaseCredentials) => {
    setIsLoading(true);
    try {
      await cavos.register(provider, credentials);
      updateState();
    } catch (error) {
      console.error(`[CavosProvider] ${provider} register error:`, error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [cavos, updateState]);

  const execute = useCallback(async (calls: Call | Call[], _options?: { gasless?: boolean }) => {
    return cavos.execute(calls);
  }, [cavos]);

  const renewSession = useCallback(async () => {
    return cavos.renewSession();
  }, [cavos]);

  const signMessage = useCallback(async (typedData: TypedData) => {
    return cavos.signMessage(typedData);
  }, [cavos]);

  const getOnramp = useCallback((provider: OnrampProvider) => {
    return cavos.getOnramp(provider);
  }, [cavos]);

  const logout = useCallback(async () => {
    await cavos.logout();
    updateState();
  }, [cavos, updateState]);

  const isAccountDeployed = useCallback(async () => {
    return cavos.isAccountDeployed();
  }, [cavos]);

  const deployAccount = useCallback(async () => {
    return cavos.deployAccount();
  }, [cavos]);

  const getBalance = useCallback(async () => {
    return cavos.getBalance();
  }, [cavos]);

  const resendVerificationEmail = useCallback(async (email: string) => {
    return cavos.resendVerificationEmail(email);
  }, [cavos]);

  const value: CavosContextValue = {
    cavos,
    isAuthenticated,
    user,
    address,
    hasActiveSession,
    login,
    register,
    execute,
    renewSession,
    signMessage,
    getOnramp,
    logout,
    isLoading,
    isAccountDeployed,
    deployAccount,
    getBalance,
    resendVerificationEmail,
    walletStatus,
  };

  return (
    <CavosContext.Provider value={value}>
      {children}
    </CavosContext.Provider>
  );
}

export function useCavos(): CavosContextValue {
  const context = useContext(CavosContext);
  if (!context) {
    throw new Error('useCavos must be used within a CavosProvider');
  }
  return context;
}
