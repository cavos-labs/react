'use client';
import React, { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react';
import { CavosSDK, WalletStatus } from '../CavosSDK';
import { CavosConfig, UserInfo, OnrampProvider, LoginProvider, Signature, FirebaseCredentials } from '../types';
import { SessionKeyPolicy } from '../types/session';
import { Call, type TypedData } from 'starknet';
import { CavosAuthModal } from './components/CavosAuthModal';

export interface CavosModalConfig {
  appName?: string;
  appLogo?: string;
  providers?: ('google' | 'apple' | 'email')[];
  primaryColor?: string;
  onSuccess?: (address: string) => void;
}

export interface CavosContextValue {
  cavos: CavosSDK;
  openModal: () => void;
  closeModal: () => void;
  isAuthenticated: boolean;
  user: UserInfo | null;
  address: string | null;
  hasActiveSession: boolean;
  login: (provider: LoginProvider, credentials?: FirebaseCredentials) => Promise<void>;
  register: (provider: LoginProvider, credentials: FirebaseCredentials) => Promise<void>;
  execute: (calls: Call | Call[], options?: { gasless?: boolean }) => Promise<string>;
  renewSession: () => Promise<string>;
  revokeSession: (sessionKey: string) => Promise<string>;
  emergencyRevokeAllSessions: () => Promise<string>;
  signMessage: (typedData: TypedData) => Promise<Signature>;
  getOnramp: (provider: OnrampProvider) => string;
  logout: () => Promise<void>;
  isLoading: boolean;
  isAccountDeployed: () => Promise<boolean>;
  deployAccount: () => Promise<string>;
  /** Get current balance */
  getBalance: () => Promise<string>;
  /** Resend verification email */
  resendVerificationEmail: (email: string) => Promise<void>;
  /** Wallet status for tracking deploy/session registration state */
  walletStatus: WalletStatus;
  /** Get all wallets associated with this user */
  getAssociatedWallets: () => Promise<{ address: string; name?: string }[]>;
  /** Switch active wallet */
  switchWallet: (name?: string) => Promise<void>;
  /** Register the current session key on-chain using the current JWT */
  registerCurrentSession: () => Promise<string>;
  /** Export current session as base64 token for use with Cavos CLI */
  exportSession: () => string;
  /** Update session policy before registration */
  updateSessionPolicy: (policy: SessionKeyPolicy) => void;
  /** Public key of the current session key (safe to display) */
  sessionPublicKey: string | null;
}

const CavosContext = createContext<CavosContextValue | null>(null);

export interface CavosProviderProps {
  config: CavosConfig;
  modal?: CavosModalConfig;
  children: ReactNode;
}

const DEFAULT_WALLET_STATUS: WalletStatus = {
  isDeploying: false,
  isDeployed: false,
  isRegistering: false,
  isSessionActive: false,
  isReady: false,
};

export function CavosProvider({ config, modal, children }: CavosProviderProps) {
  const [cavos] = useState(() => new CavosSDK(config));
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<UserInfo | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [hasActiveSession, setHasActiveSession] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [walletStatus, setWalletStatus] = useState<WalletStatus>(DEFAULT_WALLET_STATUS);
  const [sessionPublicKey, setSessionPublicKey] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const openModal = useCallback(() => setModalOpen(true), []);
  const closeModal = useCallback(() => setModalOpen(false), []);

  const updateState = useCallback(() => {
    setIsAuthenticated(cavos.isAuthenticated());
    setUser(cavos.getUserInfo());
    setAddress(cavos.getAddress());
    setHasActiveSession(cavos.isAuthenticated());
    setSessionPublicKey(cavos.getSessionPublicKey());
  }, [cavos]);

  // Subscribe to wallet status changes
  useEffect(() => {
    const unsubscribe = cavos.onWalletStatusChange(setWalletStatus);
    return unsubscribe;
  }, [cavos]);

  // Auto-open modal if wallet setup is still in progress on page load (e.g. after OAuth redirect)
  useEffect(() => {
    if (!isLoading && isAuthenticated && (walletStatus.isDeploying || walletStatus.isRegistering)) {
      setModalOpen(true);
    }
  }, [isLoading, isAuthenticated, walletStatus.isDeploying, walletStatus.isRegistering]);

  useEffect(() => {
    const initialize = async () => {
      if (typeof window === 'undefined') return;
      console.log('[CavosContext] initialize() starting');

      const urlParams = new URLSearchParams(window.location.search);
      const authData = urlParams.get('auth_data') || urlParams.get('zk_auth_data');
      console.log('[CavosContext] authData:', authData ? 'present' : 'null');

      try {
        if (authData) {
          // If this is the child auth tab (opened via window.open), write auth data
          // to localStorage so the original tab picks it up, then close this tab.
          // handlePopupCallback() returns true for child tabs, false for redirect fallbacks.
          CavosSDK.handlePopupCallback();
          // Process auth in this tab regardless — handles the redirect-fallback case,
          // and provides a usable state if window.close() is blocked by the browser.
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

  const execute = useCallback(async (calls: Call | Call[], options?: { gasless?: boolean }) => {
    const txHash = await cavos.execute(calls, options);
    // If this was the first tx (JWT path), the session is now registered — update React state
    updateState();
    return txHash;
  }, [cavos, updateState]);

  const renewSession = useCallback(async () => {
    return cavos.renewSession();
  }, [cavos]);

  const revokeSession = useCallback(async (sessionKey: string) => {
    return cavos.revokeSession(sessionKey);
  }, [cavos]);

  const emergencyRevokeAllSessions = useCallback(async () => {
    return cavos.emergencyRevokeAllSessions();
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
    openModal,
    closeModal,
    isAuthenticated,
    user,
    address,
    hasActiveSession,
    login,
    register,
    execute,
    renewSession,
    revokeSession,
    emergencyRevokeAllSessions,
    signMessage,
    getOnramp,
    logout,
    isLoading,
    isAccountDeployed,
    deployAccount,
    getBalance,
    resendVerificationEmail,
    walletStatus,
    getAssociatedWallets: async () => cavos.getAssociatedWallets(),
    switchWallet: async (name?: string) => {
      await cavos.switchWallet(name);
      updateState();
    },
    registerCurrentSession: async () => cavos.registerCurrentSession(),
    exportSession: () => cavos.exportSession(),
    updateSessionPolicy: (policy: SessionKeyPolicy) => cavos.updateSessionPolicy(policy),
    sessionPublicKey,
  };

  return (
    <CavosContext.Provider value={value}>
      {children}
      {modal !== undefined && (
        <CavosAuthModal
          open={modalOpen}
          onClose={closeModal}
          onSuccess={modal.onSuccess}
          appName={modal.appName}
          appLogo={modal.appLogo}
          providers={modal.providers}
          primaryColor={modal.primaryColor}
        />
      )}
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
