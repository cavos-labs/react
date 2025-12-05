'use client';
import React, { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react';
import { CavosSDK } from '../CavosSDK';
import { CavosConfig, UserInfo, OnrampProvider, LoginProvider, TypedData, Signature } from '../types';
import { Call } from 'starknet';
import { PasskeyModal } from './components/PasskeyModal';

export interface CavosContextValue {
  cavos: CavosSDK;
  isAuthenticated: boolean;
  user: UserInfo | null;
  address: string | null;
  hasActiveSession: boolean;
  requiresWalletCreation: boolean;
  login: (provider: LoginProvider, redirectUri?: string) => Promise<void>;
  createWallet: () => Promise<void>;
  execute: (calls: Call | Call[], options?: { gasless?: boolean }) => Promise<string>;
  signMessage: (message: string | TypedData) => Promise<Signature>;
  deleteAccount: () => Promise<void>;
  retryWalletUnlock: () => Promise<void>;
  getOnramp: (provider: OnrampProvider) => string;
  logout: () => Promise<void>;
  isLoading: boolean;
}

const CavosContext = createContext<CavosContextValue | null>(null);

export interface CavosProviderProps {
  config: CavosConfig;
  children: ReactNode;
}

export function CavosProvider({ config, children }: CavosProviderProps) {
  const [cavos] = useState(() => new CavosSDK(config));
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<UserInfo | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [hasActiveSession, setHasActiveSession] = useState(false);
  const [requiresWalletCreation, setRequiresWalletCreation] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const initialize = async () => {
      const urlParams = new URLSearchParams(window.location.search);
      const authData = urlParams.get('auth_data');

      try {
        if (authData) {
          // Handle OAuth callback
          await cavos.handleCallback(authData);
          // Clean up URL
          window.history.replaceState({}, document.title, window.location.pathname);
        } else {
          // Try to restore session
          await cavos.init();
        }

        // Update state if authenticated
        if (cavos.isAuthenticated()) {
          setIsAuthenticated(true);
          setUser(cavos.getUserInfo());
          const addr = cavos.getAddress();
          if (addr) {
            setAddress(addr);
            setRequiresWalletCreation(false);
          } else {
            setRequiresWalletCreation(true);
          }
        }
      } catch (error: any) {
        console.error('[CavosProvider] Initialization error:', error);

        // Check if user is authenticated but wallet restoration failed
        if (cavos.isAuthenticated() && !cavos.getAddress()) {
          // Keep the user authenticated so they don't get logged out
          setIsAuthenticated(true);
          setUser(cavos.getUserInfo());

          // Only show PasskeyModal if user doesn't have an existing wallet
          // If they have a wallet but cancelled passkey, don't show the modal
          const userHasWallet = await cavos.hasWallet();
          if (!userHasWallet) {
            // User is new and needs to create a wallet
            setRequiresWalletCreation(true);
          } else {
            // User has a wallet but cancelled passkey unlock - don't show modal
            setRequiresWalletCreation(false);
          }
        } else {
          setIsAuthenticated(false);
        }
      } finally {
        setIsLoading(false);
      }
    };

    initialize();
  }, [cavos]);

  const login = useCallback(async (provider: LoginProvider, redirectUri?: string) => {
    if (!cavos) throw new Error('Cavos SDK not initialized');
    setIsLoading(true);
    try {
      await cavos.login(provider, redirectUri);
      // After login, re-initialize to get user info and address
      await cavos.init();
      if (cavos.getAddress()) {
        setAddress(cavos.getAddress());
        setRequiresWalletCreation(false);
      }
    } catch (error) {
      console.error(`[CavosProvider] ${provider} login error:`, error);
      setIsLoading(false);
      throw error;
    }
  }, [cavos]);

  const createWallet = useCallback(async () => {
    if (!cavos) throw new Error('Cavos SDK not initialized');
    setIsLoading(true);
    try {
      await cavos.createWallet();
      setAddress(cavos.getAddress());
      setRequiresWalletCreation(false);
    } catch (error: any) {
      console.error('[CavosProvider] Create wallet error:', error);
      // Re-throw the error so developers can handle it
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [cavos]);

  const execute = useCallback(async (calls: Call | Call[], options?: { gasless?: boolean }) => {
    if (!cavos) throw new Error('Cavos SDK not initialized');
    return cavos.execute(calls, options);
  }, [cavos]);

  const signMessage = useCallback(async (message: string | TypedData) => {
    if (!cavos) throw new Error('Cavos SDK not initialized');
    return cavos.signMessage(message);
  }, [cavos]);

  const deleteAccount = useCallback(async () => {
    if (!cavos) throw new Error('Cavos SDK not initialized');
    await cavos.deleteAccount();
    // Clear state after successful deletion (logout is called in SDK)
    setIsAuthenticated(false);
    setUser(null);
    setAddress(null);
    setHasActiveSession(false);
    setRequiresWalletCreation(false);
  }, [cavos]);

  const retryWalletUnlock = useCallback(async () => {
    if (!cavos) throw new Error('Cavos SDK not initialized');
    await cavos.retryWalletUnlock();
    // Update address after successful unlock
    setAddress(cavos.getAddress());
    setRequiresWalletCreation(false);
  }, [cavos]);

  const getOnramp = useCallback((provider: OnrampProvider) => {
    if (!cavos) throw new Error('Cavos SDK not initialized');
    return cavos.getOnramp(provider);
  }, [cavos]);

  const logout = useCallback(async () => {
    if (!cavos) throw new Error('Cavos SDK not initialized');
    await cavos.logout();
    setIsAuthenticated(false);
    setUser(null);
    setAddress(null);
    setHasActiveSession(false);
    setRequiresWalletCreation(false);
  }, [cavos]);

  const value: CavosContextValue = {
    cavos,
    isAuthenticated,
    user,
    address,
    hasActiveSession,
    requiresWalletCreation,
    login,
    createWallet,
    execute,
    signMessage,
    deleteAccount,
    retryWalletUnlock,
    getOnramp,
    logout,
    isLoading,
  };

  return (
    <CavosContext.Provider value={value}>
      {children}
      <PasskeyModal
        isOpen={requiresWalletCreation}
        onCreatePasskey={createWallet}
        onClose={logout}
        config={config.passkeyModal}
        isLoading={isLoading}
      />
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
