'use client';
import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { CavosSDK } from '../CavosSDK';
import { CavosConfig, UserInfo, OnrampProvider, LoginProvider } from '../types';
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
  signMessage: (message: string | string[]) => Promise<{ r: string; s: string }>;
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
      } catch (error) {
        console.error('[CavosProvider] Initialization error:', error);
        setIsAuthenticated(false);
      } finally {
        setIsLoading(false);
      }
    };

    initialize();
  }, [cavos]);

  const loginWithGoogle = async (redirectUri?: string) => {
    setIsLoading(true);
    try {
      await cavos.loginWithGoogle(redirectUri);
    } catch (error) {
      console.error('[CavosProvider] Google login error:', error);
      setIsLoading(false);
      throw error;
    }
  };

  const loginWithApple = async (redirectUri?: string) => {
    setIsLoading(true);
    try {
      await cavos.loginWithApple(redirectUri);
    } catch (error) {
      console.error('[CavosProvider] Apple login error:', error);
      setIsLoading(false);
      throw error;
    }
  };

  const login = async (provider: LoginProvider, redirectUri?: string) => {
    setIsLoading(true);
    try {
      await cavos.login(provider, redirectUri);
    } catch (error) {
      console.error(`[CavosProvider] ${provider} login error:`, error);
      setIsLoading(false);
      throw error;
    }
  };

  const createWallet = async () => {
    setIsLoading(true);
    try {
      await cavos.createWallet();
      setAddress(cavos.getAddress());
      setRequiresWalletCreation(false);
    } catch (error) {
      console.error('[CavosProvider] Create wallet error:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const execute = async (calls: Call | Call[], options?: { gasless?: boolean }) => {
    return await cavos.execute(calls, options);
  };

  const getOnramp = (provider: OnrampProvider): string => {
    return cavos.getOnramp(provider);
  };

  const logout = async () => {
    await cavos.logout();
    setIsAuthenticated(false);
    setUser(null);
    setAddress(null);
    setHasActiveSession(false);
    setRequiresWalletCreation(false);
  };

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
    signMessage: async (message: string | string[]) => await cavos.signMessage(message),
    getOnramp,
    logout,
    isLoading,
  };

  return (
    <CavosContext.Provider value={value}>
      {children}
      <PasskeyModal
        isOpen={isAuthenticated && requiresWalletCreation && !isLoading}
        onCreatePasskey={createWallet}
        config={config.passkeyModal}
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
