import { useState, useCallback } from 'react';
import { useCavos } from '../CavosContext';
import { Call } from 'starknet';

export interface SessionPolicy {
  allowedMethods: Array<{ contractAddress: string; selector: string }>;
  expiresAt?: number;
  maxFees?: Array<{ tokenAddress: string; maxAmount: string }>;
}

export function useSession() {
  const { cavos } = useCavos();
  const [hasActiveSession, setHasActiveSession] = useState(() => {
    const active = cavos.hasActiveSession();
    console.log('[useSession] Initial hasActiveSession:', active);
    return active;
  });

  /**
   * Create a session with the specified policy.
   * User will sign once to authorize the session.
   */
  const createSession = useCallback(async (policy: SessionPolicy) => {
    console.log('[useSession] createSession called with policy:', policy);
    try {
      await cavos.createSession(policy);
      const isActive = cavos.hasActiveSession();
      console.log('[useSession] After createSession, hasActiveSession:', isActive);
      setHasActiveSession(isActive);
    } catch (error) {
      console.error('[useSession] createSession error:', error);
      throw error;
    }
  }, [cavos]);

  /**
   * Execute transactions using the session key.
   * No user signature required after session is created.
   */
  const executeWithSession = useCallback(async (calls: Call | Call[]) => {
    console.log('[useSession] executeWithSession called');
    return await cavos.executeWithSession(calls);
  }, [cavos]);

  /**
   * Clear the current session.
   */
  const clearSession = useCallback(() => {
    console.log('[useSession] clearSession called');
    cavos.clearSession();
    setHasActiveSession(false);
  }, [cavos]);

  return {
    hasActiveSession,
    createSession,
    executeWithSession,
    clearSession,
  };
}
