import { useState, useEffect } from 'react';
import { useCavos } from '../CavosContext';

export function useAccountDeployment() {
  const { cavos, isAuthenticated, address } = useCavos();
  const [isDeployed, setIsDeployed] = useState(false);
  const [isDeploying, setIsDeploying] = useState(false);
  const [deployError, setDeployError] = useState<Error | null>(null);
  const [isChecking, setIsChecking] = useState(true);

  // Check deployment status on mount
  useEffect(() => {
    const checkStatus = async () => {
      if (!isAuthenticated) {
        setIsChecking(false);
        return;
      }

      try {
        setIsChecking(true);
        const deployed = await cavos.isAccountDeployed();
        setIsDeployed(deployed);
      } catch (error) {
        console.error('[useAccountDeployment] Status check failed:', error);
      } finally {
        setIsChecking(false);
      }
    };

    checkStatus();
  }, [cavos, isAuthenticated]);

  const deploy = async (): Promise<string | null> => {
    setIsDeploying(true);
    setDeployError(null);

    try {
      const txHash = await cavos.deployAccount();
      setIsDeployed(true);
      setIsDeploying(false);
      return txHash;
    } catch (error: any) {
      setDeployError(error);
      setIsDeploying(false);
      return null;
    }
  };

  const refreshStatus = async () => {
    setIsChecking(true);
    try {
      const deployed = await cavos.isAccountDeployed();
      setIsDeployed(deployed);
    } catch (error) {
      console.error('[useAccountDeployment] Refresh failed:', error);
    } finally {
      setIsChecking(false);
    }
  };

  return {
    isDeployed,
    address,
    isDeploying,
    deployError,
    isChecking,
    deploy,
    refreshStatus,
  };
}
