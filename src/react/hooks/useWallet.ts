import { useCavos } from '../CavosContext';

export function useWallet() {
  const { address, isAuthenticated, user } = useCavos();

  return {
    address,
    isConnected: isAuthenticated,
    user,
  };
}
