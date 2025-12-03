import { useCavos } from '../CavosContext';

export function useAuth() {
  const { isAuthenticated, user, logout, isLoading } = useCavos();

  return {
    isAuthenticated,
    user,
    logout,
    isLoading,
  };
}
