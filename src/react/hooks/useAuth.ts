import { useCavos } from '../CavosContext';

export function useAuth() {
  const { isAuthenticated, user, loginWithGoogle, loginWithApple, logout, isLoading } = useCavos();

  return {
    isAuthenticated,
    user,
    loginWithGoogle,
    loginWithApple,
    logout,
    isLoading,
  };
}
