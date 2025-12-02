import { useCavos } from '../CavosContext';

export function useSession() {
  const { hasActiveSession, cavos } = useCavos();

  const createSession = async () => {
    // Note: Session keys not supported with ArgentX accounts
    await cavos.createSession();
  };

  return {
    hasActiveSession,
    createSession,
  };
}
