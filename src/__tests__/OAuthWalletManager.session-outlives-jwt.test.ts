import { OAuthWalletManager } from '../oauth/OAuthWalletManager';

const SESSION_STORAGE_KEY = 'cavos_oauth_session';

function installBrowserStorage() {
  const local = new Map<string, string>();
  const session = new Map<string, string>();
  const storage = (store: Map<string, string>) => ({
    getItem: jest.fn((key: string) => store.get(key) ?? null),
    setItem: jest.fn((key: string, value: string) => store.set(key, value)),
    removeItem: jest.fn((key: string) => store.delete(key)),
    clear: jest.fn(() => store.clear()),
  });

  Object.defineProperty(global, 'localStorage', { value: storage(local), configurable: true });
  Object.defineProperty(global, 'sessionStorage', { value: storage(session), configurable: true });
  Object.defineProperty(global, 'window', {
    value: { location: { href: 'https://app.test/' } },
    configurable: true,
  });
}

function createManager() {
  return new OAuthWalletManager(
    { cavosAccountClassHash: '0x1', jwksRegistryAddress: '0x2', salt: '0x3' },
    'https://backend.test',
    'app-id',
    'https://rpc.test',
    { sessionDuration: 30 * 24 * 3600 },
  ) as OAuthWalletManager & Record<string, any>;
}

/** now-relative session with an already-expired JWT, as stored by persistSession(). */
function storedSession(validUntilOffset: number, renewalDeadlineOffset: number) {
  const now = Math.floor(Date.now() / 1000);
  return JSON.stringify({
    sessionPrivateKey: '0x111',
    sessionPubKey: '0x222',
    nonce: '0x333',
    nonceParams: {
      sessionPubKey: '0x222',
      validAfter: String(now - 3600),
      validUntil: String(now + validUntilOffset),
      renewalDeadline: String(now + renewalDeadlineOffset),
      randomness: '4',
    },
    jwt: 'header.payload.signature',
    jwtClaims: {
      sub: 'user',
      nonce: '0x333',
      exp: now - 60,
      iss: 'https://accounts.google.com',
      aud: 'audience',
    },
    walletAddress: '0xabc',
    walletName: 'default',
  });
}

const DAY = 24 * 3600;

describe('session lifetime is bounded by the session key, not the JWT', () => {
  beforeEach(installBrowserStorage);

  it('keeps a session whose JWT expired while the session key is still valid on-chain', () => {
    const manager = createManager();
    localStorage.setItem(SESSION_STORAGE_KEY, storedSession(29 * DAY, 31 * DAY));

    expect(manager.restoreSession()).toBe(true);
    expect(manager.hasValidSession()).toBe(true);
    // The key that signs transactions must survive — re-login cannot recover it.
    expect(manager.getSession()?.sessionPrivateKey).toBe('0x111');
    expect(localStorage.getItem(SESSION_STORAGE_KEY)).not.toBeNull();
  });

  it('keeps an expired session key that is still inside its renewal grace period', () => {
    const manager = createManager();
    // validUntil passed, renewalDeadline ahead: executeOnSlot() rotates the key
    // by signing with the outgoing one, so this is recoverable without a JWT.
    localStorage.setItem(SESSION_STORAGE_KEY, storedSession(-3600, 2 * DAY));

    expect(manager.restoreSession()).toBe(true);
    expect(manager.hasValidSession()).toBe(true);
  });

  it('discards a session once the renewal deadline has passed', () => {
    const manager = createManager();
    localStorage.setItem(SESSION_STORAGE_KEY, storedSession(-2 * DAY, -DAY));

    expect(manager.restoreSession()).toBe(false);
    expect(manager.getSession()).toBeNull();
    expect(localStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();
  });
});
