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
    value: { location: { href: 'https://app.test/login' } },
    configurable: true,
  });

  return { local, session };
}

function createManager() {
  const manager = new OAuthWalletManager(
    {
      cavosAccountClassHash: '0x1',
      jwksRegistryAddress: '0x2',
      salt: '0x3',
    },
    'https://backend.test',
    'app-id',
    'https://rpc.test',
  ) as OAuthWalletManager & Record<string, any>;
  manager.provider = {
    getBlock: jest.fn().mockResolvedValue({ timestamp: 10_000 }),
  };
  return manager;
}

function storedSession(overrides: Record<string, unknown> = {}) {
  return {
    sessionPrivateKey: '0x111',
    sessionPubKey: '0x222',
    nonce: '0x333',
    nonceParams: {
      sessionPubKey: '0x222',
      validAfter: '1',
      validUntil: '2',
      renewalDeadline: '3',
      randomness: '4',
    },
    jwt: 'expired.jwt.value',
    jwtClaims: {
      sub: 'user',
      nonce: '0x333',
      exp: 1,
      iss: 'issuer',
      aud: 'audience',
    },
    walletName: 'game-wallet',
    ...overrides,
  };
}

describe('OAuthWalletManager session lifecycle', () => {
  beforeEach(() => {
    installBrowserStorage();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('discards an invalid restored session but preserves its wallet name', async () => {
    const manager = createManager();
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(storedSession()));

    expect(manager.restoreSession()).toBe(false);
    expect(manager.getSession()).toBeNull();
    expect(localStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();

    await manager.initializeSession();

    expect(manager.getSession()).toEqual(expect.objectContaining({
      walletName: 'game-wallet',
    }));
    expect(manager.getSession()?.sessionPrivateKey).not.toBe('0x111');
    expect(manager.getSession()?.nonce).not.toBe('0x333');
  });

  it('rotates key material and nonce when OTP login is explicitly restarted', async () => {
    const manager = createManager();
    await manager.initializeSession();
    const firstSession = manager.getSession()!;

    Object.defineProperty(global, 'fetch', {
      value: jest.fn().mockResolvedValue({ ok: true }),
      configurable: true,
    });

    await manager.sendOtp('user@example.com');
    const secondSession = manager.getSession()!;
    const request = (global.fetch as jest.Mock).mock.calls[0][1];
    const body = JSON.parse(request.body);

    expect(secondSession.sessionPrivateKey).not.toBe(firstSession.sessionPrivateKey);
    expect(secondSession.nonce).not.toBe(firstSession.nonce);
    expect(body.nonce).toBe(secondSession.nonce);
  });
});
