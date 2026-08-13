import { CavosSDK } from '../CavosSDK';
import { OAuthWalletManager } from '../oauth/OAuthWalletManager';
import { NonceManager } from '../oauth/NonceManager';

const DAY = 24 * 3600;
const CHAIN_NOW = 1_800_000_000n;

function installBrowserStorage() {
  const store = new Map<string, string>();
  const storage = {
    getItem: jest.fn((key: string) => store.get(key) ?? null),
    setItem: jest.fn((key: string, value: string) => { store.set(key, value); }),
    removeItem: jest.fn((key: string) => { store.delete(key); }),
    clear: jest.fn(() => store.clear()),
  };
  Object.defineProperty(global, 'localStorage', { value: storage, configurable: true });
  Object.defineProperty(global, 'sessionStorage', { value: storage, configurable: true });
  Object.defineProperty(global, 'window', {
    value: { location: { href: 'https://app.test/' } },
    configurable: true,
  });
}

/** Reaches into the SDK for the manager it actually built from CavosConfig. */
function managerFor(config: any): OAuthWalletManager & Record<string, any> {
  const sdk = new CavosSDK(config) as CavosSDK & Record<string, any>;
  const manager = sdk.oauthWalletManager as OAuthWalletManager & Record<string, any>;
  manager.provider = { getBlock: jest.fn().mockResolvedValue({ timestamp: CHAIN_NOW }) };
  return manager;
}

describe('configured sessionDuration reaches the on-chain session window', () => {
  beforeEach(installBrowserStorage);

  it('mints a 30-day session when the app configures 30 days', async () => {
    const manager = managerFor({
      appId: 'app',
      network: 'sepolia',
      session: { sessionDuration: 30 * DAY },
    });

    await manager.initializeSession();
    const { validUntil, renewalDeadline } = manager.getSession()!.nonceParams;

    expect(validUntil - CHAIN_NOW).toBe(BigInt(30 * DAY));
    // The grace period extends the session; it must never cut it short.
    expect(renewalDeadline).toBeGreaterThan(validUntil);
  });

  it('matches the renewal deadline the contract stores at registration', async () => {
    // cavos_account.cairo: `renewal_deadline = valid_until + 172800`.
    const manager = managerFor({
      appId: 'app',
      network: 'sepolia',
      session: { sessionDuration: 30 * DAY },
    });

    await manager.initializeSession();
    const { validUntil, renewalDeadline } = manager.getSession()!.nonceParams;

    expect(renewalDeadline).toBe(validUntil + 172800n);
  });

  it('keeps a renewal payload the contract will accept (deadline >= valid_until)', async () => {
    // Otherwise renew_session reverts on "Renewal deadline must be >= valid_until".
    const params = NonceManager.generateNonceParams(
      '0xabc',
      CHAIN_NOW,
      BigInt(30 * DAY),
      172800n,
    );

    expect(params.renewalDeadline).toBeGreaterThanOrEqual(params.validUntil);
  });

  it('falls back to 24 hours when the app does not configure a duration', async () => {
    // Documents the silent default: an app that sets the option in the wrong place
    // gets a one-day session and no warning.
    const manager = managerFor({ appId: 'app', network: 'sepolia' });

    await manager.initializeSession();
    const { validUntil } = manager.getSession()!.nonceParams;

    expect(validUntil - CHAIN_NOW).toBe(BigInt(DAY));
  });

  it('survives a full day of use once the JWT has expired', async () => {
    const manager = managerFor({
      appId: 'app',
      network: 'sepolia',
      session: { sessionDuration: 30 * DAY },
    });

    await manager.initializeSession();
    const session = manager.getSession()!;
    const now = Math.floor(Date.now() / 1000);
    // A real 30-day session as persisted after login, one day in, JWT long dead.
    manager.session = {
      ...session,
      jwt: 'header.payload.signature',
      jwtClaims: { sub: 'u', nonce: session.nonce, exp: now - DAY, iss: 'iss', aud: 'aud' },
      nonceParams: {
        ...session.nonceParams,
        validUntil: BigInt(now + 29 * DAY),
        renewalDeadline: BigInt(now + 29 * DAY + 172800),
      },
    };

    expect(manager.hasValidSession()).toBe(true);
  });
});
