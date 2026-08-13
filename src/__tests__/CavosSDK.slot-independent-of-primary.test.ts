import { CavosSDK } from '../CavosSDK';
import { CavosError } from '../utils/errors';

function installLocalStorageMock() {
  const store = new Map<string, string>();
  Object.defineProperty(global, 'localStorage', {
    value: {
      getItem: jest.fn((key: string) => store.get(key) ?? null),
      setItem: jest.fn((key: string, value: string) => { store.set(key, value); }),
      removeItem: jest.fn((key: string) => { store.delete(key); }),
      clear: jest.fn(() => store.clear()),
    },
    configurable: true,
  });
}

function createSdk(deployAccount: jest.Mock, { slotConfigured = true } = {}) {
  const sdk = Object.create(CavosSDK.prototype) as CavosSDK & Record<string, any>;

  sdk.config = {
    appId: 'app',
    network: 'sepolia',
    slot: slotConfigured ? { rpcUrl: 'http://slot.test' } : undefined,
  };
  sdk.logger = { log: jest.fn(), warn: jest.fn(), alwaysError: jest.fn() };
  sdk._walletStatus = {
    isDeploying: false,
    isDeployed: false,
    isRegistering: false,
    isSessionActive: false,
    isReady: false,
    isSlotDeploying: false,
    isSlotDeployed: false,
    isSlotSessionActive: false,
    isSlotReady: false,
  };
  sdk.walletStatusListeners = new Set();
  sdk.isAccountDeployed = jest.fn().mockResolvedValue(false);
  sdk.deployAccount = deployAccount;
  sdk.ensureAccountClassHashIsCurrent = jest.fn().mockResolvedValue(undefined);
  sdk.autoRegisterSession = jest.fn().mockResolvedValue(undefined);
  sdk._deploySlotInBackground = jest.fn();
  sdk.getAddress = jest.fn().mockReturnValue('0xabc');
  sdk.analyticsManager = { trackWalletDeployment: jest.fn() };
  sdk.transactionManager = { isSessionRegistered: jest.fn().mockResolvedValue(false) };

  return sdk;
}

describe('Slot setup does not depend on the primary network', () => {
  beforeEach(installLocalStorageMock);

  it('starts Slot setup after a successful primary deploy', async () => {
    const sdk = createSdk(jest.fn().mockResolvedValue('0xdeploy'));

    await sdk._runDeployBackground();

    expect(sdk._deploySlotInBackground).toHaveBeenCalledTimes(1);
  });

  it('still starts Slot setup when the primary deploy fails on an unregistered JWKS kid', async () => {
    // The primary registry can go stale on its own — a Slot-only app must not be
    // left without a wallet because of it.
    const sdk = createSdk(jest.fn().mockRejectedValue(
      new CavosError('JWKS_KID_NOT_REGISTERED', 'kid is not registered in the JWKS registry', {}),
    ));

    await sdk._runDeployBackground();

    expect(sdk._deploySlotInBackground).toHaveBeenCalledTimes(1);
    expect(sdk._walletStatus.isDeployed).toBe(false);
  });

  it('starts Slot setup exactly once when the account is already deployed', async () => {
    const sdk = createSdk(jest.fn());
    sdk.isAccountDeployed = jest.fn().mockResolvedValue(true);

    await sdk._runDeployBackground();

    expect(sdk.deployAccount).not.toHaveBeenCalled();
    expect(sdk._deploySlotInBackground).toHaveBeenCalledTimes(1);
  });
});
