import { CavosSDK } from '../CavosSDK';

function installLocalStorageMock() {
  const store = new Map<string, string>();

  Object.defineProperty(global, 'localStorage', {
    value: {
      getItem: jest.fn((key: string) => store.get(key) ?? null),
      setItem: jest.fn((key: string, value: string) => {
        store.set(key, value);
      }),
      removeItem: jest.fn((key: string) => {
        store.delete(key);
      }),
      clear: jest.fn(() => {
        store.clear();
      }),
    },
    configurable: true,
  });
}

function createDeploySdk({
  deployOnly = false,
  deployed = false,
  deployHash = '0xdeploy',
  sessionActive = false,
  slotConfigured = false,
}: {
  deployOnly?: boolean;
  deployed?: boolean;
  deployHash?: string;
  sessionActive?: boolean;
  slotConfigured?: boolean;
}) {
  const sdk = Object.create(CavosSDK.prototype) as CavosSDK & Record<string, any>;

  sdk.config = {
    appId: 'app',
    network: 'sepolia',
    deployOnly,
    slot: slotConfigured ? { rpcUrl: 'http://slot.test' } : undefined,
  };
  sdk.logger = {
    log: jest.fn(),
    warn: jest.fn(),
    alwaysError: jest.fn(),
  };
  sdk._walletStatus = {
    isDeploying: false,
    isDeployed: false,
    isRegistering: false,
    isSessionActive: false,
    isReady: false,
    isSlotDeploying: false,
    isSlotDeployed: false,
  };
  sdk.walletStatusListeners = new Set();
  sdk.isAccountDeployed = jest.fn().mockResolvedValue(deployed);
  sdk.deployAccount = jest.fn().mockResolvedValue(deployHash);
  sdk.ensureAccountClassHashIsCurrent = jest.fn().mockResolvedValue(undefined);
  sdk.autoRegisterSession = jest.fn().mockResolvedValue(undefined);
  sdk._deploySlotInBackground = jest.fn();
  sdk.getAddress = jest.fn().mockReturnValue('0xabc');
  sdk.analyticsManager = {
    trackWalletDeployment: jest.fn(),
  };
  sdk.transactionManager = {
    isSessionRegistered: jest.fn().mockResolvedValue(sessionActive),
  };

  return sdk;
}

describe('CavosSDK deployOnly', () => {
  beforeEach(() => {
    installLocalStorageMock();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('deploys a new primary wallet without auto-registering the session', async () => {
    const sdk = createDeploySdk({ deployOnly: true, deployed: false });

    await sdk._runDeployBackground();

    expect(sdk.deployAccount).toHaveBeenCalledTimes(1);
    expect(sdk.autoRegisterSession).not.toHaveBeenCalled();
    expect(sdk.getWalletStatus()).toEqual(expect.objectContaining({
      isDeploying: false,
      isDeployed: true,
      isRegistering: false,
      isSessionActive: false,
      isReady: true,
    }));
  });

  it('does not auto-register when the primary wallet is already deployed with an inactive session', async () => {
    const sdk = createDeploySdk({
      deployOnly: true,
      deployed: true,
      sessionActive: false,
    });

    await sdk._runDeployBackground();

    expect(sdk.transactionManager.isSessionRegistered).toHaveBeenCalledTimes(1);
    expect(sdk.autoRegisterSession).not.toHaveBeenCalled();
    expect(sdk.getWalletStatus()).toEqual(expect.objectContaining({
      isDeployed: true,
      isRegistering: false,
      isSessionActive: false,
      isReady: true,
    }));
  });

  it('does not auto-register when deploy races with an already-deployed primary wallet', async () => {
    const sdk = createDeploySdk({
      deployOnly: true,
      deployed: false,
      deployHash: 'already-deployed',
    });

    await sdk._runDeployBackground();

    expect(sdk.autoRegisterSession).not.toHaveBeenCalled();
    expect(sdk.getWalletStatus()).toEqual(expect.objectContaining({
      isDeploying: false,
      isDeployed: true,
      isRegistering: false,
      isSessionActive: false,
      isReady: true,
    }));
  });

  it('keeps the existing primary auto-registration behavior when deployOnly is absent', async () => {
    const sdk = createDeploySdk({ deployed: true, sessionActive: false });
    delete sdk.config.deployOnly;

    await sdk._runDeployBackground();

    expect(sdk.autoRegisterSession).toHaveBeenCalledTimes(1);
  });

  it('keeps the existing primary auto-registration behavior when deployOnly is false', async () => {
    const sdk = createDeploySdk({
      deployOnly: false,
      deployed: true,
      sessionActive: false,
    });

    await sdk._runDeployBackground();

    expect(sdk.autoRegisterSession).toHaveBeenCalledTimes(1);
  });

  it('does not disable Slot auto-registration', async () => {
    const sdk = Object.create(CavosSDK.prototype) as CavosSDK & Record<string, any>;
    sdk.config = {
      appId: 'app',
      network: 'sepolia',
      deployOnly: true,
      slot: { rpcUrl: 'http://slot.test' },
    };
    sdk.logger = {
      log: jest.fn(),
      warn: jest.fn(),
      alwaysError: jest.fn(),
    };
    sdk._walletStatus = {
      isDeploying: false,
      isDeployed: true,
      isRegistering: false,
      isSessionActive: false,
      isReady: true,
      isSlotDeploying: false,
      isSlotDeployed: false,
    };
    sdk.walletStatusListeners = new Set();
    sdk.getAddress = jest.fn().mockReturnValue('0xabc');
    sdk.slotProvider = {
      getClassHashAt: jest.fn().mockResolvedValue('0xclass'),
    };
    sdk.slotTransactionManager = {
      isSessionRegistered: jest.fn().mockResolvedValue(false),
    };
    sdk.autoRegisterSessionOnSlot = jest.fn().mockResolvedValue(undefined);

    await sdk._runSlotDeployBackground();

    expect(sdk.slotTransactionManager.isSessionRegistered).toHaveBeenCalledTimes(1);
    expect(sdk.autoRegisterSessionOnSlot).toHaveBeenCalledTimes(1);
  });
});
