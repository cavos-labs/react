import { CavosSDK } from '../CavosSDK';
import { CavosError } from '../utils/errors';

function createSdk(registerError: unknown) {
  const sdk = Object.create(CavosSDK.prototype) as CavosSDK & Record<string, any>;
  sdk._walletStatus = {
    isDeploying: false,
    isDeployed: true,
    isRegistering: false,
    isSessionActive: false,
    isReady: false,
    isSlotDeploying: false,
    isSlotDeployed: true,
    isSlotSessionActive: false,
    isSlotReady: false,
  };
  sdk.walletStatusListeners = new Set();
  sdk._slotRegistrationPromise = null;
  sdk.slotRelayerAccount = { address: '0xrelayer' };
  sdk.logger = { log: jest.fn(), alwaysError: jest.fn() };
  sdk.isJwtExpired = () => false;
  sdk.slotTransactionManager = {
    registerCurrentSessionViaOutside: jest.fn().mockRejectedValue(registerError),
    getSessionStatus: jest.fn(),
  };
  return sdk;
}

describe('CavosSDK Slot error reporting', () => {
  it('exposes the normalized code alongside the message', async () => {
    const sdk = createSdk(
      new CavosError('JWKS_KID_NOT_REGISTERED', 'kid "abc" is not registered', { kid: 'abc' }),
    );

    await expect(sdk.runAutoRegisterSessionOnSlot()).rejects.toThrow(CavosError);

    const status = sdk.getWalletStatus();
    expect(status.slotError).toContain('abc');
    expect(status.slotErrorCode).toBe('JWKS_KID_NOT_REGISTERED');
  });

  it('logs the message as its own argument so hosts that stringify still show it', async () => {
    const sdk = createSdk(new Error('relayer exploded'));

    await expect(sdk.runAutoRegisterSessionOnSlot()).rejects.toThrow('relayer exploded');

    expect(sdk.logger.alwaysError).toHaveBeenCalledWith(
      expect.stringContaining('Auto session registration on Slot failed'),
      'relayer exploded',
      expect.any(Error),
    );
  });

  it('leaves no stale code behind when a later write clears the error', async () => {
    const sdk = createSdk(new CavosError('SLOT_SESSION_NOT_ACTIVE', 'not active'));
    await expect(sdk.runAutoRegisterSessionOnSlot()).rejects.toThrow(CavosError);
    expect(sdk.getWalletStatus().slotErrorCode).toBe('SLOT_SESSION_NOT_ACTIVE');

    sdk.updateWalletStatus({ slotError: undefined });

    expect(sdk.getWalletStatus().slotErrorCode).toBeUndefined();
  });
});
