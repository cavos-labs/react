import { CavosSDK } from '../CavosSDK';
import type { Call } from 'starknet';

const call: Call = {
  contractAddress: '0x123',
  entrypoint: 'buy_card',
  calldata: ['0x1'],
};

function createSlotSdk({
  status,
  renewRejects = false,
}: {
  status: { registered: boolean; active: boolean; expired: boolean; canRenew: boolean };
  renewRejects?: boolean;
}) {
  const sdk = Object.create(CavosSDK.prototype) as CavosSDK & Record<string, any>;
  const newSession = {
    walletAddress: '0xabc',
    sessionPrivateKey: '0x1',
    sessionPubKey: '0x2',
    nonce: '0x3',
    nonceParams: {
      sessionPubKey: '0x2',
      validAfter: 1n,
      validUntil: 2n,
      renewalDeadline: 3n,
      randomness: 4n,
    },
  };

  sdk._walletStatus = {
    isDeploying: false,
    isDeployed: true,
    isRegistering: false,
    isSessionActive: status.active,
    isReady: true,
    isSlotDeploying: false,
    isSlotDeployed: true,
  };
  sdk.walletStatusListeners = new Set();
  sdk.slotRelayerAccount = { address: '0xrelayer' };
  sdk.oauthWalletManager = {
    generateNewSession: jest.fn().mockResolvedValue(newSession),
    commitRenewedSession: jest.fn(),
  };
  sdk.slotTransactionManager = {
    getSessionStatus: jest.fn().mockResolvedValue(status),
    executeViaOutsideExecution: jest.fn().mockResolvedValue('0xoutside'),
    renewSessionOnNoFeeChain: renewRejects
      ? jest.fn().mockRejectedValue(new Error('renew failed'))
      : jest.fn().mockResolvedValue('0xrenew'),
    executeOnNoFeeChain: jest.fn().mockImplementation(() => {
      if (status.expired && !status.canRenew) {
        throw new Error('SESSION_EXPIRED: Session has expired outside grace period. Please login again.');
      }
      return Promise.resolve('0xexecute');
    }),
  };

  return { sdk, newSession };
}

describe('CavosSDK.executeOnSlot', () => {
  it('executes directly when the Slot session is active', async () => {
    const { sdk } = createSlotSdk({
      status: { registered: true, active: true, expired: false, canRenew: false },
    });

    await expect(sdk.executeOnSlot(call)).resolves.toBe('0xexecute');

    expect(sdk.slotTransactionManager.renewSessionOnNoFeeChain).not.toHaveBeenCalled();
    expect(sdk.slotTransactionManager.getSessionStatus).toHaveBeenCalledTimes(1);
    expect(sdk.slotTransactionManager.executeOnNoFeeChain).toHaveBeenCalledWith([call], expect.objectContaining({
      waitForTransaction: false,
      sessionStatus: expect.objectContaining({
        registered: true,
        active: true,
        expired: false,
      }),
    }));
  });

  it('renews an expired Slot session inside grace before executing the original call', async () => {
    const { sdk, newSession } = createSlotSdk({
      status: { registered: true, active: true, expired: true, canRenew: true },
    });

    await expect(sdk.executeOnSlot(call, { waitForTransaction: true })).resolves.toBe('0xexecute');

    expect(sdk.oauthWalletManager.generateNewSession).toHaveBeenCalledTimes(1);
    expect(sdk.slotTransactionManager.renewSessionOnNoFeeChain).toHaveBeenCalledWith(newSession, {
      waitForTransaction: true,
    });
    expect(sdk.oauthWalletManager.commitRenewedSession).toHaveBeenCalledWith(newSession);
    expect(sdk.slotTransactionManager.getSessionStatus).toHaveBeenCalledTimes(1);
    expect(sdk.slotTransactionManager.executeOnNoFeeChain).toHaveBeenCalledWith([call], expect.objectContaining({
      waitForTransaction: true,
      sessionStatus: expect.objectContaining({
        registered: true,
        active: true,
        expired: false,
      }),
    }));
  });

  it('keeps the old session when Slot renewal fails', async () => {
    const { sdk } = createSlotSdk({
      status: { registered: true, active: true, expired: true, canRenew: true },
      renewRejects: true,
    });

    await expect(sdk.executeOnSlot(call)).rejects.toThrow('renew failed');

    expect(sdk.oauthWalletManager.commitRenewedSession).not.toHaveBeenCalled();
    expect(sdk.slotTransactionManager.executeOnNoFeeChain).not.toHaveBeenCalled();
  });

  it('keeps outside-grace expiration as a login-required error', async () => {
    const { sdk } = createSlotSdk({
      status: { registered: true, active: false, expired: true, canRenew: false },
    });

    await expect(sdk.executeOnSlot(call)).rejects.toThrow('SESSION_EXPIRED');

    expect(sdk.oauthWalletManager.generateNewSession).not.toHaveBeenCalled();
    expect(sdk.slotTransactionManager.renewSessionOnNoFeeChain).not.toHaveBeenCalled();
  });

  it('uses outside execution for an unregistered Slot session', async () => {
    const { sdk } = createSlotSdk({
      status: { registered: false, active: false, expired: false, canRenew: false },
    });

    await expect(sdk.executeOnSlot(call)).resolves.toBe('0xoutside');

    expect(sdk.slotTransactionManager.executeViaOutsideExecution).toHaveBeenCalledWith(
      [call],
      sdk.slotRelayerAccount,
      expect.objectContaining({
        waitForTransaction: false,
        sessionStatus: expect.objectContaining({ registered: false }),
      }),
    );
    expect(sdk.slotTransactionManager.getSessionStatus).toHaveBeenCalledTimes(1);
    expect(sdk.slotTransactionManager.executeOnNoFeeChain).not.toHaveBeenCalled();
  });
});
