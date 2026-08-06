import { OAuthTransactionManager, type SessionStatus } from '../oauth/OAuthTransactionManager';
import type { Call } from 'starknet';

const call: Call = {
  contractAddress: '0x123',
  entrypoint: 'play',
  calldata: [],
};

function createManager(status: SessionStatus) {
  const oauthManager = {
    getSession: jest.fn().mockReturnValue({ jwt: 'jwt', walletAddress: '0xabc' }),
    buildJWTSignatureData: jest.fn().mockResolvedValue(['0xjwt']),
    buildSessionSignature: jest.fn().mockReturnValue(['0xsession']),
  };
  const manager = Object.create(OAuthTransactionManager.prototype) as OAuthTransactionManager & Record<string, any>;
  manager.oauthManager = oauthManager;
  manager.chainIdOverride = '0x1';
  manager.provider = { getBlock: jest.fn().mockResolvedValue({ timestamp: 100 }) };
  manager.generateOutsideExecutionNonce = jest.fn().mockReturnValue('0xnonce');
  manager.computeOutsideExecutionMessageHash = jest.fn().mockReturnValue('0xhash');
  manager.buildOutsideExecutionCalldata = jest.fn().mockReturnValue([]);
  manager.getSessionStatus = jest.fn().mockResolvedValue(status);

  const relayer = {
    address: '0xrelayer',
    execute: jest.fn().mockResolvedValue({ transaction_hash: '0xtx' }),
  };
  return { manager, oauthManager, relayer };
}

describe('OAuthTransactionManager Slot signature selection', () => {
  it.each([
    ['unregistered', { registered: false, active: false, expired: false, canRenew: false }],
    ['inactive', { registered: true, active: false, expired: false, canRenew: false }],
    ['expired', { registered: true, active: false, expired: true, canRenew: false }],
  ] as Array<[string, SessionStatus]>)('uses JWT for an %s session', async (_label, status) => {
    const { manager, oauthManager, relayer } = createManager(status);

    await expect(manager.executeViaOutsideExecution([call], relayer as any, { sessionStatus: status }))
      .resolves.toBe('0xtx');

    expect(oauthManager.buildJWTSignatureData).toHaveBeenCalledWith('0xhash');
    expect(oauthManager.buildSessionSignature).not.toHaveBeenCalled();
  });

  it('uses SESSION_V1 only for a registered, active, unexpired session', async () => {
    const status: SessionStatus = {
      registered: true,
      active: true,
      expired: false,
      canRenew: false,
    };
    const { manager, oauthManager, relayer } = createManager(status);

    await expect(manager.executeViaOutsideExecution([call], relayer as any, { sessionStatus: status }))
      .resolves.toBe('0xtx');

    expect(oauthManager.buildJWTSignatureData).not.toHaveBeenCalled();
    expect(oauthManager.buildSessionSignature).toHaveBeenCalledWith('0xhash', [call]);
  });
});
