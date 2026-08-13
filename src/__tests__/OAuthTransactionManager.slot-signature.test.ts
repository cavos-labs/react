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
  manager.provider = {
    getBlock: jest.fn().mockResolvedValue({ timestamp: 100 }),
    getNonceForAddress: jest.fn().mockResolvedValue('0x204'),
  };
  manager.generateOutsideExecutionNonce = jest.fn().mockReturnValue('0xnonce');
  manager.computeOutsideExecutionMessageHash = jest.fn().mockReturnValue('0xhash');
  manager.buildOutsideExecutionCalldata = jest.fn().mockReturnValue([]);
  manager.getSessionStatus = jest.fn().mockResolvedValue(status);
  manager.logger = { warn: jest.fn(), alwaysError: jest.fn() };

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

    // The JWKS modulus must be read from the chain the tx executes on — this manager's
    // provider — not from the primary-network provider held by OAuthWalletManager.
    expect(oauthManager.buildJWTSignatureData).toHaveBeenCalledWith(
      '0xhash',
      undefined,
      { provider: manager.provider },
    );
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

  it('retries a stale relayer nonce with the nonce expected by Slot', async () => {
    const status: SessionStatus = {
      registered: false,
      active: false,
      expired: false,
      canRenew: false,
    };
    const { manager, relayer } = createManager(status);
    relayer.execute
      .mockRejectedValueOnce(new Error(
        'Invalid transaction nonce: "Invalid transaction nonce of contract. ' +
        'Account nonce: 0x203; got: 0x202."',
      ))
      .mockResolvedValueOnce({ transaction_hash: '0xretry' });

    await expect(manager.executeViaOutsideExecution([call], relayer as any, { sessionStatus: status }))
      .resolves.toBe('0xretry');

    expect(relayer.execute).toHaveBeenCalledTimes(2);
    expect(relayer.execute.mock.calls[0][1]).not.toHaveProperty('nonce');
    expect(relayer.execute.mock.calls[1][1]).toEqual(expect.objectContaining({ nonce: 0x203n }));
  });

  it('does not retry unrelated relayer failures', async () => {
    const status: SessionStatus = {
      registered: false,
      active: false,
      expired: false,
      canRenew: false,
    };
    const { manager, relayer } = createManager(status);
    relayer.execute.mockRejectedValueOnce(new Error('contract reverted'));

    await expect(manager.executeViaOutsideExecution([call], relayer as any, { sessionStatus: status }))
      .rejects.toThrow('contract reverted');

    expect(relayer.execute).toHaveBeenCalledTimes(1);
  });

  it('recognizes RPC error code 52 and refreshes the pre-confirmed nonce', async () => {
    const status: SessionStatus = {
      registered: false,
      active: false,
      expired: false,
      canRenew: false,
    };
    const { manager, relayer } = createManager(status);
    relayer.execute
      .mockRejectedValueOnce({ code: 52, message: 'RPC: starknet_addInvokeTransaction' })
      .mockResolvedValueOnce({ transaction_hash: '0xrefreshed' });

    await expect(manager.executeViaOutsideExecution([call], relayer as any, { sessionStatus: status }))
      .resolves.toBe('0xrefreshed');

    expect(manager.provider.getNonceForAddress).toHaveBeenCalledWith(
      relayer.address,
      'pre_confirmed',
    );
    expect(relayer.execute.mock.calls[1][1]).toEqual(expect.objectContaining({ nonce: 0x204n }));
  });

  it('serializes relayer writes across transaction manager instances', async () => {
    const status: SessionStatus = {
      registered: false,
      active: false,
      expired: false,
      canRenew: false,
    };
    const first = createManager(status);
    const second = createManager(status);
    let releaseFirst!: (value: { transaction_hash: string }) => void;
    const sharedRelayer = {
      address: '0xshared-relayer',
      execute: jest.fn()
        .mockImplementationOnce(() => new Promise(resolve => { releaseFirst = resolve; }))
        .mockResolvedValueOnce({ transaction_hash: '0xsecond' }),
    };

    const firstExecution = first.manager.executeViaOutsideExecution(
      [call], sharedRelayer as any, { sessionStatus: status },
    );
    await new Promise(resolve => setImmediate(resolve));
    const secondExecution = second.manager.executeViaOutsideExecution(
      [call], sharedRelayer as any, { sessionStatus: status },
    );
    await new Promise(resolve => setImmediate(resolve));

    expect(sharedRelayer.execute).toHaveBeenCalledTimes(1);

    releaseFirst({ transaction_hash: '0xfirst' });
    await expect(Promise.all([firstExecution, secondExecution]))
      .resolves.toEqual(['0xfirst', '0xsecond']);
    expect(sharedRelayer.execute).toHaveBeenCalledTimes(2);
  });
});
