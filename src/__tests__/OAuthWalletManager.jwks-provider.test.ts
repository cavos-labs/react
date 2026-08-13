import { OAuthWalletManager } from '../oauth/OAuthWalletManager';
import { CavosError } from '../utils/errors';

const b64url = (obj: unknown) =>
  Buffer.from(JSON.stringify(obj)).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const JWT = [
  b64url({ alg: 'RS256', kid: 'test-kid', typ: 'JWT' }),
  b64url({ sub: 'user-1', iss: 'https://accounts.google.com', aud: 'client', exp: 4102444800, nonce: '0x9' }),
  Buffer.alloc(256, 7).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
].join('.');

function createManager() {
  const manager = new OAuthWalletManager(
    { cavosAccountClassHash: '0x1', jwksRegistryAddress: '0x2', salt: '0x3' },
    'https://backend.test',
    'app-id',
    'https://primary-rpc.test',
  ) as OAuthWalletManager & Record<string, any>;

  manager.session = {
    sessionPrivateKey: '0x1',
    sessionPubKey: '0x2',
    jwt: JWT,
    jwtClaims: {
      sub: 'user-1',
      iss: 'https://accounts.google.com',
      aud: 'client',
      exp: 4102444800,
    },
    nonce: '0x9',
    nonceParams: { validUntil: 4102444800, randomness: '0x5' },
    walletAddress: '0xabc',
    walletName: 'test',
  };
  return manager;
}

/**
 * Regression: the account contract verifies the RSA signature against its OWN chain's
 * JWKS registry. Building the Garaga witness from a different chain's modulus produces
 * a signature that reverts on-chain — the cause of intermittent Slot login failures,
 * where the SDK read the mainnet registry while executing on Katana.
 */
describe('OAuthWalletManager JWKS provider routing', () => {
  const zeroLimbs = () => Promise.resolve(new Array(28).fill('0x0'));

  it('reads get_key from the provider it is given, not the primary provider', async () => {
    const manager = createManager();
    const primaryCall = jest.fn().mockImplementation(zeroLimbs);
    const slotCall = jest.fn().mockImplementation(zeroLimbs);
    manager.provider = { callContract: primaryCall };
    const slotProvider = { callContract: slotCall, channel: { nodeUrl: 'https://slot-rpc.test' } };

    await expect(
      manager.buildJWTSignatureData('0x1', undefined, { provider: slotProvider as any }),
    ).rejects.toThrow(CavosError);

    expect(slotCall).toHaveBeenCalledTimes(1);
    expect(slotCall.mock.calls[0][0]).toEqual(
      expect.objectContaining({ contractAddress: '0x2', entrypoint: 'get_key' }),
    );
    expect(primaryCall).not.toHaveBeenCalled();
  });

  it('falls back to the primary provider when no provider is given', async () => {
    const manager = createManager();
    const primaryCall = jest.fn().mockImplementation(zeroLimbs);
    manager.provider = { callContract: primaryCall };

    await expect(manager.buildJWTSignatureData('0x1')).rejects.toThrow(CavosError);
    expect(primaryCall).toHaveBeenCalledTimes(1);
  });

  it('reports an unregistered kid with a normalized code and the chain it queried', async () => {
    const manager = createManager();
    manager.provider = { callContract: jest.fn() };
    const slotProvider = {
      callContract: jest.fn().mockImplementation(zeroLimbs),
      channel: { nodeUrl: 'https://slot-rpc.test' },
    };

    const err = await manager
      .buildJWTSignatureData('0x1', undefined, { provider: slotProvider as any })
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(CavosError);
    expect((err as CavosError).code).toBe('JWKS_KID_NOT_REGISTERED');
    expect((err as CavosError).message).toContain('test-kid');
    expect((err as CavosError).message).toContain('https://slot-rpc.test');
  });
});
