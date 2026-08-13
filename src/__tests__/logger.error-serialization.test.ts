import { Logger } from '../utils/logger';
import { CavosError } from '../utils/errors';

/**
 * Regression: Capacitor's native console bridge JSON-serializes console arguments.
 * `message` and `stack` are non-enumerable on Error, so a raw Error printed as `{}`
 * and integrators lost the entire cause of Slot registration failures.
 */
describe('Logger error serialization', () => {
  let spy: jest.SpyInstance;

  beforeEach(() => {
    spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    spy.mockRestore();
  });

  const loggedJson = () => JSON.stringify(spy.mock.calls[0].slice(1));

  it('keeps the message of a plain Error through JSON serialization', () => {
    new Logger(false).alwaysError('boom happened:', new Error('boom'));

    const json = loggedJson();
    expect(json).toContain('boom');
    expect(json).not.toBe('[{}]');
  });

  it('preserves the normalized code and details of a CavosError', () => {
    new Logger(false).alwaysError(
      'failed:',
      new CavosError('JWKS_KID_NOT_REGISTERED', 'kid "abc" is not registered', { kid: 'abc' }),
    );

    const json = loggedJson();
    expect(json).toContain('JWKS_KID_NOT_REGISTERED');
    expect(json).toContain('abc');
  });

  it('follows the cause chain where starknet.js hides the revert reason', () => {
    const inner = new Error('Transaction reverted: Invalid session key signature');
    const outer = new Error('RPC request failed');
    (outer as any).baseError = inner;

    new Logger(false).alwaysError('tx failed:', outer);

    expect(loggedJson()).toContain('Invalid session key signature');
  });

  it('still redacts sensitive values inside an error', () => {
    const err = new Error('nope') as any;
    err.sessionPrivateKey = '0x1234';

    new Logger(false).alwaysError('failed:', err);

    const json = loggedJson();
    expect(json).toContain('[REDACTED]');
    expect(json).not.toContain('0x1234');
  });
});
