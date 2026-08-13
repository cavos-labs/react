/**
 * Normalized SDK errors.
 *
 * Host consoles (notably Capacitor's native bridge) JSON-serialize whatever is
 * passed to console.error, and a plain Error has no enumerable own properties —
 * it prints as `{}`. Attaching a stable `code` gives integrators something they
 * can branch on and report without depending on message text or on the console
 * rendering the Error at all.
 */

export type CavosErrorCode =
  /** The JWT's `kid` is absent from the on-chain JWKS registry of the queried chain. */
  | 'JWKS_KID_NOT_REGISTERED'
  /** Slot is configured but no relayer account is available to submit the outer tx. */
  | 'SLOT_RELAYER_UNAVAILABLE'
  /** Slot session registration was submitted but the session is not active on-chain. */
  | 'SLOT_SESSION_NOT_ACTIVE';
// Note: `JWT_EXPIRED` is carried by JwtExpiredError in CavosSDK.ts, which predates this
// module and is part of the public API. getErrorCode() reads it just the same.

export class CavosError extends Error {
  readonly code: CavosErrorCode;
  /** Extra context, surfaced by the logger. Never put secrets here. */
  readonly details?: Record<string, unknown>;

  constructor(code: CavosErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'CavosError';
    this.code = code;
    this.details = details;
    // Keep instanceof working when the SDK is compiled down to ES5.
    Object.setPrototypeOf(this, CavosError.prototype);
  }
}

const LOGGED = Symbol.for('cavos.errorLogged');

/**
 * Mark an error as already reported, so an outer catch that re-catches a rethrown
 * error does not log the same failure a second time under a different heading.
 */
export function markErrorLogged<T>(err: T): T {
  try {
    if (err && typeof err === 'object') {
      Object.defineProperty(err, LOGGED, { value: true, enumerable: false, configurable: true });
    }
  } catch {
    // Frozen or exotic error objects: fall through, worst case is a duplicate log line.
  }
  return err;
}

export function wasErrorLogged(err: unknown): boolean {
  return !!(err && typeof err === 'object' && (err as any)[LOGGED] === true);
}

/** Read a normalized error code off an unknown thrown value, if it has one. */
export function getErrorCode(err: unknown): string | undefined {
  if (err instanceof CavosError) return err.code;
  const code = (err as { code?: unknown })?.code;
  return typeof code === 'string' ? code : undefined;
}
