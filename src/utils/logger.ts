/**
 * Safe logging utility for Cavos SDK
 * Sanitizes sensitive data before logging
 */

const SENSITIVE_KEYS = [
  'privateKey',
  'sessionPrivateKey',
  'relayerPrivateKey',
  'jwt',
  'password',
  'secret',
  'apiKey',
  'token',
];

/**
 * Convert an error into a plain object that survives JSON serialization.
 *
 * `message` and `stack` are non-enumerable on Error, and starknet.js exposes the
 * on-chain revert reason through non-enumerable `baseError` / `response` members.
 * Hosts that JSON-stringify console arguments — notably Capacitor's native console
 * bridge — therefore print a bare `Error` as `{}` and lose the entire cause.
 */
function serializeError(err: any, depth = 0): any {
  const out: Record<string, any> = {
    name: err?.name,
    message: err?.message ?? String(err),
  };

  if (typeof err?.code === 'string' || typeof err?.code === 'number') {
    out.code = err.code;
  }
  if (err?.details !== undefined) out.details = err.details;
  if (err?.stack) out.stack = err.stack;

  // Own enumerable extras (starknet.js RpcError carries `request`, `baseError`, …).
  for (const [key, value] of Object.entries(err ?? {})) {
    if (key in out || key === 'cause' || key === 'baseError') continue;
    out[key] = value;
  }

  // Follow the cause chain — that is where the revert reason usually lives.
  if (depth < 3) {
    const nested = err?.cause ?? err?.baseError;
    if (nested !== undefined && nested !== null) {
      out.cause = typeof nested === 'object' ? serializeError(nested, depth + 1) : nested;
    }
  }

  return out;
}

/**
 * Redact sensitive values from objects
 */
function sanitize(data: any): any {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    // Redact JWT tokens (3 parts separated by dots)
    if (data.split('.').length === 3 && data.length > 100) {
      return `[JWT:${data.substring(0, 20)}...]`;
    }
    // Redact private keys (hex strings starting with 0x and > 40 chars)
    if (data.startsWith('0x') && data.length > 40) {
      return `[REDACTED:${data.substring(0, 10)}...]`;
    }
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(sanitize);
  }

  // Error, or an error-like object from another realm / a bundled copy of starknet.js
  // where `instanceof Error` does not hold.
  if (data instanceof Error || (typeof data?.message === 'string' && typeof data?.stack === 'string')) {
    // Sanitize the fields, not the wrapper — the wrapper is itself error-shaped
    // (it has message + stack) and would re-enter this branch forever.
    return sanitizeObject(serializeError(data));
  }

  if (typeof data === 'object') {
    return sanitizeObject(data);
  }

  return data;
}

function sanitizeObject(data: any): any {
  const sanitized: any = {};
  for (const [key, value] of Object.entries(data)) {
    const keyLower = key.toLowerCase();
    const isSensitive = SENSITIVE_KEYS.some(sk => keyLower.includes(sk.toLowerCase()));

    if (isSensitive) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = sanitize(value);
    }
  }
  return sanitized;
}

export class Logger {
  private enabled: boolean;
  private prefix: string;

  constructor(enabled: boolean = false, prefix: string = '[CavosSDK]') {
    this.enabled = enabled;
    this.prefix = prefix;
  }

  log(...args: any[]) {
    if (!this.enabled) return;
    const sanitized = args.map(sanitize);
    console.log(this.prefix, ...sanitized);
  }

  warn(...args: any[]) {
    if (!this.enabled) return;
    const sanitized = args.map(sanitize);
    console.warn(this.prefix, ...sanitized);
  }

  error(...args: any[]) {
    if (!this.enabled) return;
    const sanitized = args.map(sanitize);
    console.error(this.prefix, ...sanitized);
  }

  /**
   * Always log errors, even if logging is disabled
   * (but still sanitize)
   */
  alwaysError(...args: any[]) {
    const sanitized = args.map(sanitize);
    console.error(this.prefix, ...sanitized);
  }
}
