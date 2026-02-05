/**
 * Safe logging utility for Cavos SDK
 * Sanitizes sensitive data before logging
 */

const SENSITIVE_KEYS = [
  'privateKey',
  'ephemeralPrivateKey',
  'relayerPrivateKey',
  'jwt',
  'password',
  'secret',
  'apiKey',
  'token',
];

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

  if (typeof data === 'object') {
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

  return data;
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
