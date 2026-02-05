/**
 * Custom error classes for email verification
 */

export class EmailVerificationRequiredError extends Error {
  constructor(
    message: string,
    public email: string
  ) {
    super(message);
    this.name = 'EmailVerificationRequiredError';
    Object.setPrototypeOf(this, EmailVerificationRequiredError.prototype);
  }
}

export class EmailNotVerifiedError extends Error {
  constructor(
    message: string,
    public email: string
  ) {
    super(message);
    this.name = 'EmailNotVerifiedError';
    Object.setPrototypeOf(this, EmailNotVerifiedError.prototype);
  }
}
