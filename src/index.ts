// Main SDK
export { CavosSDK } from './CavosSDK';
export type { WalletStatus, WalletStatusListener } from './CavosSDK';

// Types
export * from './types';

// React integration
export * from './react';

// Managers (for advanced usage)
export { SessionManager } from './session/SessionManager';
export { PaymasterIntegration } from './paymaster/PaymasterIntegration';

// OAuth Wallet (for oauth-wallet auth mode)
export { OAuthWalletManager, OAuthTransactionManager, NonceManager, AddressSeedManager } from './oauth';

// Email verification errors
export { EmailVerificationRequiredError, EmailNotVerifiedError } from './oauth/errors';

// Utilities
export { CryptoUtils } from './crypto/encryption';
