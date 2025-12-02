import { Call } from 'starknet';

export interface SessionPolicy {
  expiresAt: number;
  allowedMethods: string[];
  spendingLimits?: {
    maxAmount: string;
    period: number;
  };
  whitelistedAddresses?: string[];
}

export interface SessionKey {
  publicKey: string;
  privateKey: string;
  policy: SessionPolicy;
  createdAt: number;
}

export interface SessionData {
  sessionKey: SessionKey;
  accountAddress: string;
  chainId: string;
}

export interface ExecuteOptions {
  gasless?: boolean;
  maxFee?: string;
}
