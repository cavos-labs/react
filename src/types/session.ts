import { Call } from 'starknet';

export interface SessionPolicy {
  allowedMethods: Array<{
    contractAddress: string;
    selector: string;
  }>;
  expiresAt: number;
  maxFees?: Array<{
    tokenAddress: string;
    maxAmount: string;
  }>;
}

export interface CavosSessionKey {
  publicKey: string;
  privateKey: string;
  policy: SessionPolicy;
  createdAt: number;
}

export interface SessionData {
  sessionKey: CavosSessionKey;
  accountAddress: string;
  chainId: string;
}

export interface ExecuteOptions {
  gasless?: boolean;
  maxFee?: string;
}
