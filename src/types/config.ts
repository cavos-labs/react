import type { PasskeyModalConfig } from './modal';

export interface CavosConfig {
  /** Your app ID from Cavos dashboard (https://cavos.xyz/dashboard) */
  appId: string;
  /** Backend URL for OAuth orchestration (default: https://cavos.xyz) */
  backendUrl?: string;
  /** StarkNet RPC URL (optional, uses default if not provided) */
  starknetRpcUrl?: string;
  /** Network to use (default: sepolia) */
  network?: 'mainnet' | 'sepolia';
  /** AVNU Paymaster API key for gasless transactions (optional, uses Cavos shared key if not provided) */
  paymasterApiKey?: string;
  /** Enable debug logging (default: false) */
  enableLogging?: boolean;
  /** Passkey modal configuration */
  passkeyModal?: PasskeyModalConfig;
}

export interface AuthConfig {
  backendUrl: string;
  appId: string;
}
