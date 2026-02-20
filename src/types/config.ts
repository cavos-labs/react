export interface CavosConfig {
  /** Your app ID from Cavos dashboard (https://cavos.xyz/dashboard) */
  appId: string;
  /** Backend URL for OAuth orchestration (default: https://cavos.xyz) */
  backendUrl?: string;
  /** StarkNet RPC URL (optional, uses default if not provided) */
  starknetRpcUrl?: string;
  /** Network to use (default: sepolia) */
  network?: 'mainnet' | 'sepolia';
  /** Paymaster API key for gasless transactions */
  paymasterApiKey?: string;
  /** Custom paymaster URL (overrides default AVNU URLs) */
  paymasterUrl?: string;
  /** Enable debug logging (default: false) */
  enableLogging?: boolean;
  /** OAuth Wallet configuration (optional, uses defaults for network if not provided) */
  oauthWallet?: Partial<OAuthWalletConfig>;
  /** Session configuration for session keys */
  session?: SessionConfig;
}

/** Configuration for session key duration and default policy */
export interface SessionConfig {
  /** Session duration in seconds (default: 86400 = 24 hours) */
  sessionDuration?: number;
  /** Grace period for renewal in seconds (default: 172800 = 48 hours) */
  renewalGracePeriod?: number;
  /** Default policy applied to all sessions (allowed contracts, spending limits, max calls) */
  defaultPolicy?: import('./session').SessionKeyPolicy;
}

/** Configuration for OAuth Wallet mode */
export interface OAuthWalletConfig {
  /** Address of the deployed JWKS Registry contract */
  jwksRegistryAddress: string;
  /** Address of the OAuth Account class hash (for deployment) */
  cavosAccountClassHash: string;
  /** Salt for address derivation (default: '0') */
  salt?: string;
  /**
   * @deprecated No longer used - deployment is now self-custodial via PaymasterRpc
   */
  deployerContractAddress?: string;
  /**
   * @deprecated No longer used - no relayer dependency
   */
  relayerAddress?: string;
  /**
   * @deprecated No longer used - no relayer dependency
   */
  relayerPrivateKey?: string;
}

export interface AuthConfig {
  backendUrl: string;
  appId: string;
}
