export interface SlotConfig {
  /** RPC URL of the Cartridge-managed Katana Slot instance (forked from mainnet) */
  rpcUrl: string;
  /**
   * Chain ID for the Slot chain.
   * Katana nodes report SN_MAIN via RPC but internally use a custom chain ID.
   * You MUST provide the exact internal VM chain ID to avoid signature mismatches.
   * Find it by calling get_tx_info().chain_id from a deployed Cairo contract.
   */
  chainId?: string;
  /**
   * Cavos Account class hash on this Slot chain.
   * Required for blank (non-forked) Katana instances where the class was declared
   * separately via deploy_to_katana.js. If omitted, uses the same class hash as
   * the primary network (mainnet/sepolia).
   */
  /**
   * Address of the account that will act as the relayer for sending `execute_from_outside_v2`
   * on the Katana slot. Defaults to the primary network's relayer, but MUST be overridden
   * with a funded account address on a blank Katana instance.
   */
  relayerAddress?: string;
  /**
   * Private key for the relayer account on the Katana slot.
   */
  relayerPrivateKey?: string;
}

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
  /**
   * Cartridge Slot configuration. When provided, wallets are automatically
   * deployed to the Slot chain after deploying on the primary network.
   * No paymaster needed — Slot runs with no_fee = true.
   */
  slot?: SlotConfig;
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
  /**
   * Stable OAuth Account class hash used for deterministic address derivation.
   * Keep this fixed once accounts exist on-chain, otherwise the derived address changes.
   * It is also the default deployment class hash.
   * The upgrade target is not configurable — see `LATEST_CAVOS_ACCOUNT_CLASS_HASH_*` in config/defaults.ts.
   */
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
