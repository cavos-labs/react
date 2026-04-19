import { OAuthWalletConfig } from '../types/config';

/** Default Cavos-managed relayer for Slot (Katana) — handles execute_from_outside_v2 for JWT session registration. */
export const DEFAULT_SLOT_RELAYER_ADDRESS = '0x1d50c5720b760213700aa19ae017bd1bf54ab208325093899df658ac2259897';
export const DEFAULT_SLOT_RELAYER_PRIVATE_KEY = '0x61d6bcc6dd46bacd5aa23152703a455b306ecad09320f4ed28ec9b4bb27f62e';

export const DEFAULT_OAUTH_CONFIG_SEPOLIA: OAuthWalletConfig = {
    jwksRegistryAddress: '0x0112c6a8a69e4d9a2e74b4638e1495d69266de9f6f796727d4a52a7ab0a48db2',
    cavosAccountClassHash: '0x44da9541701ddd2f9ff59be13f7ef10d41577f6a828b41ff1931109faf2b984',
    salt: '0x0',
};

export const DEFAULT_OAUTH_CONFIG_MAINNET: OAuthWalletConfig = {
    jwksRegistryAddress: '0x076ff6853197538b4d4c925b2c775014fae9b5c14f63262b13f2e49f732e21f7',
    cavosAccountClassHash: '0x44da9541701ddd2f9ff59be13f7ef10d41577f6a828b41ff1931109faf2b984',
    salt: '0x0',
};

/**
 * Latest Cavos account class hash the SDK will upgrade existing accounts to.
 * Not configurable by the dev — kept here so every client converges to the
 * same target after a new account implementation is deployed.
 */
export const LATEST_CAVOS_ACCOUNT_CLASS_HASH_SEPOLIA = '0x44da9541701ddd2f9ff59be13f7ef10d41577f6a828b41ff1931109faf2b984';
export const LATEST_CAVOS_ACCOUNT_CLASS_HASH_MAINNET = '0x44da9541701ddd2f9ff59be13f7ef10d41577f6a828b41ff1931109faf2b984';

export function getLatestCavosAccountClassHash(network: 'mainnet' | 'sepolia'): string {
    return network === 'mainnet'
        ? LATEST_CAVOS_ACCOUNT_CLASS_HASH_MAINNET
        : LATEST_CAVOS_ACCOUNT_CLASS_HASH_SEPOLIA;
}
