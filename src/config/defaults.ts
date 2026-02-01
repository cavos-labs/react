import { OAuthWalletConfig } from '../types/config';

export const DEFAULT_OAUTH_CONFIG_SEPOLIA: OAuthWalletConfig = {
    jwksRegistryAddress: '0x05a19f14719dec9e27eb2aa38c5b68277bdb5c41570e548504722f737a3da6c6',
    cavosAccountClassHash: '0x6c2525f28e5f0f39a8413c10576a394388ae222c1fc6c03f2d43ceb023259',
    salt: '0x0',
    deployerContractAddress: '0x0593443b1719fb6a948f653fdb35850b6d07b5a3aecf1ab203727dbfd1c52757',
    relayerAddress: '0x3d57e5e7421a70396a69274e8dd57dadfc5e38541d27e7a742116c3ef34bb33',
    relayerPrivateKey: '0x4f7f6f0f318769325539bad869cde209e2cc559753517b9a825314bc393ede',
};

// Placeholder for mainnet defaults
export const DEFAULT_OAUTH_CONFIG_MAINNET: OAuthWalletConfig = {
    jwksRegistryAddress: '0x07787f624d6869ae306dc17b49174b284dbadd1e999c1c8733ce72eb7ac518c2',
    cavosAccountClassHash: '0x6c2525f28e5f0f39a8413c10576a394388ae222c1fc6c03f2d43ceb023259',
    salt: '0x0',
    deployerContractAddress: '0x02e058d2c9d65d29e493be3eb699c2bd1b9216cb0f1cec868be1ac521931b9c8',
    relayerAddress: '0x1d50c5720b760213700aa19ae017bd1bf54ab208325093899df658ac2259897',
    relayerPrivateKey: '0x61d6bcc6dd46bacd5aa23152703a455b306ecad09320f4ed28ec9b4bb27f62e',
};
