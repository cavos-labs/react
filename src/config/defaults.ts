import { OAuthWalletConfig } from '../types/config';

export const DEFAULT_OAUTH_CONFIG_SEPOLIA: OAuthWalletConfig = {
    jwksRegistryAddress: '0x0112c6a8a69e4d9a2e74b4638e1495d69266de9f6f796727d4a52a7ab0a48db2',
    cavosAccountClassHash: '0x755458283925308628a12e6b1eef2c4d115330087b608e2df09159c62bf0e6b',
    salt: '0x0',
};

export const DEFAULT_OAUTH_CONFIG_MAINNET: OAuthWalletConfig = {
    jwksRegistryAddress: '0x076ff6853197538b4d4c925b2c775014fae9b5c14f63262b13f2e49f732e21f7',
    cavosAccountClassHash: '0x755458283925308628a12e6b1eef2c4d115330087b608e2df09159c62bf0e6b',
    salt: '0x0',
};
