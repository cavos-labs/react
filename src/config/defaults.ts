import { OAuthWalletConfig } from '../types/config';

/** Default Cavos-managed relayer for Slot (Katana) — handles execute_from_outside_v2 for JWT session registration. */
export const DEFAULT_SLOT_RELAYER_ADDRESS = '0x0656b69B8CcFE63932698c7f7e24Aa2745887240F2BDE82b66DeF746fa0FCaF2';
export const DEFAULT_SLOT_RELAYER_PRIVATE_KEY = '0x058295e9af8fd50ed9175e597b1d7b18d09e41d62c7f8e0987abeebbd6ab41ae';

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
