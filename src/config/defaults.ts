import { OAuthWalletConfig } from '../types/config';

/** Default Cavos-managed relayer for Slot (Katana) — handles execute_from_outside_v2 for JWT session registration. */
export const DEFAULT_SLOT_RELAYER_ADDRESS = '0x00ca74bcc56be5081102f4291a9477fe35adec24a8bc46d56c6e29663fb5f3c9';
export const DEFAULT_SLOT_RELAYER_PRIVATE_KEY = '0x1ae9b7d1462214de34ed645960f4a3a1626a75dd3f76775f47213331eb456dc';

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
