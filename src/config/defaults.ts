import { OAuthWalletConfig } from '../types/config';

export const DEFAULT_OAUTH_CONFIG_SEPOLIA: OAuthWalletConfig = {
    jwksRegistryAddress: '0x059e9f82d07557ebdf16a9a09a86ad9f8a129b04ae4939103ef4baa9d6cfd021',
    cavosAccountClassHash: '0x32c636754e41c2ac5c1667045a7a8933571acb3b4a880facce9fae45de0a417',
    salt: '0x0',
};

export const DEFAULT_OAUTH_CONFIG_MAINNET: OAuthWalletConfig = {
    jwksRegistryAddress: '0x0012117d272d8eaab706d9488b3a9838c6d686342823e72348d8c466c71e89b4',
    cavosAccountClassHash: '0x32c636754e41c2ac5c1667045a7a8933571acb3b4a880facce9fae45de0a417',
    salt: '0x0',
};
