import { OAuthWalletConfig } from '../types/config';

export const DEFAULT_OAUTH_CONFIG_SEPOLIA: OAuthWalletConfig = {
    jwksRegistryAddress: '0x04159cfcf03bfd6c294245147f065f2efb09c12c33f46c4611c86d8e4f3fb639',
    cavosAccountClassHash: '0x251b5653a58c50e90df6fad69eda58ba91b2a5ebc8d8bdad579810294690dec',
    salt: '0x0',
};

export const DEFAULT_OAUTH_CONFIG_MAINNET: OAuthWalletConfig = {
    jwksRegistryAddress: '0x047b308fa90f10eb7323316b57b5a114348598ea1ddd086eefcefb67e1f5550f',
    cavosAccountClassHash: '0x251b5653a58c50e90df6fad69eda58ba91b2a5ebc8d8bdad579810294690dec',
    salt: '0x0',
};
