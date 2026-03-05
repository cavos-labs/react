import { OAuthWalletConfig } from '../types/config';

export const DEFAULT_OAUTH_CONFIG_SEPOLIA: OAuthWalletConfig = {
    jwksRegistryAddress: '0x074e56464afb566ca9d7c753eb378dbcc7c77f30b280737164c803c83355c75f',
    cavosAccountClassHash: '0x60ff7e871fde02c13c1f85bec33a48ca9dfdced09c8017f169e04cde6310e4f',
    salt: '0x0',
};

export const DEFAULT_OAUTH_CONFIG_MAINNET: OAuthWalletConfig = {
    jwksRegistryAddress: '0x060bb574466f7ac59df3ad58f3bd31c0ca94b563b2249340367cf82aea4c6c93',
    cavosAccountClassHash: '0x60ff7e871fde02c13c1f85bec33a48ca9dfdced09c8017f169e04cde6310e4f',
    salt: '0x0',
};
