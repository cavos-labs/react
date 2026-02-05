import { OAuthWalletConfig } from '../types/config';

export const DEFAULT_OAUTH_CONFIG_SEPOLIA: OAuthWalletConfig = {
    jwksRegistryAddress: '0x05a19f14719dec9e27eb2aa38c5b68277bdb5c41570e548504722f737a3da6c6',
    cavosAccountClassHash: '0x8085433f275c2a6c532c9c5843e4566cf6dff00e48a816970ceaf0e4b930da',
    salt: '0x0',
};

export const DEFAULT_OAUTH_CONFIG_MAINNET: OAuthWalletConfig = {
    jwksRegistryAddress: '0x07787f624d6869ae306dc17b49174b284dbadd1e999c1c8733ce72eb7ac518c2',
    cavosAccountClassHash: '0x8085433f275c2a6c532c9c5843e4566cf6dff00e48a816970ceaf0e4b930da',
    salt: '0x0',
};
