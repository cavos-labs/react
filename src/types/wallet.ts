export interface WalletData {
  address: string;
  publicKey: string;
  encryptedPrivateKey: string;
  createdAt: number;
  lastSyncedAt: number;
  provider: 'google' | 'apple';
}

export interface EncryptedWallet {
  iv: string;
  ciphertext: string;
  salt: string;
  tag: string;
}

export interface DecryptedWallet {
  address: string;
  publicKey: string;
  privateKey: string;
}

export type OnrampProvider = 'RAMP_NETWORK';
