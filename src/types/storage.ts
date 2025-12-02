import { EncryptedWallet } from './wallet';

export interface CloudStorageProvider {
  saveWallet(walletData: EncryptedWallet): Promise<void>;
  loadWallet(): Promise<EncryptedWallet | null>;
  deleteWallet(): Promise<void>;
  isAvailable(): Promise<boolean>;
}

export interface StorageConfig {
  provider: 'google-drive' | 'icloud';
  accessToken: string;
  refreshToken?: string;
}
