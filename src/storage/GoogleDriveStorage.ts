import axios from 'axios';
import { CloudStorageProvider, EncryptedWallet } from '../types';

const DRIVE_API_BASE = 'https://www.googleapis.com/drive/v3';
const UPLOAD_API_BASE = 'https://www.googleapis.com/upload/drive/v3';

const BACKUP_FOLDER_NAME = 'Cavos Backup Keys DO NOT DELETE';

export class GoogleDriveStorage implements CloudStorageProvider {
  private accessToken: string;
  private _refreshToken?: string; // Stored for future token refresh implementation
  private walletFilename: string;

  constructor(accessToken: string, appId: string, network: string, refreshToken?: string) {
    this.accessToken = accessToken;
    this._refreshToken = refreshToken;
    // Use appId and network to create unique filename per app and network
    this.walletFilename = `${appId}_${network}_cavos_wallet.json`;
  }

  async isAvailable(): Promise<boolean> {
    try {
      await axios.get(`${DRIVE_API_BASE}/about?fields=user`, {
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
        },
      });
      return true;
    } catch (error) {
      console.error('[GoogleDriveStorage] Availability check failed:', error);
      return false;
    }
  }

  async saveWallet(walletData: EncryptedWallet): Promise<void> {
    try {
      // Ensure backup folder exists
      const folderId = await this.getOrCreateBackupFolder();

      // Check if wallet file already exists
      const existingFileId = await this.findWalletFile();

      const metadata = {
        name: this.walletFilename,
        mimeType: 'application/json',
        parents: existingFileId ? undefined : [folderId], // Only set parents on creation
      };

      const body = JSON.stringify(walletData);

      if (existingFileId) {
        // Update existing file content
        await axios.patch(
          `${UPLOAD_API_BASE}/files/${existingFileId}?uploadType=media`,
          body,
          {
            headers: {
              Authorization: `Bearer ${this.accessToken}`,
              'Content-Type': 'application/json',
            },
          }
        );

        // Ensure file is in the backup folder (move if necessary)
        // We get the current parents to check if we need to move it
        const fileInfo = await axios.get(`${DRIVE_API_BASE}/files/${existingFileId}?fields=parents`, {
          headers: { Authorization: `Bearer ${this.accessToken}` }
        });

        const currentParents = fileInfo.data.parents || [];
        if (!currentParents.includes(folderId)) {
          // Add to new folder
          await axios.patch(
            `${DRIVE_API_BASE}/files/${existingFileId}?addParents=${folderId}`,
            {},
            {
              headers: { Authorization: `Bearer ${this.accessToken}` }
            }
          );
        }

      } else {
        // Create new file
        const form = new FormData();
        form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
        form.append('file', new Blob([body], { type: 'application/json' }));

        await axios.post(
          `${UPLOAD_API_BASE}/files?uploadType=multipart`,
          form,
          {
            headers: {
              Authorization: `Bearer ${this.accessToken}`,
            },
          }
        );
      }
    } catch (error: any) {
      console.error('[GoogleDriveStorage] Save wallet failed:', error);
      throw new Error(`Failed to save wallet to Google Drive: ${error.message}`);
    }
  }

  async loadWallet(): Promise<EncryptedWallet | null> {
    try {
      const fileId = await this.findWalletFile();

      if (!fileId) {
        return null;
      }

      const response = await axios.get(
        `${DRIVE_API_BASE}/files/${fileId}?alt=media`,
        {
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
          },
        }
      );

      return response.data as EncryptedWallet;
    } catch (error: any) {
      console.error('[GoogleDriveStorage] Load wallet failed:', error);
      throw new Error(`Failed to load wallet from Google Drive: ${error.message}`);
    }
  }

  async deleteWallet(): Promise<void> {
    try {
      const fileId = await this.findWalletFile();

      if (!fileId) {
        return;
      }

      await axios.delete(`${DRIVE_API_BASE}/files/${fileId}`, {
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
        },
      });
    } catch (error: any) {
      console.error('[GoogleDriveStorage] Delete wallet failed:', error);
      throw new Error(`Failed to delete wallet from Google Drive: ${error.message}`);
    }
  }

  /**
   * Find or create the backup folder
   */
  private async getOrCreateBackupFolder(): Promise<string> {
    try {
      // Check if folder exists
      const response = await axios.get(`${DRIVE_API_BASE}/files`, {
        params: {
          q: `mimeType='application/vnd.google-apps.folder' and name='${BACKUP_FOLDER_NAME}' and trashed=false`,
          spaces: 'drive',
          fields: 'files(id, name)',
        },
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
        },
      });

      const files = response.data.files || [];
      if (files.length > 0) {
        return files[0].id;
      }

      // Create folder if it doesn't exist
      const createResponse = await axios.post(
        `${DRIVE_API_BASE}/files`,
        {
          name: BACKUP_FOLDER_NAME,
          mimeType: 'application/vnd.google-apps.folder',
        },
        {
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json',
          },
        }
      );

      return createResponse.data.id;
    } catch (error: any) {
      console.error('[GoogleDriveStorage] Get/Create backup folder failed:', error);
      throw new Error(`Failed to get or create backup folder: ${error.message}`);
    }
  }

  /**
   * Find the wallet file in Google Drive
   */
  private async findWalletFile(): Promise<string | null> {
    try {
      const response = await axios.get(`${DRIVE_API_BASE}/files`, {
        params: {
          q: `name='${this.walletFilename}' and trashed=false`,
          spaces: 'drive',
          fields: 'files(id, name)',
        },
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
        },
      });

      const files = response.data.files || [];
      return files.length > 0 ? files[0].id : null;
    } catch (error) {
      console.error('[GoogleDriveStorage] Find wallet file failed:', error);
      return null;
    }
  }
}
