import { CloudStorageProvider, EncryptedWallet } from '../types';

const WALLET_RECORD_TYPE = 'CavosWallet';
const WALLET_RECORD_NAME = 'wallet_data';
const CLOUDKIT_JS_URL = 'https://cdn.apple-cloudkit.com/ck/2/cloudkit.js';

/**
 * iCloud Storage using CloudKit JS
 * Note: Requires CloudKit JS library to be loaded and configured
 * https://developer.apple.com/documentation/cloudkitjs
 */
export class iCloudStorage implements CloudStorageProvider {
  private container: any;
  private database: any;

  /**
   * Ensure CloudKit JS is loaded
   */
  static async ensureLoaded(): Promise<void> {
    if (typeof window === 'undefined') return;

    if ((window as any).CloudKit) {
      return;
    }

    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = CLOUDKIT_JS_URL;
      script.async = true;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error('Failed to load CloudKit JS'));
      document.head.appendChild(script);
    });
  }

  constructor(containerId: string, apiToken: string, environment: 'development' | 'production' = 'production') {
    if (typeof window === 'undefined') {
      // SSR handling or non-browser env
      return;
    }

    if (!(window as any).CloudKit) {
      throw new Error('CloudKit JS is not loaded. Call iCloudStorage.ensureLoaded() first.');
    }

    const CloudKit = (window as any).CloudKit;

    // Check if button container exists
    const buttonContainer = document.getElementById('apple-sign-in-button');
    console.log('[iCloudStorage] Button container found:', !!buttonContainer);

    console.log('[iCloudStorage] Configuring CloudKit with:', {
      containerId,
      apiToken: apiToken.substring(0, 10) + '...',
      environment
    });

    try {
      CloudKit.configure({
        containers: [{
          containerIdentifier: containerId,
          apiTokenAuth: {
            apiToken,
            persist: true,
            signInButton: {
              id: 'apple-sign-in-button',
              theme: 'black'
            }
          },
          environment,
        }],
      });
      console.log('[iCloudStorage] CloudKit configured successfully');
    } catch (err) {
      console.error('[iCloudStorage] CloudKit configuration failed:', err);
    }

    this.container = CloudKit.getDefaultContainer();
    this.database = this.container.privateCloudDatabase;

    // Listen for auth events
    this.container.whenUserSignsIn().then((userIdentity: any) => {
      console.log('[iCloudStorage] User signed in to CloudKit:', userIdentity);
      // Reload page or notify app to refresh wallet
      // window.location.reload(); 
    });

    this.container.whenUserSignsOut().then(() => {
      console.log('[iCloudStorage] User signed out of CloudKit');
    });
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.ensureAuthenticated();
      return true;
    } catch (error) {
      console.error('[iCloudStorage] Availability check failed:', error);
      return false;
    }
  }

  private async ensureAuthenticated(): Promise<void> {
    try {
      const userIdentity = await this.container.setUpAuth();
      if (!userIdentity) {
        // If no identity, we can't proceed. The user must be signed in to iCloud.
        // In a real app, you would show a "Connect iCloud" button that calls setUpAuth again.
        throw new Error('User is not signed in to iCloud');
      }
    } catch (error) {
      throw error;
    }
  }

  async saveWallet(walletData: EncryptedWallet): Promise<void> {
    try {
      await this.ensureAuthenticated();

      // Check if record exists
      const existingRecord = await this.loadWalletRecord();

      if (existingRecord) {
        // Update existing record
        existingRecord.fields.data = { value: JSON.stringify(walletData) };
        existingRecord.fields.updatedAt = { value: Date.now() };

        await this.database.saveRecords([existingRecord]);
      } else {
        // Create new record
        const record = {
          recordType: WALLET_RECORD_TYPE,
          recordName: WALLET_RECORD_NAME,
          fields: {
            data: { value: JSON.stringify(walletData) },
            createdAt: { value: Date.now() },
            updatedAt: { value: Date.now() },
          },
        };

        await this.database.saveRecords([record]);
      }
    } catch (error: any) {
      console.error('[iCloudStorage] Save wallet failed:', error);
      throw new Error(`Failed to save wallet to iCloud: ${error.message}`);
    }
  }

  async loadWallet(): Promise<EncryptedWallet | null> {
    try {
      await this.ensureAuthenticated();
      const record = await this.loadWalletRecord();

      if (!record || !record.fields.data) {
        return null;
      }

      const walletData = JSON.parse(record.fields.data.value);
      return walletData as EncryptedWallet;
    } catch (error: any) {
      console.error('[iCloudStorage] Load wallet failed:', error);
      throw new Error(`Failed to load wallet from iCloud: ${error.message}`);
    }
  }

  async deleteWallet(): Promise<void> {
    try {
      await this.ensureAuthenticated();
      const record = await this.loadWalletRecord();

      if (!record) {
        return;
      }

      await this.database.deleteRecords([{ recordName: WALLET_RECORD_NAME }]);
    } catch (error: any) {
      console.error('[iCloudStorage] Delete wallet failed:', error);
      throw new Error(`Failed to delete wallet from iCloud: ${error.message}`);
    }
  }

  /**
   * Load the wallet record from iCloud
   */
  private async loadWalletRecord(): Promise<any | null> {
    try {
      // ensureAuthenticated is called by public methods
      const response = await this.database.fetchRecords([
        { recordName: WALLET_RECORD_NAME },
      ]);

      if (response.records && response.records.length > 0) {
        return response.records[0];
      }

      return null;
    } catch (error: any) {
      // Record not found is expected on first use
      if (error.ckErrorCode === 'RECORD_NOT_FOUND') {
        return null;
      }
      throw error;
    }
  }
}
