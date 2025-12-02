import { CavosConfig } from '../types';

export class AnalyticsManager {
    private backendUrl: string;
    private appId: string;
    private network: string;
    private enabled: boolean;

    constructor(config: CavosConfig) {
        this.backendUrl = config.backendUrl || 'https://cavos.xyz';
        this.appId = config.appId;
        this.network = config.network || 'sepolia';
        this.enabled = true; // Can be toggled via config if needed
    }

    /**
     * Track wallet deployment
     */
    async trackWalletDeployment(address: string, email?: string): Promise<void> {
        if (!this.enabled) return;

        try {
            await fetch(`${this.backendUrl}/api/analytics/wallet`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    address,
                    appId: this.appId,
                    network: this.network,
                    email,
                }),
            });
        } catch (error) {
            console.warn('[AnalyticsManager] Failed to track wallet:', error);
            // Fail silently to not disrupt user flow
        }
    }

    /**
     * Track transaction execution
     */
    async trackTransaction(hash: string, walletAddress: string, status: 'pending' | 'confirmed' | 'failed' = 'pending'): Promise<void> {
        if (!this.enabled) return;

        try {
            await fetch(`${this.backendUrl}/api/analytics/transaction`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    hash,
                    walletAddress,
                    appId: this.appId,
                    status,
                    network: this.network,
                }),
            });
        } catch (error) {
            console.warn('[AnalyticsManager] Failed to track transaction:', error);
        }
    }
}
