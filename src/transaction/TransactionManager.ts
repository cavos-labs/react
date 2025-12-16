import { Account, Call } from 'starknet';
import { AnalyticsManager } from '../analytics/AnalyticsManager';

export interface ExecuteOptions {
    gasless?: boolean;
}

export class TransactionManager {
    private account: Account;
    private paymasterApiKey: string;
    private network: 'mainnet' | 'sepolia';
    private analyticsManager: AnalyticsManager | null = null;

    private static readonly BASE_URL = 'https://starknet.api.avnu.fi';
    private static readonly SEPOLIA_BASE_URL = 'https://sepolia.api.avnu.fi';

    constructor(
        account: Account,
        paymasterApiKey: string,
        network: 'mainnet' | 'sepolia' = 'sepolia',
        analyticsManager?: AnalyticsManager
    ) {
        this.account = account;
        this.paymasterApiKey = paymasterApiKey;
        this.network = network;
        if (analyticsManager) {
            this.analyticsManager = analyticsManager;
        }
    }

    async execute(calls: Call | Call[], options?: ExecuteOptions): Promise<string> {
        const callsArray = Array.isArray(calls) ? calls : [calls];

        if (options?.gasless) {
            return this.executeGasless(callsArray);
        }

        // Regular execution (user pays gas)
        const result = await this.account.execute(callsArray);
        return result.transaction_hash;
    }

    private async executeGasless(calls: Call[]): Promise<string> {
        try {
            const baseUrl = this.network === 'sepolia'
                ? TransactionManager.SEPOLIA_BASE_URL
                : TransactionManager.BASE_URL;

            // Format calls for AVNU API
            const formattedCalls = calls.map(call => ({
                contractAddress: call.contractAddress,
                entrypoint: call.entrypoint,
                calldata: call.calldata ? (call.calldata as string[]).map(c => `0x${BigInt(c).toString(16)}`) : [],
            }));

            // Step 1: Build typed data
            const buildResponse = await fetch(`${baseUrl}/paymaster/v1/build-typed-data`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': this.paymasterApiKey,
                },
                body: JSON.stringify({
                    userAddress: this.account.address,
                    calls: formattedCalls,
                }),
            });

            if (!buildResponse.ok) {
                throw new Error(`Build typed data failed: ${await buildResponse.text()}`);
            }

            const typedData = await buildResponse.json();

            // Step 2: Sign the typed data
            const signature = await this.account.signMessage(typedData);

            // Format signature for API
            const signatureArray = Array.isArray(signature)
                ? signature.map(s => `0x${BigInt(s).toString(16)}`)
                : [`0x${BigInt((signature as any).r).toString(16)}`, `0x${BigInt((signature as any).s).toString(16)}`];

            // Step 3: Execute via paymaster
            const executeResponse = await fetch(`${baseUrl}/paymaster/v1/execute`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'api-key': this.paymasterApiKey,
                },
                body: JSON.stringify({
                    userAddress: this.account.address,
                    typedData: JSON.stringify(typedData),
                    signature: signatureArray,
                }),
            });

            if (!executeResponse.ok) {
                throw new Error(`Execute failed: ${await executeResponse.text()}`);
            }

            const result = await executeResponse.json();

            // Track transaction analytics
            if (this.analyticsManager) {
                await this.analyticsManager.trackTransaction(
                    result.transactionHash,
                    this.account.address,
                    'pending'
                );
            }

            return result.transactionHash;
        } catch (error: any) {
            console.error('[TransactionManager] Gasless execution failed:', error);
            throw new Error(`Failed to execute gasless transaction: ${error.message || error}`);
        }
    }
}
