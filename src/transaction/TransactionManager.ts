import { Account, Call } from 'starknet';
import { executeCalls, GaslessOptions, BASE_URL, SEPOLIA_BASE_URL } from '@avnu/gasless-sdk';
import { AnalyticsManager } from '../analytics/AnalyticsManager';

export interface ExecuteOptions {
  gasless?: boolean;
}

export class TransactionManager {
  private account: Account;
  private paymasterApiKey: string;
  private network: 'mainnet' | 'sepolia';
  private analyticsManager: AnalyticsManager | null = null;

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
      console.log('[TransactionManager] Executing gasless transaction with AVNU SDK...');

      const baseUrl = this.network === 'sepolia' ? SEPOLIA_BASE_URL : BASE_URL;

      const options: GaslessOptions = {
        baseUrl,
        apiKey: this.paymasterApiKey,
      };

      const result = await executeCalls(
        this.account,
        calls,
        {}, // No deployment data needed here as account is already deployed
        options
      );

      console.log('[TransactionManager] Gasless transaction submitted:', result.transactionHash);

      // Track transaction analytics
      if (this.analyticsManager) {
        await this.analyticsManager.trackTransaction(
          result.transactionHash,
          this.account.address,
          'pending' // We assume pending initially
        );
      }

      return result.transactionHash;
    } catch (error: any) {
      console.error('[TransactionManager] Gasless execution failed:', error);
      throw new Error(`Failed to execute gasless transaction: ${error.message || error}`);
    }
  }
}
