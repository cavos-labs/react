import { Account, Call } from 'starknet';
import axios from 'axios';

export class PaymasterIntegration {
  private apiKey: string | null = null;
  private enabled: boolean = false;
  private paymasterUrl: string = 'https://paymaster.avnu.fi';

  constructor(apiKey?: string) {
    if (apiKey) {
      this.apiKey = apiKey;
      this.enabled = true;
    }
  }

  /**
   * Check if gasless transactions are available
   */
  isGaslessAvailable(): boolean {
    return this.enabled && this.apiKey !== null;
  }

  /**
   * Execute gasless transaction using AVNU Paymaster
   * Note: This is a placeholder implementation.
   * Integrate with AVNU Paymaster API directly when available.
   */
  async executeGasless(calls: Call | Call[], account: Account): Promise<string> {
    if (!this.apiKey) {
      throw new Error('Paymaster API key not configured');
    }

    const callsArray = Array.isArray(calls) ? calls : [calls];

    try {
      // Direct API call to AVNU Paymaster
      const response = await axios.post(
        `${this.paymasterUrl}/execute`,
        {
          account_address: account.address,
          calls: callsArray,
        },
        {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
          },
        }
      );

      return response.data.transaction_hash;
    } catch (error: any) {
      console.error('[PaymasterIntegration] Gasless execution failed:', error);
      throw new Error(`Gasless transaction failed: ${error.message}`);
    }
  }

  /**
   * Estimate if transaction is eligible for gasless execution
   */
  async isEligibleForGasless(calls: Call | Call[], account: Account): Promise<boolean> {
    if (!this.apiKey) {
      return false;
    }

    try {
      const callsArray = Array.isArray(calls) ? calls : [calls];

      // Check eligibility via API
      const response = await axios.post(
        `${this.paymasterUrl}/check-eligibility`,
        {
          account_address: account.address,
          calls: callsArray,
        },
        {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
          },
        }
      );

      return response.data.eligible || false;
    } catch (error) {
      console.error('[PaymasterIntegration] Eligibility check failed:', error);
      return false;
    }
  }

  /**
   * Set API key
   */
  setApiKey(apiKey: string): void {
    this.apiKey = apiKey;
    this.enabled = true;
  }

  /**
   * Disable gasless transactions
   */
  disable(): void {
    this.enabled = false;
  }

  /**
   * Enable gasless transactions
   */
  enable(): void {
    if (this.apiKey) {
      this.enabled = true;
    } else {
      throw new Error('Cannot enable gasless without API key');
    }
  }
}
