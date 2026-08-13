import { useCavos } from '../CavosContext';
import { Call, RpcProvider } from 'starknet';

export interface UseSlotReturn {
  /** True once the wallet is confirmed deployed on the Slot chain. */
  isSlotDeployed: boolean;
  /** True only after the current session is confirmed active on Slot. */
  isSlotReady: boolean;
  /** True when the current Slot session is registered, active, and unexpired. */
  isSlotSessionActive: boolean;
  /** Last Slot setup error, if registration or deployment failed. */
  slotError?: string;
  /**
   * Stable code for `slotError` when the SDK recognizes the failure
   * (e.g. 'JWKS_KID_NOT_REGISTERED', 'JWT_EXPIRED'). Branch on this, not on the message.
   */
  slotErrorCode?: string;
  /** True while the wallet is being deployed to the Slot chain. */
  isSlotDeploying: boolean;
  /** Execute calls on the Slot chain (no paymaster, session key reused). */
  executeOnSlot: (calls: Call | Call[], options?: { waitForTransaction?: boolean }) => Promise<string>;
  /** Raw RpcProvider for the Slot — use for read queries or Dojo SDK integration. */
  slotProvider: RpcProvider | null;
}

export function useSlot(): UseSlotReturn {
  const { walletStatus, executeOnSlot, getSlotProvider } = useCavos();
  return {
    isSlotDeployed: walletStatus.isSlotDeployed,
    isSlotReady: walletStatus.isSlotReady,
    isSlotSessionActive: walletStatus.isSlotSessionActive,
    slotError: walletStatus.slotError,
    slotErrorCode: walletStatus.slotErrorCode,
    isSlotDeploying: walletStatus.isSlotDeploying,
    executeOnSlot,
    slotProvider: getSlotProvider(),
  };
}
