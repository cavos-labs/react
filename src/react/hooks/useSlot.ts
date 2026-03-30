import { useCavos } from '../CavosContext';
import { Call, RpcProvider } from 'starknet';

export interface UseSlotReturn {
  /** True once the wallet is confirmed deployed on the Slot chain. */
  isSlotDeployed: boolean;
  /** True while the wallet is being deployed to the Slot chain. */
  isSlotDeploying: boolean;
  /** Execute calls on the Slot chain (no paymaster, session key reused). */
  executeOnSlot: (calls: Call | Call[]) => Promise<string>;
  /** Raw RpcProvider for the Slot — use for read queries or Dojo SDK integration. */
  slotProvider: RpcProvider | null;
}

export function useSlot(): UseSlotReturn {
  const { walletStatus, executeOnSlot, getSlotProvider } = useCavos();
  return {
    isSlotDeployed: walletStatus.isSlotDeployed,
    isSlotDeploying: walletStatus.isSlotDeploying,
    executeOnSlot,
    slotProvider: getSlotProvider(),
  };
}
