import { useState } from 'react';
import { Call } from 'starknet';
import { useCavos } from '../CavosContext';

type ExecuteOptions = { gasless?: boolean };

export function useTransaction() {
  const { cavos } = useCavos();
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);

  const sendTransaction = async (calls: Call | Call[], options?: ExecuteOptions) => {
    setIsSending(true);
    setError(null);
    setTxHash(null);

    try {
      const hash = await cavos.execute(calls, options);
      setTxHash(hash);
      return hash;
    } catch (err) {
      setError(err as Error);
      throw err;
    } finally {
      setIsSending(false);
    }
  };

  return {
    sendTransaction,
    isSending,
    error,
    txHash,
  };
}
