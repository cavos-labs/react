# @cavos/react

A library to add secure, easy-to-use wallets to your React application.

It lets your users log in with Google or Apple and creates a secure wallet for them. They do not need to worry about private keys or seed phrases.

## Why use this?

- **Easy Login**: Users sign in with their existing Google or Apple accounts.
- **Secure**: The private keys are created on the user's device, encrypted with their passkeys which generates a blob saved on our platform for the user to restore it. Only the user can access their wallet.
- **Free Transactions**: We pay the gas fees for your users, so they do not need to buy ETH or STRK to start using your app.
- **Works Everywhere**: Users can access their wallet from any device by logging in.

## Installation

Run this command in your project folder:

```bash
npm install @cavos/react starknet
```

## How to use it

### 1. Setup

Wrap your application with the `CavosProvider`. This makes the wallet features available throughout your app.

```tsx
import { CavosProvider } from '@cavos/react';

function App() {
  return (
    <CavosProvider
      config={{
        appId: 'your-app-id', // Get this from your Cavos dashboard
        network: 'sepolia', // Use 'mainnet' for real money, 'sepolia' for testing
      }}
    >
      <YourApp />
    </CavosProvider>
  );
}
```

### 2. Login Buttons

Add buttons to let users log in.

```tsx
import { useCavos } from '@cavos/react';

function Login() {
  const { login, isAuthenticated, user } = useCavos();

  if (isAuthenticated) {
    return <p>Hello, {user?.email}!</p>;
  }

  return (
    <div>
      <button onClick={() => login('google')}>Login with Google</button>
      <button onClick={() => login('apple')}>Login with Apple</button>
    </div>
  );
}
```

### 3. Creating the Wallet

After logging in, the user needs to create their wallet. This happens automatically with a secure passkey (FaceID or TouchID).

Our library handles the user interface for this. You just need to make sure the `CavosProvider` is set up correctly.

### 4. Sending Transactions

You can send transactions on the blockchain easily.

```tsx
import { useCavos } from '@cavos/react';

function SendMoney() {
  const { execute } = useCavos();

  const handleSend = async () => {
    try {
      // Single transaction
      const transactionHash = await execute(
        {
          contractAddress: '0x...', // The address of the contract you want to interact with
          entrypoint: 'transfer',   // The function to call
          calldata: ['0x...', '1000', '0'], // recipient, amount_low, amount_high
        },
        { gasless: true } // Enable gasless transactions
      );

      console.log('Transaction hash:', transactionHash);
    } catch (error) {
      console.error('Transaction failed:', error);
    }
  };

  const handleMulticall = async () => {
    try {
      // Multiple transactions (executed atomically)
      const transactionHash = await execute(
        [
          {
            contractAddress: '0x...',
            entrypoint: 'approve',
            calldata: ['0x...', '1000', '0'],
          },
          {
            contractAddress: '0x...',
            entrypoint: 'transfer',
            calldata: ['0x...', '500', '0'],
          },
        ],
        { gasless: true }
      );

      console.log('Multicall transaction hash:', transactionHash);
    } catch (error) {
      console.error('Multicall failed:', error);
    }
  };

  return (
    <div>
      <button onClick={handleSend}>Send Transaction</button>
      <button onClick={handleMulticall}>Send Multicall</button>
    </div>
  );
}
```

### 5. Buying Crypto (Onramp)

You can let users buy crypto with their credit card directly in your app.

```tsx
import { useCavos } from '@cavos/react';

function BuyCrypto() {
  const { getOnramp } = useCavos();

  const handleBuy = () => {
    try {
      // Get the secure link to buy crypto
      const url = getOnramp('RAMP_NETWORK');
      // Open it in a new tab
      window.open(url, '_blank');
    } catch (error) {
      console.error('Error getting onramp link:', error);
    }
  };

  return <button onClick={handleBuy}>Buy Crypto</button>;
}
```

### 6. Handling Wallet Unlock Errors

If a user cancels the passkey prompt or wallet unlock fails, you can handle the error and allow them to retry.

```tsx
import { useCavos } from '@cavos/react';

function WalletStatus() {
  const { isAuthenticated, address, retryWalletUnlock } = useCavos();
  const [isRetrying, setIsRetrying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleRetry = async () => {
    setIsRetrying(true);
    setError(null);
    
    try {
      await retryWalletUnlock();
      console.log('Wallet unlocked successfully');
    } catch (err: any) {
      console.error('Wallet unlock failed:', err);
      setError(err.message || 'Failed to unlock wallet');
    } finally {
      setIsRetrying(false);
    }
  };

  // User is authenticated but wallet is not loaded
  if (isAuthenticated && !address) {
    return (
      <div>
        <p>Your wallet needs to be unlocked with your passkey.</p>
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <button onClick={handleRetry} disabled={isRetrying}>
          {isRetrying ? 'Unlocking...' : 'Unlock Wallet'}
        </button>
      </div>
    );
  }

  return <p>Wallet Address: {address}</p>;
}
```

### 7. Account Deletion

Allow users to permanently delete their account and wallet.

```tsx
import { useCavos } from '@cavos/react';

function AccountSettings() {
  const { deleteAccount } = useCavos();

  const handleDelete = async () => {
    const confirmed = window.confirm(
      'Are you sure you want to delete your account? This action cannot be undone.'
    );

    if (!confirmed) return;

    try {
      await deleteAccount();
      console.log('Account deleted successfully');
      // User will be logged out automatically
    } catch (error) {
      console.error('Failed to delete account:', error);
    }
  };

  return (
    <button onClick={handleDelete} style={{ color: 'red' }}>
      Delete Account
    </button>
  );
}
```

## Need Help?

If you have questions, please check our GitHub repository or contact support.
