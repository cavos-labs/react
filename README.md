# @cavos/react

A library to add secure, easy-to-use wallets to your React application.

It lets your users log in with Google or Apple and creates a secure wallet for them. They do not need to worry about private keys or seed phrases.

## Why use this?

- **Easy Login**: Users sign in with their existing Google or Apple accounts.
- **Secure**: The private keys are created on the user's device and never sent to our servers. Only the user can access their wallet.
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
      const transactionHash = await execute(
        {
          contractAddress: '0x...', // The address of the contract you want to interact with
          entrypoint: 'transfer',   // The function to call
          calldata: ['0x...', '100'], // The arguments for the function
        },
        { gasless: true } // This makes the transaction free for the user
      );

      console.log('Transaction sent:', transactionHash);
    } catch (error) {
      console.error('Error sending transaction:', error);
    }
  };

  return <button onClick={handleSend}>Send Money</button>;
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

## Need Help?

If you have questions, please check our GitHub repository or contact support.
