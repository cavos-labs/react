# @cavos/react

A library to add secure, easy-to-use wallets to your React application using OAuth-based authentication.

Users log in with Google, Apple, or email/password (Firebase) and get a smart account wallet on Starknet. No seed phrases, no private key management—just simple, secure authentication.

## Why use this?

- **Easy Login**: Users sign in with Google, Apple, or email/password
- **Self-Custodial**: JWT-based authentication with ephemeral session keys—no server holds your keys
- **Gasless Transactions**: Powered by AVNU Paymaster for free transactions
- **Session Management**: Automatic session registration and renewal with grace periods
- **Works Everywhere**: Access your wallet from any device by logging in

## Installation

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
        appId: 'your-app-id', // Get this from Cavos dashboard
        network: 'sepolia',   // 'mainnet' or 'sepolia'
      }}
    >
      <YourApp />
    </CavosProvider>
  );
}
```

### 2. Login with OAuth

Add login buttons for Google, Apple, or Firebase email/password.

```tsx
import { useCavos } from '@cavos/react';

function Login() {
  const { login, register, isAuthenticated, user, walletStatus } = useCavos();

  if (isAuthenticated) {
    return (
      <div>
        <p>Logged in as: {user?.id}</p>
        <p>Status: {walletStatus.isReady ? 'Ready' : 'Setting up...'}</p>
      </div>
    );
  }

  return (
    <div>
      {/* OAuth Login */}
      <button onClick={() => login('google')}>
        Login with Google
      </button>
      <button onClick={() => login('apple')}>
        Login with Apple
      </button>

      {/* Email/Password (Firebase) */}
      <button onClick={() => login('firebase', {
        email: 'user@example.com',
        password: 'password123'
      })}>
        Login with Email
      </button>

      {/* Register with Email/Password */}
      <button onClick={() => register('firebase', {
        email: 'user@example.com',
        password: 'password123'
      })}>
        Sign Up with Email
      </button>
    </div>
  );
}
```

### 3. Wallet Status Tracking

The SDK automatically tracks wallet deployment and session registration state.

```tsx
import { useCavos } from '@cavos/react';

function WalletStatus() {
  const { walletStatus, address } = useCavos();

  return (
    <div>
      <p>Address: {address}</p>
      <p>Deployed: {walletStatus.isDeployed ? 'Yes' : 'No'}</p>
      <p>Session Active: {walletStatus.isSessionActive ? 'Yes' : 'No'}</p>
      <p>Ready: {walletStatus.isReady ? 'Yes' : 'No'}</p>

      {walletStatus.isDeploying && <p>Deploying account...</p>}
      {walletStatus.isRegistering && <p>Registering session...</p>}
    </div>
  );
}
```

**WalletStatus fields:**
- `isDeploying`: Account deployment in progress
- `isDeployed`: Account exists on-chain
- `isRegistering`: Session registration in progress
- `isSessionActive`: Session registered and valid
- `isReady`: Wallet is ready to execute transactions (all setup complete)

### 4. Sending Transactions

Execute transactions on Starknet. The SDK automatically:
- Checks if the session is registered on-chain
- Registers the session if needed (via deployer)
- Uses gasless execution via AVNU Paymaster

```tsx
import { useCavos } from '@cavos/react';

function SendTransaction() {
  const { execute, walletStatus } = useCavos();

  const handleSend = async () => {
    if (!walletStatus.isReady) {
      console.log('Wallet not ready yet');
      return;
    }

    try {
      // Single transaction
      const txHash = await execute({
        contractAddress: '0x...',
        entrypoint: 'transfer',
        calldata: ['0x...', '1000', '0'], // recipient, amount_low, amount_high
      });

      console.log('Transaction hash:', txHash);
    } catch (error) {
      console.error('Transaction failed:', error);
    }
  };

  const handleMulticall = async () => {
    try {
      // Multiple transactions (executed atomically)
      const txHash = await execute([
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
      ]);

      console.log('Multicall hash:', txHash);
    } catch (error) {
      console.error('Multicall failed:', error);
    }
  };

  return (
    <div>
      <button onClick={handleSend} disabled={!walletStatus.isReady}>
        Send Transaction
      </button>
      <button onClick={handleMulticall} disabled={!walletStatus.isReady}>
        Send Multicall
      </button>
    </div>
  );
}
```

### 5. Session Renewal

Sessions have a `max_block` expiry and a grace period. When expired, renew with:

```tsx
import { useCavos } from '@cavos/react';

function SessionManager() {
  const { renewSession } = useCavos();

  const handleRenew = async () => {
    try {
      const txHash = await renewSession();
      console.log('Session renewed:', txHash);
    } catch (error) {
      console.error('Renewal failed:', error);
    }
  };

  return <button onClick={handleRenew}>Renew Session</button>;
}
```

If the grace period expired, the SDK automatically falls back to `registerSessionViaDeployer()`.

### 6. Manual Account Deployment

Usually deployment happens automatically on first login, but you can trigger it manually:

```tsx
import { useCavos } from '@cavos/react';

function DeployAccount() {
  const { deployAccount, isAccountDeployed } = useCavos();
  const [deployed, setDeployed] = useState(false);

  useEffect(() => {
    isAccountDeployed().then(setDeployed);
  }, []);

  const handleDeploy = async () => {
    try {
      const txHash = await deployAccount();
      console.log('Deploy tx:', txHash);
      setDeployed(true);
    } catch (error) {
      console.error('Deploy failed:', error);
    }
  };

  if (deployed) return <p>Account deployed!</p>;

  return <button onClick={handleDeploy}>Deploy Account</button>;
}
```

### 7. Getting Balance

Check the wallet's ETH balance:

```tsx
import { useCavos } from '@cavos/react';

function Balance() {
  const { getBalance } = useCavos();
  const [balance, setBalance] = useState('0');

  useEffect(() => {
    const fetchBalance = async () => {
      const bal = await getBalance();
      setBalance((Number(bal) / 1e18).toFixed(4));
    };

    fetchBalance();
    const interval = setInterval(fetchBalance, 30000); // Poll every 30s

    return () => clearInterval(interval);
  }, [getBalance]);

  return <p>Balance: {balance} ETH</p>;
}
```

### 8. Buying Crypto (Onramp)

Let users buy crypto with a credit card (mainnet only):

```tsx
import { useCavos } from '@cavos/react';

function BuyCrypto() {
  const { getOnramp } = useCavos();

  const handleBuy = () => {
    try {
      const url = getOnramp('RAMP_NETWORK');
      window.open(url, '_blank');
    } catch (error) {
      console.error('Onramp error:', error);
    }
  };

  return <button onClick={handleBuy}>Buy Crypto</button>;
}
```

### 9. Logout

Clear the session and reset wallet state:

```tsx
import { useCavos } from '@cavos/react';

function LogoutButton() {
  const { logout } = useCavos();

  return <button onClick={() => logout()}>Logout</button>;
}
```

## Configuration Options

```tsx
interface CavosConfig {
  appId: string;                    // Your app ID from Cavos dashboard
  network?: 'mainnet' | 'sepolia';  // Default: 'sepolia'
  backendUrl?: string;              // Custom backend URL (optional)
  paymasterApiKey?: string;         // AVNU Paymaster key (optional, uses default)
  starknetRpcUrl?: string;          // Custom RPC URL (optional)
  enableLogging?: boolean;          // Enable SDK logs (default: false)
}
```

## Architecture

- **OAuth Wallet**: JWT-based authentication with ephemeral session keys
- **Session Management**: On-chain session registration with `max_block` expiry and grace period
- **Paymaster**: AVNU Paymaster sponsorship for gasless transactions
- **Self-Custody**: No server holds keys—JWT + ephemeral key is the auth mechanism
- **Account Recovery**: Re-login with OAuth to regain access

## API Reference

### useCavos()

Returns:
```typescript
{
  // Authentication
  login: (provider: 'google' | 'apple' | 'firebase', credentials?: FirebaseCredentials) => Promise<void>
  register: (provider: 'firebase', credentials: FirebaseCredentials) => Promise<void>
  logout: () => Promise<void>
  isAuthenticated: boolean
  user: UserInfo | null

  // Wallet
  address: string | null
  walletStatus: WalletStatus

  // Transactions
  execute: (calls: Call | Call[]) => Promise<string>
  deployAccount: () => Promise<string>
  renewSession: () => Promise<string>

  // Utilities
  isAccountDeployed: () => Promise<boolean>
  getBalance: () => Promise<string>
  getOnramp: (provider: OnrampProvider) => string

  // Loading state
  isLoading: boolean
}
```

### WalletStatus

```typescript
{
  isDeploying: boolean      // Deployment in progress
  isDeployed: boolean       // Account exists on-chain
  isRegistering: boolean    // Session registration in progress
  isSessionActive: boolean  // Session is registered
  isReady: boolean          // Ready to execute (all setup complete)
}
```

## Need Help?

- GitHub: [github.com/your-org/cavos](https://github.com)
- Documentation: [docs.cavos.app](https://docs.cavos.app)
- Support: support@cavos.app
