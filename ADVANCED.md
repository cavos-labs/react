# Advanced Specification (@cavos/react)

## Message Signing

Sign messages with the user's wallet for authentication or proof of ownership.

### Basic Message Signing

```tsx
import { useCavos } from '@cavos/react';

function SignMessage() {
  const { signMessage } = useCavos();

  const handleSign = async () => {
    const signature = await signMessage('Hello, Starknet!');
    
    // Signature contains r and s as BigInt
    console.log('r:', signature.r);
    console.log('s:', signature.s);
    
    // Convert to hex if needed
    const hexSig = {
      r: '0x' + signature.r.toString(16),
      s: '0x' + signature.s.toString(16)
    };
  };
}
```

**Signature Format:**
The signature is returned in Starknet's native format:
```typescript
interface Signature {
  r: bigint;  // First part of signature
  s: bigint;  // Second part of signature
}
```

## Advanced Configuration

### Custom RPC Endpoints
Use your own RPC endpoint for better performance or privacy:

```tsx
<CavosProvider
  config={{
    appId: 'your-app-id',
    network: 'mainnet',
    starknetRpcUrl: 'https://your-custom-rpc.com/v0_8',
  }}
>
  <App />
</CavosProvider>
```

### Custom Paymaster
Use your own paymaster for gasless transactions:

```tsx
<CavosProvider
  config={{
    appId: 'your-app-id',
    paymasterApiKey: 'your-avnu-api-key',
  }}
>
  <App />
</CavosProvider>
```

## Session Management

### Understanding Session State
The SDK manages session state automatically:

```tsx
const { hasActiveSession, requiresWalletCreation } = useCavos();

if (requiresWalletCreation) {
  // User needs to create wallet (passkey prompt will show)
  console.log('Wallet creation required');
}
```

### Passkey Persistence
A core feature of Cavos is allowing users to recover their wallet using just their Passkey.
The SDK supports a **Passkey-Only** flow where no email/OAuth is required. The wallet is derived deterministically from the user's Passkey public key.

**Manual Session Clearing:**
Sessions are cleared automatically on logout, but you can also clear manually:

```tsx
const { logout } = useCavos();
// Clears session, wallet cache, and localStorage
await logout();
```

## Direct SDK Access
Access the underlying SDK instance for advanced operations:

```tsx
const { cavos } = useCavos();
// cavos.createPasskeyOnlyWallet()
// cavos.recoverWalletWithPasskey()
```

## Error Handling

### Common Error Types
1.  **Authentication Errors**: `popup_closed_by_user`
2.  **Passkey Errors**: `NotAllowedError` (User cancelled), `NotSupportedError`
3.  **Transaction Errors**: `Insufficient credits`, `Contract not found`

## Troubleshooting

### Passkey Prompt Not Showing
*   **Protocol**: Must be served over **HTTPS** (or localhost).
*   **Domain**: Passkeys are bound to the domain. `example.com` passkeys verify on `example.com` only.

### Session Not Persisting
*   Incognito mode may clear `localStorage` / `indexedDB`.
*   Passkeys require WebAuthn support (modern browsers).
