/**
 * WebAuthnManager handles Passkey operations for secure key derivation.
 * It uses the PRF (Pseudo-Random Function) extension to derive a stable encryption key
 * from the user's authenticator without exposing the private key.
 */
export class WebAuthnManager {
    private static readonly RP_NAME = 'Cavos Wallet';

    // Check if WebAuthn and PRF are supported
    static async isSupported(): Promise<boolean> {
        return (
            window.PublicKeyCredential !== undefined &&
            typeof (window as any).PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function' &&
            await (window as any).PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        );
    }

    /**
     * Register a new Passkey and derive an encryption key
     * @param userId User's unique identifier (e.g. email or social ID)
     * @param challenge Random challenge from server (or locally generated for client-side derivation)
     */
    async register(userId: string, challenge: Uint8Array): Promise<{ encryptionKey: CryptoKey; credentialId: string }> {
        // Create user handle
        const userHandle = new TextEncoder().encode(userId);

        // PRF input (salt) - In a real app, this might come from the server or be a constant
        const prfSalt = new Uint8Array(32).fill(1); // Simple salt for demo

        const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
            challenge: challenge as any,
            rp: {
                name: WebAuthnManager.RP_NAME,
                id: window.location.hostname, // Must match current domain
            },
            user: {
                id: userHandle as any,
                name: userId,
                displayName: userId,
            },
            pubKeyCredParams: [
                { alg: -7, type: 'public-key' }, // ES256
                { alg: -257, type: 'public-key' }, // RS256
            ],
            authenticatorSelection: {
                authenticatorAttachment: 'platform', // Use platform authenticator (TouchID/FaceID)
                requireResidentKey: true,
                userVerification: 'required',
            },
            extensions: {
                // @ts-ignore - PRF extension types might not be in standard lib yet
                prf: {
                    eval: {
                        first: prfSalt as any,
                    },
                },
            },
        };

        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions,
        });

        if (!credential) {
            throw new Error('Failed to create credential');
        }

        // Extract PRF result
        const extensionResults = (credential as PublicKeyCredential).getClientExtensionResults();
        // @ts-ignore
        const prfResult = extensionResults.prf;

        if (!prfResult || !prfResult.results || !prfResult.results.first) {
            throw new Error('PRF extension not supported or failed');
        }

        // Import the derived key for AES-GCM
        const rawKey = new Uint8Array(prfResult.results.first as any);
        const encryptionKey = await window.crypto.subtle.importKey(
            'raw',
            rawKey,
            'AES-GCM',
            true,
            ['encrypt', 'decrypt']
        );

        return {
            encryptionKey,
            credentialId: credential.id
        };
    }

    /**
     * Authenticate with existing Passkey and derive the same encryption key
     */
    async authenticate(challenge: Uint8Array): Promise<{ encryptionKey: CryptoKey; credentialId: string }> {
        const prfSalt = new Uint8Array(32).fill(1); // Must match registration salt

        const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
            challenge: challenge as any,
            rpId: window.location.hostname,
            userVerification: 'required',
            extensions: {
                // @ts-ignore
                prf: {
                    eval: {
                        first: prfSalt as any,
                    },
                },
            },
        };

        const credential = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions,
        });

        if (!credential) {
            throw new Error('Failed to authenticate');
        }

        // Extract PRF result
        const extensionResults = (credential as PublicKeyCredential).getClientExtensionResults();
        // @ts-ignore
        const prfResult = extensionResults.prf;

        if (!prfResult || !prfResult.results || !prfResult.results.first) {
            throw new Error('PRF extension not supported or failed');
        }

        // Import the derived key
        const rawKey = new Uint8Array(prfResult.results.first as any);
        const encryptionKey = await window.crypto.subtle.importKey(
            'raw',
            rawKey,
            'AES-GCM',
            true,
            ['encrypt', 'decrypt']
        );

        return {
            encryptionKey,
            credentialId: credential.id
        };
    }

    /**
     * Encrypt data using the derived key
     */
    async encrypt(key: CryptoKey, data: string): Promise<{ ciphertext: string; iv: string }> {
        const encodedData = new TextEncoder().encode(data);
        const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM

        const encryptedBuffer = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv,
            },
            key,
            encodedData
        );

        return {
            ciphertext: this.arrayBufferToBase64(encryptedBuffer),
            iv: this.arrayBufferToBase64(iv.buffer as ArrayBuffer),
        };
    }

    /**
     * Decrypt data using the derived key
     */
    async decrypt(key: CryptoKey, ciphertext: string, iv: string): Promise<string> {
        const encryptedData = this.base64ToArrayBuffer(ciphertext);
        const ivBuffer = this.base64ToArrayBuffer(iv);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer,
            },
            key,
            encryptedData
        );

        return new TextDecoder().decode(decryptedBuffer);
    }

    // Helpers
    private arrayBufferToBase64(buffer: ArrayBuffer | ArrayBufferLike): string {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    private base64ToArrayBuffer(base64: string): ArrayBuffer {
        const binary_string = window.atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }
}
