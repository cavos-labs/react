import { EncryptedWallet } from '../types';

export class CryptoUtils {
  /**
   * Derive encryption key from user credentials using PBKDF2
   */
  static async deriveKey(userId: string, email: string, salt: Uint8Array | ArrayBuffer): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = encoder.encode(`${userId}:${email}`);

    const baseKey = await crypto.subtle.importKey(
      'raw',
      keyMaterial,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    // Ensure salt is a proper Uint8Array
    const saltBuffer = salt instanceof Uint8Array ? salt : new Uint8Array(salt);

    return (crypto.subtle.deriveKey as any)(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 100000,
        hash: 'SHA-256',
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt private key with AES-256-GCM
   */
  static async encryptPrivateKey(
    privateKey: string,
    userId: string,
    email: string
  ): Promise<EncryptedWallet> {
    const encoder = new TextEncoder();
    const data = encoder.encode(privateKey);

    // Generate random salt and IV
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Derive encryption key
    const key = await this.deriveKey(userId, email, salt);

    // Encrypt
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
      },
      key,
      data
    );

    // Extract authentication tag (last 16 bytes)
    const encryptedArray = new Uint8Array(encrypted);
    const ciphertext = encryptedArray.slice(0, -16);
    const tag = encryptedArray.slice(-16);

    return {
      iv: this.arrayBufferToBase64(iv),
      ciphertext: this.arrayBufferToBase64(ciphertext),
      salt: this.arrayBufferToBase64(salt),
      tag: this.arrayBufferToBase64(tag),
    };
  }

  /**
   * Decrypt private key with AES-256-GCM
   */
  static async decryptPrivateKey(
    encryptedData: EncryptedWallet,
    userId: string,
    email: string
  ): Promise<string> {
    const salt = this.base64ToArrayBuffer(encryptedData.salt);
    const iv = this.base64ToArrayBuffer(encryptedData.iv);
    const ciphertext = this.base64ToArrayBuffer(encryptedData.ciphertext);
    const tag = this.base64ToArrayBuffer(encryptedData.tag);

    // Combine ciphertext and tag
    const encrypted = new Uint8Array([...new Uint8Array(ciphertext), ...new Uint8Array(tag)]);

    // Derive decryption key
    const key = await this.deriveKey(userId, email, new Uint8Array(salt));

    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(iv),
      },
      key,
      encrypted
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  /**
   * Convert ArrayBuffer to base64 string
   */
  static arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert base64 string to ArrayBuffer
   */
  static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
