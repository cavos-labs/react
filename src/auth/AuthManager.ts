import axios from 'axios';
import { AuthData, UserInfo, OAuthProvider, AuthConfig } from '../types';

export class AuthManager {
  private backendUrl: string;
  private appId: string;
  private authData: AuthData | null = null;
  private provider: OAuthProvider | null = null;

  constructor(config: AuthConfig) {
    this.backendUrl = config.backendUrl;
    this.appId = config.appId;
  }

  /**
   * Initiate Google OAuth flow
   */
  async loginWithGoogle(redirectUri?: string): Promise<void> {
    try {
      // Use current URL or provided redirect URI
      const finalRedirectUri = redirectUri || window.location.href;

      // Get authorization URL from backend
      const response = await axios.get(`${this.backendUrl}/api/auth0/google`, {
        params: {
          redirect_uri: finalRedirectUri,
        },
      });

      const { url } = response.data;

      // Redirect to OAuth provider
      window.location.href = url;
    } catch (error: any) {
      console.error('[AuthManager] Google login failed:', error);
      throw new Error(`Google login failed: ${error.message}`);
    }
  }

  /**
   * Initiate Apple OAuth flow
   */
  async loginWithApple(redirectUri?: string): Promise<void> {
    try {
      // Use current URL or provided redirect URI
      const finalRedirectUri = redirectUri || window.location.href;

      // Get authorization URL from backend
      const response = await axios.get(`${this.backendUrl}/api/auth0/apple`, {
        params: {
          redirect_uri: finalRedirectUri,
        },
      });

      const { url } = response.data;

      // Redirect to OAuth provider
      window.location.href = url;
    } catch (error: any) {
      console.error('[AuthManager] Apple login failed:', error);
      throw new Error(`Apple login failed: ${error.message}`);
    }
  }

  /**
   * Handle OAuth callback
   */
  async handleCallback(authDataString: string): Promise<void> {
    try {
      const authData = JSON.parse(decodeURIComponent(authDataString)) as AuthData;

      this.authData = authData;

      // Determine provider from user info
      if (authData.user.email.includes('appleid')) {
        this.provider = { name: 'apple', displayName: 'Apple' };
      } else {
        this.provider = { name: 'google', displayName: 'Google' };
      }

      // Save session
      this.saveSession();
    } catch (error: any) {
      console.error('[AuthManager] Callback handling failed:', error);
      throw new Error(`Callback handling failed: ${error.message}`);
    }
  }

  /**
   * Save session to local storage
   */
  private saveSession(): void {
    if (typeof window === 'undefined') return;
    if (!this.authData || !this.provider) return;

    const sessionData = {
      authData: this.authData,
      provider: this.provider,
      timestamp: Date.now(),
    };

    localStorage.setItem('cavos_session', JSON.stringify(sessionData));
  }

  /**
   * Restore session from local storage
   */
  restoreSession(): boolean {
    if (typeof window === 'undefined') return false;

    try {
      const sessionString = localStorage.getItem('cavos_session');
      if (!sessionString) return false;

      const sessionData = JSON.parse(sessionString);

      // TODO: Check for token expiration and refresh if needed
      // For now, we assume the token is valid or will be refreshed by the backend

      this.authData = sessionData.authData;
      this.provider = sessionData.provider;

      return true;
    } catch (error) {
      console.error('[AuthManager] Failed to restore session:', error);
      this.clearSession();
      return false;
    }
  }

  /**
   * Get current user info
   */
  getUserInfo(): UserInfo | null {
    return this.authData?.user || null;
  }

  /**
   * Get access token
   */
  getAccessToken(): string | null {
    return this.authData?.access_token || null;
  }

  /**
   * Get refresh token
   */
  getRefreshToken(): string | null {
    return this.authData?.refresh_token || null;
  }

  /**
   * Get current provider
   */
  getProvider(): OAuthProvider | null {
    return this.provider;
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return this.authData !== null;
  }

  /**
   * Logout
   */
  logout(): void {
    this.authData = null;
    this.provider = null;
    this.clearSession();
  }

  /**
   * Clear session from local storage
   */
  private clearSession(): void {
    if (typeof window === 'undefined') return;
    localStorage.removeItem('cavos_session');
  }

  /**
   * Get full auth data
   */
  getAuthData(): AuthData | null {
    return this.authData;
  }

  /**
   * Set auth data (for restoration from storage)
   */
  setAuthData(authData: AuthData, provider: OAuthProvider): void {
    this.authData = authData;
    this.provider = provider;
    this.saveSession();
  }

  /**
   * Get app ID
   */
  getAppId(): string {
    return this.appId;
  }
}
