export interface AuthData {
  access_token: string;
  refresh_token?: string;
  id_token: string;
  expires_in: number;
  user: UserInfo;
}

export interface UserInfo {
  id: string;
  email: string;
  name: string;
  picture?: string;
}

export interface OAuthProvider {
  name: 'google' | 'apple';
  displayName: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  user: UserInfo | null;
  accessToken: string | null;
  provider: OAuthProvider | null;
}

export type LoginProvider = 'google' | 'apple' | 'firebase';

export interface FirebaseCredentials {
  email: string;
  password: string;
}
