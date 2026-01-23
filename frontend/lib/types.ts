export interface User {
  id: string;
  email: string;
  username?: string;
  createdAt: string;
}

export interface Consent {
  id: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  createdAt: string;
}

export interface ConsentsResponse {
  consents: Consent[];
  total: number;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterCredentials {
  email: string;
  password: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
}

export interface RegisterResponse {
  user: User;
}

export interface ApiError {
  error: string;
  message?: string;
}
