import { 
  LoginCredentials, 
  RegisterCredentials, 
  AuthResponse, 
  RegisterResponse,
  ConsentsResponse,
  User 
} from './types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

/**
 * API Service for authentication
 */
export class ApiService {
  /**
   * Register a new user
   */
  static async register(credentials: RegisterCredentials): Promise<RegisterResponse> {
    const response = await fetch(`${API_URL}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Registration failed');
    }

    return response.json();
  }

  /**
   * Login user
   */
  static async login(credentials: LoginCredentials): Promise<AuthResponse> {
    const response = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Login failed');
    }

    return response.json();
  }

  /**
   * Refresh access token
   */
  static async refresh(refreshToken: string): Promise<{ accessToken: string }> {
    const response = await fetch(`${API_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Token refresh failed');
    }

    return response.json();
  }

  /**
   * Logout user
   */
  static async logout(refreshToken: string): Promise<void> {
    const response = await fetch(`${API_URL}/auth/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Logout failed');
    }
  }

  /**
   * Get user info (decode JWT on client side)
   */
  static getUserFromToken(token: string): User | null {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split('')
          .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );

      const payload = JSON.parse(jsonPayload);
      return {
        id: payload.sub,
        email: payload.email || '',
        username: payload.username || undefined,
        createdAt: payload.createdAt || new Date(payload.iat * 1000).toISOString(),
      };
    } catch (error) {
      console.error('Failed to decode token:', error);
      return null;
    }
  }

  /**
   * Get user consents
   */
  static async getConsents(accessToken: string): Promise<ConsentsResponse> {
    const response = await fetch(`${API_URL}/user/consents`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to get consents');
    }

    return response.json();
  }

  /**
   * Revoke consent for a client
   */
  static async revokeConsent(accessToken: string, clientId: string): Promise<void> {
    const response = await fetch(`${API_URL}/user/consents/${clientId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to revoke consent');
    }
  }

  /**
   * Update user profile (username)
   */
  static async updateProfile(accessToken: string, username: string): Promise<{ user: User }> {
    const response = await fetch(`${API_URL}/user/profile`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error_description || error.error || 'Failed to update profile');
    }

    return response.json();
  }
}
