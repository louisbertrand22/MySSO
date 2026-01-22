'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { ApiService } from '@/lib/api';
import { User, LoginCredentials, RegisterCredentials } from '@/lib/types';

interface AuthContextType {
  user: User | null;
  accessToken: string | null;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (credentials: RegisterCredentials) => Promise<void>;
  logout: () => Promise<void>;
  refreshAccessToken: () => Promise<void>;
  setTokens: (accessToken: string, refreshToken: string) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Helper function to check if a token is expired or about to expire (within 5 minutes)
  const isTokenExpired = (token: string): boolean => {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const exp = payload.exp;
      if (!exp) return true;
      
      // Check if token expires in less than 5 minutes (300 seconds)
      const now = Math.floor(Date.now() / 1000);
      const bufferTime = 300; // 5 minutes buffer
      return exp < (now + bufferTime);
    } catch {
      return true; // If we can't parse it, consider it expired
    }
  };

  const refreshAccessToken = async () => {
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await ApiService.refresh(refreshToken);
    setAccessToken(response.accessToken);
    
    const userData = ApiService.getUserFromToken(response.accessToken);
    setUser(userData);
    localStorage.setItem('accessToken', response.accessToken);
  };


  useEffect(() => {
    const initAuth = async () => {
      // 1. Get both tokens from localStorage
      const accessToken = localStorage.getItem('accessToken');
      const refreshToken = localStorage.getItem('refreshToken');

      if (accessToken && !isTokenExpired(accessToken)) {
        // Access token is still valid, use it directly
        try {
          setAccessToken(accessToken);
          const userData = ApiService.getUserFromToken(accessToken);
          setUser(userData);
        } catch {
          // If token parsing fails, fall through to refresh logic
          localStorage.removeItem('accessToken');
        }
      } else if (refreshToken) {
        // Access token is expired or missing, but we have a refresh token
        try {
          await refreshAccessToken();
        } catch {
          // Refresh failed, clear tokens
          localStorage.removeItem('refreshToken');
          localStorage.removeItem('accessToken');
        }
      } else {
        // No valid tokens, user needs to login
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
      }
      
      // 2. Indicate that the app has finished checking the initial state
      setIsLoading(false);
    };

    initAuth();
  }, []);

  const login = async (credentials: LoginCredentials) => {
    try {
      const response = await fetch('http://localhost:3000/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
        credentials: 'include',
      });

      if (!response.ok) throw new Error('Login failed');
      
      const data = await response.json();
      // Store tokens and set state
      localStorage.setItem('accessToken', data.accessToken);
      setAccessToken(data.accessToken);
      if (data.refreshToken) {
        localStorage.setItem('refreshToken', data.refreshToken);
      }
      setUser(data.user);
      return data; 
    } catch (error) {
      console.error(error);
      throw error;
    }
  };

  const register = async (credentials: RegisterCredentials) => {
    await ApiService.register(credentials);
    // After registration, automatically log in
    await login(credentials);
  };

  const logout = async () => {
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (refreshToken) {
      try {
        await ApiService.logout(refreshToken);
      } catch (error) {
        console.error('Logout error:', error);
      }
    }
    
    // Clear state
    setAccessToken(null);
    setUser(null);
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('accessToken');
  };

  const setTokens = (accessToken: string, refreshToken: string) => {
    // Store tokens in localStorage
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
    
    // Set access token in state
    setAccessToken(accessToken);
    
    // Decode and set user from access token
    const userData = ApiService.getUserFromToken(accessToken);
    setUser(userData);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        accessToken,
        isLoading,
        login,
        register,
        logout,
        refreshAccessToken,
        setTokens,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
