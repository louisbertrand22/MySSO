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

  const refreshAccessToken = async () => {
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await ApiService.refresh(refreshToken);
    setAccessToken(response.accessToken);
    
    const userData = ApiService.getUserFromToken(response.accessToken);
    setUser(userData);
  };

  // Load refresh token from localStorage and attempt to refresh on mount
  useEffect(() => {
    const initAuth = async () => {
      const refreshToken = localStorage.getItem('refreshToken');
      if (refreshToken) {
        try {
          await refreshAccessToken();
        } catch (error) {
          // Silently clear invalid/expired refresh token
          // This is expected behavior when tokens expire
          localStorage.removeItem('refreshToken');
        }
      }
      setIsLoading(false);
    };

    initAuth();
  }, []);

  const login = async (credentials: LoginCredentials) => {
    const response = await ApiService.login(credentials);
    
    // Store access token in memory
    setAccessToken(response.accessToken);
    
    // Store refresh token in localStorage (consider HttpOnly cookie in production)
    localStorage.setItem('refreshToken', response.refreshToken);
    
    // Decode and set user from access token
    const userData = ApiService.getUserFromToken(response.accessToken);
    setUser(userData);
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
  };

  const setTokens = (accessToken: string, refreshToken: string) => {
    // Store access token in memory
    setAccessToken(accessToken);
    
    // Store refresh token in localStorage
    localStorage.setItem('refreshToken', refreshToken);
    
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
