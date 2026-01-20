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
    localStorage.setItem('accessToken', response.accessToken);
  };


  useEffect(() => {
    const initAuth = async () => {
      // 1. On récupère les deux tokens
      const accessToken = localStorage.getItem('accessToken');
      const refreshToken = localStorage.getItem('refreshToken');

      if (refreshToken) {
        try {
          await refreshAccessToken();
        } catch {
          localStorage.removeItem('refreshToken');
          localStorage.removeItem('accessToken');
        }
      } else if (accessToken) {
        // Si on a un access token mais pas de refresh, 
        // on devrait au moins essayer de récupérer les infos user
        try {
          const res = await fetch('http://localhost:3000/auth/me', {
            headers: { 'Authorization': `Bearer ${accessToken}` }
          });
          const userData = await res.json();
          setUser(userData.user);
        } catch {
          localStorage.removeItem('accessToken');
        }
      }
      
      // 2. On indique que l'application a fini de vérifier l'état initial
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
      // Stockage du token (indispensable pour que le backend reconnaisse l'utilisateur après)
      localStorage.setItem('accessToken', data.accessToken); 
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
