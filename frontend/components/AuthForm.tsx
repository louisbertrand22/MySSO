'use client';

import { useState, FormEvent, useEffect } from 'react';

interface AuthFormProps {
  mode: 'login' | 'register';
  onSubmit: (email: string, password: string) => Promise<void>;
  error: string | null;
}

export default function AuthForm({ mode, onSubmit, error }: AuthFormProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [emailError, setEmailError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);

  // Load saved email on component mount (only for login mode)
  useEffect(() => {
    if (mode === 'login') {
      try {
        const savedEmail = localStorage.getItem('savedUsername');
        if (savedEmail) {
          setEmail(savedEmail);
          setRememberMe(true);
        }
      } catch (error) {
        // localStorage might not be available (e.g., private browsing mode)
        console.warn('Failed to load saved email:', error);
      }
    }
  }, [mode]);

  const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email) {
      setEmailError('Email is required');
      return false;
    }
    if (!emailRegex.test(email)) {
      setEmailError('Please enter a valid email address');
      return false;
    }
    setEmailError('');
    return true;
  };

  const validatePassword = (password: string): boolean => {
    if (!password) {
      setPasswordError('Password is required');
      return false;
    }
    
    if (mode === 'register') {
      if (password.length < 8) {
        setPasswordError('Password must be at least 8 characters');
        return false;
      }
      
      if (!/[A-Z]/.test(password)) {
        setPasswordError('Password must contain at least one uppercase letter');
        return false;
      }
      
      if (!/[a-z]/.test(password)) {
        setPasswordError('Password must contain at least one lowercase letter');
        return false;
      }
      
      if (!/[0-9]/.test(password)) {
        setPasswordError('Password must contain at least one number');
        return false;
      }
      
      if (confirmPassword && password !== confirmPassword) {
        setPasswordError('Passwords do not match');
        return false;
      }
    }
    
    setPasswordError('');
    return true;
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    const isEmailValid = validateEmail(email);
    const isPasswordValid = validatePassword(password);
    
    if (!isEmailValid || !isPasswordValid) {
      return;
    }

    setIsSubmitting(true);
    try {
      // Save or remove username based on rememberMe checkbox (only for login)
      if (mode === 'login') {
        try {
          if (rememberMe) {
            localStorage.setItem('savedUsername', email);
          } else {
            localStorage.removeItem('savedUsername');
          }
        } catch (error) {
          // localStorage might not be available (e.g., private browsing mode)
          console.warn('Failed to save/remove email:', error);
        }
      }
      
      await onSubmit(email, password);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div>
        <label htmlFor="email" className="block text-sm font-medium text-gray-700">
          Email address
        </label>
        <div className="mt-1">
          <input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onBlur={() => validateEmail(email)}
            className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          />
        </div>
        {emailError && (
          <p className="mt-2 text-sm text-red-600">{emailError}</p>
        )}
      </div>

      <div>
        <label htmlFor="password" className="block text-sm font-medium text-gray-700">
          Password
        </label>
        <div className="mt-1">
          <input
            id="password"
            name="password"
            type="password"
            autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onBlur={() => validatePassword(password)}
            className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          />
        </div>
        {passwordError && (
          <p className="mt-2 text-sm text-red-600">{passwordError}</p>
        )}
      </div>

      {mode === 'register' && (
        <div>
          <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
            Confirm Password
          </label>
          <div className="mt-1">
            <input
              id="confirmPassword"
              name="confirmPassword"
              type="password"
              autoComplete="new-password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              onBlur={() => validatePassword(password)}
              className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            />
          </div>
        </div>
      )}

      {mode === 'login' && (
        <div className="flex items-center">
          <input
            id="remember-me"
            name="remember-me"
            type="checkbox"
            checked={rememberMe}
            onChange={(e) => {
              const isChecked = e.target.checked;
              setRememberMe(isChecked);
              // Immediately remove saved email when unchecked for better UX
              if (!isChecked) {
                try {
                  localStorage.removeItem('savedUsername');
                } catch (error) {
                  console.warn('Failed to remove saved email:', error);
                }
              }
            }}
            className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
          />
          <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-900">
            Remember my email
          </label>
        </div>
      )}

      {error && (
        <div className="rounded-md bg-red-50 p-4">
          <div className="flex">
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">{error}</h3>
            </div>
          </div>
        </div>
      )}

      <div>
        <button
          type="submit"
          disabled={isSubmitting}
          className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isSubmitting ? 'Loading...' : mode === 'login' ? 'Sign in' : 'Sign up'}
        </button>
      </div>
    </form>
  );
}
