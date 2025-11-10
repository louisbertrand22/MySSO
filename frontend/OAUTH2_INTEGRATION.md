# Frontend OAuth2 Integration

This guide explains how to integrate the OAuth2 authorization code flow in the frontend application.

## Overview

The OAuth2 authorization code flow allows client applications to authenticate users through the SSO server without handling credentials directly.

## Files Added

- `/app/callback/page.tsx` - OAuth2 callback handler page
- `/lib/oauth2/client.ts` - OAuth2 client helper functions

## Integration Steps

### 1. Configure Environment Variables

Add to `.env.local`:

```bash
NEXT_PUBLIC_API_URL=http://localhost:3000
NEXT_PUBLIC_ALLOWED_ORIGINS=http://localhost:3001
```

### 2. Create Callback Route

The callback route (`/app/callback/page.tsx`) is already created and handles:
- Extracting the authorization code from the URL
- Exchanging the code for access and refresh tokens
- Storing the tokens
- Redirecting to the dashboard

### 3. Update AuthContext (if needed)

Make sure your `AuthContext` has a `setTokens` method to store the tokens:

```typescript
const setTokens = (accessToken: string, refreshToken: string) => {
  localStorage.setItem('accessToken', accessToken);
  localStorage.setItem('refreshToken', refreshToken);
  // Update state
};
```

### 4. Initiate OAuth2 Flow

Use the helper function to start the OAuth2 flow:

```typescript
import { initiateOAuth2Flow } from '@/lib/oauth2/client';

// In your component
const handleSSO = () => {
  // Optional: Get access token if user is already authenticated
  const accessToken = localStorage.getItem('accessToken');
  
  // Start OAuth2 flow
  initiateOAuth2Flow(undefined, accessToken);
};

// In your JSX
<button onClick={handleSSO}>
  Sign in with SSO
</button>
```

## Complete Example

### Login Page with SSO Option

```typescript
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { initiateOAuth2Flow } from '@/lib/oauth2/client';

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);

  const handleSSO = () => {
    // Initiate OAuth2 flow
    initiateOAuth2Flow();
  };

  const handleRegularLogin = async (email: string, password: string) => {
    try {
      await login({ email, password });
      router.push('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="max-w-md w-full space-y-8">
        <h2 className="text-3xl font-bold text-center">Sign In</h2>
        
        {/* SSO Button */}
        <button
          onClick={handleSSO}
          className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700"
        >
          Sign in with SSO
        </button>

        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300" />
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-500">Or</span>
          </div>
        </div>

        {/* Regular Login Form */}
        <form onSubmit={(e) => {
          e.preventDefault();
          const formData = new FormData(e.currentTarget);
          handleRegularLogin(
            formData.get('email') as string,
            formData.get('password') as string
          );
        }}>
          <input
            name="email"
            type="email"
            required
            placeholder="Email"
            className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
          />
          <input
            name="password"
            type="password"
            required
            placeholder="Password"
            className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm mt-2"
          />
          <button
            type="submit"
            className="mt-4 w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gray-600 hover:bg-gray-700"
          >
            Sign in with Email
          </button>
        </form>

        {error && (
          <div className="rounded-md bg-red-50 p-4">
            <p className="text-sm text-red-800">{error}</p>
          </div>
        )}
      </div>
    </div>
  );
}
```

## Flow Diagram

```
┌─────────┐                                  ┌─────────┐
│ Client  │                                  │   SSO   │
│  App    │                                  │ Server  │
└────┬────┘                                  └────┬────┘
     │                                            │
     │ 1. User clicks "Sign in with SSO"         │
     │                                            │
     │ 2. Redirect to /login?redirect_uri=...    │
     ├──────────────────────────────────────────>│
     │                                            │
     │ 3. User authenticates (provides token)    │
     │                                            │
     │ 4. Redirect to callback?code=...          │
     │<──────────────────────────────────────────┤
     │                                            │
     │ 5. Exchange code for tokens (POST /token) │
     ├──────────────────────────────────────────>│
     │                                            │
     │ 6. Return access_token + refresh_token    │
     │<──────────────────────────────────────────┤
     │                                            │
     │ 7. Store tokens and redirect to dashboard │
     │                                            │
```

## Security Considerations

1. **HTTPS Only in Production**: Always use HTTPS for OAuth2 flows in production
2. **Validate Redirect URI**: The server validates redirect URIs against a whitelist
3. **Short-Lived Codes**: Authorization codes expire in 60 seconds
4. **Single-Use Codes**: Each code can only be used once
5. **Secure Storage**: Store tokens in secure storage (httpOnly cookies preferred)

## Error Handling

The callback page handles common errors:

- **No code**: User arrived at callback without an authorization code
- **Invalid code**: Authorization code is invalid or expired
- **Token exchange failure**: Server rejected the token exchange
- **Network errors**: Connection issues with the SSO server

All errors display a user-friendly message with a link back to login.

## Testing

### Test the Complete Flow

1. Start the SSO server:
   ```bash
   cd /home/runner/work/MySSO/MySSO
   npm run dev
   ```

2. Start the frontend:
   ```bash
   cd frontend
   npm run dev
   ```

3. Navigate to the login page and click "Sign in with SSO"

4. You'll be redirected to the SSO server

5. After authentication, you'll be redirected back to `/callback`

6. The callback page will exchange the code for tokens

7. You'll be redirected to the dashboard

### Test Error Cases

- Try accessing `/callback` without a code
- Try reusing an authorization code
- Try using an expired code (wait 60+ seconds)

## Troubleshooting

### "redirect_uri not allowed"

Make sure your redirect URI is in the whitelist in `authCodeService.ts`:

```typescript
private static ALLOWED_REDIRECT_URIS = [
  'http://localhost:5173/callback',
  'http://localhost:3001/callback',
];
```

### "Invalid authorization code"

- Check that the code hasn't expired (60 second limit)
- Verify you're using the same redirect_uri in both requests
- Ensure the code hasn't been used already

### CORS Errors

Add your frontend origin to the CORS configuration in the server's `.env`:

```
ALLOWED_ORIGINS=http://localhost:3001,http://localhost:5173
```

## Next Steps

1. **Add SSO button to your login page**
2. **Customize the callback page design**
3. **Add error tracking/monitoring**
4. **Implement token refresh on expiration**
5. **Add loading states and progress indicators**
