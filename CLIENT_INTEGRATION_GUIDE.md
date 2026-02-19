# MySSO Client Integration Guide

**A Complete Guide for Integrating Your Application with MySSO's OpenID Connect (OIDC) Provider**

## 📚 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Integration Steps](#integration-steps)
  - [Step 1: Register Your Client Application](#step-1-register-your-client-application)
  - [Step 2: Configure Your Application](#step-2-configure-your-application)
  - [Step 3: Implement the OIDC Flow](#step-3-implement-the-oidc-flow)
- [Code Examples](#code-examples)
  - [JavaScript/TypeScript (Web/SPA)](#javascripttypescript-webspa)
  - [Python](#python)
  - [Node.js (Backend)](#nodejs-backend)
  - [React Example](#react-example)
- [PKCE Implementation](#pkce-implementation)
- [Token Validation](#token-validation)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## Overview

MySSO is a fully-featured OpenID Connect (OIDC) provider that supports:

- ✅ **OpenID Connect Core 1.0** - Complete OIDC implementation
- ✅ **OAuth 2.0 Authorization Code Flow** - Secure token exchange
- ✅ **PKCE (Proof Key for Code Exchange)** - Enhanced security for public clients
- ✅ **Multiple Scopes** - `openid`, `profile`, `email`, and custom admin scopes
- ✅ **RS256 JWT Signing** - Industry-standard token signatures
- ✅ **Consent Management** - User authorization for client apps
- ✅ **Token Refresh** - Long-lived sessions with refresh tokens

### What is OIDC?

OpenID Connect is an identity layer on top of OAuth 2.0 that allows clients to verify user identity and obtain basic profile information. It's the standard used by Google, Microsoft, and other major identity providers.

---

## Prerequisites

Before integrating with MySSO, ensure you have:

1. **Access to the MySSO server** (e.g., `https://sso.example.com`)
2. **A registered client application** with:
   - Client ID
   - Client Secret (for confidential clients)
   - Registered redirect URIs
3. **Basic understanding of OAuth 2.0/OIDC** (this guide will help!)

---

## Quick Start

### 1. Discover OIDC Configuration

MySSO provides auto-discovery through the standard endpoint:

```bash
curl https://sso.lucho-dev.xyz/.well-known/openid-configuration
```

**Response:**
```json
{
  "issuer": "https://sso.lucho-dev.xyz",
  "authorization_endpoint": "https://sso.lucho-dev.xyz/authorize",
  "token_endpoint": "https://sso.lucho-dev.xyz/token",
  "userinfo_endpoint": "https://sso.lucho-dev.xyz/userinfo",
  "jwks_uri": "https://sso.lucho-dev.xyz/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
  "code_challenge_methods_supported": ["plain", "S256"]
}
```

### 2. Basic Integration Flow

```
User → Your App → MySSO (login) → MySSO (consent) → Your App (with code) 
→ Exchange code for tokens → Access user info
```

---

## Integration Steps

### Step 1: Register Your Client Application

Contact your MySSO administrator to register your application. Provide:

- **Application Name**: Your app's name (e.g., "My Awesome App")
- **Redirect URIs**: Where users will be redirected after authentication
  - Example: `https://myapp.com/auth/callback`
  - For development: `http://localhost:3001/callback`
- **Client Type**: 
  - **Public** (for SPAs, mobile apps) - No client secret, must use PKCE
  - **Confidential** (for backend apps) - Has client secret
- **Requested Scopes**: `openid email profile` (or custom scopes)

You'll receive:
- **Client ID**: `my-app-client-id`
- **Client Secret**: `secret123` (only for confidential clients)

### Step 2: Configure Your Application

Create a configuration file or environment variables:

```bash
# .env
OIDC_ISSUER=https://sso.lucho-dev.xyz
OIDC_CLIENT_ID=my-app-client-id
OIDC_CLIENT_SECRET=secret123
OIDC_REDIRECT_URI=https://myapp.com/auth/callback
OIDC_SCOPES=openid email profile
```

### Step 3: Implement the OIDC Flow

The standard OIDC authorization code flow consists of:

1. **Redirect to Authorization Endpoint** with parameters
2. **User authenticates** at MySSO
3. **User provides consent** (if required)
4. **Receive authorization code** via redirect
5. **Exchange code for tokens** (access, refresh, ID token)
6. **Validate and use tokens**

---

## Code Examples

### JavaScript/TypeScript (Web/SPA)

#### Step 1: Generate PKCE Parameters (Required for Public Clients)

```javascript
// PKCE Helper Functions
function generateRandomString(length) {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const values = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(values)
    .map(x => possible[x % possible.length])
    .join('');
}

async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Generate PKCE parameters
const codeVerifier = generateRandomString(128);
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Store codeVerifier in sessionStorage for later use
sessionStorage.setItem('code_verifier', codeVerifier);
```

#### Step 2: Redirect to Authorization Endpoint

```javascript
function initiateLogin() {
  const state = generateRandomString(32);
  const nonce = generateRandomString(32);
  
  // Store state and nonce for validation
  sessionStorage.setItem('oauth_state', state);
  sessionStorage.setItem('oauth_nonce', nonce);
  
  const params = new URLSearchParams({
    client_id: 'my-app-client-id',
    redirect_uri: 'https://myapp.com/auth/callback',
    response_type: 'code',
    scope: 'openid email profile',
    state: state,
    nonce: nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });
  
  window.location.href = `https://sso.example.com/authorize?${params}`;
}
```

#### Step 3: Handle Callback and Exchange Code

```javascript
// In your callback page (e.g., /auth/callback)
async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  
  // Validate state
  const savedState = sessionStorage.getItem('oauth_state');
  if (state !== savedState) {
    throw new Error('Invalid state parameter');
  }
  
  // Retrieve code_verifier
  const codeVerifier = sessionStorage.getItem('code_verifier');
  
  // Exchange code for tokens
  const response = await fetch('https://sso.example.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: 'https://myapp.com/auth/callback',
      client_id: 'my-app-client-id',
      code_verifier: codeVerifier
    })
  });
  
  const tokens = await response.json();
  
  // Store tokens securely
  sessionStorage.setItem('access_token', tokens.access_token);
  sessionStorage.setItem('refresh_token', tokens.refresh_token);
  sessionStorage.setItem('id_token', tokens.id_token);
  
  // Clean up temporary data
  sessionStorage.removeItem('code_verifier');
  sessionStorage.removeItem('oauth_state');
  sessionStorage.removeItem('oauth_nonce');
  
  // Redirect to your app
  window.location.href = '/dashboard';
}
```

#### Step 4: Use Access Token

```javascript
async function getUserInfo() {
  const accessToken = sessionStorage.getItem('access_token');
  
  const response = await fetch('https://sso.lucho-dev.xyz/userinfo', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  const userInfo = await response.json();
  console.log('User Info:', userInfo);
  // { sub: "user-id", email: "user@example.com", email_verified: true }
}
```

### Python

```python
import secrets
import hashlib
import base64
import requests
from urllib.parse import urlencode

# Configuration
OIDC_ISSUER = "https://sso.lucho-dev.xyz"
CLIENT_ID = "my-app-client-id"
CLIENT_SECRET = "secret123"  # Only for confidential clients
REDIRECT_URI = "https://myapp.com/auth/callback"

# Step 1: Generate PKCE parameters
def generate_pkce():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge

# Step 2: Build authorization URL
def get_authorization_url():
    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    
    # Store these in session for later
    # session['code_verifier'] = code_verifier
    # session['state'] = state
    # session['nonce'] = nonce
    
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'nonce': nonce,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    return f"{OIDC_ISSUER}/authorize?{urlencode(params)}"

# Step 3: Exchange authorization code for tokens
def exchange_code_for_tokens(code, code_verifier):
    token_url = f"{OIDC_ISSUER}/token"
    
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'code_verifier': code_verifier
    }
    
    # For confidential clients, add client_secret
    # data['client_secret'] = CLIENT_SECRET
    
    response = requests.post(token_url, json=data)
    response.raise_for_status()
    
    return response.json()

# Step 4: Get user info
def get_user_info(access_token):
    userinfo_url = f"{OIDC_ISSUER}/userinfo"
    
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    response = requests.get(userinfo_url, headers=headers)
    response.raise_for_status()
    
    return response.json()

# Example usage in a Flask app
from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = 'your-secret-key'

@app.route('/login')
def login():
    auth_url = get_authorization_url()
    return redirect(auth_url)

@app.route('/auth/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')
    
    # Validate state
    if state != session.get('state'):
        return 'Invalid state', 400
    
    # Exchange code for tokens
    code_verifier = session.get('code_verifier')
    tokens = exchange_code_for_tokens(code, code_verifier)
    
    # Store tokens
    session['access_token'] = tokens['access_token']
    session['id_token'] = tokens['id_token']
    
    # Get user info
    user_info = get_user_info(tokens['access_token'])
    
    return redirect('/dashboard')
```

### Node.js (Backend)

```javascript
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();

// Configuration
const config = {
  issuer: 'https://sso.example.com',
  clientId: 'my-app-client-id',
  clientSecret: 'secret123',
  redirectUri: 'https://myapp.com/auth/callback',
  scopes: 'openid email profile'
};

// Session middleware
app.use(session({
  secret: 'session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true }
}));

// PKCE helpers
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
}

// Login route
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(32).toString('hex');
  const nonce = crypto.randomBytes(32).toString('hex');
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  
  // Store in session
  req.session.state = state;
  req.session.nonce = nonce;
  req.session.codeVerifier = codeVerifier;
  
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: config.scopes,
    state: state,
    nonce: nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });
  
  res.redirect(`${config.issuer}/authorize?${params}`);
});

// Callback route
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  
  // Validate state
  if (state !== req.session.state) {
    return res.status(400).send('Invalid state');
  }
  
  try {
    // Exchange code for tokens
    const tokenResponse = await fetch(`${config.issuer}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: config.redirectUri,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code_verifier: req.session.codeVerifier
      })
    });
    
    const tokens = await tokenResponse.json();
    
    // Store tokens in session
    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token;
    req.session.idToken = tokens.id_token;
    
    // Clean up
    delete req.session.state;
    delete req.session.nonce;
    delete req.session.codeVerifier;
    
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Token exchange failed:', error);
    res.status(500).send('Authentication failed');
  }
});

// Protected route example
app.get('/api/user', async (req, res) => {
  if (!req.session.accessToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const userInfoResponse = await fetch(`${config.issuer}/userinfo`, {
      headers: { 'Authorization': `Bearer ${req.session.accessToken}` }
    });
    
    const userInfo = await userInfoResponse.json();
    res.json(userInfo);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user info' });
  }
});

app.listen(3001, () => {
  console.log('App running on http://localhost:3001');
});
```

### React Example

```typescript
// hooks/useAuth.ts
import { useState, useEffect } from 'react';

interface AuthConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scopes: string;
}

export function useAuth(config: AuthConfig) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // Generate PKCE parameters
  const generatePKCE = async () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const codeVerifier = btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    
    return { codeVerifier, codeChallenge };
  };

  const login = async () => {
    const { codeVerifier, codeChallenge } = await generatePKCE();
    const state = crypto.randomUUID();
    const nonce = crypto.randomUUID();
    
    sessionStorage.setItem('code_verifier', codeVerifier);
    sessionStorage.setItem('oauth_state', state);
    sessionStorage.setItem('oauth_nonce', nonce);
    
    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: 'code',
      scope: config.scopes,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    });
    
    window.location.href = `${config.issuer}/authorize?${params}`;
  };

  const handleCallback = async (code: string, state: string) => {
    const savedState = sessionStorage.getItem('oauth_state');
    if (state !== savedState) {
      throw new Error('Invalid state');
    }
    
    const codeVerifier = sessionStorage.getItem('code_verifier');
    
    const response = await fetch(`${config.issuer}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: config.redirectUri,
        client_id: config.clientId,
        code_verifier: codeVerifier
      })
    });
    
    const tokens = await response.json();
    
    sessionStorage.setItem('access_token', tokens.access_token);
    sessionStorage.setItem('refresh_token', tokens.refresh_token);
    
    sessionStorage.removeItem('code_verifier');
    sessionStorage.removeItem('oauth_state');
    sessionStorage.removeItem('oauth_nonce');
    
    await fetchUserInfo(tokens.access_token);
  };

  const fetchUserInfo = async (accessToken: string) => {
    const response = await fetch(`${config.issuer}/userinfo`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    
    const userInfo = await response.json();
    setUser(userInfo);
    setIsAuthenticated(true);
  };

  const logout = () => {
    sessionStorage.clear();
    setUser(null);
    setIsAuthenticated(false);
  };

  useEffect(() => {
    const accessToken = sessionStorage.getItem('access_token');
    if (accessToken) {
      fetchUserInfo(accessToken).finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  return { isAuthenticated, user, loading, login, handleCallback, logout };
}

// App.tsx
import { useAuth } from './hooks/useAuth';

function App() {
  const auth = useAuth({
    issuer: 'https://sso.example.com',
    clientId: 'my-app-client-id',
    redirectUri: window.location.origin + '/callback',
    scopes: 'openid email profile'
  });

  if (auth.loading) return <div>Loading...</div>;

  if (!auth.isAuthenticated) {
    return (
      <div>
        <h1>Welcome</h1>
        <button onClick={auth.login}>Sign In with SSO</button>
      </div>
    );
  }

  return (
    <div>
      <h1>Hello, {auth.user.email}</h1>
      <button onClick={auth.logout}>Sign Out</button>
    </div>
  );
}

// Callback.tsx
import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';

function Callback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const auth = useAuth({
    issuer: 'https://sso.example.com',
    clientId: 'my-app-client-id',
    redirectUri: window.location.origin + '/callback',
    scopes: 'openid email profile'
  });

  useEffect(() => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    
    if (code && state) {
      auth.handleCallback(code, state)
        .then(() => navigate('/dashboard'))
        .catch(err => {
          console.error('Authentication failed:', err);
          navigate('/login');
        });
    }
  }, [searchParams]);

  return <div>Completing sign in...</div>;
}
```

---

## PKCE Implementation

PKCE (Proof Key for Code Exchange) is **required** for public clients and **recommended** for all clients.

### Why PKCE?

PKCE protects against authorization code interception attacks, especially important for:
- Single Page Applications (SPAs)
- Mobile applications
- Any client that can't securely store a client secret

### How PKCE Works

1. **Generate a random `code_verifier`** (43-128 characters)
2. **Create a `code_challenge`** by hashing the verifier with SHA-256
3. **Send `code_challenge`** in the authorization request
4. **Send `code_verifier`** in the token request
5. **Server verifies** that the verifier matches the challenge

### PKCE Implementations by Language

#### JavaScript (Browser)

```javascript
// Generate code_verifier (random string)
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

// Generate code_challenge (SHA-256 hash of verifier)
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(digest));
}

function base64URLEncode(buffer) {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
```

#### Python

```python
import secrets
import hashlib
import base64

def generate_code_verifier():
    return base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')

def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
```

#### Node.js

```javascript
const crypto = require('crypto');

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
}
```

#### Java

```java
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class PKCE {
    public static String generateCodeVerifier() {
        SecureRandom sr = new SecureRandom();
        byte[] code = new byte[32];
        sr.nextBytes(code);
        return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(code);
    }
    
    public static String generateCodeChallenge(String verifier) throws Exception {
        byte[] bytes = verifier.getBytes("US-ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes, 0, bytes.length);
        byte[] digest = md.digest();
        return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(digest);
    }
}
```

---

## Token Validation

### Validating ID Tokens

ID tokens are JWTs that should be validated before use:

1. **Verify the signature** using the public key from `/jwks.json`
2. **Validate claims**:
   - `iss` (issuer) matches your OIDC issuer
   - `aud` (audience) matches your client ID
   - `exp` (expiration) hasn't passed
   - `nonce` matches the one you sent (if used)

#### Example: Validate ID Token (Node.js)

```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  jwksUri: 'https://sso.example.com/jwks.json'
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

function validateIdToken(idToken, clientId, nonce) {
  return new Promise((resolve, reject) => {
    jwt.verify(idToken, getKey, {
      audience: clientId,
      issuer: 'https://sso.example.com',
      algorithms: ['RS256']
    }, (err, decoded) => {
      if (err) return reject(err);
      
      // Validate nonce
      if (nonce && decoded.nonce !== nonce) {
        return reject(new Error('Invalid nonce'));
      }
      
      resolve(decoded);
    });
  });
}
```

#### Example: Validate ID Token (Python)

```python
from jose import jwt
import requests

# Fetch JWKS
jwks_url = "https://sso.example.com/jwks.json"
jwks = requests.get(jwks_url).json()

# Validate ID token
def validate_id_token(id_token, client_id, nonce):
    try:
        claims = jwt.decode(
            id_token,
            jwks,
            algorithms=['RS256'],
            audience=client_id,
            issuer='https://sso.example.com'
        )
        
        # Validate nonce
        if nonce and claims.get('nonce') != nonce:
            raise ValueError('Invalid nonce')
        
        return claims
    except Exception as e:
        raise ValueError(f'Token validation failed: {e}')
```

### Refreshing Access Tokens

Access tokens expire after 15 minutes. Use the refresh token to get a new one:

```javascript
async function refreshAccessToken(refreshToken) {
  const response = await fetch('https://sso.example.com/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken })
  });
  
  const data = await response.json();
  
  // Store new access token
  sessionStorage.setItem('access_token', data.accessToken);
  
  return data.accessToken;
}
```

---

## Security Best Practices

### 1. Use HTTPS in Production

**Always** use HTTPS for production deployments. MySSO enforces secure cookies in production mode.

### 2. Implement PKCE

Use PKCE for **all** clients, especially public clients (SPAs, mobile apps).

### 3. Validate State Parameter

Always validate the `state` parameter to prevent CSRF attacks:

```javascript
// Before authorization
const state = crypto.randomUUID();
sessionStorage.setItem('oauth_state', state);

// In callback
const receivedState = params.get('state');
const savedState = sessionStorage.getItem('oauth_state');

if (receivedState !== savedState) {
  throw new Error('CSRF detected: Invalid state parameter');
}
```

### 4. Validate Nonce in ID Token

The nonce prevents replay attacks:

```javascript
// Before authorization
const nonce = crypto.randomUUID();
sessionStorage.setItem('oauth_nonce', nonce);

// After receiving ID token
const decoded = jwt.decode(idToken);
const savedNonce = sessionStorage.getItem('oauth_nonce');

if (decoded.nonce !== savedNonce) {
  throw new Error('Invalid nonce in ID token');
}
```

### 5. Secure Token Storage

**Browser Applications:**
- ✅ Use `sessionStorage` for access tokens (cleared on tab close)
- ❌ Avoid `localStorage` (persists across sessions, XSS risk)
- ✅ Consider httpOnly cookies for refresh tokens (set by backend)

**Backend Applications:**
- ✅ Store tokens in server-side sessions
- ✅ Use encrypted session stores
- ❌ Never log tokens or include in error messages

### 6. Handle Token Expiration

Implement automatic token refresh before expiration:

```javascript
// Check token expiration before API calls
async function makeAuthenticatedRequest(url) {
  let accessToken = sessionStorage.getItem('access_token');
  
  // Decode to check expiration (don't trust blindly, validate signature too)
  const decoded = jwt.decode(accessToken);
  const expiresAt = decoded.exp * 1000; // Convert to milliseconds
  const now = Date.now();
  
  // Refresh if expiring in next 5 minutes
  if (expiresAt - now < 5 * 60 * 1000) {
    const refreshToken = sessionStorage.getItem('refresh_token');
    accessToken = await refreshAccessToken(refreshToken);
  }
  
  return fetch(url, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
}
```

### 7. Logout Properly

Clear all stored tokens and session data:

```javascript
function logout() {
  // Clear tokens
  sessionStorage.removeItem('access_token');
  sessionStorage.removeItem('refresh_token');
  sessionStorage.removeItem('id_token');
  
  // Optional: Call logout endpoint to revoke tokens server-side
  fetch('https://sso.example.com/auth/logout', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  // Redirect to login
  window.location.href = '/login';
}
```

### 8. Scope Principle of Least Privilege

Only request the scopes you actually need:

```javascript
// ✅ Good - Only request what you need
scope: 'openid email'

// ❌ Bad - Requesting unnecessary scopes
scope: 'openid email profile read:users admin'
```

---

## Troubleshooting

### Common Errors and Solutions

#### Error: `invalid_grant`

**Cause**: Authorization code is invalid, expired, or already used.

**Solutions**:
- Authorization codes expire after 60 seconds. Ensure you exchange them quickly.
- Each code can only be used once. Don't retry with the same code.
- Verify the `redirect_uri` matches exactly what was used in the authorization request.
- If using PKCE, ensure `code_verifier` matches the `code_challenge`.

#### Error: `invalid_client`

**Cause**: Client authentication failed.

**Solutions**:
- Verify your `client_id` is correct.
- For confidential clients, verify your `client_secret` is correct.
- Ensure your client is registered with the SSO server.

#### Error: `redirect_uri_mismatch`

**Cause**: The redirect URI is not registered for your client.

**Solutions**:
- Contact your SSO administrator to add your redirect URI.
- Ensure the redirect URI in your request exactly matches the registered one (including trailing slashes, ports, etc.).
- Development: `http://localhost:3001/callback` ≠ `http://localhost:3001/callback/`

#### Error: `unauthorized` or `401`

**Cause**: Access token is missing, invalid, or expired.

**Solutions**:
- Verify you're including the token: `Authorization: Bearer <token>`
- Check if the token has expired (15 minutes by default).
- Try refreshing the token using the refresh token.
- Ensure you're using the access token, not the ID token or refresh token.

#### Error: `invalid_scope`

**Cause**: Requested scopes are not allowed for your client.

**Solutions**:
- Only request scopes that were registered for your client.
- Check with your SSO administrator for your allowed scopes.
- Common scopes: `openid`, `email`, `profile`

#### PKCE Errors

**Error**: `PKCE verification failed`

**Solutions**:
- Ensure you're sending the same `code_verifier` that was used to generate the `code_challenge`.
- Verify your SHA-256 hashing and base64url encoding are correct.
- Check that you're using the correct `code_challenge_method` (S256 or plain).

#### CORS Errors

**Error**: `Access to fetch at ... has been blocked by CORS policy`

**Solutions**:
- Contact your SSO administrator to add your origin to the allowed origins.
- Ensure you're making requests from the correct origin.
- For development, ensure `http://localhost:3001` is in the allowed origins.

---

## FAQ

### Q: Do I need PKCE for my application?

**A**: Yes! PKCE is **required** for public clients (SPAs, mobile apps) and **highly recommended** for all clients. MySSO supports both `plain` and `S256` methods, but `S256` is more secure.

### Q: What's the difference between access_token and id_token?

**A**: 
- **access_token**: Used to access protected resources (APIs). Opaque or JWT.
- **id_token**: Contains user identity information. Always a JWT. Used to authenticate the user.
- **refresh_token**: Used to obtain new access tokens without re-authenticating.

### Q: How long do tokens last?

**A**: 
- **Access tokens**: 15 minutes
- **Refresh tokens**: 7 days (configurable)
- **Authorization codes**: 60 seconds

### Q: Can I use MySSO with mobile apps?

**A**: Yes! Use the authorization code flow with PKCE. For mobile apps:
- Use deep links or custom URL schemes for redirect URIs
- Implement PKCE (required for public clients)
- Use secure storage for tokens (iOS Keychain, Android KeyStore)

### Q: What scopes are available?

**A**: Standard scopes include:
- `openid` (required for OIDC)
- `email` (user's email address)
- `profile` (user's profile information)

Your SSO administrator may have configured additional custom scopes like `admin`, `read:users`, etc.

### Q: How do I test my integration?

**A**: 
1. Use the OIDC discovery endpoint to verify configuration
2. Test the full flow in a development environment
3. Verify token validation
4. Test error scenarios (expired codes, invalid scopes, etc.)
5. Check PKCE implementation with both valid and invalid verifiers

### Q: Can I use an existing OIDC library?

**A**: Yes! MySSO is compatible with standard OIDC libraries:
- **JavaScript**: `oidc-client-ts`, `@auth0/auth0-react`
- **Python**: `authlib`, `python-jose`
- **Node.js**: `passport-openidconnect`, `openid-client`
- **Java**: `pac4j`, `Spring Security OAuth`
- **.NET**: `Microsoft.AspNetCore.Authentication.OpenIdConnect`

Just configure them with MySSO's discovery endpoint.

### Q: What if I encounter rate limiting?

**A**: MySSO doesn't currently implement rate limiting, but it's planned for future releases. Implement exponential backoff in your client to handle potential rate limiting gracefully.

### Q: How do I revoke tokens?

**A**: Call the logout endpoint with your access token:

```javascript
POST /auth/logout
Authorization: Bearer <access_token>
```

This will revoke your session and all associated tokens.

### Q: Can I use MySSO for SSO across multiple applications?

**A**: Yes! That's exactly what it's designed for. Register each application as a separate client with MySSO. Users will only need to log in once, and they can authorize access to multiple applications.

---

## Additional Resources

- **OpenID Connect Discovery**: `GET /.well-known/openid-configuration`
- **JWKS Endpoint**: `GET /jwks.json`
- **Technical Documentation**: See `docs/OIDC_ENDPOINTS.md`
- **OAuth 2.0 Flow**: See `docs/OAUTH2_FLOW.md`
- **Security Guide**: See `docs/SECURITY.md`

## Support

For issues or questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review the [FAQ](#faq)
3. Contact your SSO administrator
4. Report issues to the repository maintainers

---

## Quick Reference Card

### Essential Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/openid-configuration` | GET | OIDC discovery |
| `/authorize` | GET | Start authorization |
| `/token` | POST | Exchange code for tokens |
| `/userinfo` | GET | Get user information |
| `/jwks.json` | GET | Public keys for JWT validation |
| `/auth/refresh` | POST | Refresh access token |
| `/auth/logout` | POST | Logout and revoke tokens |

### Required Parameters

**Authorization Request:**
- `client_id` - Your client identifier (required)
- `redirect_uri` - Callback URL (required)
- `response_type` - Set to `code` (required)
- `scope` - Requested scopes, e.g., `openid email profile` (required)
- `state` - CSRF protection token (recommended)
- `nonce` - Replay protection for ID token (recommended)
- `code_challenge` - PKCE challenge (required for public clients)
- `code_challenge_method` - `S256` or `plain` (required for public clients)

**Token Request:**
- `grant_type` - Set to `authorization_code` (required)
- `code` - Authorization code from callback (required)
- `redirect_uri` - Same as authorization request (required)
- `client_id` - Your client identifier (optional but recommended)
- `client_secret` - For confidential clients (required for confidential)
- `code_verifier` - PKCE verifier (required if challenge was used)

### Token Lifetimes

| Token Type | Lifetime |
|------------|----------|
| Authorization Code | 60 seconds |
| Access Token | 15 minutes |
| Refresh Token | 7 days |

### Standard Scopes

| Scope | Returns |
|-------|---------|
| `openid` | Required for OIDC, returns `sub` claim |
| `email` | User's email and email_verified |
| `profile` | User's name and profile info |

### Common HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 302 | Redirect (authorization flow) |
| 400 | Bad Request (invalid parameters) |
| 401 | Unauthorized (invalid/expired token) |
| 403 | Forbidden (insufficient scopes) |
| 500 | Server Error |

---

**Happy integrating! 🚀**
