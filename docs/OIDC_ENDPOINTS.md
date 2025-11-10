# OpenID Connect Endpoints Documentation

This document provides detailed information about the OpenID Connect (OIDC) endpoints implemented in MySSO, including PKCE support for enhanced security.

## Table of Contents

- [Discovery Endpoint](#discovery-endpoint)
- [JWKS Endpoint](#jwks-endpoint)
- [Authorization Endpoint](#authorization-endpoint)
- [Token Endpoint](#token-endpoint)
- [UserInfo Endpoint](#userinfo-endpoint)
- [Complete OIDC Flow Example](#complete-oidc-flow-example)
- [PKCE Flow Example](#pkce-flow-example)

## Discovery Endpoint

### GET /.well-known/openid-configuration

Returns the OpenID Connect discovery document containing metadata about the authorization server.

**Request:**
```bash
curl http://localhost:3000/.well-known/openid-configuration
```

**Response:**
```json
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/authorize",
  "token_endpoint": "http://localhost:3000/token",
  "userinfo_endpoint": "http://localhost:3000/userinfo",
  "jwks_uri": "http://localhost:3000/jwks.json",
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "claims_supported": ["sub", "name", "email", "email_verified", "updated_at", "iat", "auth_time", "nonce"],
  "code_challenge_methods_supported": ["plain", "S256"],
  "grant_types_supported": ["authorization_code", "refresh_token"]
}
```

## JWKS Endpoint

### GET /jwks.json

Returns the JSON Web Key Set (JWKS) containing the public keys used to verify JWT signatures.

**Request:**
```bash
curl http://localhost:3000/jwks.json
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-1",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

## Authorization Endpoint

### GET /authorize

Initiates the OAuth2/OIDC authorization flow. Requires user authentication via Bearer token.

**Parameters:**
- `client_id` (required): The client identifier
- `redirect_uri` (required): The callback URI
- `response_type` (optional): The response type (default: "code")
- `scope` (optional): Space-separated list of scopes (default: "openid profile email")
- `state` (optional): CSRF protection token
- `nonce` (optional): OIDC nonce for replay attack prevention
- `code_challenge` (optional): PKCE code challenge
- `code_challenge_method` (optional): PKCE method ("plain" or "S256", default: "plain")

**Request Example (without PKCE):**
```bash
# First, login to get an access token
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# Use the access token to authorize
curl -i "http://localhost:3000/authorize?client_id=my-client&redirect_uri=http://localhost:5173/callback&scope=openid%20profile%20email&state=random-state-value&nonce=random-nonce-value" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Request Example (with PKCE - S256):**
```bash
# Generate PKCE code verifier and challenge (example in bash)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | base64 | tr -d "=+/" | tr "/+" "_-")

# Authorize with PKCE
curl -i "http://localhost:3000/authorize?client_id=my-client&redirect_uri=http://localhost:5173/callback&scope=openid%20profile%20email&state=random-state&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
Redirects to the callback URI with the authorization code:
```
http://localhost:5173/callback?code=AUTH_CODE&state=random-state-value
```

## Token Endpoint

### POST /token

Exchanges an authorization code for access, refresh, and ID tokens.

**Parameters (form-encoded or JSON):**
- `grant_type` (required): Must be "authorization_code"
- `code` (required): The authorization code
- `redirect_uri` (required): The same redirect URI used in authorization
- `client_id` (optional): The client identifier
- `client_secret` (optional): The client secret (for confidential clients)
- `code_verifier` (optional): PKCE code verifier (required if code_challenge was used)

**Request Example (without PKCE):**
```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTH_CODE_FROM_AUTHORIZE",
    "redirect_uri": "http://localhost:5173/callback"
  }'
```

**Request Example (with PKCE):**
```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTH_CODE_FROM_AUTHORIZE",
    "redirect_uri": "http://localhost:5173/callback",
    "code_verifier": "'"$CODE_VERIFIER"'"
  }'
```

**Request Example (confidential client with secret):**
```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTH_CODE_FROM_AUTHORIZE",
    "redirect_uri": "http://localhost:5173/callback",
    "client_id": "my-client",
    "client_secret": "CLIENT_SECRET"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**ID Token Claims:**
The `id_token` is a JWT containing:
```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "email_verified": true,
  "iat": 1699999999,
  "auth_time": 1699999999,
  "nonce": "random-nonce-value",
  "iss": "http://localhost:3000",
  "aud": "my-client",
  "exp": 1699999999
}
```

## UserInfo Endpoint

### GET /userinfo

Returns claims about the authenticated user. Requires a valid access token.

**Request:**
```bash
curl http://localhost:3000/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

**Response (with openid, profile, and email scopes):**
```json
{
  "sub": "user-id",
  "name": "user",
  "updated_at": 1699999999,
  "email": "user@example.com",
  "email_verified": true
}
```

**Response (with only openid scope):**
```json
{
  "sub": "user-id"
}
```

**Response (with openid and email scopes):**
```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "email_verified": true
}
```

## Complete OIDC Flow Example

Here's a complete example of the OpenID Connect authorization code flow:

```bash
#!/bin/bash

# Configuration
BASE_URL="http://localhost:3000"
CLIENT_ID="my-client"
REDIRECT_URI="http://localhost:5173/callback"
STATE="random-state-$(date +%s)"
NONCE="random-nonce-$(date +%s)"

# Step 1: Register a user
echo "Step 1: Registering user..."
curl -X POST $BASE_URL/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "SecurePassword123!"
  }'

# Step 2: Login to get access token
echo -e "\n\nStep 2: Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST $BASE_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "SecurePassword123!"
  }')

ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4)
echo "Access Token: $ACCESS_TOKEN"

# Step 3: Request authorization
echo -e "\n\nStep 3: Requesting authorization..."
AUTH_REDIRECT=$(curl -s -i "$BASE_URL/authorize?client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid%20profile%20email&state=$STATE&nonce=$NONCE" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | grep -i "location:" | cut -d' ' -f2 | tr -d '\r')

# Extract authorization code from redirect
AUTH_CODE=$(echo $AUTH_REDIRECT | grep -o 'code=[^&]*' | cut -d'=' -f2)
echo "Authorization Code: $AUTH_CODE"

# Step 4: Exchange code for tokens
echo -e "\n\nStep 4: Exchanging code for tokens..."
TOKEN_RESPONSE=$(curl -s -X POST $BASE_URL/token \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"authorization_code\",
    \"code\": \"$AUTH_CODE\",
    \"redirect_uri\": \"$REDIRECT_URI\"
  }")

echo "Token Response:"
echo $TOKEN_RESPONSE | jq '.'

NEW_ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
ID_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"id_token":"[^"]*' | cut -d'"' -f4)

# Step 5: Get user info
echo -e "\n\nStep 5: Getting user info..."
curl -s $BASE_URL/userinfo \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" | jq '.'

# Step 6: Decode ID token (requires jwt-cli or similar)
if command -v jwt &> /dev/null; then
  echo -e "\n\nStep 6: Decoded ID Token:"
  jwt decode $ID_TOKEN
fi
```

## PKCE Flow Example

PKCE (Proof Key for Code Exchange) is recommended for public clients and provides additional security.

```bash
#!/bin/bash

BASE_URL="http://localhost:3000"
CLIENT_ID="my-public-client"
REDIRECT_URI="http://localhost:5173/callback"
STATE="random-state-$(date +%s)"

# Generate PKCE code verifier and challenge
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | base64 | tr -d "=+/" | tr "/+" "_-")

echo "Code Verifier: $CODE_VERIFIER"
echo "Code Challenge: $CODE_CHALLENGE"

# Login and get access token
LOGIN_RESPONSE=$(curl -s -X POST $BASE_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "SecurePassword123!"
  }')

ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4)

# Request authorization with PKCE
AUTH_REDIRECT=$(curl -s -i "$BASE_URL/authorize?client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid%20email&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | grep -i "location:" | cut -d' ' -f2 | tr -d '\r')

AUTH_CODE=$(echo $AUTH_REDIRECT | grep -o 'code=[^&]*' | cut -d'=' -f2)
echo "Authorization Code: $AUTH_CODE"

# Exchange code for tokens with code verifier
TOKEN_RESPONSE=$(curl -s -X POST $BASE_URL/token \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"authorization_code\",
    \"code\": \"$AUTH_CODE\",
    \"redirect_uri\": \"$REDIRECT_URI\",
    \"code_verifier\": \"$CODE_VERIFIER\"
  }")

echo "Token Response:"
echo $TOKEN_RESPONSE | jq '.'
```

## Security Features

### PKCE (Proof Key for Code Exchange)
- Supports both `plain` and `S256` methods
- Recommended for public clients (mobile apps, SPAs)
- Required when `code_challenge` is provided during authorization
- Prevents authorization code interception attacks

### Nonce
- Used to prevent replay attacks on ID tokens
- Included in the ID token when provided in authorization request
- Should be validated by the client

### Client Authentication
- **Public Clients**: No client_secret required (use PKCE instead)
- **Confidential Clients**: Must provide valid client_secret
- Supports `client_secret_post` (in request body) and `client_secret_basic` (in Authorization header)

### Code Expiration
- Authorization codes expire in 60 seconds
- Codes are single-use only
- Used codes are immediately deleted from the database

### TLS/HTTPS
- **REQUIRED** in production (`NODE_ENV=production`)
- Cookies are marked as `Secure` in production
- All sensitive data transmitted over encrypted connections

## Troubleshooting

### Common Errors

**Error: `invalid_grant`**
- Authorization code expired (>60 seconds)
- Code already used
- Invalid redirect_uri
- PKCE verification failed

**Error: `invalid_client`**
- Invalid client_id
- Invalid client_secret
- Client not found

**Error: `unauthorized`**
- Missing or invalid access token
- Token expired

**Error: `invalid_request`**
- Missing required parameters
- Invalid parameter format
- Invalid code_challenge_method

## Additional Resources

- [OpenID Connect Core Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [MySSO OAuth2 Flow Documentation](OAUTH2_FLOW.md)
