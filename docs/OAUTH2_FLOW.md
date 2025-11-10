# OAuth2 Authorization Code Flow

This document describes the OAuth2 authorization code flow implementation in MySSO.

## Overview

The authorization code flow is a secure OAuth2 flow that allows third-party applications to obtain access tokens without exposing user credentials.

## Flow Diagram

```
1. Client redirects user to /login?redirect_uri=...
2. User authenticates (provides access token in header)
3. SSO generates authorization code (valid for 60 seconds)
4. SSO redirects user to client's redirect_uri with code
5. Client exchanges code for access/refresh tokens via /token
6. Client uses access token to access protected resources
```

## API Endpoints

### 1. Authorization Endpoint

**GET /login** or **GET /authorize**

Request an authorization code.

**Parameters:**
- `redirect_uri` (required): URI where the user will be redirected after authorization

**Headers:**
- `Authorization: Bearer <access_token>` (required): Valid access token from prior login

**Response:**
- **302 Redirect** to `redirect_uri?code=<authorization_code>`
- **400 Bad Request** if redirect_uri is invalid or missing
- **401 Unauthorized** if access token is missing or invalid

**Example:**
```bash
curl -i "http://localhost:3000/login?redirect_uri=http://localhost:5173/callback" \
  -H "Authorization: Bearer eyJhbGc..."
```

**Response:**
```
HTTP/1.1 302 Found
Location: http://localhost:5173/callback?code=168ba0dd-dfcf-440a-987a-fd96f96c4f60
```

### 2. Token Endpoint

**POST /token**

Exchange authorization code for access and refresh tokens.

**Body Parameters:**
- `grant_type` (required): Must be "authorization_code"
- `code` (required): Authorization code from the authorization endpoint
- `redirect_uri` (required): Same redirect_uri used in authorization request

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "eyJhbGc..."
}
```

**Error Response:**
```json
{
  "error": "invalid_grant",
  "error_description": "Invalid, expired, or already used authorization code"
}
```

**Example:**
```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "168ba0dd-dfcf-440a-987a-fd96f96c4f60",
    "redirect_uri": "http://localhost:5173/callback"
  }'
```

## Security Features

### 1. Single-Use Authorization Codes

Authorization codes are deleted immediately after use to prevent replay attacks.

### 2. Short Expiration Time

Authorization codes expire after 60 seconds to minimize the window of vulnerability.

### 3. Redirect URI Validation

Only whitelisted redirect URIs are allowed to prevent authorization code interception.

**Development Mode:**
- All localhost URLs are allowed (any port)

**Production Mode:**
- Only explicitly whitelisted URIs are allowed
- Configured in `AuthCodeService.ALLOWED_REDIRECT_URIS`

### 4. HTTPS Enforcement

In production mode:
- Cookies are marked as `Secure` (HTTPS only)
- Redirect URIs should use HTTPS

### 5. Redirect URI Matching

The redirect_uri used in the token exchange must exactly match the one used in the authorization request.

## Configuration

### Redirect URI Whitelist

Edit `src/services/authCodeService.ts`:

```typescript
private static ALLOWED_REDIRECT_URIS = [
  'https://myapp.com/callback',
  'https://app.mycompany.com/auth/callback',
];
```

### Code Expiration

Default: 60 seconds (configurable in `authCodeService.ts`)

```typescript
private static AUTH_CODE_EXPIRATION_SECONDS = 60;
```

## Cleanup of Expired Codes

Expired authorization codes should be cleaned up periodically to prevent database bloat.

### Manual Cleanup

```typescript
import { AuthCodeService } from './services/authCodeService';

// Clean up expired codes
const deletedCount = await AuthCodeService.cleanupExpiredCodes();
console.log(`Deleted ${deletedCount} expired codes`);
```

### Automated Cleanup (Cron Job)

Example using node-cron:

```typescript
import cron from 'node-cron';
import { AuthCodeService } from './services/authCodeService';

// Run cleanup every hour
cron.schedule('0 * * * *', async () => {
  const deletedCount = await AuthCodeService.cleanupExpiredCodes();
  console.log(`[Cleanup] Deleted ${deletedCount} expired auth codes`);
});
```

## Client Implementation Example

### Step 1: Redirect to Authorization Endpoint

```javascript
// Client-side code
const redirectUri = 'http://localhost:5173/callback';
const accessToken = localStorage.getItem('accessToken'); // From prior login

window.location.href = `http://localhost:3000/login?redirect_uri=${encodeURIComponent(redirectUri)}`;
// Note: In a real implementation, the Authorization header would be set
// This is a simplified example
```

### Step 2: Handle Callback

```javascript
// Client-side code in /callback route
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');

if (!code) {
  console.error('No authorization code received');
  return;
}

// Exchange code for tokens
const response = await fetch('http://localhost:3000/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: 'http://localhost:5173/callback',
  }),
});

const tokens = await response.json();

if (tokens.access_token) {
  // Store tokens
  localStorage.setItem('accessToken', tokens.access_token);
  localStorage.setItem('refreshToken', tokens.refresh_token);
  
  // Redirect to app
  window.location.href = '/dashboard';
}
```

## Error Handling

### Common Errors

1. **invalid_request**
   - Missing or invalid redirect_uri
   - Redirect URI not in whitelist

2. **unauthorized**
   - Missing or invalid access token
   - User not authenticated

3. **invalid_grant**
   - Invalid authorization code
   - Expired authorization code
   - Already used authorization code
   - Redirect URI mismatch

4. **server_error**
   - Internal server error
   - Database error

## Testing

See the test scripts in `/tmp/test_oauth2_flow.sh` for complete examples.

### Test Complete Flow

```bash
# 1. Register user
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPassword123"}'

# 2. Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPassword123"}'

# 3. Get authorization code (use access token from step 2)
curl -i "http://localhost:3000/login?redirect_uri=http://localhost:5173/callback" \
  -H "Authorization: Bearer <access_token>"

# 4. Exchange code for tokens
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"<code>","redirect_uri":"http://localhost:5173/callback"}'
```

## Database Schema

### AuthCode Table

```prisma
model AuthCode {
  id          String   @id @default(cuid())
  code        String   @unique
  userId      String
  user        User     @relation(fields: [userId], references: [id])
  redirectUri String
  createdAt   DateTime @default(now())
  expiresAt   DateTime
  usedAt      DateTime?
}
```

## Production Checklist

- [ ] Configure ALLOWED_REDIRECT_URIS with production URLs
- [ ] Enable HTTPS (set NODE_ENV=production)
- [ ] Set up cron job for expired code cleanup
- [ ] Configure CORS with production origins
- [ ] Monitor authorization code usage
- [ ] Set up rate limiting on /login and /token endpoints
- [ ] Add logging for security events
- [ ] Test with production redirect URIs

## Additional Resources

- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 Authorization Code Flow](https://oauth.net/2/grant-types/authorization-code/)
