# User Consent Screen

This document describes the OAuth2 user consent screen implementation in MySSO.

## Overview

The consent screen is a critical part of the OAuth2 authorization flow. It ensures users explicitly grant permission before a client application can access their data. This implementation follows OAuth2 best practices for user consent.

## Features

- ✅ **Explicit User Consent**: Users must explicitly approve or deny access
- ✅ **Client Information Display**: Shows application name and requested permissions
- ✅ **Consent Persistence**: Stores user consent decisions for audit purposes
- ✅ **Skip on Subsequent Requests**: After initial consent, users aren't prompted again
- ✅ **Secure Denial Handling**: Proper error codes when users deny access
- ✅ **JWT-Protected Routes**: All consent endpoints require authentication
- ✅ **Cascade Delete**: Consents automatically removed when user account is deleted

## Authorization Flow

### First-Time Authorization

1. **User initiates OAuth flow**: Client redirects to `/authorize` with parameters
2. **Authentication check**: System verifies user is logged in (JWT token)
3. **Consent check**: System checks if user has previously consented
4. **Redirect to consent screen**: If no consent exists, redirect to `/consent`
5. **Display consent information**: Show client name and requested scopes
6. **User decision**: User approves or denies access
7. **Process decision**: 
   - **Approve**: Store consent, generate auth code, redirect to client
   - **Deny**: Redirect to client with `error=access_denied`

### Subsequent Authorizations

1. **User initiates OAuth flow**: Client redirects to `/authorize` with parameters
2. **Authentication check**: System verifies user is logged in
3. **Consent check**: System finds existing consent
4. **Skip consent screen**: Immediately generate auth code and redirect

## API Endpoints

### GET /authorize

OAuth2 authorization endpoint. Initiates the authorization flow.

**Query Parameters:**
- `client_id` (required): Client application identifier
- `redirect_uri` (required): Where to redirect after authorization
- `response_type` (optional): Type of response (default: "code")
- `scope` (optional): Requested scopes (default: "openid profile email")
- `state` (optional): Client state value for CSRF protection

**Headers:**
- `Authorization: Bearer <access_token>` (required)

**Response:**
- **302 Redirect** to `/consent` if consent not yet granted
- **302 Redirect** to `redirect_uri` with code if consent already exists

**Example:**
```bash
curl -i "http://localhost:3000/authorize?client_id=test_client&redirect_uri=http://localhost:5173/callback&state=xyz123" \
  -H "Authorization: Bearer <access_token>"
```

### GET /consent

Returns consent screen information (protected endpoint).

**Query Parameters:**
- `client_id` (required): Client application identifier
- `redirect_uri` (required): Callback URI
- `scope` (optional): Requested scopes
- `state` (optional): Client state value

**Headers:**
- `Authorization: Bearer <access_token>` (required)

**Response:**
```json
{
  "client": {
    "id": "client_abc123",
    "name": "My Application"
  },
  "scopes": ["openid", "profile", "email"],
  "redirect_uri": "http://localhost:5173/callback",
  "state": "xyz123"
}
```

**Example:**
```bash
curl -s "http://localhost:3000/consent?client_id=test_client&redirect_uri=http://localhost:5173/callback" \
  -H "Authorization: Bearer <access_token>" | jq .
```

### POST /auth/authorize

Handles user's consent decision (protected endpoint).

**Headers:**
- `Authorization: Bearer <access_token>` (required)
- `Content-Type: application/json` (required)

**Request Body:**
```json
{
  "client_id": "client_abc123",
  "redirect_uri": "http://localhost:5173/callback",
  "approved": true,
  "scope": "openid profile email",
  "state": "xyz123"
}
```

**Response:**

**If Approved:**
- **302 Redirect** to `redirect_uri` with authorization code
- Example: `http://localhost:5173/callback?code=auth_code_123&state=xyz123`

**If Denied:**
- **302 Redirect** to `redirect_uri` with error
- Example: `http://localhost:5173/callback?error=access_denied&error_description=User+denied+authorization&state=xyz123`

**Example - Approve:**
```bash
curl -i -X POST http://localhost:3000/auth/authorize \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "client_id": "test_client",
    "redirect_uri": "http://localhost:5173/callback",
    "approved": true,
    "scope": "openid profile email",
    "state": "xyz123"
  }'
```

**Example - Deny:**
```bash
curl -i -X POST http://localhost:3000/auth/authorize \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "client_id": "test_client",
    "redirect_uri": "http://localhost:5173/callback",
    "approved": false,
    "state": "xyz123"
  }'
```

## Database Schema

### UserConsent Model

Stores user consent decisions for audit and subsequent authorization checks.

```prisma
model UserConsent {
  id        String   @id @default(cuid())
  userId    String
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  clientId  String
  client    Client   @relation(fields: [clientId], references: [clientId], onDelete: Cascade)
  scopes    String[]
  createdAt DateTime @default(now())

  @@unique([userId, clientId])
  @@index([userId])
  @@index([clientId])
}
```

**Features:**
- Unique constraint on (userId, clientId) prevents duplicates
- Cascade delete when user or client is deleted
- Indexed for fast lookups
- Stores granted scopes for audit purposes

## Security Considerations

### Authentication Required

All consent-related endpoints require valid JWT authentication:
- Users must be logged in to view consent screens
- JWT middleware validates all requests
- Expired or invalid tokens are rejected

### CSRF Protection

The OAuth2 `state` parameter provides CSRF protection:
- Clients should generate unique state values
- State is returned in redirects
- Clients should verify state matches their request

### Redirect URI Validation

All redirect URIs are validated against client's registered URIs:
- Prevents open redirect vulnerabilities
- Client registration enforces allowed URIs
- Invalid URIs are rejected before consent

### Consent Persistence

User consent is stored for security and audit:
- Track when users granted access
- Revoke access by deleting consent records
- Automatic cleanup when accounts are deleted

## Error Codes

### access_denied
User explicitly denied the authorization request.

**Example Redirect:**
```
http://localhost:5173/callback?error=access_denied&error_description=User+denied+authorization&state=xyz123
```

### invalid_request
Missing or invalid required parameters.

**Example Response:**
```json
{
  "error": "invalid_request",
  "error_description": "Missing or invalid client_id parameter"
}
```

### invalid_client
Client ID not found or invalid.

**Example Response:**
```json
{
  "error": "invalid_client",
  "error_description": "Client not found"
}
```

### unauthorized
User is not authenticated or token is invalid.

**Example Response:**
```json
{
  "error": "unauthorized",
  "error_description": "User must be authenticated"
}
```

## Testing

A comprehensive test script is available to verify the consent flow:

```bash
# Use the included test data seeding script
cd /home/runner/work/MySSO/MySSO
node scripts/seed_test_data.js

# Then test the flow manually
# 1. Login
# 2. Request authorization (should redirect to consent)
# 3. View consent screen
# 4. Deny consent (should redirect with error)
# 5. Approve consent (should redirect with code)
# 6. Request authorization again (should skip consent)
```

## Revoking Consent

To revoke user consent, use the ConsentService:

```typescript
import { ConsentService } from './services/consentService';

// Revoke consent for a specific client
await ConsentService.revokeConsent(userId, clientId);

// Consent is also automatically revoked when:
// - User account is deleted (cascade delete)
// - Client application is deleted (cascade delete)
```

## Future Enhancements

Potential improvements for the consent system:

1. **Scope Granularity**: Allow users to approve/deny individual scopes
2. **Consent Management UI**: User dashboard to view and revoke consents
3. **Consent Expiration**: Automatic expiration after a time period
4. **Consent Versioning**: Track when scopes change and re-prompt
5. **Audit Logging**: Enhanced logging of consent decisions
6. **Remember Device**: Option to skip consent on trusted devices

## Related Documentation

- [OAuth2 Flow](OAUTH2_FLOW.md) - Complete OAuth2 implementation guide
- [Logout](LOGOUT.md) - Session management and logout
- [Security](SECURITY.md) - Security architecture and best practices

## Compliance

This implementation helps satisfy requirements for:

- **GDPR**: Explicit user consent for data access
- **OAuth 2.0 Specification**: Proper consent handling
- **OpenID Connect**: User authorization for identity claims
