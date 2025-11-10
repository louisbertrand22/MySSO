# Secure Logout and Revocation

This document describes the secure logout and session revocation implementation in MySSO.

## Features

### 1. POST /auth/logout Endpoint

The logout endpoint supports secure session termination with the following features:

- **HttpOnly Cookie Support**: Refresh tokens are automatically read from cookies
- **Session Revocation**: All active sessions are properly revoked in the database
- **Security Logging**: All logout events are logged for audit purposes
- **Multi-device Logout**: Support for logging out from all devices simultaneously

### 2. Cookie Management

#### Login
When a user logs in via `POST /auth/login`, the system:
- Generates an access token and refresh token
- Sets the refresh token as an HttpOnly cookie
- Creates a session record in the database
- Returns both tokens in the response body

Cookie attributes:
```javascript
{
  httpOnly: true,              // Prevents XSS attacks
  secure: production,          // HTTPS only in production
  sameSite: 'strict',         // CSRF protection
  maxAge: 7 days              // Same as refresh token expiration
}
```

#### Refresh
The `POST /auth/refresh` endpoint:
- Accepts refresh token from body OR cookie
- Validates the token
- Performs token rotation (deletes old token, creates new one)
- Updates the HttpOnly cookie with the new refresh token

#### Logout
The `POST /auth/logout` endpoint:
- Accepts refresh token from body OR cookie
- Deletes the refresh token from the database
- Revokes the associated session(s)
- **Always clears the HttpOnly cookie**
- Logs the security event

### 3. Session Tracking

Sessions are created in the database when tokens are generated and include:

```typescript
interface Session {
  id: string;
  userId: string;
  createdAt: DateTime;
  expiresAt: DateTime;
  revokedAt: DateTime?;  // Set when session is revoked
}
```

### 4. Logout Options

#### Single Device Logout
```bash
POST /auth/logout
{
  "refreshToken": "token_value"  # Optional if using cookie
}
```

This will:
- Delete the specific refresh token
- Revoke the most recent session
- Clear the cookie

#### All Devices Logout
```bash
POST /auth/logout
{
  "refreshToken": "token_value",  # Optional if using cookie
  "all": true
}
```

This will:
- Delete ALL refresh tokens for the user
- Revoke ALL active sessions for the user
- Clear the cookie

### 5. Security Logging

All security events are logged with structured JSON format:

```json
{
  "timestamp": "2025-11-10T11:00:00.000Z",
  "event": "LOGOUT",
  "userId": "user_id",
  "allDevices": false
}
```

Log events include:
- `LOGOUT`: User logout event
- `TOKEN_REVOCATION`: Token revocation event
- `SESSION_REVOCATION`: Session revocation event

### 6. Revoked Token Protection

The system ensures revoked tokens cannot be reused:

1. **Database Validation**: All refresh tokens must exist in the database
2. **Token Rotation**: Old tokens are deleted on refresh
3. **Session Tracking**: Sessions track revocation timestamp
4. **No Resurrection**: Deleted tokens cannot be restored

## API Examples

### Login with Cookie
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}' \
  -c cookies.txt
```

### Logout (Single Device)
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -c cookies.txt
```

### Logout (All Devices)
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"all":true}' \
  -b cookies.txt \
  -c cookies.txt
```

### Verify Logout (Should Fail)
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -b cookies.txt
```

## Database Schema

### Session Table
```prisma
model Session {
  id        String    @id @default(cuid())
  userId    String
  user      User      @relation(fields: [userId], references: [id])
  createdAt DateTime  @default(now())
  expiresAt DateTime
  revokedAt DateTime?  // Audit field for revocation tracking
}
```

## Implementation Checklist

- [x] Create the route POST /auth/logout
- [x] Delete refresh token from cookie and database
- [x] Add global deletion (deleteMany) for all user sessions
- [x] Support cookie-based logout
- [x] Verify that no revoked refresh token is accepted
- [x] Invalidate all sessions on all devices (optional "all" parameter)
- [x] Add security logging (complete revocation tracking)
- [x] Add `revokedAt` field to Session table for audit

## Security Considerations

1. **Always clear cookies**: Even on error, cookies are cleared
2. **No token persistence**: Refresh tokens are never left in the database after logout
3. **Session audit trail**: `revokedAt` field provides complete audit history
4. **Token rotation**: Prevents token reuse attacks
5. **HttpOnly cookies**: Prevents XSS token theft
6. **Secure flag**: Enforces HTTPS in production
7. **SameSite strict**: Prevents CSRF attacks

## Testing

Run the test guide:
```bash
node scripts/testLogout.js
```

This will provide step-by-step instructions for manual testing of the logout functionality.
