# JWT Authentication Middleware

This directory contains middleware for protecting routes with JWT authentication.

## Files

- `auth.middleware.ts` - Main middleware implementation
- `index.ts` - Barrel exports for clean imports

## Usage

### Strict Authentication (authMiddleware)

Requires a valid JWT token in the Authorization header. Returns 401 if token is missing, invalid, or expired.

```typescript
import { authMiddleware } from './middleware';

// Protect a route
router.get('/protected-route', authMiddleware, controller.handler);
```

### Optional Authentication (optionalAuthMiddleware)

Allows requests without tokens but attaches user info if a valid token is present.

```typescript
import { optionalAuthMiddleware } from './middleware';

// Route works with or without authentication
router.get('/optional-auth-route', optionalAuthMiddleware, controller.handler);
```

### Accessing User Information

```typescript
import { AuthenticatedRequest } from './middleware';

async function handler(req: AuthenticatedRequest, res: Response) {
  if (req.user) {
    // User is authenticated
    const userId = req.user.sub;
    const email = req.user.email;
  } else {
    // User is not authenticated (only with optionalAuthMiddleware)
  }
}
```

## Token Format

The middleware expects tokens in the following format:

```
Authorization: Bearer <JWT_TOKEN>
```

## Error Responses

### Missing Authorization Header
```json
{
  "error": "unauthorized",
  "message": "No authorization header provided"
}
```

### Invalid Header Format
```json
{
  "error": "unauthorized",
  "message": "Invalid authorization header format. Expected: Bearer <token>"
}
```

### Expired Token
```json
{
  "error": "token_expired",
  "message": "Token has expired"
}
```

### Invalid Token
```json
{
  "error": "invalid_token",
  "message": "Invalid token"
}
```

## Security Considerations

1. **Token Verification**: Uses the existing JwtService with RS256 algorithm
2. **Error Handling**: Different error types are handled appropriately
3. **Type Safety**: TypeScript interfaces ensure type-safe user access
4. **Rate Limiting**: Consider adding rate limiting middleware to prevent abuse (see security scan results)

## Examples

### Protected User Info Endpoint

```typescript
// In routes/authRoutes.ts
router.get('/userinfo', authMiddleware, AuthController.userinfo);

// In controllers/authController.ts
static async userinfo(req: AuthenticatedRequest, res: Response) {
  const userId = req.user!.sub; // Type-safe access
  // ... fetch and return user info
}
```
