# Scope and Permission Management

This document describes the implementation of scope-based access control in MySSO.

## Overview

The scope management system provides fine-grained access control for OAuth2 clients and API endpoints. It allows you to:

- Define available scopes with descriptions
- Restrict which scopes each OAuth2 client can request
- Validate scopes during the authorization flow
- Include scopes in JWT access tokens
- Protect endpoints with scope requirements

## Available Scopes

### Default OAuth2/OIDC Scopes

- **openid** - Authenticate user and get basic profile information
- **profile** - Access basic profile information (name, username, picture, etc.)
- **email** - Access email address

### Administrative Scopes

- **admin** - Access administrative functions and endpoints

### Resource Scopes

- **read:users** - Read user information
- **write:users** - Create and modify user information
- **delete:users** - Delete users
- **read:clients** - Read OAuth2 client information
- **write:clients** - Create and modify OAuth2 clients
- **delete:clients** - Delete OAuth2 clients

## Database Models

### Scope Model

Stores the available scopes in the system.

```prisma
model Scope {
  id          String   @id @default(cuid())
  name        String   @unique
  description String
  createdAt   DateTime @default(now())

  @@index([name])
}
```

### Client Model (Updated)

OAuth2 clients now have an `allowedScopes` field.

```prisma
model Client {
  // ... other fields
  allowedScopes String[]      @default(["openid", "profile", "email"])
}
```

## Authorization Flow with Scopes

### 1. Authorization Request

When a client initiates the OAuth2 flow, it can request specific scopes:

```bash
GET /authorize?client_id=<client_id>&redirect_uri=<uri>&scope=openid%20profile%20email%20admin
Authorization: Bearer <access_token>
```

### 2. Scope Validation

The system validates requested scopes against:
- Available scopes in the database
- Client's allowed scopes

Only scopes that are both valid and allowed for the client are granted.

### 3. Consent Screen

The consent screen displays the requested scopes with their descriptions:

```json
{
  "client": {
    "id": "client_abc123",
    "name": "My Application"
  },
  "scopes": [
    {
      "name": "openid",
      "description": "Authenticate user and get basic profile information"
    },
    {
      "name": "profile",
      "description": "Access basic profile information (name, picture, etc.)"
    },
    {
      "name": "email",
      "description": "Access email address"
    }
  ],
  "redirect_uri": "http://localhost:5173/callback"
}
```

### 4. Token Generation

When the user approves, the granted scopes are:
- Stored in the UserConsent table
- Included in the JWT access token

## JWT Token with Scopes

Access tokens include scopes in two formats for compatibility:

```json
{
  "sub": "user_id",
  "email": "user@example.com",
  "scope": "openid profile email",
  "scopes": ["openid", "profile", "email"],
  "iat": 1699999999,
  "exp": 1700000899,
  "iss": "http://localhost:3000"
}
```

## Scope Middleware

### requireScope(scope)

Requires a specific scope for access:

```typescript
import { requireScope } from './middleware';

router.get('/admin/dashboard', 
  authMiddleware, 
  requireScope('admin'), 
  AdminController.dashboard
);
```

### requireAnyScope(...scopes)

Requires at least one of the specified scopes:

```typescript
import { requireAnyScope } from './middleware';

router.get('/admin/users', 
  authMiddleware, 
  requireAnyScope('read:users', 'admin'), 
  AdminController.listUsers
);
```

### requireAllScopes(...scopes)

Requires all of the specified scopes:

```typescript
import { requireAllScopes } from './middleware';

router.delete('/admin/users/:id', 
  authMiddleware, 
  requireAllScopes('delete:users', 'admin'), 
  AdminController.deleteUser
);
```

## Protected Endpoints

### Admin Endpoints

All admin endpoints require authentication and specific scopes:

| Endpoint | Method | Required Scopes | Description |
|----------|--------|-----------------|-------------|
| `/admin/dashboard` | GET | `admin` | Admin dashboard with statistics |
| `/admin/users` | GET | `read:users` OR `admin` | List all users |
| `/admin/scopes` | GET | `admin` | List all available scopes |
| `/admin/clients` | GET | `read:clients` OR `admin` | List all OAuth2 clients |

### Example Request

```bash
# Login to get access token
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"password123"}'

# Access admin endpoint with scope
curl -H "Authorization: Bearer <access_token_with_admin_scope>" \
  http://localhost:3000/admin/dashboard
```

## Error Responses

### Insufficient Scope

If the token doesn't have the required scope:

```json
{
  "error": "insufficient_scope",
  "message": "This endpoint requires the 'admin' scope",
  "required_scope": "admin",
  "user_scopes": ["openid", "profile", "email"]
}
```

### Invalid Scope

If a client requests scopes it's not allowed to have:

```json
{
  "error": "invalid_scope",
  "error_description": "No valid scopes requested for this client"
}
```

## ScopeService API

The ScopeService provides methods for scope management:

```typescript
import { ScopeService } from './services/scopeService';

// Get all scopes
const scopes = await ScopeService.getAllScopes();

// Get scope by name
const scope = await ScopeService.getScopeByName('admin');

// Validate scopes exist
const isValid = await ScopeService.validateScopes(['openid', 'admin']);

// Filter to only valid scopes
const validScopes = await ScopeService.filterValidScopes(['openid', 'invalid', 'admin']);

// Get scope details for display
const details = await ScopeService.getScopeDetails(['openid', 'profile']);

// Validate against client allowed scopes
const allowed = ScopeService.validateClientScopes(
  ['openid', 'profile', 'admin'],
  ['openid', 'profile', 'email']
);
// Returns: ['openid', 'profile']
```

## Setup and Seeding

### 1. Run Database Migrations

```bash
npm run prisma:migrate
```

### 2. Seed Default Scopes

```bash
node scripts/seed_scopes.js
```

### 3. Update Existing Clients (if needed)

```bash
node scripts/update_client_scopes.js
```

## Security Best Practices

### Never Grant Undeclared Scopes

The system validates that:
1. Requested scopes exist in the Scope table
2. Requested scopes are in the client's allowedScopes list
3. Only validated scopes are stored and included in tokens

### Scope Validation Flow

```
User Request → Parse Scopes → Validate Existence → 
Validate Client Allowed → Filter Valid → Grant Consent → 
Include in Token → Verify on Protected Endpoint
```

### Strict API Verification

Protected endpoints verify scopes from the JWT token on every request. There is no caching of permissions.

## Adding New Scopes

### 1. Add to Database

```sql
INSERT INTO "Scope" (id, name, description, "createdAt")
VALUES (
  'cuid_here',
  'new:scope',
  'Description of the new scope',
  NOW()
);
```

Or use Prisma:

```typescript
await prisma.scope.create({
  data: {
    name: 'new:scope',
    description: 'Description of the new scope',
  },
});
```

### 2. Update Client Allowed Scopes

```typescript
await prisma.client.update({
  where: { clientId: 'your_client_id' },
  data: {
    allowedScopes: {
      push: 'new:scope',
    },
  },
});
```

### 3. Protect Endpoints

```typescript
router.get('/api/resource',
  authMiddleware,
  requireScope('new:scope'),
  controller.method
);
```

## Testing

### Test Scope-Protected Endpoint

```bash
# 1. Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# 2. Try accessing admin endpoint (should fail if no admin scope)
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:3000/admin/dashboard

# Expected response without admin scope:
# {"error":"insufficient_scope","message":"This endpoint requires the 'admin' scope",...}
```

### Test OAuth2 Flow with Scopes

```bash
# 1. Create a client with specific allowed scopes
# 2. Request authorization with scopes
# 3. Check consent screen shows only allowed scopes
# 4. Approve consent
# 5. Exchange code for token
# 6. Verify token contains granted scopes
# 7. Test protected endpoint with token
```

## Future Enhancements

Potential improvements for the scope system:

1. **Scope Groups** - Group related scopes together
2. **Scope Hierarchies** - Parent scopes that include child scopes
3. **Dynamic Scopes** - Client-specific custom scopes
4. **Scope Expiration** - Time-limited scope grants
5. **Scope Auditing** - Track scope usage and access patterns
6. **Consent Refresh** - Re-prompt when scopes change

## Related Documentation

- [OAuth2 Flow](OAUTH2_FLOW.md)
- [Consent Management](CONSENT.md)
- [Security](SECURITY.md)
