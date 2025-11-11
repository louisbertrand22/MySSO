# MySSO

Custom Single Sign-On (SSO) implementation with OpenID Connect and OAuth2 support.

> **📖 For Client Developers**: If you're looking to integrate your application with MySSO, see the **[Client Integration Guide](CLIENT_INTEGRATION_GUIDE.md)** for complete step-by-step instructions, code examples, and best practices.

## 🚀 Features

- **Full OpenID Connect Support** - Complete OIDC implementation with discovery, JWKS, ID tokens
- **PKCE (Proof Key for Code Exchange)** - Enhanced security for public clients (plain & S256)
- **OAuth2 Authorization Code Flow** - Standards-compliant OAuth2 with consent management
- **User Consent Management** - Explicit user authorization for client applications with scope-based permissions
- **Nonce Support** - Replay attack prevention for ID tokens
- **RSA JWT Signing (RS256)** - Secure token signing with public key distribution via JWKS
- **Client Authentication** - Support for both confidential and public clients
- **Scope-based Access Control** - Fine-grained permissions with admin, user, and client management scopes
- **Argon2id Password Hashing** - Modern, secure password hashing resistant to GPU attacks
- **Prisma ORM** - Type-safe database access with PostgreSQL
- **TypeScript** - Full type safety and modern JavaScript features
- **Security-first Design** - Single-use codes, short expiration, HTTPS enforcement, CSRF protection

## 📋 Prerequisites

- Node.js 18+ 
- PostgreSQL database
- npm or yarn

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd MySSO
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```
   This will automatically generate RSA keys for JWT signing and the Prisma client.

3. **Configure environment**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and configure your database connection. For local development with Docker:
   ```
   DATABASE_URL="postgresql://postgres:postgres@localhost:5432/mysso?schema=public"
   ```

4. **Start the database**
   ```bash
   docker compose up -d
   ```
   This will start a PostgreSQL database on port 5432.

5. **Setup database schema**
   ```bash
   npm run prisma:migrate
   ```
   Note: `prisma generate` is automatically run during `npm install`, so you only need to run migrations.
   
   To view and manage your database, you can run:
   ```bash
   npm run prisma:studio
   ```

6. **Seed default scopes**
   ```bash
   node scripts/seed_scopes.js
   ```
   This creates the default OAuth2/OIDC scopes and administrative scopes.

## 🚀 Running the Server

### Development mode (with auto-reload)
```bash
npm run dev
```

### Production mode
```bash
npm run build
npm start
```

The server will start on the port specified in `.env` (default: 3000).

## 📍 Available Endpoints

### Authentication Endpoints
- **Register**: `POST /auth/register` - Create a new user account
- **Login**: `POST /auth/login` - Login and get tokens
- **Refresh**: `POST /auth/refresh` - Refresh access token
- **Logout**: `POST /auth/logout` - Logout and revoke tokens

### OAuth2/OIDC Endpoints
- **Authorization**: `GET /authorize` - OAuth2/OIDC authorization endpoint (supports PKCE)
- **Consent Screen**: `GET /consent?client_id=...` - View consent screen with scopes
- **Handle Consent**: `POST /auth/authorize` - Approve or deny consent
- **Token Exchange**: `POST /token` - Exchange authorization code for tokens (returns id_token for OIDC)
- **UserInfo**: `GET /userinfo` - Get authenticated user info (scope-based claims)

### Admin Endpoints (Protected by Scopes)
- **Admin Dashboard**: `GET /admin/dashboard` - Admin statistics (requires `admin` scope)
- **List Users**: `GET /admin/users` - List all users (requires `read:users` or `admin` scope)
- **List Scopes**: `GET /admin/scopes` - List available scopes (requires `admin` scope)
- **List Clients**: `GET /admin/clients` - List OAuth2 clients (requires `read:clients` or `admin` scope)

### Discovery & Health
- **Health Check**: `GET /health`
- **Test JWT**: `GET /test/jwt`
- **OpenID Configuration**: `GET /.well-known/openid-configuration`
- **JWKS**: `GET /jwks.json`

## 🔐 OpenID Connect & OAuth2

MySSO implements full OpenID Connect (OIDC) support with OAuth2 authorization code flow:

### Key Features
- ✅ **OpenID Connect Discovery** - Auto-configuration via `/.well-known/openid-configuration`
- ✅ **PKCE Support** - Both `plain` and `S256` methods for public clients
- ✅ **ID Token** - OIDC-compliant ID tokens with nonce support
- ✅ **Scope-based Claims** - UserInfo endpoint returns claims based on granted scopes
- ✅ **Client Authentication** - Support for confidential clients with client_secret
- ✅ **Single-use Codes** - Authorization codes are one-time use with 60-second expiration
- ✅ **Nonce Support** - Replay attack prevention for ID tokens

### Quick Example
```bash
# 1. Login to get access token
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# 2. Request authorization with PKCE
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | base64 | tr -d "=+/" | tr "/+" "_-")

curl -i "http://localhost:3000/authorize?client_id=my-client&redirect_uri=http://localhost:5173/callback&scope=openid%20email&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256" \
  -H "Authorization: Bearer <access_token>"

# 3. Exchange code for tokens (including id_token)
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type":"authorization_code",
    "code":"<code>",
    "redirect_uri":"http://localhost:5173/callback",
    "code_verifier":"'$CODE_VERIFIER'"
  }'
```

**📖 Complete Documentation**: 
- **[Client Integration Guide](CLIENT_INTEGRATION_GUIDE.md)** - **START HERE** for integrating your app with MySSO
- [OpenID Connect Endpoints](docs/OIDC_ENDPOINTS.md) - Full OIDC implementation guide
- [OAuth2 Flow Guide](docs/OAUTH2_FLOW.md) - OAuth2 authorization code flow

## 🔌 Integrating Your Application

To integrate your application with MySSO as an identity provider:

1. **Read the [Client Integration Guide](CLIENT_INTEGRATION_GUIDE.md)** - Complete guide with code examples
2. **Register your application** with the MySSO administrator
3. **Implement OIDC/OAuth2 flow** using the provided examples
4. **Test your integration** with the development environment

The Client Integration Guide includes:
- Step-by-step integration instructions
- Code examples for JavaScript, Python, Node.js, React, and more
- PKCE implementation guides
- Security best practices
- Troubleshooting and FAQ

**Quick Links for Developers:**
- Discovery Endpoint: `GET /.well-known/openid-configuration`
- Authorization: `GET /authorize`
- Token Exchange: `POST /token`
- User Info: `GET /userinfo`
- JWKS (for token validation): `GET /jwks.json`

## 🗂️ Project Structure

```
MySSO/
├── src/
│   ├── config/          # Configuration files
│   │   └── env.ts       # Environment variables
│   ├── controllers/     # Request handlers
│   │   └── authController.ts
│   ├── routes/          # Route definitions
│   │   └── authRoutes.ts
│   ├── services/        # Business logic
│   │   ├── jwtService.ts
│   │   └── hashService.ts
│   ├── middleware/      # Express middleware
│   └── server.ts        # Express server setup
├── prisma/
│   └── schema.prisma    # Database schema
├── scripts/
│   └── generateKeys.js  # RSA key generation
└── keys/                # RSA keys (auto-generated, gitignored)
```

## 🗄️ Database Schema

### Tables
- **User** - User accounts with email and password hash
- **Session** - User sessions with expiration and revocation tracking
- **RefreshToken** - Refresh tokens for maintaining user sessions
- **AuthCode** - OAuth2/OIDC authorization codes with PKCE support, nonce, and single-use enforcement
- **Client** - OAuth2/OIDC clients with secret, redirect URIs, and allowed scopes
- **UserConsent** - User consent records for client applications
- **Scope** - Available scopes and their descriptions

## 🔐 Security

### Authentication & Encryption
- **Argon2id Password Hashing** - Industry-leading password hashing with recommended parameters
- **RS256 JWT Signing** - RSA SHA-256 for secure token signatures
- **Private Key Protection** - Keys stored locally and excluded from version control
- **Environment-based Configuration** - Sensitive data via environment variables

### OAuth2/OIDC Security
- **PKCE Support** - Proof Key for Code Exchange (plain & S256) for public clients
- **Nonce Validation** - Replay attack prevention for ID tokens
- **Single-use Authorization Codes** - Codes deleted immediately after use
- **Short-lived Codes** - 60-second expiration for authorization codes
- **Client Authentication** - Secret verification for confidential clients
- **Redirect URI Validation** - Strict exact-match validation against registered URIs
- **Scope-based Authorization** - Fine-grained permissions per client
- **HTTPS Enforcement** - Required in production environment
- **HttpOnly Cookies** - Secure refresh token storage
- **SameSite Strict** - CSRF protection for cookies
- **Token Rotation** - Refresh tokens rotated on each use

### Production Checklist
- ✅ Use strong DATABASE_URL with secure credentials
- ✅ Set NODE_ENV=production to enable HTTPS-only cookies
- ✅ Generate strong RSA keys (automatically done via postinstall)
- ✅ Configure ALLOWED_ORIGINS for CORS
- ✅ Use TLS/HTTPS for all endpoints
- ✅ Regularly rotate client secrets
- ✅ Monitor and audit security logs

## 🧪 Testing

Test the server health:
```bash
curl http://localhost:3000/health
```

Generate a test JWT:
```bash
curl http://localhost:3000/test/jwt
```

View OpenID configuration:
```bash
curl http://localhost:3000/.well-known/openid-configuration
```

## 📝 Development Scripts

- `npm run dev` - Start development server with auto-reload
- `npm run build` - Build TypeScript to JavaScript
- `npm start` - Run production server
- `npm run prisma:generate` - Generate Prisma client
- `npm run prisma:migrate` - Run database migrations
- `npm run prisma:studio` - Open Prisma Studio
- `scripts/testOAuth2Flow.sh` - Test OAuth2 authorization code flow

## 🔐 Scope-Based Access Control

MySSO implements fine-grained scope and permission management:

### Available Scopes

- **OAuth2/OIDC Scopes**: `openid`, `profile`, `email`
- **Admin Scope**: `admin` - Access administrative functions
- **User Management**: `read:users`, `write:users`, `delete:users`
- **Client Management**: `read:clients`, `write:clients`, `delete:clients`

### Protected Endpoints

- `/admin/dashboard` - Requires `admin` scope
- `/admin/users` - Requires `read:users` OR `admin` scope
- `/admin/scopes` - Requires `admin` scope
- `/admin/clients` - Requires `read:clients` OR `admin` scope

### Features

- ✅ Scope validation in authorization flow
- ✅ Client-specific allowed scopes
- ✅ Scopes included in JWT tokens
- ✅ Middleware for scope-based protection
- ✅ Consent screen displays scope details
- ✅ Strict validation (never grant undeclared scopes)

See [docs/SCOPES.md](docs/SCOPES.md) for complete documentation.

## 🔮 Future Enhancements

- Rate limiting on authentication endpoints
- Multi-Factor Authentication (MFA)
- Admin UI for client and user management
- Account recovery and password reset
- Email verification
- Consent management UI (view/revoke consents)
- Scope groups and hierarchies
- Dynamic client registration (RFC 7591)
- Token introspection endpoint (RFC 7662)
- Token revocation endpoint (RFC 7009)

## 📄 License

MIT