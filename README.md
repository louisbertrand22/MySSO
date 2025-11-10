# MySSO

Custom Single Sign-On (SSO) implementation with OpenID Connect and OAuth2 support.

## 🚀 Features

- **OpenID Connect & OAuth2** - Full OIDC/OAuth2 protocol support
- **RSA JWT Signing** - Secure token signing with RS256 algorithm
- **Argon2id Password Hashing** - Modern, secure password hashing
- **Prisma ORM** - Type-safe database access
- **TypeScript** - Full type safety and modern JavaScript features
- **Extensible Architecture** - Ready for MFA, consent screens, and admin UI

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

### OAuth2 Endpoints
- **Authorization**: `GET /login?redirect_uri=...` or `GET /authorize?redirect_uri=...` - OAuth2 authorization endpoint
- **Token Exchange**: `POST /token` - Exchange authorization code for tokens
- **UserInfo**: `GET /userinfo` - Get authenticated user info

### Discovery & Health
- **Health Check**: `GET /health`
- **Test JWT**: `GET /test/jwt`
- **OpenID Configuration**: `GET /.well-known/openid-configuration`
- **JWKS**: `GET /jwks.json`

## 🔐 OAuth2 Authorization Code Flow

MySSO now supports the OAuth2 authorization code flow for third-party client authentication:

1. **Initiate Flow**: Client redirects to `/login?redirect_uri=<callback_url>`
2. **User Authenticates**: User provides access token (from prior login)
3. **Get Code**: Server generates authorization code and redirects to callback
4. **Exchange Code**: Client exchanges code for access/refresh tokens via `/token`
5. **Access Resources**: Client uses tokens to access protected endpoints

**Example:**
```bash
# 1. Login to get access token
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# 2. Request authorization code
curl -i "http://localhost:3000/login?redirect_uri=http://localhost:5173/callback" \
  -H "Authorization: Bearer <access_token>"

# 3. Exchange code for tokens
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"<code>","redirect_uri":"http://localhost:5173/callback"}'
```

**Documentation**: See [docs/OAUTH2_FLOW.md](docs/OAUTH2_FLOW.md) for complete guide

**Security Features**:
- ✅ Single-use authorization codes
- ✅ 60-second code expiration
- ✅ Redirect URI whitelist validation
- ✅ HTTPS enforcement in production

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
- **AuthCode** - OAuth2 authorization codes with expiration and single-use enforcement

## 🔐 Security

- Passwords are hashed using **Argon2id** with recommended parameters
- JWTs are signed using **RS256** (RSA SHA-256)
- Private keys are stored locally and gitignored
- Environment variables for sensitive configuration
- **OAuth2 Security**:
  - Single-use authorization codes
  - Short-lived codes (60 seconds)
  - Redirect URI whitelist validation
  - HTTPS enforcement in production
  - HttpOnly cookies for refresh tokens
  - SameSite strict for CSRF protection

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

## 🔮 Future Enhancements

- PKCE support for enhanced mobile/SPA security
- Rate limiting on authentication endpoints
- Client registration and management
- Scope-based access control

- Multi-Factor Authentication (MFA)
- User consent screens
- Admin UI for client and user management
- Session management
- Account recovery
- Email verification

## 📄 License

MIT