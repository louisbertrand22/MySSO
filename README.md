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
   This will automatically generate RSA keys for JWT signing.

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
   npm run prisma:generate
   ```
   
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

- **Health Check**: `GET /health`
- **Test JWT**: `GET /test/jwt`
- **OpenID Configuration**: `GET /.well-known/openid-configuration`
- **Authorization**: `GET /authorize` (placeholder)
- **Token**: `POST /token` (placeholder)
- **UserInfo**: `GET /userinfo` (placeholder)
- **JWKS**: `GET /jwks.json`

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
- **User** - User accounts with email, username, and password hash
- **Client** - OAuth2/OIDC client applications
- **AuthCode** - Authorization codes for OAuth2 flow
- **RefreshToken** - Refresh tokens for token refresh flow

## 🔐 Security

- Passwords are hashed using **Argon2id** with recommended parameters
- JWTs are signed using **RS256** (RSA SHA-256)
- Private keys are stored locally and gitignored
- Environment variables for sensitive configuration

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

## 🔮 Future Enhancements

- Multi-Factor Authentication (MFA)
- User consent screens
- Admin UI for client and user management
- Session management
- Account recovery
- Email verification

## 📄 License

MIT