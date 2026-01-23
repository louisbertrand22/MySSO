# Production Environment Variables Quick Reference

This is a quick reference for setting up environment variables for production deployment on Render.

## Required Environment Variables

### NODE_ENV
```
NODE_ENV=production
```
**Purpose**: Enables production mode
- Enforces HTTPS-only cookies
- Strict CORS checking
- Production optimizations

### BASE_URL
```
BASE_URL=https://your-service-name.onrender.com
```
**Purpose**: Your public backend URL
- Used for JWT issuer claim
- Used in OpenID Connect discovery
- Must use HTTPS in production
- **No trailing slash**

### DATABASE_URL
```
DATABASE_URL=postgresql://user:password@host:port/database
```
**Purpose**: PostgreSQL database connection string

**Supabase example** (recommended):
```
DATABASE_URL=postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?pgbouncer=true
```

**Render PostgreSQL example**:
```
DATABASE_URL=postgresql://user:password@host.render.com:5432/database
```

### JWT_SECRET
```
JWT_SECRET=your-strong-random-secret-here
```
**Purpose**: Secret key for signing JWT tokens
- **Must be changed from default value**
- Generate with: `openssl rand -base64 32`
- Keep this secret and never commit to version control

### ALLOWED_ORIGINS
```
ALLOWED_ORIGINS=https://your-frontend.com,https://app.example.com
```
**Purpose**: CORS allowed origins (comma-separated)
- Include all your frontend URLs
- Must be exact matches
- No trailing slashes
- No spaces between URLs

## Optional Environment Variables

### PORT
```
PORT=3000
```
**Purpose**: Server port (Render sets this automatically)
- Default: 3000
- Usually not needed as Render provides this

### JWT_EXPIRATION
```
JWT_EXPIRATION=3600
```
**Purpose**: Access token expiration in seconds
- Default: 3600 (1 hour)

### JWT_ISSUER
```
JWT_ISSUER=https://your-service-name.onrender.com
```
**Purpose**: JWT issuer claim
- Default: Uses BASE_URL value
- Usually not needed unless you want a different issuer

### KEYS_DIR
```
KEYS_DIR=./keys
```
**Purpose**: Directory where RSA keys are stored
- Default: `./keys` in project root
- Usually not needed

## Example: Complete Production Configuration

```bash
# Required
NODE_ENV=production
BASE_URL=https://mysso-backend.onrender.com
DATABASE_URL=postgresql://postgres.abcdefgh:MyPassword123@aws-0-us-west-1.pooler.supabase.com:6543/postgres?pgbouncer=true
JWT_SECRET=sK9mN2pQ7vR4xY8zA3bC5dE1fG6hJ0iL
ALLOWED_ORIGINS=https://my-frontend.com,https://admin.my-frontend.com

# Optional (can be omitted to use defaults)
JWT_EXPIRATION=3600
PORT=3000
```

## Validation

When you start the server with `NODE_ENV=production`, it will validate:

✅ **BASE_URL is set** - Should not use default localhost value

✅ **BASE_URL uses HTTPS** - Required for security (except localhost)

✅ **JWT_SECRET is changed** - Should not be "changeme"

✅ **ALLOWED_ORIGINS is set** - Required to restrict CORS

If all checks pass, you'll see:
```
✅ Production configuration validated successfully
```

If issues are found, you'll see warnings:
```
⚠️  Production Configuration Issues:
   - BASE_URL should use HTTPS in production for security
   - JWT_SECRET is using default value - please set a strong secret
   - ALLOWED_ORIGINS should be set in production to restrict CORS
```

## Security Notes

🔒 **Never commit these values to version control!**
- Set them in Render dashboard under "Environment" tab
- Use Render's environment variable encryption
- JWT_SECRET should be unique and random

🔒 **Use strong secrets**
- JWT_SECRET: At least 32 characters, random
- DATABASE_URL: Strong password, limited access
- Rotate secrets periodically

🔒 **Use HTTPS everywhere**
- BASE_URL must use HTTPS
- ALLOWED_ORIGINS should use HTTPS
- Never use HTTP in production

## Troubleshooting

### Error: "BASE_URL should use HTTPS in production"
**Fix**: Change BASE_URL from `http://` to `https://`

### Error: "JWT_SECRET is using default value"
**Fix**: Set JWT_SECRET to a strong random value
```bash
# Generate a secret
openssl rand -base64 32
```

### Error: "ALLOWED_ORIGINS should be set in production"
**Fix**: Add your frontend URL(s) to ALLOWED_ORIGINS
```
ALLOWED_ORIGINS=https://your-frontend.com
```

### CORS errors in browser
**Fix**: Ensure your frontend URL is in ALLOWED_ORIGINS
- Check for typos
- Verify no trailing slashes
- Check HTTP vs HTTPS

## Next Steps

1. Set all required environment variables in Render dashboard
2. Deploy your application
3. Run database migrations: `npx prisma migrate deploy`
4. Seed scopes: `node scripts/seed_scopes.js`
5. Test endpoints: `/health`, `/.well-known/openid-configuration`
6. Verify logs show: `✅ Production configuration validated successfully`

For complete deployment guide, see [RENDER_DEPLOYMENT.md](RENDER_DEPLOYMENT.md)
