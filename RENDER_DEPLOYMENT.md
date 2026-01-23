# Render Deployment Guide

This guide provides step-by-step instructions for deploying MySSO backend to Render.

## Prerequisites

- A [Render](https://render.com) account
- A database (Supabase recommended, or Render PostgreSQL)
- Your frontend URL (if applicable)

## Step 1: Prepare Your Database

### Option A: Using Supabase (Recommended)

1. Create a free account at [supabase.com](https://supabase.com)
2. Create a new project
3. Navigate to Project Settings > Database
4. Copy your connection string (Use "Connection pooling" URI for better performance)
   - Format: `postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?pgbouncer=true`

### Option B: Using Render PostgreSQL

1. In your Render dashboard, create a new PostgreSQL instance
2. Copy the Internal Database URL
3. Use this URL for the `DATABASE_URL` environment variable

## Step 2: Create a New Web Service on Render

1. Go to your [Render Dashboard](https://dashboard.render.com)
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository
4. Configure the service:

### Build & Deploy Settings

| Setting | Value |
|---------|-------|
| **Name** | `mysso-backend` (or your preferred name) |
| **Region** | Choose closest to your users |
| **Branch** | `main` (or your production branch) |
| **Root Directory** | Leave empty (unless repo is in subdirectory) |
| **Runtime** | `Node` |
| **Build Command** | `npm install && npm run build` |
| **Start Command** | `node dist/server.js` |

### Environment Variables

Click **"Advanced"** and add the following environment variables:

#### Required Variables

```bash
# Node Environment
NODE_ENV=production

# Server Port (Render provides this automatically, but you can set it)
PORT=3000

# Base URL - Your Render service URL
# IMPORTANT: Replace with your actual Render URL after deployment
# Format: https://your-service-name.onrender.com (no trailing slash)
BASE_URL=https://your-service-name.onrender.com

# Database URL
# Use your Supabase or Render PostgreSQL connection string
DATABASE_URL=postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?pgbouncer=true

# JWT Secret
# IMPORTANT: Generate a strong random secret
# You can generate one with: openssl rand -base64 32
JWT_SECRET=your-strong-random-secret-here

# CORS - Allowed Origins
# Comma-separated list of allowed frontend URLs
# Example: https://your-frontend.onrender.com,https://app.example.com
ALLOWED_ORIGINS=https://your-frontend-url.com
```

#### Optional Variables

```bash
# JWT Configuration
JWT_EXPIRATION=3600
JWT_ISSUER=https://your-service-name.onrender.com

# Keys Directory (optional, defaults to ./keys)
# KEYS_DIR=./keys
```

## Step 3: Deploy

1. Click **"Create Web Service"**
2. Render will automatically:
   - Install dependencies (`npm install`)
   - Generate RSA keys (via `postinstall` script)
   - Generate Prisma client
   - Build TypeScript (`npm run build`)
   - Start the server (`node dist/server.js`)

## Step 4: Run Database Migrations

After the first deployment:

1. Go to your service's **Shell** tab in Render dashboard
2. Run the migration command:
   ```bash
   npx prisma migrate deploy
   ```
3. Seed the default scopes:
   ```bash
   node scripts/seed_scopes.js
   ```

## Step 5: Verify Deployment

Once deployed, test your endpoints:

### Health Check
```bash
curl https://your-service-name.onrender.com/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-23T...",
  "uptime": 123.456
}
```

### OpenID Configuration
```bash
curl https://your-service-name.onrender.com/.well-known/openid-configuration
```

Should return the OIDC discovery document with your production URLs.

### JWKS Endpoint
```bash
curl https://your-service-name.onrender.com/jwks.json
```

Should return the public keys for JWT verification.

## Step 6: Update BASE_URL (Important!)

After your first deployment, Render assigns a permanent URL:

1. Copy your service URL (e.g., `https://mysso-xyz123.onrender.com`)
2. Go to **Environment** tab in Render dashboard
3. Update `BASE_URL` with your actual Render URL
4. Click **"Save Changes"**
5. Render will automatically redeploy with the correct URL

## Security Checklist

Before going to production, verify:

- ✅ `NODE_ENV=production` is set
- ✅ `BASE_URL` is set to your Render HTTPS URL
- ✅ `BASE_URL` uses HTTPS (not HTTP)
- ✅ `JWT_SECRET` is changed from default value
- ✅ `JWT_SECRET` is a strong random string
- ✅ `ALLOWED_ORIGINS` includes only your trusted frontend URLs
- ✅ `DATABASE_URL` is set correctly
- ✅ Database migrations have been run
- ✅ Default scopes have been seeded
- ✅ Health check endpoint returns 200 OK
- ✅ OpenID configuration is accessible
- ✅ JWKS endpoint returns valid keys

## Troubleshooting

### Build Fails

**Issue**: Build fails with "Cannot find module" errors

**Solution**: Ensure all dependencies are in `dependencies` (not `devDependencies`) in `package.json`

### Server Won't Start

**Issue**: Server crashes on startup

**Solution**: 
1. Check logs in Render dashboard
2. Verify `DATABASE_URL` is correct
3. Ensure migrations have been run
4. Check that RSA keys were generated (should happen automatically)

### CORS Errors

**Issue**: Frontend gets CORS errors when calling API

**Solution**:
1. Add your frontend URL to `ALLOWED_ORIGINS`
2. Format: `https://your-frontend.com` (no trailing slash)
3. Multiple URLs: `https://app1.com,https://app2.com` (comma-separated, no spaces)

### Database Connection Issues

**Issue**: "Error connecting to database"

**Solution**:
- For Supabase: Use the "Connection pooling" URL (port 6543, not 5432)
- Check that IP restrictions are disabled or Render IPs are whitelisted
- Verify credentials are correct

### Invalid JWT Issuer

**Issue**: JWT tokens have wrong issuer

**Solution**: Ensure `BASE_URL` is set to your production URL (not localhost)

## Continuous Deployment

Render automatically redeploys when you push to your connected branch:

1. Push code to your repository
2. Render detects the changes
3. Runs build and deploy automatically
4. Zero-downtime deployment

## Monitoring

### View Logs
- Go to **Logs** tab in Render dashboard
- Real-time streaming logs
- Look for startup messages confirming configuration

### Check Metrics
- Go to **Metrics** tab
- Monitor CPU, Memory, and Request metrics
- Set up alerts for high resource usage

## Scaling

### Free Tier
- Service spins down after 15 minutes of inactivity
- First request after spin-down may be slow (cold start)

### Paid Tiers
- Always-on service (no spin-down)
- Better performance
- Custom domains
- More resources

## Custom Domain (Optional)

1. Go to **Settings** tab
2. Scroll to **Custom Domain**
3. Add your domain (e.g., `auth.yourdomain.com`)
4. Follow DNS configuration instructions
5. Update `BASE_URL` and `ALLOWED_ORIGINS` accordingly

## Need Help?

- Render Documentation: [render.com/docs](https://render.com/docs)
- MySSO Documentation: See [README.md](README.md)
- Check [SUPABASE_MIGRATION.md](SUPABASE_MIGRATION.md) for database setup

## Next Steps

After deploying your backend:

1. Register OAuth2 clients for your applications
2. Configure your frontend to use the production BASE_URL
3. Test the complete authentication flow
4. Monitor logs for any issues
5. Set up custom domain (optional)

---

**🎉 Congratulations!** Your MySSO backend is now running in production on Render.
