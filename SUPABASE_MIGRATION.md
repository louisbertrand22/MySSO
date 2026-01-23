# Supabase Migration Guide

This guide will help you migrate your MySSO database to Supabase, a PostgreSQL-based backend-as-a-service platform.

## Why Supabase?

Supabase provides several advantages over self-hosted PostgreSQL:
- **Managed Database**: No need to manage PostgreSQL yourself
- **Connection Pooling**: Built-in PgBouncer for better connection management
- **Automatic Backups**: Daily backups with point-in-time recovery
- **Free Tier**: Generous free tier for development and small projects
- **Real-time Subscriptions**: Optional real-time features if needed
- **Dashboard**: Web-based database management interface
- **Global Distribution**: Deploy close to your users

## Prerequisites

- A Supabase account (free at [supabase.com](https://supabase.com))
- Access to your current database (if migrating existing data)
- Your MySSO project cloned locally

## Step 1: Create a Supabase Project

1. Sign up or log in to [supabase.com](https://supabase.com)
2. Click "New Project"
3. Fill in the project details:
   - **Name**: Choose a name (e.g., "mysso-production")
   - **Database Password**: Generate a strong password (save this!)
   - **Region**: Choose the region closest to your users
   - **Pricing Plan**: Select Free or Pro based on your needs
4. Click "Create new project" and wait for it to initialize (~2 minutes)

## Step 2: Get Your Connection String

1. In your Supabase dashboard, go to **Project Settings** (gear icon in the sidebar)
2. Navigate to **Database** section
3. Scroll down to **Connection string**
4. You'll see two types of connection strings:

   **Connection pooling (Recommended for production)**
   ```
   postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?pgbouncer=true
   ```
   
   **Direct connection**
   ```
   postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres
   ```

5. **Use the connection pooling URI** for better performance and connection management
6. Replace `[PASSWORD]` with your database password

## Step 3: Update Your Environment Configuration

1. Open your `.env` file (or create one from `.env.example`)
2. Update the `DATABASE_URL` with your Supabase connection string:

   ```bash
   DATABASE_URL="postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?pgbouncer=true"
   ```

3. Save the file

## Step 4: Run Prisma Migrations

With your Supabase connection configured, run the migrations to create the database schema:

```bash
npm run prisma:migrate
```

This will create all necessary tables (User, Session, RefreshToken, AuthCode, Client, UserConsent, Scope) in your Supabase database.

## Step 5: Seed Default Data

Run the seed script to create default OAuth2/OIDC scopes:

```bash
# Run the seed script directly with Node.js
node scripts/seed_scopes.js
```

This creates the default scopes needed for OAuth2/OIDC functionality.

## Step 6: Verify the Migration

1. **Test connection string format:**
   ```bash
   npm run test:supabase
   ```
   This validates that various Supabase connection string formats are compatible

2. **Check via Supabase Dashboard:**
   - Go to the **Table Editor** in your Supabase dashboard
   - You should see all 7 tables: User, Session, RefreshToken, AuthCode, Client, UserConsent, Scope

3. **Check via Prisma Studio:**
   ```bash
   npm run prisma:studio
   ```
   This will open a web interface where you can view and manage your data

4. **Test the application:**
   ```bash
   npm run dev
   ```
   Visit http://localhost:3000/health to ensure the server starts correctly

## Migrating Existing Data (Optional)

If you have existing data in a local PostgreSQL database that you want to migrate to Supabase:

### Option 1: Using pg_dump and psql

1. **Export your local database:**
   ```bash
   # Adjust the -h, -U, and -d parameters to match your local PostgreSQL setup
   pg_dump -h localhost -U postgres -d mysso --data-only > data_backup.sql
   ```

2. **Import to Supabase:**
   ```bash
   psql "postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres" < data_backup.sql
   ```

### Option 2: Using Prisma Studio

1. Open Prisma Studio with your **local** database:
   ```bash
   # Temporarily use local DATABASE_URL
   DATABASE_URL="postgresql://postgres:postgres@localhost:5432/mysso" npm run prisma:studio
   ```

2. Export data manually or use a migration script

3. Switch to Supabase DATABASE_URL and import the data

## Production Deployment Checklist

When deploying to production with Supabase:

- ✅ Use the **connection pooling** URI (port 6543) for better performance
- ✅ Store DATABASE_URL in your deployment platform's environment variables (never commit to git)
- ✅ Set `NODE_ENV=production` in your environment variables
- ✅ Enable SSL/HTTPS for all endpoints
- ✅ Configure `ALLOWED_ORIGINS` for CORS
- ✅ Use strong JWT_SECRET
- ✅ Regularly review and rotate client secrets
- ✅ Enable Supabase's backup retention
- ✅ Monitor database performance via Supabase dashboard
- ✅ Set up database alerts in Supabase for high usage

## Supabase Dashboard Features

Your Supabase dashboard provides several useful features:

- **Table Editor**: Browse and edit data directly
- **SQL Editor**: Run custom SQL queries
- **Database**: View connection strings and settings
- **API**: Auto-generated REST and GraphQL APIs (optional)
- **Logs**: View database logs
- **Reports**: Database performance metrics
- **Backups**: Manage database backups (Pro plan)

## Connection Pooling vs Direct Connection

### Connection Pooling (Recommended)
- Port: `6543`
- Uses PgBouncer for connection management
- Better for serverless and applications with many connections
- Recommended for production deployments
- Some PostgreSQL features may be limited (advanced prepared statements)

### Direct Connection
- Port: `5432`
- Direct PostgreSQL connection
- Full PostgreSQL feature support
- Better for long-running processes
- Limited concurrent connections (based on your plan)

For MySSO with Prisma, **connection pooling is recommended** as it handles connections efficiently and works well with serverless deployments.

## Troubleshooting

### Connection Issues

**Error: "password authentication failed"**
- Verify your password is correct
- Ensure you've replaced `[PASSWORD]` in the connection string
- Check that you're using the correct project reference

**Error: "connect ETIMEDOUT"**
- Check your internet connection
- Verify the region in your connection string matches your Supabase project
- Ensure no firewall is blocking port 6543 or 5432

**Error: "too many connections"**
- Switch to connection pooling URI (port 6543)
- Reduce connection pool size in Prisma (add `connection_limit` to DATABASE_URL)
- Upgrade your Supabase plan if needed

### Migration Issues

**Error: "relation already exists"**
- Your schema already exists; use `prisma db push` instead
- Or reset: `prisma migrate reset` (⚠️ deletes all data!)

**Prisma migrations fail with pgbouncer**
- For initial migrations, temporarily use the direct connection (port 5432)
- After migrations are complete, switch back to connection pooling

### Performance Issues

- Use the connection pooling URI for better performance
- Check the Supabase dashboard Reports section for slow queries
- Add database indexes if needed (Prisma schema already includes key indexes)
- Consider upgrading your Supabase plan for more resources

## Cost Considerations

### Supabase Free Tier
- 500 MB database space
- 1 GB file storage
- 50,000 monthly active users
- Unlimited API requests
- Perfect for development and small projects

### Supabase Pro Plan ($25/month)
- 8 GB database space
- 100 GB file storage
- Unlimited monthly active users
- Daily backups with 7-day retention
- Point-in-time recovery
- Priority support

For most MySSO deployments, the **free tier is sufficient** to get started.

## Support

- **Supabase Documentation**: https://supabase.com/docs
- **Supabase Discord**: https://discord.supabase.com
- **Prisma Documentation**: https://www.prisma.io/docs
- **MySSO Issues**: Create an issue in the GitHub repository

## Reverting to Local PostgreSQL

If you need to switch back to local PostgreSQL:

1. Start your local PostgreSQL:
   ```bash
   docker compose up -d
   ```

2. Update your `.env`:
   ```bash
   DATABASE_URL="postgresql://postgres:postgres@localhost:5432/mysso?schema=public"
   ```

3. Run migrations:
   ```bash
   npm run prisma:migrate
   ```

The database schema works identically on both Supabase and local PostgreSQL since Supabase uses PostgreSQL under the hood.
