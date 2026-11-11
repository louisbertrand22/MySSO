# Production Environment Variables

Reference for the variables of the two Vercel projects. For the deployment procedure, see
[VERCEL_DEPLOYMENT.md](VERCEL_DEPLOYMENT.md).

Set them in Vercel → project → **Settings → Environment Variables**, then **redeploy**: a variable
only applies to deployments built after it was added. Use the **Sensitive** type for secrets.

## Backend

### BASE_URL (required)
```
BASE_URL=https://sso.louis-bertrand.fr
```
Public backend URL. Issuer (`iss`) of every token and base of the OpenID Connect discovery document.
HTTPS, **no trailing slash**.

### DATABASE_URL and DIRECT_URL (required)
```
DATABASE_URL=postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?pgbouncer=true
DIRECT_URL=postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres
```
- `DATABASE_URL`: pooled connection used by the running app (serverless functions open many short connections).
- `DIRECT_URL`: direct connection used by `prisma migrate deploy`.

Copy both from Supabase → **Connect**.

### JWT_PRIVATE_KEY (required)
```
JWT_PRIVATE_KEY=<RSA private key, PEM encoded in base64>
```
Key that signs every token. The public key and `/jwks.json` are derived from it.
Generate it once:
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 -w0
```
Without it, each build generates a new key and **every deployment logs all users out** (see
[VERCEL_DEPLOYMENT.md §3](VERCEL_DEPLOYMENT.md#3-signing-key)). Raw PEM is also accepted.
`JWT_PUBLIC_KEY` can be set too, but is not needed.

### ALLOWED_ORIGINS (required)
```
ALLOWED_ORIGINS=https://my-sso.louis-bertrand.fr
```
CORS origins, comma-separated, exact matches, no trailing slash.

### FRONTEND_URL (required)
```
FRONTEND_URL=https://my-sso.louis-bertrand.fr
```
Frontend URL, used for redirects (login, consent) and links in emails.

### SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
```
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=...
SMTP_PASS=...
SMTP_FROM=MySSO <noreply@example.com>
```
Needed for email verification and password reset emails.

### TOKEN_REFRESH_RATE_LIMIT (optional, default `1000`)
Max requests per OAuth client (and caller IP), per 15 minutes, on:
- `POST /token` with `grant_type=refresh_token`;
- `POST /revoke` and `POST /introspect`.

Access tokens last 15 minutes, so each active user triggers about one refresh per 15 minutes: set it
above the number of users a client has active at the same time. These requests are exempt from the
per-IP limits, because a client backend calls them for all its users from a single IP.

### LOGIN_MAX_ATTEMPTS (optional, default `5`) and LOGIN_LOCK_MINUTES (optional, default `15`)
After `LOGIN_MAX_ATTEMPTS` wrong passwords in a row, the account is locked for `LOGIN_LOCK_MINUTES`.
A successful login or a password reset clears the counter.

### Rarely needed
- `JWT_ISSUER`: overrides the issuer; defaults to `BASE_URL`.
- `JWT_EXPIRATION`: default lifetime in seconds of tokens that do not set their own (ID tokens). Default `3600`.
- `KEYS_DIR`: directory of the local development keys. Ignored when `JWT_PRIVATE_KEY` is set.
- `JWT_SECRET`: not used to sign tokens (RS256 keys are). The startup check only warns when it keeps its default value.
- `PORT`, `NODE_ENV`: set by Vercel.

## Frontend

### NEXT_PUBLIC_API_URL (required)
```
NEXT_PUBLIC_API_URL=https://sso.louis-bertrand.fr
```
Backend URL. Inlined at **build time**: redeploy the frontend after changing it.

### NEXT_PUBLIC_ALLOWED_ORIGINS (optional)
Extra origins accepted as `returnTo` redirect targets, comma-separated.

## Startup checks

In production the backend warns at startup when:
- `BASE_URL` is missing or not HTTPS;
- `JWT_SECRET` keeps its default value;
- `ALLOWED_ORIGINS` is missing;
- `JWT_PRIVATE_KEY` is missing (logged when the first token is signed or verified).

Find these messages in Vercel → backend project → **Logs**.
