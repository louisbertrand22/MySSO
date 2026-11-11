# Deploying MySSO on Vercel

MySSO runs as **two Vercel projects** built from this repository, plus a Supabase Postgres database:

| Part | Vercel project root | Production URL | What it is |
|---|---|---|---|
| Backend | repository root (`/`) | `https://sso.louis-bertrand.fr` | Express API: OAuth2 / OIDC endpoints, `/auth/*`, `/user/*`, `/admin/*` |
| Frontend | `frontend/` | `https://my-sso.louis-bertrand.fr` | Next.js app: login, consent, account dashboard, admin, PWA |
| Database | — | Supabase | PostgreSQL, schema managed by Prisma migrations |

A push to `main` builds and deploys both projects. Vercel detects the Express app on its own:
`src/server.ts` exports the `app` (`export default app`).

For variable details and examples, see [PRODUCTION_ENV_VARS.md](PRODUCTION_ENV_VARS.md).

---

## 1. Backend environment variables

Set them in the backend project → **Settings → Environment Variables**, environment **Production**.
A variable only applies to deployments built after it was added: **redeploy** after any change.

| Variable | Required | Value |
|---|---|---|
| `BASE_URL` | yes | `https://sso.louis-bertrand.fr` (HTTPS, no trailing slash). Issuer of every token. |
| `DATABASE_URL` | yes | Supabase **pooler** URL used at runtime (port 6543, `?pgbouncer=true`). |
| `DIRECT_URL` | yes | Supabase **direct** URL (port 5432). Used by `prisma migrate`. |
| `JWT_PRIVATE_KEY` | **yes** | RSA private key, PEM encoded in base64. See [§3](#3-signing-key). |
| `ALLOWED_ORIGINS` | yes | `https://my-sso.louis-bertrand.fr` (comma-separated, exact origins). CORS. |
| `FRONTEND_URL` | yes | `https://my-sso.louis-bertrand.fr`. Used for redirects and links in emails. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | for emails | Email verification and password reset. |
| `TOKEN_REFRESH_RATE_LIMIT` | no | Refresh grants, revocations and introspections per client per 15 min. Default `1000`. |
| `LOGIN_MAX_ATTEMPTS` | no | Wrong passwords in a row before the account is locked. Default `5`. |
| `LOGIN_LOCK_MINUTES` | no | Lock duration. Default `15`. |
| `JWT_ISSUER` | no | Overrides the issuer. Defaults to `BASE_URL`; leave unset. |

Vercel sets `NODE_ENV=production` and `VERCEL=1` by itself.

## 2. Frontend environment variables

| Variable | Required | Value |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | yes | `https://sso.louis-bertrand.fr` |
| `NEXT_PUBLIC_ALLOWED_ORIGINS` | no | Extra origins accepted as `returnTo` targets, comma-separated. |

`NEXT_PUBLIC_*` values are inlined **at build time**: redeploy the frontend after changing them.

## 3. Signing key

Every token (access, refresh, ID token) is signed with an RSA key, and its public half is
published at `/jwks.json`.

**The key must come from `JWT_PRIVATE_KEY`.** Without it, `npm install` generates a new key pair
in `keys/` on every build: each deployment then invalidates every session, every refresh token held
by OAuth clients, and the JWKS cached by clients. The backend logs
`JWT_PRIVATE_KEY is not set` when this happens.

Generate a key (once):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 -w0 > jwt_private_key.txt
```

Paste the content into `JWT_PRIVATE_KEY` (type **Sensitive**), redeploy the backend, then delete the
file. The public key and the JWKS are derived from it. Raw PEM is accepted as well.

Check that production uses it: the `n` value in `https://sso.louis-bertrand.fr/jwks.json` must not
change from one deployment to the next.

**Rotating the key** logs every user out and forces OAuth clients to sign in again: replace the
variable, redeploy, and warn client owners.

## 4. Database migrations

Migrations are **not** applied by the Vercel build. Apply them yourself, **before** pushing code that
needs them: Prisma queries every column of the schema, so code deployed ahead of its migration fails
with errors such as `The column User.lockedUntil does not exist`.

```bash
# From the repository root, with the production URLs
DATABASE_URL="<supabase direct url>" DIRECT_URL="<supabase direct url>" npx prisma migrate deploy
```

Only additive migrations (new tables, new nullable or defaulted columns) are safe to apply while the
previous version is still running. For anything else, plan a short maintenance window.

The `.gitignore` excludes `*.sql`: add new migration files with `git add -f prisma/migrations/...`.

## 5. Deploying

1. Apply pending migrations ([§4](#4-database-migrations)).
2. Push to `main`. Both projects build; the frontend build runs type checking and lint.
3. Check the deployment:
   ```bash
   curl https://sso.louis-bertrand.fr/health
   curl https://sso.louis-bertrand.fr/.well-known/openid-configuration
   curl https://sso.louis-bertrand.fr/jwks.json
   ```
4. Sign in on `https://my-sso.louis-bertrand.fr` and open the dashboard.

**Rollback**: Vercel → project → Deployments → *Instant Rollback*. The database is not rolled back:
an older version must still work with the current schema.

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `invalid_token` everywhere right after a deployment | `JWT_PRIVATE_KEY` missing, keys regenerated by the build | [§3](#3-signing-key) |
| `The column … does not exist` | Migration not applied | [§4](#4-database-migrations) |
| CORS error in the browser | Frontend origin missing from `ALLOWED_ORIGINS` | Add it, redeploy the backend |
| Frontend calls `localhost` | `NEXT_PUBLIC_API_URL` missing at build time | Set it, redeploy the frontend |
| `Tenant or user not found` from Prisma | Wrong Supabase pooler URL or user | Copy the URLs again from Supabase → Connect |
| No verification or reset emails | SMTP variables missing | Set `SMTP_*`, redeploy |

## 7. Known limits

- **Rate limits are kept in memory**, per Vercel instance: they reset on cold starts and are not
  shared between instances. The account lockout (stored in the database) is not affected.
- **`logs/security.log` is not kept** on Vercel. Security events are also stored in the `AuditLog`
  table, visible in the admin area.
