# MySSO — Feature Roadmap

## Authentication & Security

- [x] **Forgot password / reset flow** — email link with short-lived signed token, invalidated on use
- [ ] **Email verification** — require users to verify their address before first login
- [ ] **Two-factor authentication (TOTP)** — Google Authenticator / Authy compatible, with backup codes
- [ ] **Passkey / WebAuthn support** — passwordless login via device biometrics
- [ ] **Social login** — OAuth2 login via GitHub / Google as identity providers
- [ ] **Account lockout policy** — lock account after N failed attempts, auto-unlock after delay
- [ ] **Password strength enforcement** — min entropy check on register and password change
- [x] **Change password** — authenticated endpoint + UI in dashboard

## Session & Token Management

- [x] **Active sessions list** — show device, IP, last seen; allow revoking individual sessions from dashboard
- [ ] **Refresh token rotation** — invalidate the previous refresh token on every use (already partially in place — verify fully)
- [ ] **Absolute session TTL** — force re-login after a configurable max lifetime regardless of activity
- [ ] **Silent refresh** — frontend proactively renews access token before expiry without user interruption

## OAuth2 / OIDC

- [ ] **PKCE enforcement** — reject authorization requests without `code_challenge` for public clients
- [ ] **Token introspection endpoint** — `POST /oauth/introspect` per RFC 7662
- [ ] **Token revocation endpoint** — `POST /oauth/revoke` per RFC 7009
- [ ] **Dynamic client registration** — `POST /oauth/register` per RFC 7591 for programmatic client onboarding
- [ ] **Refresh token scoping** — issue refresh tokens only for offline_access scope
- [ ] **`prompt=login` / `prompt=consent`** — honour the OIDC `prompt` parameter in authorize requests

## Admin Panel

- [x] **User management UI** — list, search, disable/enable, delete users; view their sessions and consents
- [x] **Client management UI** — create, edit, rotate secrets, delete OAuth2 clients; currently API-only
- [x] **Scope management UI** — add/remove scopes, set descriptions; currently seeded manually
- [x] **Audit log viewer** — searchable table of security events from `securityLogger`
- [x] **Dashboard metrics** — active users, token issuance rate, consent count per client

## User Profile

- [ ] **Avatar / profile picture** — upload or link a Gravatar
- [ ] **Display name** — separate from username, returned in `profile` scope
- [x] **Account deletion** — GDPR-compliant self-serve deletion with cascade (sessions, tokens, consents)
- [ ] **Export personal data** — download JSON of all stored data (GDPR Article 20)

## Developer Experience

- [ ] **Client self-service portal** — developers register and manage their own OAuth2 clients
- [ ] **Webhook events** — notify client apps on consent revoke, user deletion, password change
- [x] **`.well-known/openid-configuration` improvements** — expose all supported claims, ACR values
- [x] **API documentation** — OpenAPI/Swagger spec auto-generated from routes

## Frontend / UX

- [ ] **Toast notifications** — replace `alert()` in `ConsentsManager` with non-blocking toasts
- [ ] **Confirm modal** — replace `confirm()` for revoke action with an accessible modal dialog
- [ ] **Light mode** — add theme toggle with `prefers-color-scheme` default
- [ ] **Accessibility audit** — keyboard navigation, ARIA labels, focus management on modals
- [ ] **Consent screen branding** — show client logo and description on the authorize/consent page

## Infrastructure

- [ ] **Automated DB migrations in CI** — run `prisma migrate deploy` as a pre-deploy step on Render
- [ ] **Health check improvements** — include DB connectivity and Prisma status in `/health` response
- [ ] **Structured logging** — replace `console.log` with a JSON logger (e.g. `pino`) for log drain compatibility
- [ ] **Rate limiting per user/IP** — tighten limits on `/login` and `/token` endpoints
- [ ] **Key rotation script** — rotate RSA signing keys without downtime (new kid, grace period for old)
