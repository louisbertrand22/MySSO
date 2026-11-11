import { Request } from 'express';

/**
 * Extract OAuth client credentials from the request.
 * Supports client_secret_basic (Authorization: Basic) and client_secret_post (body).
 * The credentials are NOT verified here.
 */
export function getClientCredentials(req: Request): { clientId?: string; clientSecret?: string } {
  const header = req.headers.authorization;
  if (header && header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep !== -1) {
      try {
        return {
          clientId: decodeURIComponent(decoded.slice(0, sep)),
          clientSecret: decodeURIComponent(decoded.slice(sep + 1)),
        };
      } catch {
        return {};
      }
    }
  }
  const clientId = typeof req.body?.client_id === 'string' ? req.body.client_id : undefined;
  const clientSecret = typeof req.body?.client_secret === 'string' ? req.body.client_secret : undefined;
  return { clientId, clientSecret };
}

/** True when the request is a POST /token with grant_type=refresh_token */
export function isRefreshTokenGrant(req: Request): boolean {
  // originalUrl: req.path is relative to the mount point when used inside app.use('/token', ...)
  const path = req.originalUrl.split('?')[0].replace(/\/+$/, '');
  return req.method === 'POST' && path === '/token' && req.body?.grant_type === 'refresh_token';
}
