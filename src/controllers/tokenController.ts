import { Request, Response } from 'express';
import { config } from '../config/env';
import { JwtService } from '../services/jwtService';
import { ClientService } from '../services/clientService';
import { ConsentService } from '../services/consentService';
import { SecurityLogger } from '../services/securityLogger';
import { prisma } from '../services/authService';
import { getClientCredentials } from '../utils/clientCredentials';
import { isSessionActive } from '../middleware/auth.middleware';

type TokenKind = 'access_token' | 'refresh_token';

/**
 * Authenticates the calling client (client_secret_basic or client_secret_post).
 * With allowPublic, a client that sends only its client_id is accepted (RFC 7009 §2.1
 * lets public clients revoke their own tokens). Returns the client_id, or null.
 */
async function authenticateClient(req: Request, allowPublic: boolean): Promise<string | null> {
  const { clientId, clientSecret } = getClientCredentials(req);
  if (!clientId) return null;
  if (clientSecret) {
    const client = await ClientService.validateClient(clientId, clientSecret);
    return client ? client.clientId : null;
  }
  if (!allowPublic) return null;
  const client = await prisma.client.findUnique({ where: { clientId }, select: { clientId: true } });
  return client?.clientId ?? null;
}

function invalidClient(req: Request, res: Response): void {
  if (req.headers.authorization?.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="MySSO"');
  }
  res.status(401).json({ error: 'invalid_client', error_description: 'Client authentication failed' });
}

/** Order in which to try the token types: the hint first, then the other one */
function lookupOrder(hint: unknown): TokenKind[] {
  return hint === 'access_token' ? ['access_token', 'refresh_token'] : ['refresh_token', 'access_token'];
}

/** Verifies a JWT access token. Returns its claims, or null if it is not a valid access token. */
function decodeAccessToken(token: string): Record<string, any> | null {
  try {
    const claims = JwtService.verify(token);
    return claims && claims.type !== 'refresh' ? claims : null;
  } catch {
    return null;
  }
}

/** Closes a session and deletes its refresh tokens: every token of that login stops working */
async function revokeSession(sessionId: string): Promise<void> {
  await prisma.$transaction([
    prisma.session.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date() } }),
    prisma.refreshToken.deleteMany({ where: { sessionId } }),
  ]);
}

export class TokenController {
  /**
   * POST /revoke — OAuth 2.0 Token Revocation (RFC 7009).
   * Revoking a refresh token or an access token ends the whole login it belongs to:
   * the session is closed, its refresh tokens deleted and its access tokens rejected.
   * Unknown, invalid or foreign tokens get a 200 too, so the endpoint reveals nothing.
   */
  static async revoke(req: Request, res: Response): Promise<void> {
    try {
      const token = typeof req.body?.token === 'string' ? req.body.token : '';
      const clientId = await authenticateClient(req, true);
      if (!clientId) {
        invalidClient(req, res);
        return;
      }
      if (!token) {
        res.status(400).json({ error: 'invalid_request', error_description: 'Missing token parameter' });
        return;
      }

      for (const kind of lookupOrder(req.body.token_type_hint)) {
        if (kind === 'refresh_token') {
          const stored = await prisma.refreshToken.findUnique({
            where: { token },
            select: { userId: true, clientId: true, sessionId: true },
          });
          if (!stored) continue;
          // A client can only revoke the tokens it was issued
          if (stored.clientId === clientId) {
            if (stored.sessionId) await revokeSession(stored.sessionId);
            else await prisma.refreshToken.deleteMany({ where: { token } });
            SecurityLogger.logRevocation(stored.userId, 'single', { clientId, via: 'revocation_endpoint', tokenType: 'refresh_token' });
          }
          break;
        }

        const claims = decodeAccessToken(token);
        if (!claims) continue;
        if (claims.client_id === clientId && typeof claims.sid === 'string') {
          await revokeSession(claims.sid);
          SecurityLogger.logRevocation(claims.sub, 'single', { clientId, via: 'revocation_endpoint', tokenType: 'access_token' });
        }
        break;
      }

      res.set('Cache-Control', 'no-store');
      res.status(200).json({});
    } catch (error) {
      console.error('Token revocation error:', error);
      res.status(503).json({ error: 'temporarily_unavailable', error_description: 'Revocation failed, retry later' });
    }
  }

  /**
   * POST /introspect — OAuth 2.0 Token Introspection (RFC 7662).
   * Requires client authentication with a secret. A client only learns about tokens issued
   * to it: any other token is reported as { active: false }.
   */
  static async introspect(req: Request, res: Response): Promise<void> {
    res.set('Cache-Control', 'no-store');
    try {
      const token = typeof req.body?.token === 'string' ? req.body.token : '';
      const clientId = await authenticateClient(req, false);
      if (!clientId) {
        invalidClient(req, res);
        return;
      }
      if (!token) {
        res.status(400).json({ error: 'invalid_request', error_description: 'Missing token parameter' });
        return;
      }

      const inactive = { active: false };
      const now = new Date();

      for (const kind of lookupOrder(req.body.token_type_hint)) {
        if (kind === 'refresh_token') {
          const stored = await prisma.refreshToken.findUnique({
            where: { token },
            include: {
              user: { select: { isDisabled: true, username: true } },
              session: { select: { revokedAt: true, expiresAt: true } },
            },
          });
          if (!stored) continue;
          const sessionOk = !stored.session || (!stored.session.revokedAt && stored.session.expiresAt > now);
          if (stored.clientId !== clientId || stored.expiresAt <= now || !sessionOk || stored.user.isDisabled) {
            res.json(inactive);
            return;
          }
          const scopes = await ConsentService.getConsentScopes(stored.userId, clientId);
          if (!scopes) {
            res.json(inactive);
            return;
          }
          const claims = JwtService.decode(token) as { iat?: number; exp?: number } | null;
          res.json({
            active: true,
            token_type: 'refresh_token',
            client_id: clientId,
            sub: stored.userId,
            scope: scopes.join(' '),
            ...(stored.user.username ? { username: stored.user.username } : {}),
            iat: claims?.iat,
            exp: claims?.exp ?? Math.floor(stored.expiresAt.getTime() / 1000),
            iss: config.jwt.issuer,
          });
          return;
        }

        const claims = decodeAccessToken(token);
        if (!claims) continue;
        if (claims.client_id !== clientId) {
          res.json(inactive);
          return;
        }
        const user = await prisma.user.findUnique({ where: { id: claims.sub }, select: { isDisabled: true } });
        const sessionOk = typeof claims.sid !== 'string' || (await isSessionActive(claims.sid));
        if (!user || user.isDisabled || !sessionOk) {
          res.json(inactive);
          return;
        }
        res.json({
          active: true,
          token_type: 'Bearer',
          client_id: clientId,
          sub: claims.sub,
          ...(claims.scope ? { scope: claims.scope } : {}),
          ...(claims.username ? { username: claims.username } : {}),
          iat: claims.iat,
          exp: claims.exp,
          iss: claims.iss,
        });
        return;
      }

      res.json(inactive);
    } catch (error) {
      console.error('Token introspection error:', error);
      res.status(500).json({ error: 'server_error', error_description: 'Introspection failed' });
    }
  }
}
