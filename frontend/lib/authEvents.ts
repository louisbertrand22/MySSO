/**
 * Lets the API helpers tell the AuthProvider that the server rejected an access token
 * (expired, revoked session, or signing keys changed), so it can refresh or sign out
 * instead of every section showing "invalid_token".
 */
type Handler = (rejectedToken: string) => void;

let handler: Handler | null = null;

export function onUnauthorized(h: Handler): () => void {
  handler = h;
  return () => {
    if (handler === h) handler = null;
  };
}

/** fetch() that reports a 401 on a Bearer-authenticated request */
export async function authAwareFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const response = await fetch(input, init);
  if (response.status === 401) {
    const auth = new Headers(init?.headers).get('Authorization');
    if (auth?.startsWith('Bearer ')) handler?.(auth.slice(7));
  }
  return response;
}
