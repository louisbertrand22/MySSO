/**
 * OAuth2 Client Helper
 * Utilities for implementing OAuth2 authorization code flow
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

/**
 * Initiate OAuth2 authorization flow
 * Redirects the user to the SSO server for authentication
 * 
 * @param redirectUri - The URI where the user will be redirected after authorization
 * @param accessToken - Optional access token if user is already authenticated
 */
export function initiateOAuth2Flow(redirectUri?: string, accessToken?: string): void {
  // Default redirect URI is current origin + /callback
  const finalRedirectUri = redirectUri || `${window.location.origin}/callback`;
  
  // Build authorization URL
  const authUrl = new URL(`${API_URL}/login`);
  authUrl.searchParams.set('redirect_uri', finalRedirectUri);
  
  // If access token is provided, include it
  // Note: In a real implementation, you'd handle authentication differently
  // This is a simplified example for demonstration
  if (accessToken) {
    // Store access token temporarily for the redirect
    sessionStorage.setItem('oauth2_access_token', accessToken);
  }
  
  // Redirect to authorization endpoint
  window.location.href = authUrl.toString();
}

/**
 * Exchange authorization code for access and refresh tokens
 * 
 * @param code - Authorization code from the callback
 * @param redirectUri - The same redirect URI used in the authorization request
 * @returns Token response with access_token and refresh_token
 */
export async function exchangeCodeForTokens(
  code: string,
  redirectUri: string
): Promise<{
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
}> {
  const response = await fetch(`${API_URL}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error_description || 'Token exchange failed');
  }

  return response.json();
}

/**
 * Validate if a redirect URI is allowed
 * This is a client-side check for better UX, but the server will also validate
 * 
 * @param redirectUri - The redirect URI to validate
 * @returns True if the URI appears to be valid
 */
export function isValidRedirectUri(redirectUri: string): boolean {
  try {
    const url = new URL(redirectUri);
    
    // In development, allow localhost
    if (process.env.NODE_ENV === 'development') {
      if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
        return true;
      }
    }
    
    // In production, check against allowed origins
    const allowedOrigins = process.env.NEXT_PUBLIC_ALLOWED_ORIGINS?.split(',') || [];
    return allowedOrigins.some(origin => redirectUri.startsWith(origin));
  } catch {
    return false;
  }
}

/**
 * Get the current redirect URI for OAuth2 callbacks
 * 
 * @returns The callback URI for the current application
 */
export function getCallbackUri(): string {
  if (typeof window === 'undefined') {
    return '';
  }
  return `${window.location.origin}/callback`;
}
