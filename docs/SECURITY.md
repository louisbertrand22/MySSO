# Security Considerations for MySSO

## CSRF Protection

### Current Implementation
MySSO uses **SameSite='strict' cookies** for CSRF protection. This is a modern, robust approach that prevents Cross-Site Request Forgery attacks without requiring explicit CSRF tokens.

### How it Works
When a cookie is set with `sameSite: 'strict'`:
- The browser only sends the cookie with requests from the same site
- Cross-site requests (including those from malicious sites) do NOT include the cookie
- This prevents CSRF attacks at the browser level

### Cookie Configuration
```javascript
res.cookie('refreshToken', refreshToken, {
  httpOnly: true,           // Prevents XSS attacks
  secure: production,       // HTTPS only in production
  sameSite: 'strict',      // CSRF protection
  maxAge: 7 days           // Same as token expiration
});
```

### Why We Don't Need CSRF Tokens
Traditional CSRF tokens are needed when:
1. Using cookies for authentication in form-based applications
2. Browsers don't support SameSite cookies
3. Cross-origin requests need to work

MySSO is an **API-first authentication service** where:
- All requests are made via fetch/XHR from JavaScript
- SameSite='strict' is supported by all modern browsers
- Cross-origin requests are controlled via CORS
- State-changing operations require valid JWT tokens

### Additional Protection Layers

1. **CORS Configuration**
   - Strict origin validation in production
   - Credentials only allowed from approved origins
   - Rejects unauthorized cross-origin requests

2. **Token Validation**
   - All refresh tokens must exist in database
   - Tokens are validated on every request
   - Token rotation prevents reuse

3. **HttpOnly Cookies**
   - JavaScript cannot access refresh tokens
   - Prevents XSS-based token theft

## CodeQL Findings

### js/missing-token-validation
**Status**: False Positive (Design Decision)

**Finding**: Cookie middleware serving request handlers without CSRF protection.

**Reasoning**: 
- We use SameSite='strict' cookies which provide CSRF protection at the browser level
- This is more secure than traditional CSRF tokens for modern browsers
- Our API design doesn't require cross-site cookie usage
- All state-changing operations are protected by CORS and token validation

**Reference**: 
- [OWASP CSRF Prevention Cheat Sheet - SameSite Cookie Attribute](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute)
- [MDN: SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)

## Security Best Practices Implemented

✓ **HttpOnly cookies** - Prevents XSS token theft  
✓ **Secure flag** - HTTPS only in production  
✓ **SameSite strict** - CSRF protection  
✓ **Token rotation** - Prevents token reuse  
✓ **Database validation** - All tokens must exist in DB  
✓ **Session revocation** - Audit trail with revokedAt  
✓ **CORS restrictions** - Production origin validation  
✓ **Security logging** - Complete audit trail  
✓ **Token expiration** - Short-lived access tokens  
✓ **Refresh token binding** - Per-device tokens  

## Recommendations for Production

1. **Set ALLOWED_ORIGINS** environment variable to restrict CORS
2. **Use HTTPS** (required for secure cookies)
3. **Monitor security logs** for suspicious activity
4. **Regular token cleanup** - Delete expired tokens from database
5. **Rate limiting** - Add rate limiting to auth endpoints
6. **Account lockout** - Implement failed login attempt tracking

## Alternative CSRF Protection (If Needed)

If you need to support older browsers or cross-origin cookie usage, you can implement traditional CSRF tokens:

```javascript
// Install csurf package
npm install csurf

// Add CSRF middleware
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

// Apply to state-changing routes
app.post('/auth/logout', csrfProtection, AuthController.logout);

// Include CSRF token in responses
res.json({ csrfToken: req.csrfToken() });
```

However, this is **not recommended** for our use case as SameSite cookies provide superior protection for modern applications.
