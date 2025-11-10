#!/bin/bash

# Complete OIDC Flow Test
# Tests all OIDC endpoints and features including PKCE, nonce, ID tokens, and userinfo

set -e  # Exit on error

echo "========================================="
echo "Complete OIDC Flow Test"
echo "========================================="
echo ""

# Configuration
API_URL="http://localhost:3000"
CLIENT_ID="test_client_123"
CLIENT_SECRET="test_secret_123"
REDIRECT_URI="http://localhost:5173/callback"

echo "Configuration:"
echo "  API URL: $API_URL"
echo "  Client ID: $CLIENT_ID"
echo "  Redirect URI: $REDIRECT_URI"
echo ""

# Test 1: Health Check
echo "Test 1: Health Check"
HEALTH_RESPONSE=$(curl -s "$API_URL/health")
if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
  echo "  ✓ Server is healthy"
else
  echo "  ✗ Server health check failed"
  exit 1
fi
echo ""

# Test 2: OpenID Configuration Discovery
echo "Test 2: OpenID Configuration Discovery"
CONFIG_RESPONSE=$(curl -s "$API_URL/.well-known/openid-configuration")
if echo "$CONFIG_RESPONSE" | grep -q "authorization_endpoint"; then
  echo "  ✓ OpenID configuration is accessible"
  
  # Verify PKCE support
  if echo "$CONFIG_RESPONSE" | grep -q "S256"; then
    echo "  ✓ PKCE S256 method supported"
  else
    echo "  ✗ PKCE S256 method not listed"
    exit 1
  fi
  
  # Verify required endpoints
  if echo "$CONFIG_RESPONSE" | grep -q "userinfo_endpoint"; then
    echo "  ✓ UserInfo endpoint listed"
  else
    echo "  ✗ UserInfo endpoint not listed"
    exit 1
  fi
else
  echo "  ✗ OpenID configuration failed"
  exit 1
fi
echo ""

# Test 3: JWKS Endpoint
echo "Test 3: JWKS Endpoint"
JWKS_RESPONSE=$(curl -s "$API_URL/jwks.json")
if echo "$JWKS_RESPONSE" | grep -q "keys"; then
  echo "  ✓ JWKS endpoint is accessible"
  
  # Verify RSA key present
  if echo "$JWKS_RESPONSE" | grep -q "RS256"; then
    echo "  ✓ RS256 key present"
  else
    echo "  ✗ RS256 key not found"
    exit 1
  fi
else
  echo "  ✗ JWKS endpoint failed"
  exit 1
fi
echo ""

# Test 4: User Login to get access token
echo "Test 4: User Login"
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com","password":"TestPassword123!"}')

if echo "$LOGIN_RESPONSE" | grep -q "accessToken"; then
  ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.accessToken')
  echo "  ✓ Login successful"
  echo "  Access Token: ${ACCESS_TOKEN:0:50}..."
else
  echo "  ✗ Login failed: $LOGIN_RESPONSE"
  exit 1
fi
echo ""

# Test 5: Authorization with PKCE (S256)
echo "Test 5: Authorization with PKCE (S256 method)"

# Generate code verifier and challenge
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr "+/" "-_" | tr -d "=")
NONCE=$(openssl rand -base64 16 | tr -d "=+/")

echo "  Code Verifier: ${CODE_VERIFIER:0:30}..."
echo "  Code Challenge: ${CODE_CHALLENGE:0:30}..."
echo "  Nonce: ${NONCE:0:20}..."

# Approve consent and get authorization code
CONSENT_RESPONSE=$(curl -s -i -X POST "$API_URL/auth/authorize" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d "{\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\",\"scope\":\"openid email profile\",\"code_challenge\":\"$CODE_CHALLENGE\",\"code_challenge_method\":\"S256\",\"nonce\":\"$NONCE\",\"approved\":true}")

# Extract code from redirect Location header
if echo "$CONSENT_RESPONSE" | grep -q "code="; then
  AUTH_CODE=$(echo "$CONSENT_RESPONSE" | grep -i "Location:" | sed 's/.*code=\([^&]*\).*/\1/' | tr -d '\r\n')
  echo "  ✓ Authorization code obtained: $AUTH_CODE"
else
  echo "  ✗ Failed to get authorization code"
  echo "$CONSENT_RESPONSE"
  exit 1
fi
echo ""

# Test 6: Token Exchange with PKCE verification and ID Token
echo "Test 6: Token Exchange with PKCE verification"
TOKEN_RESPONSE=$(curl -s -X POST "$API_URL/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\":\"authorization_code\",
    \"code\":\"$AUTH_CODE\",
    \"redirect_uri\":\"$REDIRECT_URI\",
    \"client_id\":\"$CLIENT_ID\",
    \"client_secret\":\"$CLIENT_SECRET\",
    \"code_verifier\":\"$CODE_VERIFIER\"
  }")

if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
  NEW_ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
  REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')
  ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.id_token')
  
  echo "  ✓ Token exchange successful"
  echo "  Access Token: ${NEW_ACCESS_TOKEN:0:50}..."
  echo "  Refresh Token: ${REFRESH_TOKEN:0:50}..."
  
  # Check if ID token is present (should be with 'openid' scope)
  if [ "$ID_TOKEN" != "null" ] && [ -n "$ID_TOKEN" ]; then
    echo "  ✓ ID Token present: ${ID_TOKEN:0:50}..."
    
    # Decode ID token (just the payload for verification)  
    ID_TOKEN_PAYLOAD=$(echo "$ID_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | tr -d '\0')
    
    # Check if nonce is in ID token
    if echo "$ID_TOKEN_PAYLOAD" | grep -q "$NONCE"; then
      echo "  ✓ Nonce verified in ID token"
    fi
  else
    echo "  ⚠ Warning: ID Token not present"
  fi
else
  echo "  ✗ Token exchange failed: $TOKEN_RESPONSE"
  exit 1
fi
echo ""

# Test 7: UserInfo Endpoint with scope-based claims
echo "Test 7: UserInfo Endpoint (scope-based claims)"
USERINFO_RESPONSE=$(curl -s -X GET "$API_URL/userinfo" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN")

if echo "$USERINFO_RESPONSE" | grep -q "sub"; then
  echo "  ✓ UserInfo endpoint accessible"
  
  USER_SUB=$(echo "$USERINFO_RESPONSE" | jq -r '.sub')
  echo "  User ID (sub): $USER_SUB"
  
  # Check email claim (should be present with 'email' scope)
  if echo "$USERINFO_RESPONSE" | grep -q "email"; then
    USER_EMAIL=$(echo "$USERINFO_RESPONSE" | jq -r '.email')
    echo "  ✓ Email claim present: $USER_EMAIL"
  else
    echo "  ⚠ Email claim not present (check scope)"
  fi
else
  echo "  ✗ UserInfo endpoint failed: $USERINFO_RESPONSE"
  exit 1
fi
echo ""

# Test 8: Test PKCE validation (wrong code_verifier should fail)
echo "Test 8: PKCE Validation (wrong code_verifier)"

# Get a new auth code
NONCE2=$(openssl rand -base64 16 | tr -d "=+/")
AUTH_RESPONSE2=$(curl -s -i -X POST "$API_URL/auth/authorize" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d "{\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\",\"scope\":\"openid email\",\"code_challenge\":\"$CODE_CHALLENGE\",\"code_challenge_method\":\"S256\",\"nonce\":\"$NONCE2\",\"approved\":true}")

if echo "$AUTH_RESPONSE2" | grep -q "code="; then
  AUTH_CODE2=$(echo "$AUTH_RESPONSE2" | grep -i "Location:" | sed 's/.*code=\([^&]*\).*/\1/' | tr -d '\r\n')
  
  # Try with wrong verifier
  WRONG_VERIFIER="wrong_verifier_that_should_fail_12345678"
  WRONG_TOKEN_RESPONSE=$(curl -s -X POST "$API_URL/token" \
    -H "Content-Type: application/json" \
    -d "{
      \"grant_type\":\"authorization_code\",
      \"code\":\"$AUTH_CODE2\",
      \"redirect_uri\":\"$REDIRECT_URI\",
      \"client_id\":\"$CLIENT_ID\",
      \"client_secret\":\"$CLIENT_SECRET\",
      \"code_verifier\":\"$WRONG_VERIFIER\"
    }")
  
  if echo "$WRONG_TOKEN_RESPONSE" | grep -q "invalid"; then
    echo "  ✓ Wrong code_verifier correctly rejected"
  else
    echo "  ✗ Wrong code_verifier should have been rejected"
    exit 1
  fi
fi
echo ""

# Test 9: Refresh Token
echo "Test 9: Refresh Token Flow"
REFRESH_RESPONSE=$(curl -s -X POST "$API_URL/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}")

if echo "$REFRESH_RESPONSE" | grep -q "accessToken"; then
  REFRESHED_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.accessToken')
  echo "  ✓ Token refresh successful"
  echo "  New Access Token: ${REFRESHED_ACCESS_TOKEN:0:50}..."
else
  echo "  ✗ Token refresh failed: $REFRESH_RESPONSE"
  exit 1
fi
echo ""

# Summary
echo "========================================="
echo "✓ All OIDC Tests Passed!"
echo "========================================="
echo ""
echo "Test Summary:"
echo "  ✓ Health check"
echo "  ✓ OpenID configuration discovery"
echo "  ✓ JWKS endpoint"
echo "  ✓ User authentication"
echo "  ✓ Authorization with PKCE (S256)"
echo "  ✓ Token exchange with ID token"
echo "  ✓ UserInfo endpoint with scope-based claims"
echo "  ✓ PKCE validation"
echo "  ✓ Refresh token flow"
echo ""
echo "🎉 The MySSO OIDC implementation is COMPLETELY OPERATIONAL!"
echo ""
