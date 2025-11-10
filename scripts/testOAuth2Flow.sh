#!/bin/bash

# OAuth2 Authorization Code Flow - Complete Integration Test
# This script tests the entire OAuth2 flow from registration to token exchange

set -e  # Exit on error

echo "========================================="
echo "OAuth2 Authorization Code Flow - Complete Test"
echo "========================================="
echo ""

# Configuration
API_URL="http://localhost:3000"
REDIRECT_URI="http://localhost:5173/callback"
TEST_EMAIL="oauth2test@example.com"
TEST_PASSWORD="OAuth2TestPass123!"

echo "Configuration:"
echo "  API URL: $API_URL"
echo "  Redirect URI: $REDIRECT_URI"
echo "  Test Email: $TEST_EMAIL"
echo ""

# Step 1: Register test user
echo "Step 1: Registering test user..."
REGISTER_RESPONSE=$(curl -s -X POST "$API_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")

if echo "$REGISTER_RESPONSE" | grep -q "error"; then
  echo "  Registration failed (user may already exist): $REGISTER_RESPONSE"
  echo "  Continuing with existing user..."
else
  echo "  ✓ User registered successfully"
fi
echo ""

# Step 2: Login to get access token
echo "Step 2: Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")

if echo "$LOGIN_RESPONSE" | grep -q "error"; then
  echo "  ✗ Login failed: $LOGIN_RESPONSE"
  exit 1
fi

ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.accessToken')
if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
  echo "  ✗ Failed to extract access token"
  exit 1
fi

echo "  ✓ Login successful"
echo "  Access Token: ${ACCESS_TOKEN:0:50}..."
echo ""

# Step 3: Request authorization code
echo "Step 3: Requesting authorization code..."
AUTH_RESPONSE=$(curl -s -i -X GET "$API_URL/login?redirect_uri=$REDIRECT_URI" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

if ! echo "$AUTH_RESPONSE" | grep -q "HTTP/1.1 302"; then
  echo "  ✗ Authorization request failed"
  echo "$AUTH_RESPONSE"
  exit 1
fi

AUTH_CODE=$(echo "$AUTH_RESPONSE" | grep -i "Location:" | sed 's/.*code=\([^&]*\).*/\1/' | tr -d '\r\n')
if [ -z "$AUTH_CODE" ]; then
  echo "  ✗ Failed to extract authorization code"
  exit 1
fi

echo "  ✓ Authorization code generated: $AUTH_CODE"
echo ""

# Step 4: Exchange authorization code for tokens
echo "Step 4: Exchanging authorization code for tokens..."
TOKEN_RESPONSE=$(curl -s -X POST "$API_URL/token" \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"authorization_code\",\"code\":\"$AUTH_CODE\",\"redirect_uri\":\"$REDIRECT_URI\"}")

if echo "$TOKEN_RESPONSE" | grep -q "error"; then
  echo "  ✗ Token exchange failed: $TOKEN_RESPONSE"
  exit 1
fi

NEW_ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | jq -r '.token_type')
EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in')

if [ -z "$NEW_ACCESS_TOKEN" ] || [ "$NEW_ACCESS_TOKEN" = "null" ]; then
  echo "  ✗ Failed to extract tokens"
  exit 1
fi

echo "  ✓ Token exchange successful"
echo "  Token Type: $TOKEN_TYPE"
echo "  Expires In: $EXPIRES_IN seconds"
echo "  Access Token: ${NEW_ACCESS_TOKEN:0:50}..."
echo "  Refresh Token: ${REFRESH_TOKEN:0:50}..."
echo ""

# Step 5: Test single-use enforcement (reuse should fail)
echo "Step 5: Testing single-use enforcement (reusing code)..."
REUSE_RESPONSE=$(curl -s -X POST "$API_URL/token" \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"authorization_code\",\"code\":\"$AUTH_CODE\",\"redirect_uri\":\"$REDIRECT_URI\"}")

if echo "$REUSE_RESPONSE" | grep -q "invalid_grant"; then
  echo "  ✓ Code reuse correctly rejected"
else
  echo "  ✗ Code reuse should have been rejected"
  echo "  Response: $REUSE_RESPONSE"
  exit 1
fi
echo ""

# Step 6: Test redirect URI validation
echo "Step 6: Testing redirect URI validation..."
INVALID_REDIRECT="https://evil.com/callback"
INVALID_RESPONSE=$(curl -s -X GET "$API_URL/login?redirect_uri=$INVALID_REDIRECT" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

if echo "$INVALID_RESPONSE" | grep -q "redirect_uri not allowed"; then
  echo "  ✓ Invalid redirect URI correctly rejected"
else
  echo "  ✗ Invalid redirect URI should have been rejected"
  echo "  Response: $INVALID_RESPONSE"
  exit 1
fi
echo ""

# Step 7: Test missing redirect_uri
echo "Step 7: Testing missing redirect_uri parameter..."
NO_REDIRECT_RESPONSE=$(curl -s -X GET "$API_URL/login" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

if echo "$NO_REDIRECT_RESPONSE" | grep -q "Missing or invalid redirect_uri"; then
  echo "  ✓ Missing redirect_uri correctly rejected"
else
  echo "  ✗ Missing redirect_uri should have been rejected"
  echo "  Response: $NO_REDIRECT_RESPONSE"
  exit 1
fi
echo ""

# Step 8: Test with invalid access token
echo "Step 8: Testing with invalid access token..."
INVALID_TOKEN_RESPONSE=$(curl -s -X GET "$API_URL/login?redirect_uri=$REDIRECT_URI" \
  -H "Authorization: Bearer invalid_token_here")

if echo "$INVALID_TOKEN_RESPONSE" | grep -q "unauthorized"; then
  echo "  ✓ Invalid access token correctly rejected"
else
  echo "  ✗ Invalid access token should have been rejected"
  echo "  Response: $INVALID_TOKEN_RESPONSE"
  exit 1
fi
echo ""

# Step 9: Test userinfo endpoint with new token
echo "Step 9: Testing userinfo endpoint with new access token..."
USERINFO_RESPONSE=$(curl -s -X GET "$API_URL/userinfo" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN")

if echo "$USERINFO_RESPONSE" | grep -q "sub"; then
  echo "  ✓ Userinfo endpoint accessible with new token"
  USER_SUB=$(echo "$USERINFO_RESPONSE" | jq -r '.sub')
  USER_EMAIL=$(echo "$USERINFO_RESPONSE" | jq -r '.email')
  echo "  User ID: $USER_SUB"
  echo "  Email: $USER_EMAIL"
else
  echo "  ✗ Userinfo endpoint should be accessible"
  echo "  Response: $USERINFO_RESPONSE"
  exit 1
fi
echo ""

# Summary
echo "========================================="
echo "✓ All OAuth2 Flow Tests Passed!"
echo "========================================="
echo ""
echo "Test Summary:"
echo "  ✓ User registration"
echo "  ✓ User login"
echo "  ✓ Authorization code generation"
echo "  ✓ Token exchange"
echo "  ✓ Single-use code enforcement"
echo "  ✓ Redirect URI validation"
echo "  ✓ Missing parameter handling"
echo "  ✓ Invalid token handling"
echo "  ✓ UserInfo endpoint access"
echo ""
echo "The OAuth2 authorization code flow is working correctly!"
echo ""
