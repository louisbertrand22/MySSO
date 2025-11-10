#!/bin/bash

# Test script for OpenID Connect endpoints
# This script tests the OIDC discovery endpoint and JWKS endpoint

BASE_URL="http://localhost:3000"

echo "======================================"
echo "OpenID Connect Endpoints Test"
echo "======================================"

echo ""
echo "1. Testing OpenID Discovery Endpoint"
echo "GET /.well-known/openid-configuration"
echo "--------------------------------------"
curl -s "$BASE_URL/.well-known/openid-configuration" | jq '.'

echo ""
echo ""
echo "2. Testing JWKS Endpoint"
echo "GET /jwks.json"
echo "--------------------------------------"
curl -s "$BASE_URL/jwks.json" | jq '.'

echo ""
echo ""
echo "3. Testing Health Endpoint"
echo "GET /health"
echo "--------------------------------------"
curl -s "$BASE_URL/health" | jq '.'

echo ""
echo "======================================"
echo "Basic endpoints test complete!"
echo "======================================"
echo ""
echo "To test the full OIDC flow:"
echo "1. Start the server: npm run dev"
echo "2. Run the complete flow test in docs/OIDC_ENDPOINTS.md"
echo ""
