#!/usr/bin/env node

/**
 * RSA Key Generation Script
 * Generates RSA key pair and JWKS for JWT signing
 * This script runs automatically during npm install (postinstall)
 */

const { generateKeyPairSync } = require('crypto');
const fs = require('fs');
const path = require('path');

// Keys directory
const KEYS_DIR = process.env.KEYS_DIR || path.join(process.cwd(), 'keys');

/**
 * Generate RSA key pair
 */
function generateKeys() {
  console.log('🔐 Generating RSA keys for JWT signing...');

  // Create keys directory if it doesn't exist
  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
    console.log(`📁 Created keys directory: ${KEYS_DIR}`);
  }

  const privateKeyPath = path.join(KEYS_DIR, 'private.pem');
  const publicKeyPath = path.join(KEYS_DIR, 'public.pem');
  const jwksPath = path.join(KEYS_DIR, 'jwks.json');

  // Check if keys already exist
  if (fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath)) {
    console.log('✅ RSA keys already exist, skipping generation');
    return;
  }

  try {
    // Generate RSA key pair
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    // Save private key
    fs.writeFileSync(privateKeyPath, privateKey);
    console.log(`✅ Private key saved to: ${privateKeyPath}`);

    // Save public key
    fs.writeFileSync(publicKeyPath, publicKey);
    console.log(`✅ Public key saved to: ${publicKeyPath}`);

    // Generate JWKS
    const jwks = {
      keys: [
        {
          kty: 'RSA',
          use: 'sig',
          alg: 'RS256',
          kid: 'default',
          n: extractModulus(publicKey),
          e: 'AQAB', // Standard RSA public exponent (65537)
        },
      ],
    };

    // Save JWKS
    fs.writeFileSync(jwksPath, JSON.stringify(jwks, null, 2));
    console.log(`✅ JWKS saved to: ${jwksPath}`);

    console.log('🎉 RSA key generation completed successfully!');
  } catch (error) {
    console.error('❌ Error generating RSA keys:', error.message);
    process.exit(1);
  }
}

/**
 * Extract modulus (n) from public key PEM for JWK
 * Simplified version - returns a placeholder
 */
function extractModulus(publicKeyPem) {
  // For a real implementation, you would need to parse the PEM
  // and extract the actual modulus. For now, we'll use the crypto module
  // to export the key in JWK format if available
  try {
    const crypto = require('crypto');
    const keyObject = crypto.createPublicKey(publicKeyPem);
    const jwk = keyObject.export({ format: 'jwk' });
    return jwk.n;
  } catch (error) {
    console.warn('⚠️  Using placeholder modulus for JWK');
    return 'placeholder-modulus-value';
  }
}

// Run the key generation
if (require.main === module) {
  generateKeys();
}

module.exports = { generateKeys };
