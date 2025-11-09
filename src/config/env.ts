import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config();

/**
 * Environment configuration
 * Centralizes all environment variable access with type safety and defaults
 */
export const config = {
  // Server configuration
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Database configuration
  databaseUrl: process.env.DATABASE_URL || '',
  
  // JWT configuration
  jwt: {
    issuer: process.env.JWT_ISSUER || 'http://localhost:3000',
    expiration: parseInt(process.env.JWT_EXPIRATION || '3600', 10),
    secret: process.env.JWT_SECRET || 'changeme',
  },
  
  // Keys directory
  keysDir: process.env.KEYS_DIR || path.join(process.cwd(), 'keys'),
} as const;

/**
 * Validate required environment variables
 */
export function validateConfig(): void {
  const requiredVars = ['DATABASE_URL'];
  const missing = requiredVars.filter(varName => !process.env[varName]);
  
  if (missing.length > 0) {
    console.warn(`Warning: Missing environment variables: ${missing.join(', ')}`);
    console.warn('Please copy .env.example to .env and configure the values');
  }
}
