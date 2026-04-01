import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config();

// Base URL configuration - used by other config properties
const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

/**
 * Environment configuration
 * Centralizes all environment variable access with type safety and defaults
 */
export const config = {
  // Server configuration
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  baseUrl,
  
  // Database configuration
  databaseUrl: process.env.DATABASE_URL || '',
  
  // JWT configuration
  jwt: {
    issuer: process.env.JWT_ISSUER || baseUrl,
    expiration: parseInt(process.env.JWT_EXPIRATION || '3600', 10),
    secret: process.env.JWT_SECRET || 'changeme',
  },
  
  // Keys directory
  keysDir: process.env.KEYS_DIR || path.join(process.cwd(), 'keys'),
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3002',
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

  // Additional production checks
  if (config.nodeEnv === 'production') {
    const productionIssues: string[] = [];

    // Check BASE_URL is set for production
    if (!process.env.BASE_URL) {
      productionIssues.push('BASE_URL should be explicitly set in production (currently using default)');
    }

    // Check BASE_URL uses HTTPS in production
    if (config.baseUrl.startsWith('http://') && !config.baseUrl.includes('localhost')) {
      productionIssues.push('BASE_URL should use HTTPS in production for security');
    }

    // Check JWT_SECRET is not default
    if (config.jwt.secret === 'changeme') {
      productionIssues.push('JWT_SECRET is using default value - please set a strong secret');
    }

    // Check ALLOWED_ORIGINS is configured
    if (!process.env.ALLOWED_ORIGINS) {
      productionIssues.push('ALLOWED_ORIGINS should be set in production to restrict CORS');
    }

    if (productionIssues.length > 0) {
      console.warn('⚠️  Production Configuration Issues:');
      productionIssues.forEach(issue => console.warn(`   - ${issue}`));
      console.warn('');
    } else {
      console.log('✅ Production configuration validated successfully');
    }
  }
}
