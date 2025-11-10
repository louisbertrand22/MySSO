import express, { Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { config, validateConfig } from './config/env';
import authRoutes from './routes/authRoutes';
import clientRoutes from './routes/clientRoutes';
import { JwtService } from './services/jwtService';

// Validate configuration
validateConfig();

// Create Express app
const app = express();

// Middleware
// CORS configuration - restrict to specific origins in production
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:3000', 'http://localhost:5173'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    
    // In development, allow all origins
    if (process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    
    // In production, check against allowed origins
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Cookie parser for HttpOnly cookies
// CSRF Protection: We use SameSite='strict' cookies which prevent CSRF attacks
// by ensuring cookies are only sent with same-site requests
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * Health check endpoint
 * GET /health
 */
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

/**
 * Test JWT generation endpoint
 * GET /test/jwt
 */
app.get('/test/jwt', (_req: Request, res: Response) => {
  try {
    const token = JwtService.generateTestToken();
    const decoded = JwtService.decode(token);
    
    res.json({
      token,
      decoded,
      message: 'Test JWT generated successfully',
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to generate test JWT',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// Mount auth routes
app.use('/', authRoutes);

// Mount client routes
app.use('/', clientRoutes);

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({
    error: 'not_found',
    message: 'Route not found',
  });
});

// Error handler
app.use((err: Error, _req: Request, res: Response, _next: any) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'internal_server_error',
    message: err.message,
  });
});

// Start server
const PORT = config.port;
app.listen(PORT, () => {
  console.log(`🚀 MySSO server running on port ${PORT}`);
  console.log(`📍 Health check: http://localhost:${PORT}/health`);
  console.log(`📍 OpenID Configuration: http://localhost:${PORT}/.well-known/openid-configuration`);
  console.log(`📍 JWKS: http://localhost:${PORT}/jwks.json`);
  console.log(`🧪 Test JWT: http://localhost:${PORT}/test/jwt`);
});

export default app;
