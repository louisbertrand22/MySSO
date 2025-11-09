import express, { Request, Response } from 'express';
import cors from 'cors';
import { config, validateConfig } from './config/env';
import authRoutes from './routes/authRoutes';
import { JwtService } from './services/jwtService';

// Validate configuration
validateConfig();

// Create Express app
const app = express();

// Middleware
app.use(cors());
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
