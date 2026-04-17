import swaggerJsdoc from 'swagger-jsdoc';
import { config } from './env';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'MySSO API',
      version: '3.4.0',
      description:
        'OAuth2 / OpenID Connect SSO Provider. All protected endpoints require a Bearer JWT ' +
        'obtained from `POST /auth/login` or `POST /token`.',
      contact: { name: 'Louis BERTRAND' },
    },
    servers: [{ url: config.baseUrl, description: 'Current server' }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
      schemas: {
        Error: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            error_description: { type: 'string' },
          },
        },
        TokenResponse: {
          type: 'object',
          properties: {
            access_token: { type: 'string' },
            token_type: { type: 'string', example: 'Bearer' },
            expires_in: { type: 'integer', example: 3600 },
            refresh_token: { type: 'string' },
            id_token: { type: 'string' },
            scope: { type: 'string' },
          },
        },
        User: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            email: { type: 'string', format: 'email' },
            username: { type: 'string', nullable: true },
            isDisabled: { type: 'boolean' },
            isAdmin: { type: 'boolean' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        Client: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            clientId: { type: 'string' },
            redirectUris: { type: 'array', items: { type: 'string' } },
            allowedScopes: { type: 'array', items: { type: 'string' } },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        Scope: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            description: { type: 'string' },
          },
        },
        AuditLog: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            timestamp: { type: 'string', format: 'date-time' },
            event: { type: 'string' },
            userId: { type: 'string', nullable: true },
            email: { type: 'string', nullable: true },
            ip: { type: 'string', nullable: true },
            data: { type: 'object', nullable: true },
          },
        },
      },
    },
    tags: [
      { name: 'Auth', description: 'Authentication & session management' },
      { name: 'OAuth2/OIDC', description: 'OAuth2 and OpenID Connect flows' },
      { name: 'User', description: 'User profile & consents' },
      { name: 'Clients', description: 'OAuth2 client registration' },
      { name: 'Admin', description: 'Admin-only management endpoints (requires admin scope)' },
    ],
  },
  apis: ['./src/routes/*.ts'],
};

export const swaggerSpec = swaggerJsdoc(options);
