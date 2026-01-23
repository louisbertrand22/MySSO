/**
 * Seed Default Scopes
 * This script inserts the default OAuth2/OIDC scopes into the database
 * Run this after database migrations
 */

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const DEFAULT_SCOPES = [
  {
    name: 'openid',
    description: 'Authenticate user and get basic profile information',
  },
  {
    name: 'profile',
    description: 'Access basic profile information (name, username, picture, etc.)',
  },
  {
    name: 'email',
    description: 'Access email address',
  },
  {
    name: 'admin',
    description: 'Access administrative functions and endpoints',
  },
  {
    name: 'read:users',
    description: 'Read user information',
  },
  {
    name: 'write:users',
    description: 'Create and modify user information',
  },
  {
    name: 'delete:users',
    description: 'Delete users',
  },
  {
    name: 'read:clients',
    description: 'Read OAuth2 client information',
  },
  {
    name: 'write:clients',
    description: 'Create and modify OAuth2 clients',
  },
  {
    name: 'delete:clients',
    description: 'Delete OAuth2 clients',
  },
];

async function seedScopes() {
  console.log('🌱 Seeding default scopes...\n');

  let created = 0;
  let existing = 0;

  for (const scopeData of DEFAULT_SCOPES) {
    try {
      const scope = await prisma.scope.upsert({
        where: { name: scopeData.name },
        update: { description: scopeData.description },
        create: scopeData,
      });

      if (scope) {
        console.log(`✅ Scope: ${scopeData.name} - ${scopeData.description}`);
        created++;
      }
    } catch (error) {
      console.error(`❌ Error creating scope ${scopeData.name}:`, error.message);
      existing++;
    }
  }

  console.log(`\n📊 Summary:`);
  console.log(`   Created/Updated: ${created}`);
  console.log(`   Errors: ${existing}`);
  console.log('\n✨ Scope seeding completed!\n');
}

seedScopes()
  .catch((error) => {
    console.error('Fatal error during seeding:', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
