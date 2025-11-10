const { PrismaClient } = require('@prisma/client');
const argon2 = require('argon2');

const prisma = new PrismaClient();

async function main() {
  // Create test user
  const passwordHash = await argon2.hash('TestPassword123!', {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });

  const user = await prisma.user.upsert({
    where: { email: 'testuser@example.com' },
    update: {},
    create: {
      email: 'testuser@example.com',
      passwordHash,
    },
  });

  console.log('Created user:', user.email);

  // Create test client
  const clientSecret = await argon2.hash('test_secret_123', {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });

  const client = await prisma.client.upsert({
    where: { clientId: 'test_client_123' },
    update: {},
    create: {
      name: 'Test Application',
      clientId: 'test_client_123',
      clientSecret,
      redirectUris: ['http://localhost:5173/callback'],
    },
  });

  console.log('Created client:', client.name, client.clientId);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
