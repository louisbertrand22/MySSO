const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  const watchClient = await prisma.client.upsert({
    where: { clientId: 'watch-asset-app' },
    update: {},
    create: {
      clientId: 'watch-asset-app',
      clientSecret: 'super-secret-watch-key-2026', // Idéalement à hasher avec Argon2
      name: 'WatchAsset Investment Tracker',
      redirectUris: ['http://localhost:3001/auth/callback'],
      allowedScopes: ['openid', 'profile', 'email'],
    },
  });

  console.log('Client WatchAsset créé avec succès :', watchClient);
}

main()
  .catch((e) => console.error(e))
  .finally(async () => await prisma.$disconnect());