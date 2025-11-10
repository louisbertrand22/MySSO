/**
 * Update Existing Clients with Default Scopes
 * This script updates existing clients to have default allowed scopes
 */

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function updateClients() {
  console.log('🔄 Updating existing clients with default allowed scopes...\n');

  const clients = await prisma.client.findMany();
  
  if (clients.length === 0) {
    console.log('ℹ️  No existing clients found.\n');
    return;
  }

  const defaultScopes = ['openid', 'profile', 'email'];

  for (const client of clients) {
    // Only update if allowedScopes is empty or undefined
    if (!client.allowedScopes || client.allowedScopes.length === 0) {
      await prisma.client.update({
        where: { id: client.id },
        data: { allowedScopes: defaultScopes },
      });
      console.log(`✅ Updated client: ${client.name} (${client.clientId})`);
    } else {
      console.log(`⏭️  Skipped client: ${client.name} (${client.clientId}) - already has scopes`);
    }
  }

  console.log('\n✨ Client update completed!\n');
}

updateClients()
  .catch((error) => {
    console.error('Error updating clients:', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
