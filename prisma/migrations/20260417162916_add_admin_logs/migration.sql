-- AlterTable
ALTER TABLE "Client" ALTER COLUMN "allowedScopes" SET DEFAULT ARRAY['openid', 'profile', 'email', 'username']::TEXT[];
