-- AlterTable: per-client refresh token lifetime
ALTER TABLE "Client" ADD COLUMN "refreshTokenTtlDays" INTEGER NOT NULL DEFAULT 90;

-- AlterTable: bind refresh tokens to the OAuth client they were issued to
ALTER TABLE "RefreshToken" ADD COLUMN "clientId" TEXT;

-- CreateIndex
CREATE INDEX "RefreshToken_userId_clientId_idx" ON "RefreshToken"("userId", "clientId");

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;
