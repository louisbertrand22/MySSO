-- AlterTable
ALTER TABLE "Client" ADD COLUMN     "allowedScopes" TEXT[] DEFAULT ARRAY['openid', 'profile', 'email']::TEXT[];

-- CreateTable
CREATE TABLE "Scope" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Scope_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Scope_name_key" ON "Scope"("name");

-- CreateIndex
CREATE INDEX "Scope_name_idx" ON "Scope"("name");
