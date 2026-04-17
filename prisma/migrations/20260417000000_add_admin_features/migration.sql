-- AlterTable
ALTER TABLE "User" ADD COLUMN "isDisabled" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "event" TEXT NOT NULL,
    "userId" TEXT,
    "email" TEXT,
    "ip" TEXT,
    "data" JSONB,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AuditLog_timestamp_idx" ON "AuditLog"("timestamp");

-- CreateIndex
CREATE INDEX "AuditLog_event_idx" ON "AuditLog"("event");

-- CreateIndex
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");
