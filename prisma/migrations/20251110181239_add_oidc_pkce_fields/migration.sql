-- AlterTable
ALTER TABLE "AuthCode" ADD COLUMN "nonce" TEXT,
ADD COLUMN "codeChallenge" TEXT,
ADD COLUMN "codeChallengeMethod" TEXT;
