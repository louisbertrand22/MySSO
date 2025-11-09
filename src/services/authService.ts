import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import { PrismaClient } from "@prisma/client"

const prisma = new PrismaClient()
const JWT_SECRET = process.env.JWT_SECRET || "changeme"

// Hash du mot de passe
async function hashPassword(password: string) {
  return await bcrypt.hash(password, 10)
}

// Vérification du mot de passe
async function verifyPassword(password: string, hash: string) {
  return await bcrypt.compare(password, hash)
}

// Génération du token JWT
function generateAccessToken(userId: string) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "15m" })
}

// Génération du refresh token
function generateRefreshToken(userId: string) {
  return jwt.sign({ userId, type: "refresh" }, JWT_SECRET, { expiresIn: "7d" })
}

export {
  hashPassword,
  verifyPassword,
  generateAccessToken,
  generateRefreshToken,
  prisma
}
