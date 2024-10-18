import { randomBytes, createHash } from "crypto";
import argon2 from "argon2";

const hashPassword = async (password: string): Promise<string> => {
  return await argon2.hash(password);
}

const verifyPassword = async (password: string, hash: string): Promise<boolean> => {
  return await argon2.verify(hash, password);
}

const generateRefreshToken = (): string => {
  return randomBytes(64).toString('hex');
}

const hashToken = (token: string): string => {
  return createHash('sha256').update(token).digest('hex');
}

export {
  hashPassword,
  verifyPassword,
  generateRefreshToken,
  hashToken
}