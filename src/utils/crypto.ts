import { randomBytes, pbkdf2Sync } from "crypto"

const SALT_LENGTH = 16;
const KEY_LENGTH = 64;
const ITERATIONS = 100000;
const DIGEST = 'sha512';

const hashPassword = (password: string): string => {
  const salt = randomBytes(SALT_LENGTH).toString('hex');
  const derivedKey = pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST).toString('hex');
  return `${salt}:${derivedKey}`;
}

const verifyPassword = (password: string, hash: string): boolean => {
  const [salt, key] = hash.split(':');
  const derivedKey = pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST).toString('hex');
  return derivedKey === key;
}

export {
  hashPassword,
  verifyPassword
}