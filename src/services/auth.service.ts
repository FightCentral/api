import jwt from "jsonwebtoken";
import { Prisma, User } from "@prisma/client";
import { hashPassword, verifyPassword } from "@/utils/crypto";
import { prisma } from "@/db";

async function registerUser(email: string, password: string, name: string) {
  let existingUser = await prisma.user.findUnique({ where: { email } });

  if (existingUser)
    throw new Error('User already exists');

  existingUser = await prisma.user.findUnique({ where: { name } });

  const hashedPassword = hashPassword(password);

  if (existingUser)
    throw new Error('Name already exists');

  const user = await prisma.user.create({
    data: {
      email,
      password: hashedPassword,
      method: 'EMAIL',
      name,
    },
  });

  return user;
}


async function loginUser(email: string, password: string) {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user)
    throw new Error('Invalid credentials');

  if (user.method !== 'EMAIL')
    throw new Error('Invalid credentials');

  const isValid = verifyPassword(password, user.password!);

  if (!isValid)
    throw new Error('Invalid credentials');

  const token = generateToken(user);
  return token;
}

const generateToken = (user: {id: string, email: string}): string => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET!, {
    expiresIn: '1h',
  });
}

export {
  registerUser,
  loginUser,
  generateToken
}
