import jwt from "jsonwebtoken";
import { User, Method } from "@prisma/client";
import { generateRefreshToken, hashPassword, hashToken, verifyPassword } from "@/utils/crypto";
import { prisma } from "@/db";

const registerUser = async (email: string, password: string, name: string): Promise<{ token: string, refreshToken: string, user: User }> => {
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
      method: Method.EMAIL,
      name,
    },
  });

  const token = generateToken(user);
  const refreshToken = generateRefreshToken();
  const hashedRefreshToken = hashToken(refreshToken);

  await prisma.user.update({
    where: { id: user.id },
    data: { refreshToken: hashedRefreshToken },
  });

  return { token, refreshToken, user };
}


const loginUser = async (email: string, password: string): Promise<{ token: string, refreshToken: string, user: User }> => {
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user)
    throw new Error('Invalid credentials');

  if (user.method !== Method.EMAIL)
    throw new Error('Invalid credentials');

  const isValid = verifyPassword(password, user.password!);

  if (!isValid)
    throw new Error('Invalid credentials');

  const token = generateToken(user);
  const refreshToken = generateRefreshToken();
  const hashedRefreshToken = hashToken(refreshToken);

  await prisma.user.update({
    where: { id: user.id },
    data: { refreshToken: hashedRefreshToken },
  });

  return { token, refreshToken, user };
}

const signInGoogle = async (email: string, name: string): Promise<{ token: string, refreshToken: string, user: User }> => {
  let user: User | null = await prisma.user.findUnique({ where: { email } });

  if (!user)
    user = await createUser(email, name, Method.GOOGLE);

  if (user.method !== Method.GOOGLE)
    throw new Error('Signed up with email');

  const token = generateToken(user);
  const refreshToken = generateRefreshToken();
  const hashedRefreshToken = hashToken(refreshToken);

  await prisma.user.update({
    where: { id: user.id },
    data: { refreshToken: hashedRefreshToken },
  });

  return { token, refreshToken, user };
}

const createUser = async (email: string, name: string, method: Method): Promise<User> => {
  const user = await prisma.user.create({
    data: {
      email,
      name,
      method,
    },
  });

  return user;
}

// async function logout(user: User): Promise<void> {
//   const user = await prisma.user.findUnique({ where: { email } });

//   if (!user)
//     throw new Error('Invalid credentials');

//   if (user.method !== 'EMAIL')
//     throw new Error('Invalid credentials');

//   const isValid = verifyPassword(password, user.password!);

//   if (!isValid)
//     throw new Error('Invalid credentials');

//   const token = generateToken(user);
//   const refreshToken = generateRefreshToken();
//   const hashedRefreshToken = hashToken(refreshToken);

//   await prisma.user.update({
//     where: { id: user.id },
//     data: { refreshToken: hashedRefreshToken },
//   });

//   return { token, refreshToken };
// }

const generateToken = (user: { id: string, email: string }): string => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET!, {
    expiresIn: '15m',
  });
}

export {
  registerUser,
  loginUser,
  generateToken,
  signInGoogle
}
