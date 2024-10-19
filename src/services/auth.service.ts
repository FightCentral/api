import jwt from "jsonwebtoken";
import { User, Method } from "@prisma/client";
import { generateRefreshToken, hashPassword, hashToken, verifyPassword } from "@/utils/crypto";
import { prisma } from "@/db";

const registerUser = async (email: string, password: string, name: string): Promise<{ token: string, refreshToken: string, user: User }> => {
  const existingUserByEmail = await prisma.user.findUnique({ where: { email } });
  if (existingUserByEmail)
    throw new Error('User already exists');

  const existingUserByName = await prisma.user.findUnique({ where: { name } });
  if (existingUserByName)
    throw new Error('Name already exists');

  const hashedPassword = await hashPassword(password);

  if (existingUserByName)
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

  const isValid = await verifyPassword(password, user.password!);

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
  try {
    const user = await prisma.user.create({
      data: {
        email,
        name,
        method,
      },
    });
    return user;
  } catch (error: any) {
    if (error.code === 'P2002')
      throw new Error('Email already exists');

    throw error;
  }

}

const logout = async (user: User): Promise<void> => {
  const foundUser = await prisma.user.findUnique({ where: { email: user.email } });

  if (!foundUser)
    throw new Error('User not found');

  await prisma.user.update({
    where: { id: foundUser.id },
    data: { refreshToken: null },
  });
}

const generateToken = (user: { id: string, email: string }): string => {
  const jwtSecret = process.env.JWT_SECRET;

  if (!jwtSecret)
    throw new Error('JWT_SECRET is not defined');

  return jwt.sign({ id: user.id, email: user.email }, jwtSecret, {
    expiresIn: '15m',
  });
}

export {
  registerUser,
  loginUser,
  generateToken,
  signInGoogle,
  logout
}
