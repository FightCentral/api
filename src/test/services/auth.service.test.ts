import { registerUser, loginUser, signInGoogle, logout, generateToken } from '@/services/auth.service';
import { prisma } from '@/db';
import {
  generateRefreshToken,
  hashPassword,
  hashToken,
  verifyPassword,
} from '@/utils/crypto';
import jwt from 'jsonwebtoken';
import { Method, User } from '@prisma/client';

jest.mock('@/db', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
  },
}));

jest.mock('@/utils/crypto', () => ({
  generateRefreshToken: jest.fn(),
  hashPassword: jest.fn(),
  hashToken: jest.fn(),
  verifyPassword: jest.fn(),
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(),
}));

process.env.JWT_SECRET = 'testsecret';

describe('Auth Service', () => {
  const mockUser: User = {
    id: 'user123',
    email: 'test@example.com',
    name: 'TestUser',
    password: 'hashedpassword',
    method: Method.EMAIL,
    refreshToken: null,
    googleId: null,
    createdAt: new Date(),
    emailVerifiedAt: null,
  };

  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe('registerUser', () => {
    it('should register a new user successfully', async () => {
      (prisma.user.findUnique as jest.Mock)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);

      (hashPassword as jest.Mock).mockResolvedValue('hashedpassword');

      (prisma.user.create as jest.Mock).mockResolvedValue(mockUser);

      (jwt.sign as jest.Mock).mockReturnValue('jwt_token');

      (generateRefreshToken as jest.Mock).mockReturnValue('refresh_token');
      (hashToken as jest.Mock).mockReturnValue('hashed_refresh_token');

      (prisma.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        refreshToken: 'hashed_refresh_token',
      });

      const result = await registerUser(
        'test@example.com',
        'password123',
        'TestUser'
      );

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { name: 'TestUser' },
      });
      expect(hashPassword).toHaveBeenCalledWith('password123');
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: {
          email: 'test@example.com',
          password: 'hashedpassword',
          method: Method.EMAIL,
          name: 'TestUser',
        },
      });
      expect(jwt.sign).toHaveBeenCalledWith(
        { id: mockUser.id, email: mockUser.email },
        'testsecret',
        { expiresIn: '15m' }
      );
      expect(generateRefreshToken).toHaveBeenCalled();
      expect(hashToken).toHaveBeenCalledWith('refresh_token');
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: { refreshToken: 'hashed_refresh_token' },
      });

      expect(result).toEqual({
        token: 'jwt_token',
        refreshToken: 'refresh_token',
        user: mockUser,
      });
    });

    it('should throw an error if user with email already exists', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValueOnce(mockUser);

      await expect(
        registerUser('test@example.com', 'password123', 'TestUser')
      ).rejects.toThrow('User already exists');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });
      expect(prisma.user.findUnique).toHaveBeenCalledTimes(1);
    });

    it('should throw an error if user with name already exists', async () => {
      (prisma.user.findUnique as jest.Mock)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(mockUser);

      await expect(
        registerUser('new@example.com', 'password123', 'TestUser')
      ).rejects.toThrow('Name already exists');

      expect(prisma.user.findUnique).toHaveBeenNthCalledWith(1, {
        where: { email: 'new@example.com' },
      });
      expect(prisma.user.findUnique).toHaveBeenNthCalledWith(2, {
        where: { name: 'TestUser' },
      });
    });
  });

  describe('loginUser', () => {
    it('should login user successfully', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

      (verifyPassword as jest.Mock).mockResolvedValue(true);

      (jwt.sign as jest.Mock).mockReturnValue('jwt_token');
      (generateRefreshToken as jest.Mock).mockReturnValue('refresh_token');
      (hashToken as jest.Mock).mockReturnValue('hashed_refresh_token');

      (prisma.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        refreshToken: 'hashed_refresh_token',
      });

      const result = await loginUser('test@example.com', 'password123');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });
      expect(verifyPassword).toHaveBeenCalledWith(
        'password123',
        mockUser.password
      );
      expect(jwt.sign).toHaveBeenCalledWith(
        { id: mockUser.id, email: mockUser.email },
        'testsecret',
        { expiresIn: '15m' }
      );
      expect(generateRefreshToken).toHaveBeenCalled();
      expect(hashToken).toHaveBeenCalledWith('refresh_token');
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: { refreshToken: 'hashed_refresh_token' },
      });

      expect(result).toEqual({
        token: 'jwt_token',
        refreshToken: 'refresh_token',
        user: mockUser,
      });
    });

    it('should throw error if user does not exist', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(
        loginUser('nonexistent@example.com', 'password123')
      ).rejects.toThrow('Invalid credentials');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'nonexistent@example.com' },
      });
    });

    it('should throw error if user method is not EMAIL', async () => {
      const googleUser = { ...mockUser, method: Method.GOOGLE };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(googleUser);

      await expect(
        loginUser('test@example.com', 'password123')
      ).rejects.toThrow('Invalid credentials');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });
    });

    it('should throw error if password is invalid', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      await expect(
        loginUser('test@example.com', 'wrongpassword')
      ).rejects.toThrow('Invalid credentials');

      expect(verifyPassword).toHaveBeenCalledWith(
        'wrongpassword',
        mockUser.password
      );
    });
  });

  describe('signInGoogle', () => {
    it('should sign in existing Google user successfully', async () => {
      const existingUser = { ...mockUser, method: Method.GOOGLE };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(existingUser);

      (jwt.sign as jest.Mock).mockReturnValue('jwt_token_google');
      (generateRefreshToken as jest.Mock).mockReturnValue('refresh_token_google');
      (hashToken as jest.Mock).mockReturnValue('hashed_refresh_token_google');

      (prisma.user.update as jest.Mock).mockResolvedValue({
        ...existingUser,
        refreshToken: 'hashed_refresh_token_google',
      });

      const result = await signInGoogle('google@example.com', 'GoogleUser');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'google@example.com' },
      });
      expect(jwt.sign).toHaveBeenCalledWith(
        { id: existingUser.id, email: existingUser.email },
        'testsecret',
        { expiresIn: '15m' }
      );
      expect(generateRefreshToken).toHaveBeenCalled();
      expect(hashToken).toHaveBeenCalledWith('refresh_token_google');
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: existingUser.id },
        data: { refreshToken: 'hashed_refresh_token_google' },
      });

      expect(result).toEqual({
        token: 'jwt_token_google',
        refreshToken: 'refresh_token_google',
        user: existingUser,
      });
    });

    it('should create and sign in new Google user successfully', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValueOnce(null);
      const newUser = { ...mockUser, method: Method.GOOGLE };
      (prisma.user.create as jest.Mock).mockResolvedValue(newUser);

      (jwt.sign as jest.Mock).mockReturnValue('jwt_token_new_google');
      (generateRefreshToken as jest.Mock).mockReturnValue('refresh_token_new_google');
      (hashToken as jest.Mock).mockReturnValue('hashed_refresh_token_new_google');

      (prisma.user.update as jest.Mock).mockResolvedValue({
        ...newUser,
        refreshToken: 'hashed_refresh_token_new_google',
      });

      const result = await signInGoogle('newgoogle@example.com', 'NewGoogleUser');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'newgoogle@example.com' },
      });
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: {
          email: 'newgoogle@example.com',
          name: 'NewGoogleUser',
          method: Method.GOOGLE,
        },
      });
      expect(jwt.sign).toHaveBeenCalledWith(
        { id: newUser.id, email: newUser.email },
        'testsecret',
        { expiresIn: '15m' }
      );
      expect(generateRefreshToken).toHaveBeenCalled();
      expect(hashToken).toHaveBeenCalledWith('refresh_token_new_google');
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: newUser.id },
        data: { refreshToken: 'hashed_refresh_token_new_google' },
      });

      expect(result).toEqual({
        token: 'jwt_token_new_google',
        refreshToken: 'refresh_token_new_google',
        user: newUser,
      });
    });

    it('should throw error if existing user signed up with email', async () => {
      const existingEmailUser = { ...mockUser, method: Method.EMAIL };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(existingEmailUser);

      await expect(
        signInGoogle('test@example.com', 'TestUser')
      ).rejects.toThrow('Signed up with email');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });
    });

    it('should throw error if Google account has no email', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValueOnce(null);
      (prisma.user.create as jest.Mock).mockImplementation(() => {
        throw new Error('No email associated with this account');
      });

      await expect(
        signInGoogle('', 'NoEmailUser')
      ).rejects.toThrow('No email associated with this account');
    });
  });

  describe('logout', () => {
    it('should logout user successfully', async () => {
      const userToLogout = { ...mockUser };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(userToLogout);
      (prisma.user.update as jest.Mock).mockResolvedValue({
        ...userToLogout,
        refreshToken: null,
      });

      await logout(userToLogout);

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: userToLogout.email },
      });
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: userToLogout.id },
        data: { refreshToken: null },
      });
    });

    it('should throw error if user not found', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(logout(mockUser)).rejects.toThrow('User not found');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: mockUser.email },
      });
    });
  });

  describe('generateToken', () => {
    it('should generate a JWT token', () => {
      (jwt.sign as jest.Mock).mockReturnValue('jwt_token');

      const token = generateToken({ id: mockUser.id, email: mockUser.email });

      expect(jwt.sign).toHaveBeenCalledWith(
        { id: mockUser.id, email: mockUser.email },
        'testsecret',
        { expiresIn: '15m' }
      );
      expect(token).toBe('jwt_token');
    });
  });
});
