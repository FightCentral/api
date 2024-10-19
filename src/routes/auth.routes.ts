import { Response, Router, Request } from "express";
import passport from "passport";
import { registerUser, loginUser, signInGoogle, logout } from "../services/auth.service";
import { User } from "@prisma/client";
import authenticateJWT from "@/middlewares/auth.middleware";

const router = Router();

const accessTokenDuration = 15 * 60 * 1000;
const refreshTokenDuration = 7 * 24 * 60 * 60 * 1000;

type CookiesOptions = {
  httpOnly: boolean;
  secure: boolean;
  maxAge: number;
  sameSite: 'strict' | 'lax' | 'none';
}

const cookieOptions = (maxAge: number): CookiesOptions => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  maxAge,
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
});

router.post('/register', async (req, res) => {
  try {
    const { token, refreshToken } = await registerUser(req.body.email, req.body.password, req.body.name);
    res.cookie('access_token', token, cookieOptions(accessTokenDuration));
    res.cookie('refresh_token', refreshToken, cookieOptions(refreshTokenDuration));
    res.json({ token, refreshToken });
  } catch (err: any) {
    res.status(400).json({ error: err?.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { token, refreshToken } = await loginUser(req.body.email, req.body.password);
    res.cookie('access_token', token, cookieOptions(accessTokenDuration));
    res.cookie('refresh_token', refreshToken, cookieOptions(refreshTokenDuration));
    res.json({ token, refreshToken });
  } catch (err: any) {
    res.status(400).json({ error: err?.message });
  }
});

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false }),
  async (req: Request, res: Response): Promise<void> => {
    try {
      if (!req.user) {
        res.status(400).json({ error: 'Invalid credentials' });
        return
      }

      const user = req.user as User;

      const { token, refreshToken } = await signInGoogle(user.email, user.name!);

      res.cookie('access_token', token, cookieOptions(accessTokenDuration));
      res.cookie('refresh_token', refreshToken, cookieOptions(refreshTokenDuration));
      res.json({ token, refreshToken });
    } catch (err: any) {
      res.status(400).json({ error: err?.message });
    }
  }
);

router.post('/logout', authenticateJWT, async (req: Request, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(400).json({ error: 'Already logged out' });
      return;
    }

    const user = req.user as User;
    await logout(user);

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.json({ message: 'Logged out' });
  } catch (err: any) {
    res.status(400).json({ error: err?.message });
  }
});

export default router
