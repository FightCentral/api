import { Response, Router, Request, NextFunction, RequestHandler } from "express";
import passport from "passport";
import { registerUser, loginUser, generateToken, signInGoogle } from "../services/auth.service";
import { User } from "@prisma/client";

const router = Router();

router.post('/register', async (req, res) => {
  try {
    const { token, refreshToken } = await registerUser(req.body.email, req.body.password, req.body.name);
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 15 * 60 * 1000,
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.json({ token, refreshToken });
  } catch (err: any) {
    res.status(400).json({ error: err?.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { token, refreshToken } = await loginUser(req.body.email, req.body.password);
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 15 * 60 * 1000,
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.json({ token, refreshToken });
  } catch (err: any) {
    res.status(400).json({ error: err?.message });
  }
});

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false }),
  async (req: Request, res: Response): Promise<any> => {
    try {
      if (!req.user) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      const user = req.user as User;

      const { token, refreshToken } = await signInGoogle(user.email, user.name!);

      res.cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 15 * 60 * 1000,
      });
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.redirect('/api/dashboard');
    } catch (err: any) {
      res.status(400).json({ error: err?.message });
    }
  }
);

// router.post('/logout', async (req: Request, res: Response) => {
//   if (!req.user)
//     return res.status(400).json({ error: 'Already logged out' });

//   logout(user);
//   res.cookie('token', '', { httpOnly: true });
//   // delete req.user;
//   // delete refreshToken from db;
//   // clear cookie
//   const user = req.user as User;
//   await prisma.user.update({}).where({ id: user.id }).set({ refreshToken: null });
//   res.clearCookie('token');
//   res.json({ message: 'Logged out' });
// });

export default router
