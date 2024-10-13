import { Response, Router, Request, NextFunction, RequestHandler } from "express";
import passport from "passport";
import { registerUser, loginUser, generateToken } from "../services/auth.service";
import { User } from "@prisma/client";
import RequestWithUser from "@/types/request";

const router = Router();

router.post('/register', async (req, res) => {
  try {
    const user = await registerUser(req.body.email, req.body.password, req.body.name);
    res.status(201).json({ message: 'User registered', userId: user.id });
  } catch (err: any) {
    res.status(400).json({ error: err?.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const token = await loginUser(req.body.email, req.body.password);
    res.cookie('token', token, { httpOnly: true });
    res.json({ token });
  } catch (err: any) {
    res.status(400).json({ error: err?.message });
  }
});

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false }),
  (req: Request, res: Response): any => {
    if (!req.user)
      return res.status(400).json({ error: 'Invalid credentials' });

    const user = req.user as User;

    if (!user)
      return res.status(400).json({ error: 'Invalid credentials' });

    const token = generateToken({id: user.id, email: user.email});
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/dashboard');

    return null;
  }
);

export default router
