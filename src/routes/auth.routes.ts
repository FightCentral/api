import { Response, Router, Request, NextFunction, RequestHandler } from "express";
import passport from "passport";
import { registerUser, loginUser, generateToken } from "../services/auth.service";

const router = Router();

router.post('/register', async (req, res) => {
  try {
    const { token, refreshToken } = await registerUser(req.body.email, req.body.password, req.body.name);
    res.cookie('token', token, { httpOnly: true });
    res.cookie('refreshToken', refreshToken, { httpOnly: true });
    res.json({ token, refreshToken });
  } catch (err: any) {
    res.status(400).json({ error: err?.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { token, refreshToken } = await loginUser(req.body.email, req.body.password);
    res.cookie('token', token, { httpOnly: true });
    res.cookie('refreshToken', refreshToken, { httpOnly: true });
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
      console.log(req)
      console.log(req.user)

      // loginUserGoogle(email, name);

      // if (!req.user)
      //   return res.status(400).json({ error: 'Invalid credentials' });

      // const user = req.user as User;

      // if (!user)
      //   return res.status(400).json({ error: 'Invalid credentials' });

      // const { token, refreshToken } = await loginUser(req.body.email, req.body.password);

      // res.cookie('token', token, { httpOnly: true });
      // res.cookie('refreshToken', refreshToken, { httpOnly: true });
    } catch (err: any) {
      res.status(400).json({ error: err?.message });
    }
  }
);

// router.post('/logout', async (req: Request, res: Response) => {
//   if (!req.user)
//     return res.status(400).json({ error: 'Already logged out' });
//   // delete req.user;
//   // delete refreshToken from db;
//   // clear cookie
//   res.cookie('token', '', { httpOnly: true });
//   const user = req.user as User;
//   await prisma.user.update({}).where({ id: user.id }).set({ refreshToken: null });
//   res.clearCookie('token');
//   res.json({ message: 'Logged out' });
// });

export default router
