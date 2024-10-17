import { Router } from "express";
import authenticateJWT from "../middlewares/auth.middleware";

const router = Router();

router.get('/dashboard', authenticateJWT, (req, res) => {
  console.log(req.cookies)
  res.json({ message: `Welcome, ${JSON.stringify(req.user)}` });
});

export default router
