import { Router } from "express";
import { authenticateToken } from "../middlewares/auth.middleware";

const router = Router();

router.get('/dashboard', authenticateToken, (req, res) => {
  res.json({ message: `Welcome, ${JSON.stringify(req.user)}` });
});

export default router
