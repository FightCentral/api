import { NextFunction } from "express";
import jwt from "jsonwebtoken";

const authenticateToken = (req: any, res: any, next: NextFunction) => {
  const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access Denied' });

  jwt.verify(token, process.env.JWT_SECRET!, (err: any, user: any) => {
    if (err) return res.status(403).json({ error: 'Invalid Token' });
    req.user = user;
    next();
  });
}

export {
  authenticateToken
};
