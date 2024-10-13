import express from 'express';
import pino from 'pino-http'
import logger from './logger';
import dotenv from "dotenv"
import cookieParser from "cookie-parser"
import passport from "passport"

dotenv.config()

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(pino({ logger }))

app.use(passport.initialize());

import authRoutes from "./routes/auth.routes"
import protectedRoutes from "./routes/protected.routes";

app.use('/auth', authRoutes);
app.use('/api', protectedRoutes);

const port = process.env.PORT || 8080;

app.listen(port, () => {
  return logger.info(`Express is listening at http://localhost:${port}`);
});

app.get('/health', (req, res) => {
  res.send({ status: "ok" });
});