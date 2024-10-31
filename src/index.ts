import express, { Application } from 'express';
import helmet from 'helmet';
import pino from 'pino-http'
import logger from './logger';
import dotenv from "dotenv"
import cookieParser from "cookie-parser"
import passport from "passport"
import cors from "cors"

import authRoutes from "./routes/auth.routes"
import protectedRoutes from "./routes/protected.routes";

import { googleStrategy, jwtStrategy } from './services/passport.service';

dotenv.config()

const app: Application = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(pino({ logger }))

app.use(passport.initialize());
passport.use(jwtStrategy);
passport.use(googleStrategy);

app.use('/auth', authRoutes);
app.use('/api', protectedRoutes);

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.get('/health', (req, res) => {
  res.send({ status: "ok" });
});

const port = process.env.PORT || 8080;

app.listen(port, () => {
  return logger.info(`Express is listening at http://localhost:${port}`);
});