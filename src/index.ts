import express from 'express';
import pino from 'pino-http'
import logger from './logger';
import dotenv from "dotenv"

dotenv.config()

const app = express();
const port = process.env.PORT || 8080;

app.use(pino({ logger }))

app.get('/health', (req, res) => {
  res.send({ status: "ok" });
});

app.listen(port, () => {
  return logger.info(`Express is listening at http://localhost:${port}`);
});