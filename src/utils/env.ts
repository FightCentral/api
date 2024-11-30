import logger from "@/logger";

const getEnv = (key: string, fallback?: string): string => {
  if (!(key in process.env)) {
    logger.info(`${key} not found`);
    return fallback ?? "";
  }

  const value = process.env[key];
  if (!value) {
    logger.warn(`${key} is empty`);
    return fallback ?? "";
  }

  return value;
}

export default getEnv;