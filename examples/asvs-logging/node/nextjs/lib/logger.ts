// lib/logger.ts: Pino for application logs (next.config: serverExternalPackages: ['pino']).
import pino from 'pino';

export const logger = pino({
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: { paths: ['req.headers.authorization', 'req.headers.cookie', '*.password', '*.token'], remove: true },
});
