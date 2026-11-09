// Pino with redaction for application logs. Security events go to Bower, not here.
import pino from 'pino';

export const logger = pino({
  // ISO UTC timestamps (ASVS 5.0 V16.2.2).
  timestamp: pino.stdTimeFunctions.isoTime,
  // Never write credentials, cookies or bodies (V16.2.5).
  redact: {
    paths: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]', '*.password', '*.token', 'body'],
    remove: true,
  },
  // pino writes JSON, which escapes CR and LF in values (V16.4.1).
});
