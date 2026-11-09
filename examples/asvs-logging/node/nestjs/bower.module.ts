// NestJS: middleware for request context, a guard-failure filter and an auth event helper.
// Copy examples/asvs-logging/node/bower-events.mjs next to this file.
import { randomUUID } from 'node:crypto';
import {
  ArgumentsHost, BadRequestException, Catch, ExceptionFilter, ForbiddenException, HttpException, Injectable, MiddlewareConsumer,
  Module, NestMiddleware, NestModule,
} from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import type { NextFunction, Request, Response } from 'express';
import { BowerClient, buildEvent, clientIp } from './bower-events.mjs';

type BowerRequest = Request & { bowerRequestId?: string; bowerClientIp?: string; user?: { id?: string; role?: string } };

const trusted = (process.env.TRUSTED_PROXIES ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const app = { name: process.env.BOWER_APP_NAME ?? 'nestjs-example', environment: process.env.NODE_ENV ?? 'development', version: '1.0.0' };

/**
 * Request ID (honours a W3C traceparent) and trusted-proxy client IP, computed once per request.
 * Also called from emit(): Nest's body parser runs before module middleware, so a malformed
 * body reaches the exception filter without it. Leave app.set('trust proxy') off.
 */
function ensureContext(req: Request): BowerRequest {
  const r = req as BowerRequest;
  if (!r.bowerRequestId) {
    const traceparent = req.get('traceparent');
    r.bowerRequestId = traceparent?.length === 55 ? traceparent.slice(3, 35) : randomUUID();
    r.bowerClientIp = clientIp(req.socket.remoteAddress, req.get('x-forwarded-for'), trusted);
  }
  return r;
}

@Injectable()
export class BowerSecurity {
  private readonly client = new BowerClient();

  emit(req: Request, spec: Record<string, unknown>) {
    ensureContext(req);
    const event = buildEvent(app, {
      ...spec,
      sourceIp: (req as BowerRequest).bowerClientIp,
      userAgent: req.get('user-agent'),
      route: req.route?.path ?? req.path,
      request: { correlationId: (req as BowerRequest).bowerRequestId, method: req.method, path: req.originalUrl },
    });
    void this.client.send(event);
  }
}

@Injectable()
export class BowerContextMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    res.setHeader('x-request-id', ensureContext(req).bowerRequestId!);
    next();
  }
}

/** Guards throw ForbiddenException / UnauthorizedException; this records them (ASVS 5.0 V16.3.2). */
@Catch()
export class BowerExceptionFilter implements ExceptionFilter {
  constructor(private readonly bower: BowerSecurity) {}

  catch(error: unknown, host: ArgumentsHost) {
    const req = host.switchToHttp().getRequest<Request>();
    const res = host.switchToHttp().getResponse<Response>();
    const user = (req as BowerRequest).user;
    if (error instanceof ForbiddenException) {
      this.bower.emit(req, { eventCategory: 'authorisation', eventType: 'authorisation_failure', eventAction: 'authz.function',
        eventResult: 'denied', eventSeverity: 'medium', actor: { userId: user?.id, role: user?.role },
        target: { type: 'route', id: `${req.method} ${req.route?.path ?? req.path}` } });
    } else if (error instanceof BadRequestException) {
      // Malformed bodies and ValidationPipe rejections (V16.3.3). Never the submitted values.
      this.bower.emit(req, { eventCategory: 'application-security', eventType: 'input_validation_failure', eventAction: 'validation.reject',
        eventResult: 'failure', eventSeverity: 'low', reason: 'BadRequest' });
    } else if (!(error instanceof HttpException)) {
      this.bower.emit(req, { eventCategory: 'application-security', eventType: 'application_error', eventAction: 'error.unhandled',
        eventResult: 'failure', eventSeverity: 'medium', reason: 'UnhandledException',
        labels: { errorType: error instanceof Error ? error.name : 'Error' } });
    }
    // UnauthorizedException: authentication failures are emitted where the credential check
    // happens (AuthService), with the username; the filter doesn't know it.
    const status = error instanceof HttpException ? error.getStatus() : 500;
    res.status(status).json({ error: error instanceof HttpException && status < 500 ? error.message : 'internal error', requestId: (req as BowerRequest).bowerRequestId });
  }
}

@Module({
  providers: [BowerSecurity, { provide: APP_FILTER, useClass: BowerExceptionFilter }],
  exports: [BowerSecurity],
})
export class BowerModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(BowerContextMiddleware).forRoutes('*');
  }
}

// In AuthService.validateUser():
//   if (!ok) this.bower.emit(req, { eventCategory: 'authentication', eventType: 'authentication_failure',
//     eventAction: 'authentication.attempt', eventResult: 'failure', eventSeverity: 'low',
//     reason: 'InvalidCredentials', actor: { username } });
