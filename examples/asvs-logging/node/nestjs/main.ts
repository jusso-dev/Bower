// main.ts: a minimal NestJS app using BowerModule. Run with check.sh (builds in a temp copy).
import 'reflect-metadata';
import { Body, Controller, ForbiddenException, Get, HttpCode, Module, Post, Req, UnauthorizedException } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { Request } from 'express';
import { BowerModule, BowerSecurity } from './bower.module.js';

@Controller()
class DemoController {
  constructor(private readonly bower: BowerSecurity) {}

  @Post('login')
  @HttpCode(204)
  login(@Req() req: Request, @Body() body: { username?: string; password?: string }) {
    if (`${body?.username}:${body?.password}` !== 'demo:demo-password') {
      this.bower.emit(req, { eventCategory: 'authentication', eventType: 'authentication_failure', eventAction: 'authentication.attempt',
        eventResult: 'failure', eventSeverity: 'low', reason: 'InvalidCredentials', actor: { username: body?.username ?? '' } });
      throw new UnauthorizedException('invalid credentials');
    }
    this.bower.emit(req, { eventCategory: 'authentication', eventType: 'authentication_success', eventAction: 'authentication.login',
      eventResult: 'success', actor: { userId: 'user-demo', username: body.username }, labels: { authMethod: 'password' } });
  }

  @Get('admin/users')
  admin(@Req() req: Request) {
    (req as any).user = { id: 'user-demo', role: 'member' };
    throw new ForbiddenException('forbidden'); // as a guard would
  }
}

@Module({ imports: [BowerModule], controllers: [DemoController] })
class AppModule {}

const app = await NestFactory.create(AppModule, { logger: ['error', 'warn'] });
await app.listen(Number(process.env.PORT ?? 3000), '127.0.0.1');
