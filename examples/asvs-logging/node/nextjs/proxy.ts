// proxy.ts (Next.js 16; middleware.ts before 16): request ID and the peer address for every
// request. It only sets headers; events are sent from route handlers and server actions.
import { NextResponse, type NextRequest } from 'next/server';

export function proxy(request: NextRequest) {
  const traceparent = request.headers.get('traceparent');
  const requestId = traceparent?.length === 55 ? traceparent.slice(3, 35) : crypto.randomUUID();
  const forwarded = new Headers(request.headers);
  forwarded.set('x-request-id', requestId);
  // Overwrite anything the client sent. Set from the platform's verified peer address: on a
  // self-hosted Node server behind your own proxy, configure the proxy to set x-real-ip; on a
  // managed platform use its documented client IP header.
  forwarded.set('x-bower-peer', request.headers.get('x-real-ip') ?? '');
  const response = NextResponse.next({ request: { headers: forwarded } });
  response.headers.set('x-request-id', requestId);
  return response;
}

export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
