// proxy.ts (Next.js 16; middleware.ts before 16): request ID and the peer address for every
// request. It only sets headers; events are sent from route handlers and server actions.
import { NextResponse, type NextRequest } from 'next/server';

export function proxy(request: NextRequest) {
  const traceparent = request.headers.get('traceparent');
  const requestId = traceparent?.length === 55 ? traceparent.slice(3, 35) : crypto.randomUUID();
  const forwarded = new Headers(request.headers);
  forwarded.set('x-request-id', requestId);
  // Overwrite anything the client sent. BOWER_PEER_HEADER names the header your own proxy or
  // platform always sets to the verified peer address (for example x-real-ip). Unset, no peer
  // address is trusted and events carry no source IP.
  const peerHeader = process.env.BOWER_PEER_HEADER?.trim();
  forwarded.set('x-bower-peer', peerHeader ? (request.headers.get(peerHeader) ?? '') : '');
  const response = NextResponse.next({ request: { headers: forwarded } });
  response.headers.set('x-request-id', requestId);
  return response;
}

export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
