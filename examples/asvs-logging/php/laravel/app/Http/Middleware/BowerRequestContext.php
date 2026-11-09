<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Bower\BowerEvents;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

/**
 * Request ID (honours a W3C traceparent) and trusted-proxy client IP for Bower events.
 * Register it first in bootstrap/app.php. It reads REMOTE_ADDR itself, so Laravel's
 * TrustProxies setting cannot widen which proxies are believed.
 */
final class BowerRequestContext
{
    public function handle(Request $request, Closure $next): Response
    {
        $traceparent = (string) $request->header('traceparent', '');
        $requestId = strlen($traceparent) === 55 ? substr($traceparent, 3, 32) : (string) Str::uuid();
        $trusted = array_values(array_filter(array_map('trim', explode(',', (string) config('bower.trusted_proxies', '')))));
        $request->attributes->set('bower.request_id', $requestId);
        $request->attributes->set('bower.client_ip', BowerEvents::clientIp(
            (string) $request->server('REMOTE_ADDR', ''),
            $request->header('X-Forwarded-For'),
            $trusted,
        ));
        $response = $next($request);
        $response->headers->set('X-Request-Id', $requestId);
        return $response;
    }
}
