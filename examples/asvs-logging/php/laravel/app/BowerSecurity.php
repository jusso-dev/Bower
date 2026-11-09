<?php

declare(strict_types=1);

namespace App;

use Bower\BowerEvents;
use Illuminate\Http\Request;

/** Builds and sends a Bower event with the request context. Never throws. */
final class BowerSecurity
{
    public static function emit(Request $request, array $spec): void
    {
        $app = ['name' => config('app.name'), 'environment' => config('app.env'), 'version' => '1.0.0'];
        $route = $request->route()?->uri();
        $event = BowerEvents::build($app, $spec + [
            'sourceIp' => $request->attributes->get('bower.client_ip'),
            'userAgent' => $request->userAgent(),
            'route' => $route !== null ? '/' . ltrim($route, '/') : $request->getPathInfo(),
            'request' => [
                'correlationId' => $request->attributes->get('bower.request_id'),
                'method' => $request->getMethod(),
                'path' => $request->getPathInfo(),
            ],
        ]);
        // Send after the response is flushed, so a slow collector never delays the user.
        app()->terminating(static fn () => BowerEvents::send($event));
    }
}
