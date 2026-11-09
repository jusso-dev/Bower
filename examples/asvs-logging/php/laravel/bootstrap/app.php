<?php

// bootstrap/app.php (Laravel 11 and later): the parts that wire Bower in.

use App\BowerSecurity;
use App\Http\Middleware\BowerRequestContext;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__ . '/../routes/web.php', api: __DIR__ . '/../routes/api.php')
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->prepend(BowerRequestContext::class);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // Authorisation failures (Gate and policies) (ASVS 5.0 V16.3.2, V8.2.1).
        $exceptions->render(function (AccessDeniedHttpException|AuthorizationException $e, Request $request) {
            BowerSecurity::emit($request, ['eventCategory' => 'authorisation', 'eventType' => 'authorisation_failure',
                'eventAction' => 'authz.function', 'eventResult' => 'denied', 'eventSeverity' => 'medium',
                'actor' => ['userId' => (string) $request->user()?->getAuthIdentifier()],
                'target' => ['type' => 'route', 'id' => $request->route()?->getName() ?? $request->getPathInfo()]]);
            return null; // keep Laravel's normal 403 response
        });
        $exceptions->render(function (ValidationException $e, Request $request) {
            // Field names only: never the submitted values.
            BowerSecurity::emit($request, ['eventCategory' => 'application-security', 'eventType' => 'input_validation_failure',
                'eventAction' => 'validation.reject', 'eventResult' => 'failure', 'eventSeverity' => 'low',
                'reason' => 'ValidationFailed', 'attributes' => ['fields' => array_keys($e->errors())]]);
            return null;
        });
        $exceptions->render(function (TooManyRequestsHttpException $e, Request $request) {
            BowerSecurity::emit($request, ['eventCategory' => 'api-security', 'eventType' => 'anti_automation_triggered',
                'eventAction' => 'ratelimit.exceeded', 'eventResult' => 'denied', 'eventSeverity' => 'low', 'reason' => 'RateLimited']);
            return null;
        });
        // Last resort (V16.3.4, V16.5.4): every other reported exception. Laravel already
        // returns a generic page when APP_DEBUG=false (V16.5.1).
        $exceptions->report(function (Throwable $e) {
            if (app()->bound('request')) {
                BowerSecurity::emit(request(), ['eventCategory' => 'application-security', 'eventType' => 'application_error',
                    'eventAction' => 'error.unhandled', 'eventResult' => 'failure', 'eventSeverity' => 'medium',
                    'reason' => 'UnhandledException', 'labels' => ['errorType' => (new ReflectionClass($e))->getShortName()]]);
            }
        });
    })
    ->create();
