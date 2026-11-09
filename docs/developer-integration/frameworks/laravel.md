# Laravel

Uses [`php/BowerEvents.php`](../../../examples/asvs-logging/php/BowerEvents.php) (PHP 8.2 and
later, `ext-curl`). Read the [shared guidance](../asvs-logging-frameworks.md) first.

## Files

| File | What it does |
|---|---|
| [`laravel/app/Http/Middleware/BowerRequestContext.php`](../../../examples/asvs-logging/php/laravel/app/Http/Middleware/BowerRequestContext.php) | Request ID and trusted client IP. Prepend it in `bootstrap/app.php` |
| [`laravel/app/BowerSecurity.php`](../../../examples/asvs-logging/php/laravel/app/BowerSecurity.php) | `BowerSecurity::emit($request, $spec)`: adds context and sends after the response (`app()->terminating`) |
| [`laravel/app/Listeners/BowerAuthListener.php`](../../../examples/asvs-logging/php/laravel/app/Listeners/BowerAuthListener.php) | Laravel `Login`, `Failed`, `Lockout`, `Logout` and `PasswordReset` events |
| [`laravel/bootstrap/app.php`](../../../examples/asvs-logging/php/laravel/bootstrap/app.php) | Exception renderers for authorisation, validation (field names only) and rate limits, plus a last-resort reporter |
| [`laravel/config/logging-bower.php`](../../../examples/asvs-logging/php/laravel/config/logging-bower.php) | A JSON Monolog channel that drops secret-named context keys through the `tap` class [`laravel/app/Logging/DropSecretContext.php`](../../../examples/asvs-logging/php/laravel/app/Logging/DropSecretContext.php) |
| [`laravel/config/bower.php`](../../../examples/asvs-logging/php/laravel/config/bower.php) | `bower.trusted_proxies` from `TRUSTED_PROXIES`, so the list survives `php artisan config:cache` |

Register the listener with `Event::subscribe(BowerAuthListener::class)` in
`AppServiceProvider::boot()`.

## Client IP

The middleware reads `REMOTE_ADDR` and applies `bower.trusted_proxies` (from `TRUSTED_PROXIES`) itself, so a wide
`TrustProxies` setting can't change which address Bower records. Keep `TrustProxies` limited to
the same networks for everything else.

## Things to watch

- The `Failed` event's `credentials` array holds the submitted password. The listener reads
  only the email or username.
- `ValidationException` carries submitted values. The renderer sends only the field names.
- Set `APP_DEBUG=false` in production, so error pages stay generic (ASVS 5.0 V16.5.1).

## What was run

[`server.php`](../../../examples/asvs-logging/php/server.php) uses the same helper and event
calls without Laravel. It was run on PHP's built-in server (PHP 8.3) against a local collector
with the ASVS pack: all four test requests were accepted, with nothing leaked. The Laravel
files were linted with `php -l` only: Laravel itself was not run. The helper matches the
cross-language contract.
