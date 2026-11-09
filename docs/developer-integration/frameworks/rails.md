# Rails

Uses [`ruby/bower_events.rb`](../../../examples/asvs-logging/ruby/bower_events.rb), which
needs only the standard library (Ruby 3.2 and later). Read the
[shared guidance](../asvs-logging-frameworks.md) first.

## Files

| File | Put it in | What it does |
|---|---|---|
| [`rails/app/middleware/bower_request_context.rb`](../../../examples/asvs-logging/ruby/rails/app/middleware/bower_request_context.rb) | `app/middleware/` | Rack middleware: request ID, trusted client IP, last-resort `application_error`; `BowerSecurity.emit(env, spec)` |
| [`rails/config/initializers/bower.rb`](../../../examples/asvs-logging/ruby/rails/config/initializers/bower.rb) | `config/initializers/` | Inserts the middleware first, adds `filter_parameters`, and hooks Devise/Warden sign-in, failure and logout |
| [`rails/app/controllers/concerns/bower_authorisation.rb`](../../../examples/asvs-logging/ruby/rails/app/controllers/concerns/bower_authorisation.rb) | `app/controllers/concerns/` | Records Pundit and CanCanCan denials as `authorisation_failure`, with the route pattern |

## Client IP

The middleware reads `REMOTE_ADDR` and applies `TRUSTED_PROXIES` itself. Don't use
`request.remote_ip` for security events: it trusts private address ranges by default, which
may include hosts you don't control.

## Authentication events

With Devise, Warden's `after_authentication`, `before_failure` and `before_logout` hooks send
`authentication_success`, `authentication_failure` and `session_terminated`. Without Devise,
call `BowerSecurity.emit(request.env, ...)` from your sessions controller after the
credential check.

## Application logs

`filter_parameters` keeps passwords, tokens, OTP codes, cookies and authorisation headers out
of Rails logs and error reports (ASVS 5.0 V16.2.5). For JSON logs, use your usual formatter;
JSON escapes CR and LF.

## What was run

The Rack middleware and helper were run in a plain Rack app
([`rack_app.ru`](../../../examples/asvs-logging/ruby/rack_app.ru), rack 3 with WEBrick)
against a local collector with the ASVS pack: all four test requests produced accepted events,
with nothing leaked. The Rails initialiser and concern were syntax-checked with `ruby -c`
only: Rails itself was not run. The helper matches the cross-language contract.
