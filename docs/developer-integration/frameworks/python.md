# Django, Flask and FastAPI

All three use [`python/bower_events.py`](../../../examples/asvs-logging/python/bower_events.py),
which needs only the standard library (Python 3.10 and later). Read the
[shared guidance](../asvs-logging-frameworks.md) first.

```python
import bower_events
bower = bower_events.BowerClient()                  # BOWER_COLLECTOR_URL, BOWER_INGEST_TOKEN
event = bower_events.build_event(APP, {"eventCategory": "authentication", ...})
bower.send_async(event)                              # background thread, never raises
ip = bower_events.client_ip(peer, x_forwarded_for, TRUSTED)
```

[`logging_config.py`](../../../examples/asvs-logging/python/logging_config.py) is a `dictConfig`
for application logs: JSON lines, UTC, control characters stripped, and secret-named fields
replaced.

## Flask

[`flask_app.py`](../../../examples/asvs-logging/python/flask_app.py):

- `before_request` sets `g.request_id` and `g.client_ip`; `after_request` returns `X-Request-Id`.
- Don't add werkzeug's `ProxyFix` with a fixed hop count. `client_ip()` checks the peer
  against `TRUSTED_PROXIES` instead.
- `request.url_rule.rule` is the route template.
- `@app.errorhandler(Exception)` turns `BadRequest` into `input_validation_failure` and other
  exceptions into `application_error`, with a generic response.

## FastAPI

[`fastapi_app.py`](../../../examples/asvs-logging/python/fastapi_app.py):

- An HTTP middleware sets `request.state.request_id` and `client_ip`.
- **Run Uvicorn with `--no-proxy-headers`.** By default Uvicorn trusts `X-Forwarded-For` from
  `127.0.0.1` and `::1` and rewrites `request.client` before your code sees it. The example was tested
  both ways: with the flag, a spoofed header is ignored.
- Events go out as `BackgroundTasks`, after the response.
- Handlers for `RequestValidationError` and `Exception` send the validation and error events.

## Django

[`django_example/`](../../../examples/asvs-logging/python/django_example):

- [`bower_middleware.py`](../../../examples/asvs-logging/python/django_example/bower_middleware.py)
  has `BowerSecurityMiddleware` (request ID, client IP, `process_exception`) and receivers
  for Django's `user_logged_in`, `user_login_failed` and `user_logged_out` signals. The
  receivers read only the username: Django passes the password in `credentials`.
- Put the middleware first in `MIDDLEWARE`, and import the module from your
  `AppConfig.ready()` so the receivers connect.
- `request.resolver_match.route` is the route pattern.
- `USE_TZ = True` keeps timestamps in UTC.

`django_example/run.py` starts the example with an in-memory database and a demo user.

## What was run

Flask, FastAPI and Django were each run against a local collector with the ASVS pack (Flask
3.1.3, FastAPI 0.162.2 on Uvicorn 0.54.0, Django 6.1.3). All four test requests produced
accepted events, with no password, CRLF or spoofed address in the redacted output. The helper
matches the cross-language contract.
