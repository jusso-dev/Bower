# Go with log/slog

Uses [`go/bowerevents`](../../../examples/asvs-logging/go/bowerevents/bowerevents.go), which
needs only the standard library (Go 1.22 and later). Read the
[shared guidance](../asvs-logging-frameworks.md) first.

```go
bower := bowerevents.NewClient()                    // BOWER_COLLECTOR_URL, BOWER_INGEST_TOKEN
event := bowerevents.Build(app, bowerevents.Spec{EventCategory: "authentication", ...}, "", time.Now())
status := bower.Send(ctx, event)                    // 0 when the collector is unreachable
ip := bowerevents.ClientIP(peer, r.Header.Get("X-Forwarded-For"), trusted)
```

## The example server

[`cmd/server/main.go`](../../../examples/asvs-logging/go/cmd/server/main.go) is a `net/http`
service:

- `withContext` middleware sets the request ID (from `traceparent` or a UUID) and client IP
  in the request context, and returns `X-Request-Id`.
- `TRUSTED_PROXIES` is empty by default, so `X-Forwarded-For` is ignored until you name your
  proxies.
- `emit()` adds context and sends in a goroutine with its own two-second timeout, detached
  from the request.
- Sign-in, authorisation and malformed-body handlers each emit one event.

## slog

The application logger is `slog.NewJSONHandler` with a `ReplaceAttr` that replaces
`password`, `token`, `authorization`, `cookie` and `body` attributes and strips CR and LF from
string values. Bower events don't go through slog: they're security records, not log lines.

## What was run

`go vet`, `gofmt` and `go build` pass (Go 1.24). The server was run against a local collector
with the ASVS pack: all four test requests produced accepted events, a spoofed
`X-Forwarded-For` was ignored, and usernames were pseudonymised with no CRLF in the output.
The helper matches the cross-language contract.
