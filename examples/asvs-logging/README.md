# ASVS logging examples

Per-framework examples for the [ASVS logging pack](../../docs/security/asvs-logging-pack.md).
The guides are in [docs/developer-integration](../../docs/developer-integration/asvs-logging-frameworks.md).

| Directory | Frameworks | Helper |
|---|---|---|
| `node/` | Express, Fastify, NestJS, Next.js | `bower-events.mjs` (no dependencies) |
| `python/` | Flask, FastAPI, Django | `bower_events.py` (standard library) |
| `ruby/` | Rails, Rack | `bower_events.rb` (standard library) |
| `php/` | Laravel, plain PHP | `BowerEvents.php` (ext-curl) |
| `java/` | Spring Boot | `BowerEvents.java` (JDK only) |
| `go/` | `net/http` with `log/slog` | `bowerevents` (standard library) |
| `aspnetcore-serilog/` | ASP.NET Core with Serilog | `BowerEvents.cs` |

Try one against a throwaway local collector (nothing leaves the machine):

```bash
dotnet build Bower.sln -c Release
examples/asvs-logging/run-local-collector.sh        # prints BOWER_COLLECTOR_URL and BOWER_INGEST_TOKEN
# in another shell, with those two variables exported:
cd examples/asvs-logging/go && go run ./cmd/server
curl -X POST -d '{"Username":"demo","Password":"wrong"}' http://127.0.0.1:8080/login
bower tap --collector "$BOWER_COLLECTOR_URL" --stage redacted   # with BOWER_INGEST_TOKEN set
```

Check every helper against the shared contract:

```bash
examples/asvs-logging/check.sh
```
