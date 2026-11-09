# ASVS logging examples

Optional per-framework examples for the `owasp-asvs-app-logging` pack. Not part of Bower's
build: no project here is in `Bower.sln`, and their packages are not Bower dependencies.

- Every helper (`node/bower-events.mjs`, `python/bower_events.py`, `go/bowerevents`,
  `ruby/bower_events.rb`, `php/BowerEvents.php`, `java/.../BowerEvents.java`,
  `aspnetcore-serilog/BowerEvents.cs`) must produce `contract/expected.jsonl` from
  `contract/cases.json`. Change all of them together, regenerate `expected.jsonl` with
  `python3 -I python/contract.py contract/cases.json > contract/expected.jsonl`, and run
  `./check.sh`. `AsvsExampleContractTests` checks `expected.jsonl` in the main CI.
- Helpers sanitise defensively (CR/LF, secret-named fields, query strings) but the collector
  is the redaction boundary. Never weaken the collector to fit an example.
- Client IP: trust `X-Forwarded-For` only from configured proxies; the default trusts none.
- No real tokens, tenant IDs or keys. The demo credential is `demo` / `demo-password`.
- Install framework dependencies in a temporary directory (the `check.sh` scripts do), never
  into the repository.
