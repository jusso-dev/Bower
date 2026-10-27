# bower-source-syslog instructions

Rust port of `src/Bower.Source.Syslog` (the specification). Its `AGENTS.md` rules
apply unchanged: default deny through pack routes, loopback by default, TLS (or an
explicit override) beyond loopback, bounded frames, connections, idle time,
submissions and UDP buffer, no frame content in logs or status.

- Keep failure codes, record fields and order, event ids, limits, defaults and
  configuration messages identical to C#. `tests/fixtures/syslog-vectors.json` is
  shared with `SyslogSourceTests`; change both runtimes together.
- Lengths that C# measures in UTF-16 code units (record value limit) use
  `encode_utf16().count()` here.
- The sink is synchronous (the store is); listeners call it on the blocking pool.
- TCP reads the next frame only after the sink settled the current one; UDP drops
  and counts. Never move this into a scheduled job.
- `tests/fixtures/tls` holds TEST-ONLY keys; never use them outside tests.
