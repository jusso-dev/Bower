# Bower.DevSinks instructions

Local stand-in destinations for `src/Bower.AppHost` only: an NDJSON endpoint
(`BOWER_OUTPUT=http`), a Unix datagram socket (`BOWER_OUTPUT=ama-syslog`) and a read-only
view of the S3 emulator bucket. Never published or deployed.

- Hold records in memory only, bounded (`DevSinkStore.Capacity`, `MaximumRecordBytes`).
  Never write payloads to disk or logs.
- Parse exactly what the outputs write (`SyslogFrame` mirrors `AmaSyslogOutput`); keep
  `DevSinksTests` in step with output format changes.
- Synthetic data only. It is not a Splunk, rsyslog or S3 compatibility claim.
