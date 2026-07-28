# AWS source adapter instructions

Parse AWS security telemetry JSON only. Do not embed AWS credentials, call live
AWS APIs from unit tests, or log raw payloads. Keep parsers pure, bounded and
deterministic. Cursor and multi-account orchestration stay outside this library
until a dedicated collector host owns authentication.
