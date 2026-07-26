# SQL Server source adapter instructions

Use EF Core LINQ only. Do not add free-form SQL, `FromSql`, `ExecuteSql`,
stored-procedure execution or schema mutation. Keep connections read-only,
queries bounded and cursor ordering deterministic. Cursor changes need restart,
overlap, concurrency and malformed-mapping tests. Never log connection strings
or source-row payloads.
