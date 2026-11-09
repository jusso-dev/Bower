# Database audit into Sentinel

ISM-1537 asks for security-relevant database events to be centrally logged: logons and
logoffs, new and privileged users, role and privilege changes, structure changes,
administrator actions, executable commands, query failures and access to important
content. ISM-1536 asks for queries from software, and the resulting errors, to be centrally
logged.

Use the database's native audit facility first. Then pick one of two paths into Sentinel:

1. **Native connector or diagnostic setting** for managed Azure databases. The records go to
   Microsoft's own tables (`AzureDiagnostics`, `SQLSecurityAuditEvents`, `CDB*`). This path
   is the fullest and needs no Bower configuration.
2. **Bower** for self-managed databases whose audit log is a file or a syslog stream. A
   signed pack parser maps the selected records to `database_audit` events, the
   [ASVS pack](../security/asvs-logging-pack.md) policy `BWR-PACK-ASVS-DB-AUDIT` selects them,
   and they land in `BowerSecurity_CL` beside the application events.

Bower doesn't ship a parser for any of these formats yet. The
[file tail](file-tail-source.md) and [syslog](syslog-source.md) sources plus a
[custom parser](../developer-integration/custom-log-parser.md) are the building blocks;
each format still needs its own signed parser, privacy fixtures and samples before it counts
as supported.

## The `database_audit` event

| Field | Value |
|---|---|
| `eventCategory` | `authentication` for logons, `administrative-activity` for DDL, DCL and privileged actions, `data-access` for reads, writes and errors |
| `eventAction` | `db.logon`, `db.logoff`, `db.logon_failure`, `db.ddl`, `db.dcl`, `db.privileged`, `db.sensitive_read`, `db.sensitive_write`, `db.query_error`, `db.audit_config` |
| `actor.username` | Database login (HMAC pseudonym after redaction) |
| `target.type`, `target.name` | `database`, `table` or `role`, and its name |
| `labels.dbEngine` | `postgresql`, `mysql`, `sqlserver`, `mongodb`, `cosmosdb` |
| `labels.dbStatementClass` | The audit class (`ROLE`, `DDL`, `READ`, `WRITE`, ...), never the statement |
| `source.ipAddress` | Client address from the audit record |

The statement text is removed by the pack privacy profile (`statement`, `queryText`,
`sqlText`). Keep statements in the native audit log, which has its own access controls, and
send Bower the class and outcome. That covers ISM-1537 without copying data values into
the SIEM. Where ISM-1536 needs the queries themselves centrally, use path 1 or forward the
native log with access restricted to database administrators.

Most applications connect with one shared login, so database audit records rarely name the
person. Join them to application events on time and `source.ipAddress`, or set the
application user in a session variable your audit facility records (for example
`application_name` in PostgreSQL).

## PostgreSQL: pgaudit

- Install the `pgaudit` extension and add it to `shared_preload_libraries`.
- Start with `pgaudit.log = 'ddl, role, misc_set'` and add `read, write` only for tables
  holding important content (use object auditing with `pgaudit.role` to scope them). Set
  `log_connections = on` and `log_disconnections = on` for logons and logoffs.
- Keep `pgaudit.log_parameter = off`: parameters carry data values.
- Self-managed: write the server log as `jsonlog` (PostgreSQL 15 and later) and tail it, or
  send it to syslog. Map `AUDIT:` records with a custom parser.
- Azure Database for PostgreSQL flexible server: set the `pgaudit.*` server parameters, then
  add a diagnostic setting with the `PostgreSQLLogs` category to the Sentinel workspace.
  Records arrive in `AzureDiagnostics` (`Category == "PostgreSQLLogs"`); audit lines have
  `AUDIT:` in `Message`.

## MySQL

Audit is not part of MySQL Community Server. Options:

| Option | Edition | Notes |
|---|---|---|
| MySQL Enterprise Audit | MySQL Enterprise Edition (commercial) | JSON output, per-account filters |
| Percona `audit_log_filter` | Percona Server for MySQL | A component in 8.4 (`component_audit_log_filter`); filters are JSON rules stored in the database |
| MariaDB `server_audit` | MariaDB; also loads into some MySQL versions | Events `CONNECT`, `QUERY_DDL`, `QUERY_DCL` keep volume down; check support on your MySQL version before relying on it |
| Azure Database for MySQL flexible server | Managed | Set `audit_log_enabled` and `audit_log_events`, then a diagnostic setting with `MySqlAuditLogs` |

Log `CONNECT` (including failures), DDL and DCL by default. Add `QUERY` only for specific
schemas, because full query logging records data values.

## SQL Server: SQL Server Audit

- Create a server audit to the Windows Security or Application log, or to a file, and a
  server audit specification with at least `FAILED_LOGIN_GROUP`, `SUCCESSFUL_LOGIN_GROUP`,
  `LOGOUT_GROUP`, `SERVER_ROLE_MEMBER_CHANGE_GROUP`, `DATABASE_ROLE_MEMBER_CHANGE_GROUP`,
  `SERVER_PERMISSION_CHANGE_GROUP`, `DATABASE_PERMISSION_CHANGE_GROUP`,
  `SCHEMA_OBJECT_CHANGE_GROUP` and `AUDIT_CHANGE_GROUP`. Add database audit specifications
  with `SELECT`, `INSERT`, `UPDATE` and `DELETE` on important tables only.
- Windows Security log target: the audit events are event ID 33205 in the Security channel.
  Bower's [Windows Event Log source](windows-event-log-source.md) can subscribe to them, but
  it needs a signed parser for 33205 (only 4625 ships today). The AMA with a Windows Security
  Events data collection rule is the native path.
- Azure SQL Database and Managed Instance: turn on auditing to the Sentinel workspace and add
  the *Azure SQL Databases* data connector. Check which table has your data: the connector's
  content queries `AzureDiagnostics | where Category == "SQLSecurityAuditEvents"`.
- `Bower.Source.SqlServer` reads an **application's own audit table** with a durable cursor.
  It doesn't read SQL Server Audit output.

## MongoDB

- Auditing is available in MongoDB Enterprise Advanced and on Atlas dedicated clusters (M10
  and up). **Community Edition has no auditing**, and neither do Atlas free and Flex tiers.
- Enterprise: set `auditLog.destination` to `file` with `format: JSON`, or to `syslog`, and
  a `filter` such as
  `{ atype: { $in: ["authenticate", "logout", "createUser", "dropUser", "grantRolesToUser", "revokeRolesFromUser", "createCollection", "dropCollection", "dropDatabase", "shutdown"] } }`.
  Add `authCheck` events only for important collections (it needs
  `auditAuthorizationSuccess`, which costs throughput).
- Atlas: enable database auditing in the project, then pull the audit logs through the Atlas
  Admin API or push them to your log pipeline. Atlas organisation and project activity is a
  separate feed.
- Community Edition: log authentication failures and administrative commands from the
  application or a proxy as `database_audit` events instead.

## Azure Cosmos DB

Cosmos DB has two log planes, and you need both:

| Plane | What it records | Category | Resource-specific table |
|---|---|---|---|
| Control plane | Account changes: keys, regions, networking, RBAC, throughput, containers created or deleted | `ControlPlaneRequests` | `CDBControlPlaneRequests` |
| Data plane | Every request against data: operation, status, caller, client IP, user agent, request charge | `DataPlaneRequests` | `CDBDataPlaneRequests` |

- Add a diagnostic setting to the Sentinel workspace in **resource-specific** mode for both
  categories. `DataPlaneRequests` is high volume; filter or sample it in a workspace
  transformation, or use the aggregated `DataPlaneRequests5M` categories where per-request
  detail isn't needed.
- Control plane records only capture changes made through Azure Resource Manager. Set
  `disableKeyBasedMetadataWriteAccess` to `true` on the account so containers and throughput
  can't be changed with account keys outside ARM, where they wouldn't be logged.
- Prefer Microsoft Entra ID and data-plane RBAC to account keys, so data-plane records
  identify a principal.
- The Azure Activity log, through the Sentinel Azure Activity connector, also records
  management operations on the account.

## ISM controls

| Control | Supported by |
|---|---|
| ISM-1537 | Native audit facilities above; `database_audit` events selected by `BWR-PACK-ASVS-DB-AUDIT`; native connectors |
| ISM-1536 | Native query logging through path 1; `db.query_error` events for failures |
| ISM-1405, ISM-1906, ISM-1907 | Central delivery to Sentinel and analysis there |

The organisation owns enabling and tuning the native audit facility, retention of the
native logs, restricting who can read statement text, and choosing a connector.
