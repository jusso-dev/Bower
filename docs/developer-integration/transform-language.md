# Transform language reference

A small, safe language for reshaping one parsed JSON record inside a signed pack
parser, before semantic mapping, redaction and policy. It is total (every program
terminates), side-effect free, deterministic and bounded. Design and rationale:
[decision record](../architecture/transform-language.md).

## Where transforms live

In the parser document's `runtime` mapping, next to `match` and `fields`:

```json
"runtime": {
  "applicationName": "linux-sshd",
  "environment": "production",
  "eventCategory": "authentication",
  "eventType": "authentication_failure",
  "eventAction": "authentication.attempt",
  "eventResult": "failure",
  "transforms": [
    ".m = regex_extract(.MESSAGE, '^Failed (?<method>password|publickey) for (?:invalid user )?(?<user>[^ ]+) from (?<ip>[0-9A-Fa-f.:]+) port [0-9]+')",
    "if .SYSLOG_IDENTIFIER == \"sshd\" && .m.user != null { .result = \"failure\" } else { .result = \"ignored\" }",
    ".user = .m.user",
    ".source_ip = .m.ip",
    ".reason = lookup(\"methods\", .m.method)",
    "del(.m)",
    ".timestamp = parse_timestamp(.__REALTIME_TIMESTAMP, \"unix_microseconds\")"
  ],
  "tables": { "methods": { "password": "InvalidCredentials", "publickey": "PublicKeyRejected" } },
  "match": { "result": "failure" },
  "fields": { "eventId": "__CURSOR", "timeGenerated": "timestamp", "actor.username": "user",
              "source.ipAddress": "source_ip", "eventOutcomeReason": "reason" }
}
```

Full example: [`packs/linux-journald-ssh`](../../packs/linux-journald-ssh).

Order at intake: parse the JSON record, run the transforms, apply `match` and `fields`
to the transformed record, then the privacy engine redacts, policy selects and the queue
persists. The semantic mapping still reads only top-level **string** fields, so convert
other results with `to_string`.

The parser file is listed in the signed pack manifest, so its transforms are covered by
the signature. Packs are validated at `bower pack build` (an invalid program cannot be
signed) and again at load. `bower pack test` and build run raw samples through the
transforms; a transform failure is decision `quarantine`, and `expectFields` asserts the
redacted output of a successful run ([field assertions](../deployment/packs.md#field-assertions-expectfields)).
Management custom-log preview
validates transforms but never runs them: previews show source fields under the
unchanged privacy floor.

## Grammar

Each array element is one statement. Whitespace is space, tab, CR and LF.

```ebnf
statement   = assignment | delete | rename | conditional ;
assignment  = target "=" expression ;
delete      = "del" "(" target ")" ;
rename      = "rename" "(" target "," target ")" ;
conditional = "if" expression block [ "else" ( block | conditional ) ] ;
block       = "{" statement { ";" statement } [ ";" ] "}" ;
target      = path ;                       (* exactly one segment *)

expression  = and { "||" and } ;
and         = unary { "&&" unary } ;
unary       = "!" unary | comparison ;
comparison  = primary [ ( "==" | "!=" | "<" | "<=" | ">" | ">=" ) primary ] ;
primary     = string | integer | "true" | "false" | "null" | path
            | identifier "(" [ expression { "," expression } ] ")"
            | "(" expression ")" ;

path        = "." segment { "." segment } ;
segment     = bare | quoted ;
bare        = ( letter | digit | "_" | "@" | "-" ) { letter | digit | "_" | "@" | "-" } ;
quoted      = '"' text '"' ;               (* for names containing "." or spaces *)
string      = '"' { char | escape } '"'    (* escapes: \" \\ \n \r \t *)
            | "'" { char } "'" ;           (* raw: no escapes; handy for regexes *)
integer     = [ "-" ] ( "0" | nonzero { digit } ) ;   (* signed 64-bit *)
identifier  = ( letter | "_" ) { letter | digit | "_" } ;
```

`.a.b` reads field `b` inside object `a`; `."a.b"` reads the top-level field named
`a.b`. Control characters are not allowed inside string literals.

## Values and semantics

Values: `null`, booleans, signed 64-bit integers, strings, arrays, objects, and opaque
numbers (any JSON number that is not a plain integer, such as `1.5` or `1E3`; it keeps
its source text and only `to_string` or copying can use it).

- Reading a missing field, or reading through a non-object, gives `null`.
- Assignment replaces a field in place or appends a new one; assigning `null` stores
  JSON `null`. `del` removes a field if present. `rename(.a, .b)` moves `a` to `b`
  (replacing `b` in place if it exists); it does nothing when `a` is absent.
- Conditions and `!`, `&&`, `||` accept booleans; `null` is false; anything else is a
  type error. `&&`, `||` and `coalesce` short-circuit. Evaluation is left to right.
- `==` and `!=` compare null, booleans, integers and strings (different types are
  unequal). Ordering (`<` and so on) compares integers only; a `null` operand gives
  `false`. Arrays, objects and opaque numbers in a comparison are a type error.
- Strings are sequences of Unicode scalar values. Case mapping and `trim` are ASCII
  only. Comparisons and searches are ordinal.

## Functions

The allow-list is fixed; nothing else can be called. Unless noted, a `null` first
argument returns `null`, other arguments must be strings, and any other type is a type
error.

| Function | Result |
|---|---|
| `lower(s)`, `upper(s)` | ASCII case mapping |
| `trim(s)` | Removes ASCII whitespace (space, `\t \n \v \f \r`) from both ends |
| `replace(s, from, to)` | Replaces every non-overlapping `from` (non-empty) |
| `split(s, sep [, limit])` | Array of parts; `sep` non-empty; `limit` an integer literal 1 to 256 (last part keeps the rest) |
| `join(array, sep)` | Joins string elements |
| `at(array, index)` | Element, negative from the end; out of range gives `null` |
| `concat(a, b, ...)` | 2 to 8 strings; any `null` gives `null` |
| `contains(s, x)`, `starts_with(s, x)`, `ends_with(s, x)` | Boolean |
| `coalesce(a, b, ...)` | First non-null of 2 to 8 arguments, evaluated lazily |
| `lookup("table", key)` | Value from `runtime.tables`, or `null`; table name must be a literal |
| `regex_match(s, 'pattern')` | Boolean; pattern must be a literal |
| `regex_extract(s, 'pattern')` | Object of named groups (`null` for a group that did not take part), or `null` when there is no match; needs at least one named group |
| `parse_timestamp(v, "format")` | Canonical UTC text `yyyy-MM-ddTHH:mm:ss[.fffffff]Z`, or `null` |
| `to_string(v)` | Strings unchanged; integers in decimal; `true`/`false`; opaque numbers as source text |
| `to_int(v)` | Integer from `[+-]digits` text (else `null`); opaque numbers give `null` |
| `to_bool(v)` | From `true`/`false` in any ASCII case (else `null`) |
| `now()` | The explicit evaluation time, canonical UTC text |

Timestamp formats (all exact; anything else gives `null`):

| Format | Accepts |
|---|---|
| `rfc3339` | `YYYY-MM-DD` `T`, `t` or space `hh:mm:ss`, optional 1 to 9 fraction digits (truncated to 100 ns), `Z`, `z` or `±hh:mm` |
| `rfc3164` | `Mmm dd hh:mm:ss` or `Mmm  d hh:mm:ss` in UTC. The year is the evaluation year, or the year before if that would be more than one day after the evaluation time |
| `common_log` | `dd/Mmm/yyyy:hh:mm:ss ±hhmm` |
| `unix_seconds`, `unix_milliseconds`, `unix_microseconds` | Integer or `-?digits` text |

Years must stay within 0001 to 9999 after conversion to UTC. Month names are English,
case-sensitive.

### Regular expressions

Bower's own linear-time engine, identical in both runtimes. Supported: literals;
`.` (any scalar except newline); classes `[...]`, `[^...]` with ranges; `\d \w \s`
and `\D \W \S` (ASCII definitions); escapes `\t \n \r` and `\` before any of
`\ . * + ? ( ) [ ] { } | ^ $ - /`; `^` and `$` (start and end of the whole value);
alternation; non-capturing `(?:...)` and named `(?<name>...)` groups; `* + ?`,
`{n}`, `{n,}`, `{n,m}` (n, m at most 100), each optionally lazy with `?`.
Not supported: plain `(...)` groups, backreferences, lookaround, flags, Unicode
classes, unescaped `{ } ]`. Matching is a leftmost-first search: alternatives and
repeats prefer what a backtracking engine would.

## Sensitivity rules

Validation tracks where values come from, using the parser's declared `fields`:

- Fields declared `sensitive: true`, and any field the parser does not declare, start
  sensitive. Declare every input field a transform reads; undeclared input is treated
  as sensitive.
- A value is sensitive if it reads a sensitive field. Everything written inside an `if`
  whose condition reads a sensitive field is sensitive too.
- A field declared `sensitive: false` can never receive a sensitive value or be changed
  under a sensitive condition (`transform-sensitive-flow`).
- A field declared sensitive can be normalised in place but never deleted or renamed
  (`transform-sensitive-field`).
- Write targets must be valid field names and cannot be credential-like (`password`,
  `token`, `secret`, `cookie`, ...), `security`, `security.*` or start with `bower`
  (`transform-invalid-target`). Reading a credential-like field fails with
  `transform-prohibited-field`.

These rules are defence in depth. Whatever a transform produces, only the allowlisted
semantic mapping reaches the envelope, and the privacy engine redacts the envelope
before it is persisted.

## Limits

| Limit | Value |
|---|---|
| Statements per program | 1 to 64 |
| Statement length | 1,024 UTF-16 units |
| Syntax nodes per statement | 256 |
| Nesting of parentheses, calls and `!` | 16 |
| Nested `if` | 4 |
| Function arguments | 8 |
| Regex literals per program | 16 |
| Regex pattern | 512 UTF-16 units, 2,048 compiled instructions, 32 named groups, repeat counts up to 100 |
| Tables | 16 tables, 1,024 entries each, 4,096 in total; names `[A-Za-z_][A-Za-z0-9_-]*` up to 64; keys 1 to 256 and values up to 1,024 UTF-16 units |
| Steps per record | 1,000,000 (one per statement and expression node, plus regex VM steps) |
| String value | 32,768 UTF-16 units |
| Array | 256 elements |
| Record | 128 top-level fields; input nesting 16 |
| Output | 65,536 UTF-16 units of canonical JSON |

## Error codes

Messages are `Transform statement N column C: CODE.` (N is 1-based, C is the 1-based
UTF-16 column) or `Transform program: CODE.`. They never contain statement text or
record values.

| Code | Meaning |
|---|---|
| `transform-syntax` | Not valid grammar |
| `transform-limit-exceeded` | A static limit above |
| `transform-unknown-function` | Function not in the allow-list |
| `transform-arity` | Wrong number of arguments |
| `transform-invalid-argument` | A literal argument is required or invalid (format, separator, limit, table or pattern) |
| `transform-invalid-regex` | Pattern outside the supported subset or over its limits |
| `transform-unknown-table` | `lookup` names an undeclared table |
| `transform-invalid-table` | `runtime.tables` breaks a table limit |
| `transform-invalid-target` | Write target not allowed |
| `transform-prohibited-field` | Reads a credential-like field |
| `transform-sensitive-field` | Deletes or renames a sensitive field |
| `transform-sensitive-flow` | Sensitive value or condition reaches a non-sensitive field |
| `transform-type-error` | Run time: wrong value type |
| `transform-budget-exceeded` | Run time: step budget spent |
| `transform-size-exceeded` | Run time: string, array, record or output too large |
| `transform-input-invalid` | Record cannot be represented; at intake this is reported as `pack-record-invalid` |

Run-time failures quarantine the record: the collector returns HTTP 400 with decision
`quarantine` and the code as the only reason, persists nothing, and counts the event in
`/v1/status` selection metrics under stage `transform`.

## Determinism

Output is canonical JSON: no whitespace, record key order, integers in decimal, opaque
numbers as written, only `"`, `\` and control characters escaped. The same record,
program and evaluation time produce the same bytes and step count in the C# and Rust
runtimes; `rust/crates/bower-pipeline/tests/fixtures/transform-vectors.json` is run by
both test suites.
