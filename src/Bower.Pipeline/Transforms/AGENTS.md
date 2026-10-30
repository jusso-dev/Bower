# Bounded parser transforms

Transforms normalize records only inside verified signed parser mappings. They run
before redaction and policy; failed evaluation must not persist the raw record.

- The interpreter has no I/O, network, reflection, environment access, or arbitrary code.
- Preserve bounded source length, parse depth, operations, strings, collections, and
  regex complexity. Regex evaluation is deterministic and non-backtracking.
- Current time is an explicit input from the caller; never read the wall clock inside
  compilation or evaluation. Output, error codes, and step counts must be reproducible.
- Preserve shared conformance vectors and add adversarial tests for new operations.
- This backport supports the Windows security pack's normalization and lookup tables;
  changes must not imply that the Rust collector has these adapters or this runtime.
