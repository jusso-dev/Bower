# Pipeline builder instructions

Pipeline documents are declarative graphs only. Validation must reject cycles,
unknown node kinds, unbounded fan-out and secret material in node config.
Version every pipeline document and keep import/export pure.

Node kinds load from a declared name or a declared ordinal only; never use bare
`Enum.TryParse`, which accepts undefined numbers. Keep the shared vectors in
`rust/crates/bower-pipeline/tests/fixtures/node-kinds.txt` passing in both runtimes.

`Transforms/` is the parser transform language. Keep it total and side-effect free:
no loops, recursion, I/O, environment, randomness or clock reads (evaluation time is an
explicit input), and no function outside the allow-list. Errors carry codes and
positions only, never statement text or values. Any change to syntax, semantics, costs
or limits must change the Rust port (`rust/crates/bower-pipeline/src/transform`) in the
same way and keep `tests/fixtures/transform-vectors.json` passing in both runtimes
(regenerate with `BOWER_TRANSFORM_VECTOR_OUTPUT`, then review the diff).
