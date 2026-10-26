# Pipeline builder instructions

Pipeline documents are declarative graphs only. Validation must reject cycles,
unknown node kinds, unbounded fan-out and secret material in node config.
Version every pipeline document and keep import/export pure.

Node kinds load from a declared name or a declared ordinal only; never use bare
`Enum.TryParse`, which accepts undefined numbers. Keep the shared vectors in
`rust/crates/bower-pipeline/tests/fixtures/node-kinds.txt` passing in both runtimes.
