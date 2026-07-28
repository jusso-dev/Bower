# Pipeline builder instructions

Pipeline documents are declarative graphs only. Validation must reject cycles,
unknown node kinds, unbounded fan-out and secret material in node config.
Version every pipeline document and keep import/export pure.
