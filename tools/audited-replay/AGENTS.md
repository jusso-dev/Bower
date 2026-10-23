# Audited offline replay

- Keep this tool Python standard library only, with no cloud access.
- Invoke the trusted, compiled Bower CLI with an argument array, never a shell.
- Require exact reviewed IDs, bounded inputs and operator/change identifiers.
- Persist and fsync intent before invocation; never reuse an audit directory.
- Preserve intent on every failure. Missing/invalid outcome means ambiguous;
  never automatically retry, resume or delete evidence.
- Never retain CLI output, raw payloads, credentials or free-form error text.
- Do not open or modify queue tables here. Queue transitions belong to the CLI.
- CLI success proves neither individual replay counts nor destination delivery.
- Test with isolated fake executables and temporary audit directories only:
  `python3 -B -m unittest discover -s tools/audited-replay -v`.
