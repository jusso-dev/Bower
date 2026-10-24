# C# parity vector generators

Not compiled. These xunit classes produced the `tests/fixtures/csharp-*` vectors used
by the Rust parity tests. To regenerate: copy a file into `tests/Bower.UnitTests/`
in a scratch worktree at the commit you want to match, build, run the test class
(`bin/<cfg>/net10.0/Bower.UnitTests -class <Name>`), copy the output into the
crate fixtures, then delete the file. Never commit it under `tests/`.

`ZzManagedPrivacyVectors.cs` writes `crates/bower-collector/tests/fixtures/csharp-managed-privacy.json`
(C#-signed managed privacy assignment envelopes with C#'s `Verify` verdict on each, and
the real C# sync job's outcome for each cached-envelope/response scenario).

Other generators live next to their fixtures, e.g.
`crates/bower-redaction/tests/vectors/generate.fsx`.
