# Signed pack interoperability fixtures

Historical `*-1.0.0.bowerpack` fixtures and `csharp-signing.pub.pem` remain unchanged.
A separate test proves they still verify with the historical public key.

Current fixtures were built using C# `PackArchive.Build`, .NET 10.0.402, with
`TimeProvider.GetUtcNow()` fixed at `2026-10-17T01:02:03.4567+00:00`:

- `linux-ssh-gateway-1.1.0.bowerpack`: explicit JSON runtime and raw sample expectations.
- `aws-security-1.1.0.bowerpack`: source pack inherited from the parent revision.
- `gcp-security-1.1.1.bowerpack`: explicit qualified service-account-key detection alternatives.

`csharp-current-signing.pub.pem` verifies these current fixtures. The ephemeral
signing private key was generated in memory and was not saved. Tests compare the
signed source bytes with the repository, run samples, and compare Rust-generated
manifests byte for byte with the C# manifests. The DCR is packaged test content;
no cloud deployment or destination verification occurred.

`csharp-vectors/report.txt` retains historical diff/interoperability observations
and updates sample outcomes from C# `PackTester.Run`, including the two raw SSH
samples. Rule and alert vectors live in `bower-detection/tests/fixtures`.
