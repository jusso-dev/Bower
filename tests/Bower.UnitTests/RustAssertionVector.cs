namespace Bower.UnitTests;

/// <summary>
/// A management assertion signed by the Rust collector (`bower-collector` test
/// `enrolment::tests::emit_cross_runtime_vector`, run with `--ignored --nocapture`), issued
/// at 2026-10-27T00:00:00Z for five minutes. The key is a throwaway test key. Rust signs,
/// C# management verifies.
/// </summary>
internal static class RustAssertionVector
{
    public const string CollectorId = "collector-é<&>'\"+`東😀";

    public const string PublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjUnIGiIrrEE8fP4ZYhsnsjrsUCR+\n" +
        "qEql+MV2CIcl7DXy5TWy0JgKESxw0rF6mAiB3SQ5hsAKo0Ju17A5yRbm2g==\n" +
        "-----END PUBLIC KEY-----";

    public const string Assertion =
        "bwc1.eyJjb2xsZWN0b3JJZCI6ImNvbGxlY3Rvci1cdTAwRTlcdTAwM0NcdTAwMjZcdTAwM0VcdTAwMjdcdTAwMjJcdTAwMkJcdTAwNjBcdTY3NzFcdUQ4M0RcdURFMDAiLCJjcmVkZW50aWFsSWQiOiIzMzk3Y2M0YzA5ZDE1ZTBjIiwiZXhwaXJlc0F0IjoiMjAyNi0xMC0yN1QwMDowNTowMC4wMDAwMDAwWiIsImlzc3VlZEF0IjoiMjAyNi0xMC0yN1QwMDowMDowMC4wMDAwMDAwWiIsImtpbmQiOiJib3dlci5jb2xsZWN0b3ItYXNzZXJ0aW9uL3YxIiwibm9uY2UiOiI5NWVlZTAxZjZjMWU0NmIzOTViMDQzNWJhY2JmNzZlMiJ9" +
        ".lvvAeneDdd83pDXxjXYUli7iM80BsNEOQmbi0wm2BAnw0PTEw6JH4y3bssMsYKvY8DqyoP-JRpslytCdkealLw";

    public static readonly DateTimeOffset Now = new(2026, 10, 27, 0, 1, 0, TimeSpan.Zero);
}
