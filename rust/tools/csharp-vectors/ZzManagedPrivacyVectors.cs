// TEMPORARY: emits managed privacy profile parity vectors for the Rust port
// (rust/crates/bower-collector/tests/fixtures/csharp-managed-privacy.json). Delete after use.
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Collector;
using Bower.Integrity;
using Bower.Redaction.Privacy;

namespace Bower.UnitTests;

public sealed class ZzManagedPrivacyVectors
{
    private const string OutputPath = "/tmp/claude-501/bower-managed-privacy-vectors.json";
    private const string CollectorId = "collector-\u00e9<&>'\"+`\u6771\ud83d\ude00";
    private const string VersionId = "0123456789abcdef0123456789abcdef";
    private const string IssuedAt = "2026-10-24T00:00:00.0000000Z\u2028<>&'\"+`\\\n\r\t\u0001\u007f\u00a0\u00e9\ud83d\ude00";
    private static readonly byte[] HmacKey = new byte[32];

    // Every character class System.Text.Json's default encoder escapes: HTML-sensitive
    // <>&'"+`, backslash, non-ASCII (BMP and astral), and line breaks.
    private const string Content =
        "apiVersion: bower.security/v1\n" +
        "kind: PrivacyProfile\n" +
        "metadata:\n" +
        "  id: contoso-app\n" +
        "  version: 1.0.0\n" +
        "  description: 'Contoso <app> & ''ops'' + \"team\" \\ `tick` caf\u00e9 \u6771\u4eac \ud83d\ude00'\n" +
        "# comment <>&'\"+` \u00fc\ttab\n" +
        "detectors:\n" +
        "  id.email: remove\n" +
        "fields:\n" +
        "  - path: actor.username\n" +
        "    action: hmac\n";

    private static readonly JsonArray Cases = [];

    [Fact]
    public void Emit_ManagedPrivacy()
    {
        (string privatePem, string publicPem, string keyId) = DetachedSigner.GenerateKeyPair();
        (string otherPrivatePem, _, _) = DetachedSigner.GenerateKeyPair();
        string content = Content.Replace("\r\n", "\n", StringComparison.Ordinal);
        string crlf = content.Replace("\n", "\r\n", StringComparison.Ordinal);
        LoadedPrivacyProfile loaded = PrivacyProfileLoader.Load(content, HmacKey);
        LoadedPrivacyProfile loadedCrlf = PrivacyProfileLoader.Load(crlf, HmacKey);

        JsonObject Fields(
            string? collector = null,
            string? versionId = null,
            string? profileId = null,
            string? version = null,
            string? contentHash = null,
            string? body = null,
            string? issuedAt = null) => new()
            {
                ["collectorId"] = collector ?? CollectorId,
                ["versionId"] = versionId ?? VersionId,
                ["profileId"] = profileId ?? loaded.Id,
                ["version"] = version ?? loaded.Version,
                ["contentHash"] = contentHash ?? loaded.Hash,
                ["content"] = body ?? content,
                ["issuedAt"] = issuedAt ?? IssuedAt
            };

        JsonObject Signed(JsonObject fields, string pem)
        {
            DetachedSignature signature = DetachedSigner.Sign(SignedBytesOf(fields), pem);
            JsonObject document = fields.DeepClone().AsObject();
            document["signature"] = new JsonObject
            {
                ["algorithm"] = signature.Algorithm,
                ["keyId"] = signature.KeyId,
                ["value"] = signature.Value
            };
            return document;
        }

        JsonObject valid = Signed(Fields(), privatePem);
        byte[] escaped = Encoding.UTF8.GetBytes(valid.ToJsonString());
        Emit("valid-default-escaping", escaped, SignedBytesOf(Fields()));

        JsonObject relaxed = new()
        {
            ["Unknown"] = new JsonObject { ["nested"] = new JsonArray(1, "x", null, 1.5e300) },
            ["COLLECTORID"] = CollectorId,
            ["VersionId"] = VersionId,
            ["profileid"] = loaded.Id,
            ["Version"] = loaded.Version,
            ["contentHash"] = loaded.Hash,
            ["content"] = content,
            ["issuedAt"] = IssuedAt,
            ["Signature"] = new JsonObject
            {
                ["Algorithm"] = valid["signature"]!["algorithm"]!.GetValue<string>(),
                ["KEYID"] = valid["signature"]!["keyId"]!.GetValue<string>(),
                ["value"] = valid["signature"]!["value"]!.GetValue<string>(),
                ["extra"] = true
            }
        };
        Emit("valid-relaxed-escaping-pascal-case-unknown-fields", Encoding.UTF8.GetBytes(relaxed.ToJsonString(new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true
        })));

        JsonObject crlfFields = Fields(contentHash: loadedCrlf.Hash, body: crlf);
        Emit("valid-crlf-content", Bytes(Signed(crlfFields, privatePem)), SignedBytesOf(crlfFields));

        string sigValue = valid["signature"]!["value"]!.GetValue<string>();
        Emit("valid-signature-value-with-whitespace", Bytes(Mutate(valid, d => d["signature"]!["value"] =
            sigValue[..10] + "\r\n " + sigValue[10..])));

        Emit("tamper-content", Bytes(Mutate(valid, d => d["content"] = content.Replace("remove", "hash", StringComparison.Ordinal))));
        Emit("tamper-content-unicode", Bytes(Mutate(valid, d => d["content"] = content.Replace("\u00e9", "e\u0301", StringComparison.Ordinal))));
        Emit("tamper-issued-at", Bytes(Mutate(valid, d => d["issuedAt"] = IssuedAt.Replace("\u2028", "\u2029", StringComparison.Ordinal))));
        Emit("tamper-version-id", Bytes(Mutate(valid, d => d["versionId"] = "11111111111111111111111111111111")));
        Emit("tamper-content-hash", Bytes(Mutate(valid, d => d["contentHash"] = "sha256:" + new string('a', 64))));
        Emit("tamper-collector-id", Bytes(Mutate(valid, d => d["collectorId"] = "collector-other")));
        Emit("tamper-signature-zero", Bytes(Mutate(valid, d => d["signature"]!["value"] = Convert.ToBase64String(new byte[64]))));
        Emit("tamper-signature-not-base64", Bytes(Mutate(valid, d => d["signature"]!["value"] = "not base64!")));
        Emit("tamper-signature-algorithm", Bytes(Mutate(valid, d => d["signature"]!["algorithm"] = "ES384")));
        Emit("tamper-signature-key-id", Bytes(Mutate(valid, d => d["signature"]!["keyId"] = "0000000000000000")));
        Emit("untrusted-key", Bytes(Signed(Fields(), otherPrivatePem)));
        Emit("signed-for-another-collector", Bytes(Signed(Fields(collector: "collector-other"), privatePem)));
        Emit("signed-wrong-hash", Bytes(Signed(Fields(contentHash: "sha256:" + new string('b', 64)), privatePem)));
        Emit("signed-metadata-mismatch-id", Bytes(Signed(Fields(profileId: "other-app"), privatePem)));
        Emit("signed-metadata-mismatch-version", Bytes(Signed(Fields(version: "1.0.1"), privatePem)));
        Emit("signed-invalid-detector", Bytes(Signed(Fields(body: content.Replace("id.email", "not-a-detector", StringComparison.Ordinal)), privatePem)));
        Emit("signed-invalid-yaml", Bytes(Signed(Fields(body: "apiVersion: [unclosed\n"), privatePem)));
        Emit("signed-empty-content", Bytes(Signed(Fields(body: " \n"), privatePem)));
        Emit("signed-wrong-kind", Bytes(Signed(Fields(body: content.Replace("kind: PrivacyProfile", "kind: Other", StringComparison.Ordinal)), privatePem)));

        Emit("missing-issued-at", Bytes(Mutate(valid, d => d.Remove("issuedAt"))));
        Emit("null-content", Bytes(Mutate(valid, d => d["content"] = null)));
        Emit("missing-signature-key-id", Bytes(Mutate(valid, d => d["signature"]!.AsObject().Remove("keyId"))));
        Emit("null-signature", Bytes(Mutate(valid, d => d["signature"] = null)));
        Emit("number-version", Bytes(Mutate(valid, d => d["version"] = 1)));
        Emit("bool-content", Bytes(Mutate(valid, d => d["content"] = true)));
        Emit("string-signature", Bytes(Mutate(valid, d => d["signature"] = "sig")));
        Emit("array-signature", Bytes(Mutate(valid, d => d["signature"] = new JsonArray())));
        Emit("number-signature-value", Bytes(Mutate(valid, d => d["signature"]!["value"] = 5)));
        Emit("root-null", "null"u8.ToArray());
        Emit("root-array", "[]"u8.ToArray());
        Emit("root-string", "\"x\""u8.ToArray());
        Emit("root-number", "1"u8.ToArray());
        Emit("root-empty-object", "{}"u8.ToArray());
        Emit("empty", []);
        Emit("whitespace", " \n"u8.ToArray());
        Emit("truncated", escaped[..(escaped.Length / 2)]);
        Emit("trailing-garbage", [.. escaped, .. " x"u8.ToArray()]);
        Emit("trailing-whitespace", [.. escaped, .. " \r\n\t"u8.ToArray()]);
        Emit("trailing-second-value", [.. escaped, .. "{}"u8.ToArray()]);
        Emit("trailing-comma", Encoding.UTF8.GetBytes(valid.ToJsonString()[..^1] + ",}"));
        Emit("comment", Encoding.UTF8.GetBytes("/* c */" + valid.ToJsonString()));
        Emit("utf8-bom", [0xEF, 0xBB, 0xBF, .. escaped]);
        Emit("invalid-utf8-in-unknown", Splice(escaped, "{"u8.ToArray(), [.. "\"u\":\""u8.ToArray(), 0xC3, 0x28, (byte)'"', (byte)',']));
        Emit("lone-surrogate-in-unknown", Splice(escaped, "{"u8.ToArray(), "\"u\":\"\\ud800\","u8.ToArray()));
        Emit("lone-surrogate-in-issued-at", Bytes(Mutate(valid, d => d["issuedAt"] = "PLACEHOLDER"), "\"PLACEHOLDER\"", "\"\\ud800\""));
        Emit("nan-in-unknown", Splice(escaped, "{"u8.ToArray(), "\"u\":NaN,"u8.ToArray()));
        Emit("big-number-in-unknown", Splice(escaped, "{"u8.ToArray(), "\"u\":1e999999,"u8.ToArray()));
        Emit("single-quoted-key", Splice(escaped, "{"u8.ToArray(), "'u':1,"u8.ToArray()));
        Emit("unescaped-control-in-string", Splice(escaped, "{"u8.ToArray(), "\"u\":\"a\u0001b\","u8.ToArray()));
        Emit("invalid-escape-in-unknown", Splice(escaped, "{"u8.ToArray(), "\"u\":\"\\x\","u8.ToArray()));
        for (int depth = 62; depth <= 66; depth++)
        {
            string nested = new string('[', depth) + new string(']', depth);
            Emit($"unknown-nesting-{depth}", Splice(escaped, "{"u8.ToArray(), Encoding.UTF8.GetBytes($"\"u\":{nested},")));
        }

        Emit("duplicate-collector-id-last-wins", Splice(escaped, "{"u8.ToArray(), "\"collectorId\":\"collector-other\","u8.ToArray()));
        Emit("duplicate-collector-id-last-wrong", Encoding.UTF8.GetBytes(valid.ToJsonString()[..^1] + ",\"collectorId\":\"collector-other\"}"));
        Emit("duplicate-case-variant-last-wrong", Encoding.UTF8.GetBytes(valid.ToJsonString()[..^1] + ",\"CollectorID\":\"collector-other\"}"));
        Emit("duplicate-null-after-value", Encoding.UTF8.GetBytes(valid.ToJsonString()[..^1] + ",\"content\":null}"));
        Emit("duplicate-signature-object", Encoding.UTF8.GetBytes(valid.ToJsonString()[..^1] + ",\"signature\":{\"value\":\"x\"}}"));
        Emit("non-ascii-case-fold-key", Encoding.UTF8.GetBytes(valid.ToJsonString().Replace("\"issuedAt\"", "\"\u0131ssuedAt\"", StringComparison.Ordinal)));
        Emit("kelvin-key", Encoding.UTF8.GetBytes(valid.ToJsonString().Replace("\"keyId\"", "\"\u212AeyId\"", StringComparison.Ordinal)));
        Emit("escaped-key", Encoding.UTF8.GetBytes(valid.ToJsonString().Replace("\"issuedAt\"", "\"\\u0069ssuedAt\"", StringComparison.Ordinal)));

        JsonObject output = new()
        {
            ["collectorId"] = CollectorId,
            ["hmacKeyId"] = "k1",
            ["hmacKey"] = Convert.ToBase64String(HmacKey),
            ["publicKey"] = publicPem,
            ["keyId"] = keyId,
            ["content"] = content,
            ["contentHash"] = loaded.Hash,
            ["crlfContentHash"] = loadedCrlf.Hash,
            ["cases"] = Cases
        };
        Directory.CreateDirectory(Path.GetDirectoryName(OutputPath)!);
        File.WriteAllText(OutputPath, output.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

        void Emit(string name, byte[] document, byte[]? signedBytes = null)
        {
            JsonObject result;
            try
            {
                VerifiedManagedPrivacyProfile verified = ManagedPrivacyProfileCache.Verify(
                    document, CollectorId, [publicPem], HmacKey, "k1");
                result = new JsonObject
                {
                    ["ok"] = true,
                    ["versionId"] = verified.VersionId,
                    ["profileId"] = verified.ProfileId,
                    ["version"] = verified.Version,
                    ["contentHash"] = verified.ContentHash
                };
            }
            catch (Exception exception)
            {
                result = new JsonObject
                {
                    ["ok"] = false,
                    ["type"] = exception.GetType().Name,
                    ["message"] = exception.Message
                };
            }

            JsonObject entry = new()
            {
                ["name"] = name,
                ["document"] = Convert.ToBase64String(document),
                ["result"] = result
            };
            if (signedBytes is not null)
            {
                entry["signedBytes"] = Convert.ToBase64String(signedBytes);
            }

            Cases.Add(entry);
        }
    }

    private static byte[] SignedBytesOf(JsonObject fields) => ManagedPrivacyProfileCache.SignedBytes(
        fields["collectorId"]!.GetValue<string>(),
        fields["versionId"]!.GetValue<string>(),
        fields["profileId"]!.GetValue<string>(),
        fields["version"]!.GetValue<string>(),
        fields["contentHash"]!.GetValue<string>(),
        fields["content"]!.GetValue<string>(),
        fields["issuedAt"]!.GetValue<string>());

    private static JsonObject Mutate(JsonObject source, Action<JsonObject> change)
    {
        JsonObject copy = source.DeepClone().AsObject();
        change(copy);
        return copy;
    }

    private static byte[] Bytes(JsonObject document, string? find = null, string? replace = null)
    {
        string text = document.ToJsonString();
        return Encoding.UTF8.GetBytes(find is null ? text : text.Replace(find, replace, StringComparison.Ordinal));
    }

    /// <summary>Inserts <paramref name="insert"/> after the first <paramref name="prefix"/>.</summary>
    private static byte[] Splice(byte[] document, byte[] prefix, byte[] insert)
    {
        int at = document.AsSpan().IndexOf(prefix) + prefix.Length;
        return [.. document[..at], .. insert, .. document[at..]];
    }
}
