// TEMPORARY: emits managed privacy profile parity vectors for the Rust port
// (rust/crates/bower-collector/tests/fixtures/csharp-managed-privacy.json). Delete after use.
//
// Two sections:
// - "cases": one signed assignment envelope each and C#'s ManagedPrivacyProfileCache.Verify
//   verdict (accepted fields, or exception type and message).
// - "scenarios": the real C# ManagedPrivacyProfileJob run once against a cached envelope
//   (or none) and one management response, recording the start-up gate state, the job
//   outcome, the cache afterwards, the gate state afterwards and the restart request.
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Bower.Collector;
using Bower.Collector.Jobs;
using Bower.Integrity;
using Bower.Management.Api;
using Bower.Packs;
using Bower.Redaction.Privacy;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

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

    private static readonly string[] ProfileFields = ["versionId", "profileId", "version", "contentHash", "content"];
    private static readonly JsonArray Cases = [];
    private static readonly JsonArray Scenarios = [];
    private static string privatePem = "";
    private static string publicPem = "";

    [Fact]
    public async Task Emit_ManagedPrivacy()
    {
        (privatePem, publicPem, string keyId) = DetachedSigner.GenerateKeyPair();
        (string otherPrivatePem, _, _) = DetachedSigner.GenerateKeyPair();
        string content = Content;
        string crlf = content.Replace("\n", "\r\n", StringComparison.Ordinal);
        LoadedPrivacyProfile loaded = PrivacyProfileLoader.Load(content, HmacKey);
        LoadedPrivacyProfile loadedCrlf = PrivacyProfileLoader.Load(crlf, HmacKey);

        JsonObject valid = Assigned(1, content);
        byte[] escaped = Bytes(valid);
        JsonObject cleared = Cleared(2);
        byte[] clearedBytes = Bytes(cleared);

        // ---------------------------------------------------------------- valid
        Emit("valid-assigned-default-escaping", escaped, SignedBytesOf(valid));
        Emit("valid-cleared-default-escaping", clearedBytes, SignedBytesOf(cleared));
        JsonObject relaxed = new()
        {
            ["COLLECTORID"] = CollectorId,
            ["AssignmentRevision"] = 1,
            ["ACTION"] = "assigned",
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
                ["value"] = valid["signature"]!["value"]!.GetValue<string>()
            }
        };
        Emit("valid-relaxed-escaping-case-insensitive-indented", Encoding.UTF8.GetBytes(relaxed.ToJsonString(new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true
        })));
        JsonObject crlfDocument = Assigned(3, crlf);
        Emit("valid-crlf-content", Bytes(crlfDocument), SignedBytesOf(crlfDocument));
        JsonObject big = Cleared(9007199254740993);
        Emit("valid-cleared-revision-above-2-pow-53", Bytes(big), SignedBytesOf(big));
        JsonObject max = Assigned(long.MaxValue, content);
        Emit("valid-assigned-revision-long-max", Bytes(max), SignedBytesOf(max));
        string sigValue = valid["signature"]!["value"]!.GetValue<string>();
        Emit("valid-signature-value-with-whitespace", Bytes(Mutate(valid, d => d["signature"]!["value"] =
            sigValue[..10] + "\r\n " + sigValue[10..])));
        Emit("cleared-with-null-profile-fields", Bytes(Mutate(cleared, d =>
        {
            d["content"] = null;
            d["versionId"] = null;
        })));
        Emit("assigned-revision-as-negative-zero", Bytes(valid, "\"assignmentRevision\":1", "\"assignmentRevision\":-0"));

        // The management API's own signer and serializer (ManagementJsonContext, web defaults).
        string keyFile = Path.Combine(Path.GetTempPath(), $"bower-vectors-{Guid.NewGuid():N}.pem");
        File.WriteAllText(keyFile, privatePem);
        ManagedPrivacyProfileSigner signer = ManagedPrivacyProfileSigner.FromFile(keyFile);
        File.Delete(keyFile);
        DateTimeOffset assignedAt = new(2026, 10, 24, 1, 23, 45, TimeSpan.FromHours(11));
        assignedAt = assignedAt.AddTicks(1234567);
        ManagedPrivacyProfile managementAssigned = signer.Sign(
            CollectorId, 12, ManagedPrivacyProfile.Assigned,
            new PrivacyProfileVersionContent(VersionId, loaded.Id, loaded.Version, loaded.Hash, content), assignedAt);
        ManagedPrivacyProfile managementCleared = signer.Sign(CollectorId, 13, ManagedPrivacyProfile.Cleared, null, assignedAt);
        Emit("valid-management-signer-assigned", JsonSerializer.SerializeToUtf8Bytes(
            managementAssigned, ManagementJsonContext.Default.ManagedPrivacyProfile));
        Emit("valid-management-signer-cleared", JsonSerializer.SerializeToUtf8Bytes(
            managementCleared, ManagementJsonContext.Default.ManagedPrivacyProfile));

        // ---------------------------------------------------------------- revision and action
        foreach ((string name, string json) in new[]
        {
            ("revision-zero", "0"), ("revision-negative", "-1"), ("revision-string", "\"1\""),
            ("revision-decimal", "1.0"), ("revision-exponent", "1e0"), ("revision-fraction", "1.5"),
            ("revision-overflow", "9223372036854775808"), ("revision-null", "null"),
            ("revision-true", "true"), ("revision-array", "[1]"), ("revision-leading-plus", "+1"),
            ("revision-leading-zero", "01"), ("revision-hex", "0x1")
        })
        {
            Emit(name, Bytes(valid, "\"assignmentRevision\":1", "\"assignmentRevision\":" + json));
        }

        Emit("missing-revision", Bytes(Mutate(valid, d => d.Remove("assignmentRevision"))));
        Emit("revision-tampered-higher", Bytes(Mutate(valid, d => d["assignmentRevision"] = 2)));
        Emit("action-uppercase", Bytes(Mutate(valid, d => d["action"] = "Assigned")));
        Emit("action-unknown", Bytes(Mutate(valid, d => d["action"] = "rollback")));
        Emit("action-null", Bytes(Mutate(valid, d => d["action"] = null)));
        Emit("action-number", Bytes(Mutate(valid, d => d["action"] = 1)));
        Emit("action-missing", Bytes(Mutate(valid, d => d.Remove("action"))));
        Emit("action-flipped-to-cleared-with-profile-fields", Bytes(Mutate(valid, d => d["action"] = "cleared")));
        Emit("action-flipped-to-cleared-without-profile-fields", Bytes(Mutate(valid, d =>
        {
            d["action"] = "cleared";
            foreach (string field in ProfileFields)
            {
                d.Remove(field);
            }
        })));
        Emit("action-flipped-to-assigned", Bytes(Mutate(cleared, d => d["action"] = "assigned")));
        Emit("cleared-with-content", Bytes(Mutate(cleared, d => d["content"] = content)));
        Emit("cleared-with-version-id", Bytes(Mutate(cleared, d => d["versionId"] = VersionId)));
        foreach (string field in ProfileFields)
        {
            Emit($"assigned-missing-{field}", Bytes(Mutate(valid, d => d.Remove(field))));
            Emit($"assigned-null-{field}", Bytes(Mutate(valid, d => d[field] = null)));
        }

        // ---------------------------------------------------------------- strict members
        Emit("unknown-member", Bytes(Mutate(valid, d => d["note"] = "not signed")));
        Emit("unknown-member-null", Bytes(Mutate(valid, d => d["note"] = null)));
        Emit("unknown-member-on-cleared", Bytes(Mutate(cleared, d => d["note"] = 1)));
        Emit("unknown-member-in-signature", Bytes(Mutate(valid, d => d["signature"]!["extra"] = true)));
        Emit("unknown-nested-in-signature", Bytes(Mutate(valid, d => d["signature"]!["extra"] = new JsonArray(new JsonArray(1)))));
        for (int depth = 61; depth <= 64; depth++)
        {
            string nested = new string('[', depth) + new string(']', depth);
            Emit($"signature-nesting-{depth}", Splice(escaped, "\"signature\":{"u8.ToArray(), Encoding.UTF8.GetBytes($"\"x\":{nested},")));
        }

        Emit("invalid-utf8-in-signature-unknown", Splice(escaped, "\"signature\":{"u8.ToArray(), [.. "\"x\":\""u8.ToArray(), 0xC3, 0x28, (byte)'"', (byte)',']));
        Emit("lone-surrogate-in-signature-unknown", Splice(escaped, "\"signature\":{"u8.ToArray(), "\"x\":\"\\ud800\","u8.ToArray()));
        Emit("non-ascii-case-fold-key", Encoding.UTF8.GetBytes(valid.ToJsonString().Replace("\"issuedAt\"", "\"\u0131ssuedAt\"", StringComparison.Ordinal)));
        Emit("kelvin-key-in-signature", Encoding.UTF8.GetBytes(valid.ToJsonString().Replace("\"keyId\"", "\"\u212AeyId\"", StringComparison.Ordinal)));
        Emit("escaped-key", Encoding.UTF8.GetBytes(valid.ToJsonString().Replace("\"issuedAt\"", "\"\\u0069ssuedAt\"", StringComparison.Ordinal)));
        Emit("duplicate-collector-id-last-wins", Splice(escaped, "{"u8.ToArray(), "\"collectorId\":\"collector-other\","u8.ToArray()));
        Emit("duplicate-collector-id-last-wrong", Encoding.UTF8.GetBytes(valid.ToJsonString()[..^1] + ",\"collectorId\":\"collector-other\"}"));
        Emit("duplicate-case-variant-last-wrong", Encoding.UTF8.GetBytes(valid.ToJsonString()[..^1] + ",\"CollectorID\":\"collector-other\"}"));
        Emit("duplicate-revision-last-wins", Splice(escaped, "{"u8.ToArray(), "\"assignmentRevision\":\"x\","u8.ToArray()));
        Emit("duplicate-null-after-value", Encoding.UTF8.GetBytes(valid.ToJsonString()[..^1] + ",\"content\":null}"));
        Emit("duplicate-signature-object", Encoding.UTF8.GetBytes(valid.ToJsonString()[..^1] + ",\"signature\":{\"value\":\"x\"}}"));

        // ---------------------------------------------------------------- tampering and trust
        Emit("tamper-content", Bytes(Mutate(valid, d => d["content"] = content.Replace("remove", "hash", StringComparison.Ordinal))));
        Emit("tamper-content-unicode", Bytes(Mutate(valid, d => d["content"] = content.Replace("\u00e9", "e\u0301", StringComparison.Ordinal))));
        Emit("tamper-issued-at", Bytes(Mutate(valid, d => d["issuedAt"] = IssuedAt.Replace("\u2028", "\u2029", StringComparison.Ordinal))));
        Emit("tamper-cleared-issued-at", Bytes(Mutate(cleared, d => d["issuedAt"] = "2026-10-24T01:00:00.0000001+00:00")));
        Emit("tamper-cleared-revision", Bytes(Mutate(cleared, d => d["assignmentRevision"] = 3)));
        Emit("tamper-version-id", Bytes(Mutate(valid, d => d["versionId"] = "11111111111111111111111111111111")));
        Emit("tamper-content-hash", Bytes(Mutate(valid, d => d["contentHash"] = "sha256:" + new string('a', 64))));
        Emit("tamper-collector-id", Bytes(Mutate(valid, d => d["collectorId"] = "collector-other")));
        Emit("tamper-signature-zero", Bytes(Mutate(valid, d => d["signature"]!["value"] = Convert.ToBase64String(new byte[64]))));
        Emit("tamper-signature-not-base64", Bytes(Mutate(valid, d => d["signature"]!["value"] = "not base64!")));
        Emit("tamper-signature-algorithm", Bytes(Mutate(valid, d => d["signature"]!["algorithm"] = "ES384")));
        Emit("tamper-signature-key-id", Bytes(Mutate(valid, d => d["signature"]!["keyId"] = "0000000000000000")));
        Emit("cleared-signature-reused-from-assigned", Bytes(Mutate(cleared, d => d["signature"] = valid["signature"]!.DeepClone())));
        Emit("untrusted-key", Bytes(Assigned(1, content, pem: otherPrivatePem)));
        Emit("untrusted-key-cleared", Bytes(Cleared(2, pem: otherPrivatePem)));
        Emit("signed-for-another-collector", Bytes(Assigned(1, content, collector: "collector-other")));
        Emit("cleared-for-another-collector", Bytes(Cleared(2, collector: "collector-other")));
        Emit("signed-wrong-hash", Bytes(Assigned(1, content, contentHash: "sha256:" + new string('b', 64))));
        Emit("signed-metadata-mismatch-id", Bytes(Assigned(1, content, profileId: "other-app")));
        Emit("signed-metadata-mismatch-version", Bytes(Assigned(1, content, version: "1.0.1")));
        Emit("signed-invalid-detector", Bytes(Assigned(1, content.Replace("id.email", "not-a-detector", StringComparison.Ordinal))));
        Emit("signed-invalid-yaml", Bytes(Assigned(1, "apiVersion: [unclosed\n", profileId: "contoso-app", version: "1.0.0")));
        Emit("signed-empty-content", Bytes(Assigned(1, " \n", profileId: "contoso-app", version: "1.0.0")));
        Emit("signed-wrong-kind", Bytes(Assigned(1, content.Replace("kind: PrivacyProfile", "kind: Other", StringComparison.Ordinal))));
        Emit("v1-envelope-without-revision-and-action", Bytes(Mutate(valid, d =>
        {
            d.Remove("assignmentRevision");
            d.Remove("action");
        })));

        // ---------------------------------------------------------------- JSON shape
        Emit("missing-issued-at", Bytes(Mutate(valid, d => d.Remove("issuedAt"))));
        Emit("missing-collector-id", Bytes(Mutate(cleared, d => d.Remove("collectorId"))));
        Emit("null-signature", Bytes(Mutate(valid, d => d["signature"] = null)));
        Emit("missing-signature-key-id", Bytes(Mutate(valid, d => d["signature"]!.AsObject().Remove("keyId"))));
        Emit("number-version", Bytes(Mutate(valid, d => d["version"] = 1)));
        Emit("string-signature", Bytes(Mutate(valid, d => d["signature"] = "sig")));
        Emit("number-signature-value", Bytes(Mutate(valid, d => d["signature"]!["value"] = 5)));
        Emit("root-null", "null"u8.ToArray());
        Emit("root-array", "[]"u8.ToArray());
        Emit("root-string", "\"x\""u8.ToArray());
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
        Emit("lone-surrogate-in-issued-at", Bytes(Mutate(valid, d => d["issuedAt"] = "PLACEHOLDER"), "\"PLACEHOLDER\"", "\"\\ud800\""));
        Emit("unescaped-control-in-string", Bytes(valid, "\"issuedAt\":\"", "\"issuedAt\":\"\u0001"));

        // ---------------------------------------------------------------- sync job scenarios
        string Profile(string version) => content.Replace("version: 1.0.0", $"version: {version}", StringComparison.Ordinal);
        byte[] A(long revision, string version = "1.0.0", string issuedAt = "2026-10-24T00:00:00.0000000+00:00", string? pem = null, string collector = CollectorId)
            => Bytes(Assigned(revision, Profile(version), issuedAt: issuedAt, pem: pem, collector: collector));
        byte[] C(long revision, string issuedAt = "2026-10-24T01:00:00.0000000+00:00", string collector = CollectorId)
            => Bytes(Cleared(revision, issuedAt: issuedAt, collector: collector));

        await Scenario("no-cache-204-never-assigned", null, false, 204, null);
        await Scenario("no-cache-allow-default-204-never-assigned", null, true, 204, null);
        await Scenario("no-cache-409-keeps-awaiting", null, false, 409, null);
        await Scenario("no-cache-allow-default-409", null, true, 409, null);
        await Scenario("no-cache-503", null, false, 503, null);
        await Scenario("no-cache-401", null, false, 401, null);
        await Scenario("no-cache-first-assignment-restarts", null, false, 200, A(1));
        await Scenario("no-cache-allow-default-first-assignment-restarts", null, true, 200, A(1));
        await Scenario("no-cache-cleared-before-first-sync", null, false, 200, C(2));
        await Scenario("no-cache-unverified-leaves-no-cache", null, false, 200, A(1, pem: otherPrivatePem));
        await Scenario("no-cache-oversized", null, false, 200, new byte[ManagedPrivacyProfileCache.MaximumDocumentBytes + 1]);
        await Scenario("no-cache-empty-200", null, false, 200, []);
        await Scenario("assigned-cache-204-keeps-protection", A(3), false, 204, null);
        await Scenario("cleared-cache-204-keeps-clear", C(3), false, 204, null);
        await Scenario("assigned-cache-409", A(3), false, 409, null);
        await Scenario("assigned-cache-503", A(3), false, 503, null);
        await Scenario("same-revision-resigned-is-no-op", A(1), false, 200, A(1));
        await Scenario("same-revision-different-issued-at", A(4), false, 200, A(4, issuedAt: "2026-10-24T09:00:00.0000000+00:00"));
        await Scenario("same-revision-different-content", A(4), false, 200, A(4, version: "3.0.0"));
        await Scenario("same-revision-cleared-vs-assigned", A(4), false, 200, C(4));
        await Scenario("same-revision-cleared-resigned-is-no-op", C(4), false, 200, C(4));
        await Scenario("same-revision-cleared-different-issued-at", C(4), false, 200, C(4, issuedAt: "2026-10-24T02:00:00.0000000+00:00"));
        await Scenario("older-signed-assignment-rollback-rejected", A(5, version: "2.0.0"), false, 200, A(4, issuedAt: "2000-01-01T00:00:00.0000000+00:00"));
        await Scenario("replay-after-clear-rejected", C(6), false, 200, A(5, version: "2.0.0"));
        await Scenario("older-clear-rejected", A(6), false, 200, C(5));
        await Scenario("signed-clear-applies-default-with-restart", A(5, version: "2.0.0"), false, 200, C(6));
        await Scenario("explicit-rollback-newer-revision-accepted", A(5, version: "2.0.0"), false, 200, A(7));
        await Scenario("newer-revision-same-protection-no-restart", A(1), false, 200, A(3, issuedAt: "2026-10-24T05:00:00.0000000+00:00"));
        await Scenario("newer-clear-while-cleared-no-restart", C(3), false, 200, C(5));
        await Scenario("assignment-after-clear-restarts", C(3), false, 200, A(4));
        await Scenario("newer-version-restarts", A(1), false, 200, A(2, version: "1.1.0"));
        await Scenario("newer-unverified-rejected", A(1), false, 200, A(2, version: "2.0.0", pem: otherPrivatePem));
        await Scenario("newer-for-another-collector-rejected", A(1), false, 200, A(2, collector: "collector-other"));
        await Scenario("newer-cleared-for-another-collector-rejected", A(1), false, 200, C(2, collector: "collector-other"));
        await Scenario("newer-with-unknown-member-rejected", A(1), false, 200, Bytes(Mutate(Assigned(2, Profile("2.0.0")), d => d["note"] = "x")));
        await Scenario("newer-revision-as-string-rejected", A(1), false, 200, Bytes(Assigned(2, Profile("2.0.0")), "\"assignmentRevision\":2", "\"assignmentRevision\":\"2\""));
        await Scenario("cache-tampered-after-start", A(1), false, 200, A(2, version: "2.0.0"), tamperCacheAfterStart: true);

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
            ["cases"] = Cases,
            ["scenarios"] = Scenarios
        };
        Directory.CreateDirectory(Path.GetDirectoryName(OutputPath)!);
        File.WriteAllText(OutputPath, output.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    private static JsonObject Assigned(
        long revision,
        string content,
        string? collector = null,
        string? profileId = null,
        string? version = null,
        string? contentHash = null,
        string? issuedAt = null,
        string? pem = null)
    {
        LoadedPrivacyProfile? loaded = null;
        try
        {
            loaded = PrivacyProfileLoader.Load(content, HmacKey);
        }
        catch (Exception exception) when (exception is InvalidDataException or ArgumentException)
        {
            // Deliberately invalid content: signed with the given metadata.
        }

        JsonObject fields = new()
        {
            ["collectorId"] = collector ?? CollectorId,
            ["assignmentRevision"] = revision,
            ["action"] = "assigned",
            ["versionId"] = VersionId,
            ["profileId"] = profileId ?? loaded?.Id ?? "contoso-app",
            ["version"] = version ?? loaded?.Version ?? "1.0.0",
            ["contentHash"] = contentHash ?? loaded?.Hash ?? "sha256:" + new string('0', 64),
            ["content"] = content,
            ["issuedAt"] = issuedAt ?? IssuedAt
        };
        return Signed(fields, pem ?? privatePem);
    }

    private static JsonObject Cleared(long revision, string? collector = null, string? issuedAt = null, string? pem = null) =>
        Signed(
            new JsonObject
            {
                ["collectorId"] = collector ?? CollectorId,
                ["assignmentRevision"] = revision,
                ["action"] = "cleared",
                ["issuedAt"] = issuedAt ?? "2026-10-24T01:00:00.0000000+00:00"
            },
            pem ?? privatePem);

    private static JsonObject Signed(JsonObject fields, string pem)
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

    private static byte[] SignedBytesOf(JsonObject fields) => ManagedPrivacyProfileCache.SignedBytes(
        fields["collectorId"]!.GetValue<string>(),
        fields["assignmentRevision"]!.GetValue<long>(),
        fields["action"]!.GetValue<string>(),
        fields["versionId"]?.GetValue<string>(),
        fields["profileId"]?.GetValue<string>(),
        fields["version"]?.GetValue<string>(),
        fields["contentHash"]?.GetValue<string>(),
        fields["content"]?.GetValue<string>(),
        fields["issuedAt"]!.GetValue<string>());

    private static void Emit(string name, byte[] document, byte[]? signedBytes = null)
    {
        JsonObject result;
        try
        {
            VerifiedManagedPrivacyProfile verified = ManagedPrivacyProfileCache.Verify(
                document, CollectorId, [publicPem], HmacKey, "k1");
            result = new JsonObject
            {
                ["ok"] = true,
                ["action"] = verified.Action,
                ["assignmentRevision"] = verified.AssignmentRevision,
                ["versionId"] = verified.VersionId,
                ["profileId"] = verified.ProfileId,
                ["version"] = verified.Version,
                ["contentHash"] = verified.ContentHash,
                ["profileHash"] = verified.Profile?.Hash,
                ["signedPayload"] = Convert.ToBase64String(verified.SignedPayload)
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

    private static async Task Scenario(
        string name,
        byte[]? cache,
        bool allowDefault,
        int status,
        byte[]? body,
        bool tamperCacheAfterStart = false)
    {
        using TemporaryDirectory directory = new();
        string trusted = Path.Combine(directory.Path, "trusted.pem");
        File.WriteAllText(trusted, publicPem);
        string hmac = Path.Combine(directory.Path, "hmac.key");
        File.WriteAllText(hmac, Convert.ToBase64String(HmacKey));
        CollectorSettings settings = new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory.Path, "queue.db"),
            PolicyDirectory = Path.Combine(AppContext.BaseDirectory, "policies", "default"),
            CollectorId = CollectorId,
            ManagementEndpoint = new Uri("http://127.0.0.1:9"),
            ManagementScope = "api://bower/.default",
            PrivacyProfileSource = PrivacyProfileSources.Management,
            ManagedPrivacyTrustedKeyFiles = [trusted],
            ManagedPrivacyAllowDefault = allowDefault,
            PrivacyHmacKeyFile = hmac
        };
        string cachePath = ManagedPrivacyProfileCache.CachePath(settings);
        if (cache is not null)
        {
            Directory.CreateDirectory(settings.ManagedPrivacyCacheDirectory);
            File.WriteAllBytes(cachePath, cache);
        }

        VerifiedManagedPrivacyProfile? cached = null;
        PolicyBundle bundle = PolicyBundle.Load(settings.PolicySources(observed => cached = observed));
        ManagedPrivacyProfileState state = new(cached, settings.ManagedPrivacyAllowDefault);
        JsonObject initial = StateOf(state);
        initial["privacyProfileHash"] = bundle.PrivacyProfileHash;
        if (tamperCacheAfterStart)
        {
            File.WriteAllBytes(cachePath, Encoding.UTF8.GetBytes(
                Encoding.UTF8.GetString(cache!).Replace("remove", "hash", StringComparison.Ordinal)));
        }

        byte[]? before = File.Exists(cachePath) ? File.ReadAllBytes(cachePath) : null;
        Lifetime lifetime = new();
        ManagedPrivacyProfileJob job = new(
            new Factory(new Handler(() =>
            {
                HttpResponseMessage response = new((HttpStatusCode)status);
                if (body is not null)
                {
                    response.Content = new ByteArrayContent(body);
                }

                return response;
            })),
            new Credential(),
            settings,
            bundle,
            state,
            lifetime,
            NullLogger<ManagedPrivacyProfileJob>.Instance);

        JsonObject? error = null;
        try
        {
            await job.RunAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            error = new JsonObject
            {
                ["type"] = exception.GetType().Name,
                ["message"] = exception.Message.Replace(cachePath, "{cachePath}", StringComparison.Ordinal)
            };
        }

        byte[]? after = File.Exists(cachePath) ? File.ReadAllBytes(cachePath) : null;
        string cacheOutcome = after is null
            ? "none"
            : before is not null && after.AsSpan().SequenceEqual(before)
                ? "unchanged"
                : body is not null && after.AsSpan().SequenceEqual(body) ? "received" : "other";
        JsonObject final = StateOf(state);
        final["stopCalls"] = lifetime.StopCalls;
        string? restartedHash;
        try
        {
            restartedHash = PolicyBundle.Load(settings.PolicySources()).PrivacyProfileHash ?? "default";
        }
        catch (ManagedPrivacyProfileException)
        {
            restartedHash = "start-up-fails";
        }

        Scenarios.Add(new JsonObject
        {
            ["name"] = name,
            ["cache"] = cache is null ? null : Convert.ToBase64String(cache),
            ["tamperCacheAfterStart"] = tamperCacheAfterStart,
            ["allowDefault"] = allowDefault,
            ["status"] = status,
            // Large all-zero bodies (size limit probes) are described, not embedded.
            ["body"] = body is null || IsLargeZeroBody(body) ? null : Convert.ToBase64String(body),
            ["zeroBodyLength"] = body is not null && IsLargeZeroBody(body) ? body.Length : null,
            ["initial"] = initial,
            ["error"] = error,
            ["cacheAfter"] = cacheOutcome,
            ["final"] = final,
            ["restartedPrivacyProfileHash"] = restartedHash
        });
    }

    private static bool IsLargeZeroBody(byte[] body) => body.Length > 4096 && !body.AsSpan().ContainsAnyExcept((byte)0);

    private static JsonObject StateOf(ManagedPrivacyProfileState state) => new()
    {
        ["state"] = state.State,
        ["revision"] = state.Revision,
        ["acceptsEvents"] = state.AcceptsEvents
    };

    private static JsonObject Mutate(JsonObject source, Action<JsonObject> change)
    {
        JsonObject copy = source.DeepClone().AsObject();
        change(copy);
        return copy;
    }

    private static byte[] Bytes(JsonObject document, string? find = null, string? replace = null)
    {
        string text = document.ToJsonString();
        if (find is not null)
        {
            if (!text.Contains(find, StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"'{find}' not found");
            }

            text = text.Replace(find, replace, StringComparison.Ordinal);
        }

        return Encoding.UTF8.GetBytes(text);
    }

    /// <summary>Inserts <paramref name="insert"/> after the first <paramref name="prefix"/>.</summary>
    private static byte[] Splice(byte[] document, byte[] prefix, byte[] insert)
    {
        int index = document.AsSpan().IndexOf(prefix);
        if (index < 0)
        {
            throw new InvalidOperationException("prefix not found");
        }

        int at = index + prefix.Length;
        return [.. document[..at], .. insert, .. document[at..]];
    }

    private sealed class Handler(Func<HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond());
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri("https://management.example.test/") };
    }

    private sealed class Lifetime : IHostApplicationLifetime
    {
        public int StopCalls { get; private set; }

        public CancellationToken ApplicationStarted => CancellationToken.None;

        public CancellationToken ApplicationStopping => CancellationToken.None;

        public CancellationToken ApplicationStopped => CancellationToken.None;

        public void StopApplication() => StopCalls++;
    }

    private sealed class Credential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("test-token", DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
}
