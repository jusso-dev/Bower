// TEMPORARY: emits management command parity vectors for the Rust port
// (rust/crates/bower-collector/tests/fixtures/csharp-management-commands.json). Delete after use.
//
// Each case is one command document (exact bytes, base64), the verification time, and the C#
// ManagementCommandVerifier.Verify verdict: the rejection code and readable command id, or the
// verified fields.
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bower.Collector;
using Bower.Integrity;

namespace Bower.UnitTests;

public sealed class ZzManagementCommandVectors
{
    private const string OutputPath = "/tmp/claude-501/bower-management-command-vectors.json";
    private const string CollectorId = "collector-é<&>'\"+`東😀";
    private static readonly DateTimeOffset Now = new(2026, 10, 26, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Emit_ManagementCommands()
    {
        (string privatePem, string publicPem, string keyId) = DetachedSigner.GenerateKeyPair();
        (string otherPrivate, _, _) = DetachedSigner.GenerateKeyPair();
        JsonArray cases = [];

        void Add(string name, string json, DateTimeOffset? now = null)
        {
            DateTimeOffset at = now ?? Now;
            using JsonDocument document = JsonDocument.Parse(json);
            ManagementCommandVerification verdict = ManagementCommandVerifier.Verify(
                document.RootElement, CollectorId, [publicPem], at);
            cases.Add(new JsonObject
            {
                ["name"] = name,
                ["document"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(json)),
                ["now"] = ManagementCommandVerifier.FormatTimestamp(at),
                ["rejectionCode"] = verdict.RejectionCode,
                ["commandId"] = verdict.CommandId,
                ["command"] = verdict.Command?.Command,
                ["nonce"] = verdict.Command?.Nonce,
                ["issuedAt"] = verdict.Command is null ? null : ManagementCommandVerifier.FormatTimestamp(verdict.Command.IssuedAt),
                ["expiresAt"] = verdict.Command is null ? null : ManagementCommandVerifier.FormatTimestamp(verdict.Command.ExpiresAt)
            });
        }

        JsonObject Signed(
            string key,
            string collector = CollectorId,
            string command = "run-canary",
            string id = "0123456789abcdef0123456789abcdef",
            string nonce = "fedcba9876543210fedcba9876543210",
            string issued = "2026-10-26T00:00:00.0000000Z",
            string expires = "2026-10-26T00:15:00.0000000Z")
        {
            DetachedSignature signature = DetachedSigner.Sign(
                ManagementCommandVerifier.SignedBytes(id, collector, command, nonce, issued, expires), key);
            return new JsonObject
            {
                ["kind"] = ManagementCommandVerifier.Kind,
                ["commandId"] = id,
                ["collectorId"] = collector,
                ["command"] = command,
                ["nonce"] = nonce,
                ["issuedAt"] = issued,
                ["expiresAt"] = expires,
                ["signature"] = new JsonObject
                {
                    ["algorithm"] = signature.Algorithm,
                    ["keyId"] = signature.KeyId,
                    ["value"] = signature.Value
                }
            };
        }

        string Text(JsonNode node) => node.ToJsonString();

        Add("valid-run-canary", Text(Signed(privatePem)));
        Add("valid-reload", Text(Signed(privatePem, command: "reload")));
        Add("valid-rotate-credential", Text(Signed(privatePem, command: "rotate-credential")));
        Add("valid-at-skew-limit", Text(Signed(privatePem, issued: "2026-10-26T00:05:00.0000000Z",
            expires: "2026-10-26T00:20:00.0000000Z")));
        Add("valid-one-hour", Text(Signed(privatePem, expires: "2026-10-26T01:00:00.0000000Z")));
        Add("untrusted-key", Text(Signed(otherPrivate)));
        JsonObject tampered = Signed(privatePem);
        tampered["command"] = "reload";
        Add("tampered-command", Text(tampered));
        JsonObject badSignature = Signed(privatePem);
        badSignature["signature"]!["value"] = "not base64!";
        Add("signature-not-base64", Text(badSignature));
        JsonObject wrongAlgorithm = Signed(privatePem);
        wrongAlgorithm["signature"]!["algorithm"] = "RS256";
        Add("signature-wrong-algorithm", Text(wrongAlgorithm));
        Add("wrong-collector", Text(Signed(privatePem, collector: "collector-other")));
        Add("unknown-command", Text(Signed(privatePem, command: "exec")));
        Add("not-yet-valid", Text(Signed(privatePem, issued: "2026-10-26T00:05:00.0000001Z",
            expires: "2026-10-26T00:20:00.0000000Z")));
        Add("expired-exactly-now", Text(Signed(privatePem, issued: "2026-10-25T23:50:00.0000000Z",
            expires: "2026-10-26T00:00:00.0000000Z")));
        Add("lifetime-over-one-hour", Text(Signed(privatePem, expires: "2026-10-26T01:00:00.0000001Z")));
        Add("expires-before-issued", Text(Signed(privatePem, issued: "2026-10-26T00:02:00.0000000Z",
            expires: "2026-10-26T00:01:00.0000000Z")));
        JsonObject extra = Signed(privatePem);
        extra["arguments"] = "/bin/sh";
        Add("unknown-member", Text(extra));
        JsonObject signatureExtra = Signed(privatePem);
        signatureExtra["signature"]!["comment"] = "ignored";
        Add("unknown-signature-member", Text(signatureExtra));
        Add("wrong-kind", Text(Signed(privatePem).Also(item => item["kind"] = "bower.collector-command/v2")));
        Add("missing-nonce", Text(Signed(privatePem).Also(item => item.Remove("nonce"))));
        Add("null-nonce", Text(Signed(privatePem).Also(item => item["nonce"] = null)));
        Add("numeric-nonce", Text(Signed(privatePem).Also(item => item["nonce"] = 12)));
        Add("uppercase-command-id", Text(Signed(privatePem, id: "0123456789ABCDEF0123456789ABCDEF")));
        Add("short-nonce", Text(Signed(privatePem, nonce: "abc")));
        Add("timestamp-without-fraction", Text(Signed(privatePem, issued: "2026-10-26T00:00:00Z")));
        Add("timestamp-with-offset", Text(Signed(privatePem, issued: "2026-10-26T00:00:00.0000000+00:00")));
        Add("timestamp-leap-second", Text(Signed(privatePem, issued: "2026-10-25T23:59:60.0000000Z")));
        Add("timestamp-invalid-date", Text(Signed(privatePem, issued: "2026-02-30T00:00:00.0000000Z")));
        Add("empty-command", Text(Signed(privatePem, command: "")));
        Add("not-an-object", "\"run-canary\"");
        Add("array", "[1,2]");
        Add("null", "null");
        Add("malformed-with-readable-id",
            "{\"commandId\":\"0123456789abcdef0123456789abcdef\",\"kind\":\"other\"}");
        Add("malformed-with-numeric-id", "{\"commandId\":1}");

        // Web defaults: property names match case-insensitively and the last duplicate wins.
        JsonObject valid = Signed(privatePem);
        string json = Text(valid);
        Add("case-insensitive-names", json.Replace("\"commandId\"", "\"CommandId\"", StringComparison.Ordinal)
            .Replace("\"nonce\"", "\"NONCE\"", StringComparison.Ordinal));
        Add("duplicate-last-wins", json.Replace(
            "\"kind\":", "\"command\":\"exec\",\"kind\":", StringComparison.Ordinal));
        Add("duplicate-last-wins-tampered", json[..^1] + ",\"command\":\"reload\"}");

        JsonObject output = new()
        {
            ["collectorId"] = CollectorId,
            ["publicKey"] = publicPem,
            ["keyId"] = keyId,
            ["cases"] = cases
        };
        Directory.CreateDirectory(Path.GetDirectoryName(OutputPath)!);
        File.WriteAllText(OutputPath, output.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.Default
        }) + "\n");
    }
}

internal static class JsonObjectExtensions
{
    public static JsonObject Also(this JsonObject node, Action<JsonObject> change)
    {
        change(node);
        return node;
    }
}
