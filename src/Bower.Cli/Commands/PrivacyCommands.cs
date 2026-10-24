using System.Security.Cryptography;
using System.Text.Json;
using Bower.Redaction.Privacy;

namespace Bower.Cli.Commands;

/// <summary><c>bower privacy validate</c>: strict privacy profile validation, metadata only.</summary>
internal static class PrivacyCommands
{
    /// <summary>Key id used with the random key when no <c>--hmac-key-file</c> is given.</summary>
    public const string ValidationKeyId = "validation";

    /// <summary>
    /// Loads the profile exactly as the collector does (running every custom detector's
    /// tests) and prints a metadata-only summary. With <c>--sample FILE</c> it also prints
    /// the redacted sample. Without <c>--hmac-key-file</c> a random key is used, so HMAC
    /// pseudonyms in the sample differ per run. Exit 1 (loader message on stderr) when the
    /// profile is invalid, 2 when the sample cannot be redacted.
    /// </summary>
    public static int Validate(string[] args)
    {
        string? path = CliOptions.Positional(args);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            Console.Error.WriteLine("Provide an existing privacy profile file: bower privacy validate FILE.");
            return 1;
        }

        string? keyFile = CliOptions.Get(args, "--hmac-key-file");
        string? samplePath = CliOptions.Get(args, "--sample");
        byte[] key = keyFile is null ? RandomNumberGenerator.GetBytes(32) : PrivacyProfileLoader.ReadKeyFile(keyFile);
        PrivacyValidationOutput output = Describe(
            File.ReadAllText(path),
            key,
            keyFile is null ? ValidationKeyId : null,
            samplePath is null ? null : File.ReadAllText(samplePath));
        Console.WriteLine(JsonSerializer.Serialize(output, CliJsonContext.Default.PrivacyValidationOutput));
        return output.Sample is { Succeeded: false } ? 2 : 0;
    }

    /// <exception cref="InvalidDataException">The profile is invalid.</exception>
    /// <exception cref="InvalidOperationException">The profile needs an HMAC key that is missing.</exception>
    public static PrivacyValidationOutput Describe(string yaml, byte[] key, string? keyId, string? sample)
    {
        LoadedPrivacyProfile profile = PrivacyProfileLoader.Load(yaml, key, keyId);
        PrivacyPolicy policy = profile.Policy;
        PrivacyValidationSample? redacted = null;
        if (sample is not null)
        {
            PrivacyScanResult result = new PrivacyEngine(policy).RedactJson(sample);
            redacted = new PrivacyValidationSample(result.Succeeded, result.FailureCode, result.RedactedJson);
        }

        return new PrivacyValidationOutput(
            true,
            profile.Id,
            profile.Version,
            profile.Hash,
            [.. policy.CustomDetectors.Select(detector => new PrivacyValidationDetector(detector.Id, detector.Action.ToString()))],
            policy.SecretFieldNames.Count,
            profile.CustomDetectorTests,
            redacted);
    }
}
