using System.IO.Compression;
using Bower.Collector;
using Bower.Integrity;
using Bower.Packs;

namespace Bower.UnitTests;

/// <summary>
/// Signed pack and trust-key rotation as an operator performs it: replace files in place,
/// then send the signed <c>reload</c> command. A reload whose restart could not load its
/// configuration is refused, so the running collector keeps its last good packs.
/// </summary>
public sealed class PackRotationTests
{
    private static string ExamplePack => Path.Combine(AppContext.BaseDirectory, "packs", "linux-ssh-gateway");

    [Theory]
    [InlineData("untrusted-key")]
    [InlineData("unsigned")]
    [InlineData("tampered-content")]
    [InlineData("malformed-manifest")]
    [InlineData("missing-pack")]
    [InlineData("missing-trusted-key")]
    [InlineData("short-hmac-key")]
    public void Reload_IsRefusedWhenTheRestartCouldNotLoadItsConfiguration(string fault)
    {
        using TemporaryDirectory directory = new();
        (string privatePem, string publicPem, _) = DetachedSigner.GenerateKeyPair();
        (string otherPrivate, _, _) = DetachedSigner.GenerateKeyPair();
        Deployment deployment = new(directory.Path);
        deployment.Install(PackArchive.Build(ExamplePack, privatePem, directory.Path), publicPem);
        CollectorSettings settings = deployment.Settings();
        Assert.Null(ManagementCommandWorker.ReloadRefusal(settings));

        switch (fault)
        {
            case "untrusted-key":
                using (TemporaryDirectory other = new())
                {
                    deployment.Install(PackArchive.Build(ExamplePack, otherPrivate, other.Path), publicPem);
                }

                break;
            case "unsigned":
                Rewrite(deployment.Pack, zip => zip.GetEntry(PackArchive.SignatureEntry)!.Delete());
                break;
            case "tampered-content":
                Rewrite(deployment.Pack, zip =>
                {
                    ZipArchiveEntry policy = zip.GetEntry("content/policies/ssh-authentication.yaml")!;
                    policy.Delete();
                    using StreamWriter writer = new(zip.CreateEntry("content/policies/ssh-authentication.yaml").Open());
                    writer.Write("apiVersion: bower.security/v1\nkind: TelemetryPolicy\n");
                });
                break;
            case "malformed-manifest":
                Rewrite(deployment.Pack, zip =>
                {
                    zip.GetEntry(PackArchive.ManifestEntry)!.Delete();
                    using StreamWriter writer = new(zip.CreateEntry(PackArchive.ManifestEntry).Open());
                    writer.Write("{\"id\": ");
                });
                break;
            case "missing-pack":
                File.Delete(deployment.Pack);
                break;
            case "missing-trusted-key":
                File.Delete(deployment.TrustedKey);
                break;
            default:
                File.WriteAllText(deployment.HmacKey, Convert.ToBase64String(new byte[8]));
                break;
        }

        string? refusal = ManagementCommandWorker.ReloadRefusal(settings);

        Assert.NotNull(refusal);
        // A type name only: never a path, key material or file content.
        Assert.DoesNotContain(directory.Path, refusal, StringComparison.Ordinal);
        Assert.Matches("^[A-Za-z]+$", refusal);
    }

    [Fact]
    public void TrustedKeyRotation_OverlapsThenRefusesPacksSignedByTheRetiredKey()
    {
        using TemporaryDirectory directory = new();
        (string oldPrivate, string oldPublic, _) = DetachedSigner.GenerateKeyPair();
        (string newPrivate, string newPublic, _) = DetachedSigner.GenerateKeyPair();
        Deployment deployment = new(directory.Path);
        string oldPack = PackArchive.Build(ExamplePack, oldPrivate, Directory.CreateDirectory(Path.Combine(directory.Path, "old")).FullName);
        string newPack = PackArchive.Build(ExamplePack, newPrivate, Directory.CreateDirectory(Path.Combine(directory.Path, "new")).FullName);

        // 1. Trust both keys (one file each) while the old-key pack is still deployed.
        deployment.Install(oldPack, oldPublic, newPublic);
        Assert.Null(ManagementCommandWorker.ReloadRefusal(deployment.Settings()));
        // 2. Deploy the pack re-signed by the new key.
        deployment.Install(newPack, oldPublic, newPublic);
        Assert.Null(ManagementCommandWorker.ReloadRefusal(deployment.Settings()));
        // 3. Retire the old key.
        deployment.Install(newPack, newPublic);
        Assert.Null(ManagementCommandWorker.ReloadRefusal(deployment.Settings()));
        // A pack signed by the retired key no longer loads, so its reload is refused.
        deployment.Install(oldPack, newPublic);
        Assert.NotNull(ManagementCommandWorker.ReloadRefusal(deployment.Settings()));
        // One key per file: two keys concatenated into one file fail closed.
        deployment.Install(newPack, oldPublic + newPublic);
        Assert.NotNull(ManagementCommandWorker.ReloadRefusal(deployment.Settings()));
    }

    private static void Rewrite(string archive, Action<ZipArchive> change)
    {
        using ZipArchive zip = ZipFile.Open(archive, ZipArchiveMode.Update);
        change(zip);
    }

    /// <summary>Files laid out as an installer does: one pack, its trust key file and an HMAC key.</summary>
    private sealed class Deployment(string directory)
    {
        public string Pack { get; } = Path.Combine(directory, "deployed", "pack.bowerpack");

        public string TrustedKey { get; } = Path.Combine(directory, "deployed", "pack-trusted.pem");

        private string[] trustedKeyFiles = [];

        public string HmacKey { get; } = Path.Combine(directory, "deployed", "privacy-hmac.key");

        public void Install(string archive, params string[] trustedKeys)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Pack)!);
            File.Copy(archive, Pack, overwrite: true);
            File.WriteAllText(TrustedKey, trustedKeys[0]);
            trustedKeyFiles = [TrustedKey, .. trustedKeys.Skip(1).Select((key, index) =>
            {
                string path = Path.Combine(directory, "deployed", $"pack-trusted-{index + 2}.pem");
                File.WriteAllText(path, key);
                return path;
            })];
            if (!File.Exists(HmacKey))
            {
                File.WriteAllText(HmacKey, Convert.ToBase64String(new byte[32]));
            }
        }

        public CollectorSettings Settings() => new()
        {
            ListenUrl = "http://127.0.0.1:4319",
            QueuePath = Path.Combine(directory, "data", "queue.db"),
            PolicyDirectory = Path.Combine(directory, "no-local-policies"),
            CollectorId = "collector-1",
            Packs = [Pack],
            PackTrustedKeyFiles = trustedKeyFiles,
            PrivacyHmacKeyFile = HmacKey,
            PrivacyHmacKeyId = "k1"
        };
    }
}
