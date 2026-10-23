using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Tools.QueueMigrationCheck;

public static class MigrationCheckCommand
{
    public static async Task<int> RunAsync(string[] args, TextWriter output, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (args is not ["--database", string path])
        {
            await output.WriteLineAsync("Usage: queue-migration-check --database PATH");
            return 1;
        }

        MigrationCheckReport report = await MigrationPreflight.CheckAsync(path, cancellationToken);
        await output.WriteLineAsync(JsonSerializer.Serialize(report, ReportJsonContext.Default.MigrationCheckReport));
        return report.Complete ? (report.Collisions.Count == 0 ? 0 : 2) : 1;
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(MigrationCheckReport))]
internal sealed partial class ReportJsonContext : JsonSerializerContext;
