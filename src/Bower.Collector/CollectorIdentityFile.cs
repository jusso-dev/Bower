namespace Bower.Collector;

public enum CollectorIdSource
{
    /// <summary><c>BOWER_COLLECTOR_ID</c> was set; the identity file is not read or written.</summary>
    Configured,

    /// <summary>Read from <c>collector-id</c> next to the queue database.</summary>
    Persisted,

    /// <summary>First start without a configured id: the machine name was written to <c>collector-id</c>.</summary>
    Created
}

/// <summary>
/// Stable default collector id. Without <c>BOWER_COLLECTOR_ID</c> the id used to be the
/// machine name on every start, which changes whenever a container or pod is recreated and
/// breaks replay deduplication and destination identity. Now the first start writes the
/// machine name it would have used to <c>collector-id</c> beside the queue database (the
/// data volume), and later starts read it back, so existing installs keep their current id
/// and recreated containers keep theirs. The Rust collector reads and writes the same file.
/// </summary>
public static class CollectorIdentityFile
{
    public const string FileName = "collector-id";
    public const int MaximumLength = 128;

    /// <summary>Resolves the id before settings are read and exports it as <c>BOWER_COLLECTOR_ID</c>.</summary>
    public static CollectorIdSource Apply(Func<string, string?>? read = null, Action<string, string>? write = null)
    {
        bool processEnvironment = read is null;
        read ??= Environment.GetEnvironmentVariable;
        write ??= Environment.SetEnvironmentVariable;
        string queuePath = QueuePath(read);
        (string id, CollectorIdSource source) = Resolve(read("BOWER_COLLECTOR_ID"), queuePath, () => Environment.MachineName);
        if (source != CollectorIdSource.Configured)
        {
            StartupEnvironment.RecordOriginal(read, "BOWER_COLLECTOR_ID", processEnvironment);
            write("BOWER_COLLECTOR_ID", id);
        }
        return source;
    }

    /// <summary>The id a start would use; <paramref name="persist"/> false never writes (reload pre-check).</summary>
    public static (string Id, CollectorIdSource Source) Resolve(string? configured, string queuePath, Func<string> machineName, bool persist = true)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return (configured, CollectorIdSource.Configured);
        }

        string directory = Path.GetDirectoryName(Path.GetFullPath(queuePath)) ?? ".";
        string path = Path.Combine(directory, FileName);
        if (File.Exists(path))
        {
            if (new FileInfo(path).Length > MaximumLength + 2)
            {
                throw new InvalidOperationException($"{path} is not a valid collector id.");
            }
            string stored = File.ReadAllText(path).Trim();
            // Fail closed: silently replacing a persisted id would fork destination identity.
            return IsValid(stored)
                ? (stored, CollectorIdSource.Persisted)
                : throw new InvalidOperationException($"{path} is not a valid collector id; fix it or set BOWER_COLLECTOR_ID.");
        }

        string id = machineName().Trim();
        if (!IsValid(id))
        {
            throw new InvalidOperationException("The machine name is not a valid collector id; set BOWER_COLLECTOR_ID.");
        }
        if (!persist)
        {
            return (id, CollectorIdSource.Created);
        }
        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, $".{FileName}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(temporary, id + "\n");
            File.Move(temporary, path);
        }
        catch (IOException) when (File.Exists(path))
        {
            // Another process created it first; its id wins.
            return Resolve(configured, queuePath, machineName, persist);
        }
        finally
        {
            File.Delete(temporary);
        }
        return (id, CollectorIdSource.Created);
    }

    /// <summary>Default queue path when <c>BOWER_QUEUE_PATH</c> is unset (as <see cref="CollectorSettings"/>).</summary>
    public static string QueuePath(Func<string, string?> read) =>
        read("BOWER_QUEUE_PATH") is { Length: > 0 } configured ? configured : Path.Combine(AppContext.BaseDirectory, "data", "bower.db");

    public static bool IsValid(string value) =>
        value.Length is > 0 and <= MaximumLength && value.All(character => !char.IsControl(character) && !char.IsWhiteSpace(character));
}
