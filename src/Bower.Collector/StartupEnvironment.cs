namespace Bower.Collector;

/// <summary>
/// The process environment as the supervisor provided it, before the start-up steps
/// (<see cref="CollectorSettingsFile"/>, <see cref="CollectorIdentityFile"/>) overwrote any
/// variable. The signed <c>reload</c> pre-check rebuilds the environment a restart will see
/// from it (<see cref="CollectorSettingsFile.RestartReader"/>).
/// </summary>
internal static class StartupEnvironment
{
    private static readonly Dictionary<string, string?> Originals = new(StringComparer.Ordinal);
    private static readonly Lock Gate = new();

    /// <summary>True once a start-up step ran against the real process environment.</summary>
    public static bool Captured { get; private set; }

    public static void RecordOriginal(Func<string, string?> read, string name, bool processEnvironment)
    {
        if (!processEnvironment)
        {
            return;
        }
        lock (Gate)
        {
            Captured = true;
            Originals.TryAdd(name, read(name));
        }
    }

    public static void MarkCaptured()
    {
        lock (Gate)
        {
            Captured = true;
        }
    }

    /// <summary>The supervisor-provided value of <paramref name="name"/>.</summary>
    public static string? Original(string name, Func<string, string?> process)
    {
        lock (Gate)
        {
            return Originals.TryGetValue(name, out string? value) ? value : process(name);
        }
    }

    public static IReadOnlyDictionary<string, string?> Snapshot()
    {
        lock (Gate)
        {
            return new Dictionary<string, string?>(Originals, StringComparer.Ordinal);
        }
    }
}
