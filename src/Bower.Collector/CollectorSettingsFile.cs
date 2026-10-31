using System.Text.RegularExpressions;

namespace Bower.Collector;

/// <summary>
/// Optional operator settings file (<c>BOWER_SETTINGS_FILE</c>) with <c>KEY=VALUE</c> lines,
/// applied to the process environment before settings are read, like systemd's
/// <c>EnvironmentFile=</c>: file values override the service environment. The MSI points it at
/// <c>%ProgramData%\Bower\bower.env</c>, which upgrades and repairs never rewrite. A missing
/// file is not an error. Only <c>BOWER_*</c> and <c>AZURE_*</c> names are accepted; malformed
/// or duplicate lines, and a group- or world-writable file on Unix, fail startup. Values are
/// never echoed in errors.
/// </summary>
public static partial class CollectorSettingsFile
{
    public const string Variable = "BOWER_SETTINGS_FILE";
    public const long MaximumBytes = 65_536;
    public const int MaximumEntries = 256;

    public static IReadOnlyDictionary<string, string> Apply(
        Func<string, string?>? read = null,
        Action<string, string>? write = null)
    {
        read ??= Environment.GetEnvironmentVariable;
        write ??= Environment.SetEnvironmentVariable;
        string? path = read(Variable);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new Dictionary<string, string>();
        }

        Dictionary<string, string> values = Parse(path);
        foreach ((string key, string value) in values)
        {
            write(key, value);
        }
        return values;
    }

    public static Dictionary<string, string> Parse(string path)
    {
        FileInfo file = new(path);
        if (file.Length > MaximumBytes)
        {
            throw new InvalidOperationException($"{Variable} exceeds {MaximumBytes} bytes.");
        }
        if (!OperatingSystem.IsWindows()
            && (file.UnixFileMode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
        {
            throw new InvalidOperationException($"{Variable} must not be group- or world-writable.");
        }

        Dictionary<string, string> values = new(StringComparer.Ordinal);
        string[] lines = File.ReadAllLines(path);
        for (int index = 0; index < lines.Length; index++)
        {
            string line = lines[index].Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }
            int equals = line.IndexOf('=', StringComparison.Ordinal);
            string key = equals < 0 ? line : line[..equals].Trim();
            if (equals < 0 || !Name().IsMatch(key) || key == Variable)
            {
                throw new InvalidOperationException($"{Variable} line {index + 1} is not a BOWER_* or AZURE_* KEY=VALUE setting.");
            }
            string value = line[(equals + 1)..].Trim();
            if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
            {
                value = value[1..^1];
            }
            if (!values.TryAdd(key, value))
            {
                throw new InvalidOperationException($"{Variable} line {index + 1} repeats {key}.");
            }
            if (values.Count > MaximumEntries)
            {
                throw new InvalidOperationException($"{Variable} has more than {MaximumEntries} settings.");
            }
        }
        return values;
    }

    [GeneratedRegex("^(BOWER|AZURE)_[A-Z0-9_]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex Name();
}
