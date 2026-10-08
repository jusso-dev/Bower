namespace Bower.Cli.Commands;

internal static class CliOptions
{
    public static string? Get(string[] args, string name)
    {
        int index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    public static string Required(string[] args, string name) =>
        Get(args, name) ?? throw new ArgumentException($"{name} is required.");

    public static IReadOnlyList<string> All(string[] args, string name)
    {
        List<string> values = [];
        for (int index = 0; index < args.Length - 1; index++)
        {
            if (args[index] == name)
            {
                values.Add(args[index + 1]);
            }
        }

        return values;
    }

    public static bool Has(string[] args, string name) => Array.IndexOf(args, name) >= 0;

    /// <summary>First argument that is not an option or an option's value.</summary>
    public static string? Positional(string[] args)
    {
        for (int index = 0; index < args.Length; index++)
        {
            if (args[index].StartsWith("--", StringComparison.Ordinal))
            {
                index++;
                continue;
            }

            return args[index];
        }

        return null;
    }

    public static int Int(string[] args, string name, int fallback) =>
        Get(args, name) is { } value ? int.Parse(value, System.Globalization.CultureInfo.InvariantCulture) : fallback;
}
