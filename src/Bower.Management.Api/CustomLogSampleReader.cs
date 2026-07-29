using System.Text;
using Bower.Pipeline;

namespace Bower.Management.Api;

public static class CustomLogSampleReader
{
    public static async Task<string> ReadAsync(
        CustomLogInput input,
        string? configuredRoots,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        bool hasSample = !string.IsNullOrWhiteSpace(input.Sample);
        bool hasPath = !string.IsNullOrWhiteSpace(input.Path);
        if (hasSample == hasPath)
        {
            throw new ArgumentException("Provide exactly one sample or server path.");
        }

        if (hasSample)
        {
            return input.Sample!;
        }

        string[] roots = (configuredRoots ?? string.Empty)
            .Split(
                Path.PathSeparator,
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(Path.GetFullPath)
            .ToArray();
        if (roots.Length == 0)
        {
            throw new InvalidOperationException(
                "Server path input is disabled. Configure BOWER_CUSTOM_LOG_ROOTS.");
        }

        string fullPath = Path.GetFullPath(input.Path!);
        string? root = roots.FirstOrDefault(candidate => IsWithinRoot(fullPath, candidate));
        if (root is null)
        {
            throw new UnauthorizedAccessException(
                "Server path is outside configured custom-log roots.");
        }
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("Custom-log sample file was not found.");
        }

        RejectSymbolicLinks(root, fullPath);
        FileInfo information = new(fullPath);
        if (information.Length > CustomLogParser.MaximumSampleBytes)
        {
            throw new InvalidDataException(
                $"Sample cannot exceed {CustomLogParser.MaximumSampleBytes} bytes.");
        }

        await using FileStream stream = new(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using StreamReader reader = new(stream, detectEncodingFromByteOrderMarks: true);
        StringBuilder sample = new();
        char[] buffer = new char[4096];
        while (true)
        {
            int read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0)
            {
                break;
            }
            sample.Append(buffer, 0, read);
            if (sample.Length > CustomLogParser.MaximumSampleBytes)
            {
                throw new InvalidDataException(
                    $"Sample cannot exceed {CustomLogParser.MaximumSampleBytes} bytes.");
            }
        }
        return sample.ToString();
    }

    private static bool IsWithinRoot(string path, string root)
    {
        string normalizedRoot = Path.TrimEndingDirectorySeparator(root)
            + Path.DirectorySeparatorChar;
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        return path.StartsWith(normalizedRoot, comparison);
    }

    private static void RejectSymbolicLinks(string root, string path)
    {
        string relative = Path.GetRelativePath(root, path);
        string current = root;
        foreach (string segment in relative.Split(
            Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            FileSystemInfo entry = Directory.Exists(current)
                ? new DirectoryInfo(current)
                : new FileInfo(current);
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new UnauthorizedAccessException(
                    "Symbolic links are not allowed in custom-log sample paths.");
            }
        }
    }
}
