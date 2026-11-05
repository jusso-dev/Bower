using System.Buffers;

namespace Bower.Source.File;

/// <summary>What a configured path resolves to at read time.</summary>
public enum FileTailPathState
{
    /// <summary>A file below an allowed root, without symbolic links (or with the one allowed link).</summary>
    Ready,

    /// <summary>The file, or a directory on its path, does not exist yet. Not an error: wait.</summary>
    Missing,

    /// <summary>A symbolic link, a directory or a path outside the allowed roots. Never read.</summary>
    Refused
}

/// <summary>
/// Path guards. Configuration paths are checked lexically (absolute, normalised, no
/// wildcards, below an allowed root); at read time every directory between the root and the
/// file must exist and not be a symbolic link, and the file must not be one unless
/// <c>allowSymlink</c> is set. An allowed link is followed exactly once and its target must
/// pass the same checks. Roots themselves are trusted operator configuration and may be links.
/// <para>
/// The checks run before and after each read, which narrows but cannot close the window for
/// a link swapped in between them: roots should be directories only trusted operators (root)
/// can write to, which is the case for <c>/var/log</c>.
/// </para>
/// </summary>
public static class FileTailPaths
{
    private static readonly SearchValues<char> Wildcards = SearchValues.Create("*?[]{}");

    public static StringComparer Comparer { get; } =
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static StringComparison Comparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    /// <summary>Absolute and already normalised: no <c>.</c>, <c>..</c>, repeated or trailing separators, wildcards or control characters.</summary>
    public static bool IsCanonical(string? path)
    {
        if (path is not { Length: >= 1 and <= FileTailSourceConfigurationLoader.MaximumPathLength }
            || path.AsSpan().ContainsAny(Wildcards)
            || path.Any(char.IsControl)
            || !Path.IsPathFullyQualified(path))
        {
            return false;
        }

        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        return string.Equals(full, path, StringComparison.Ordinal)
            && (IsFileSystemRoot(path) || !Path.EndsInDirectorySeparator(path));
    }

    public static bool IsFileSystemRoot(string path) =>
        string.Equals(Path.GetPathRoot(path), path, StringComparison.Ordinal);

    /// <summary>The allowed root the path lies strictly below, or null.</summary>
    public static string? RootOf(string path, IReadOnlyList<string> roots)
    {
        ArgumentNullException.ThrowIfNull(roots);
        return roots.FirstOrDefault(root =>
            path.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar, Comparison));
    }

    /// <summary>
    /// The path with every directory resolved through symbolic links (<c>realpath</c> of the
    /// directory, then the file name), or the path as written when its directory does not
    /// exist yet. Used to spot two inputs that name the same file through linked directories.
    /// </summary>
    public static string Canonical(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        string? directory = Path.GetDirectoryName(path);
        return directory is not null && RealDirectory(directory, 0) is { } real
            ? Path.Combine(real, Path.GetFileName(path))
            : path;
    }

    private static string? RealDirectory(string directory, int depth)
    {
        if (depth > 40 || Path.GetPathRoot(directory) is not { Length: > 0 } root)
        {
            return null; // A link loop, or not an absolute path.
        }

        string current = root;
        foreach (string segment in directory[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            string next = Path.Combine(current, segment);
            DirectoryInfo info = new(next);
            if (info.LinkTarget is { } target)
            {
                if (RealDirectory(Path.GetFullPath(target, current), depth + 1) is not { } resolved)
                {
                    return null;
                }

                next = resolved;
            }
            else if (!info.Exists)
            {
                return null;
            }

            current = next;
        }

        return current;
    }

    /// <summary>The path to open, or why it cannot be read now.</summary>
    public static (FileTailPathState State, string Path) Resolve(string path, IReadOnlyList<string> roots, bool allowSymlink)
    {
        string? root = RootOf(path, roots);
        if (root is null)
        {
            return (FileTailPathState.Refused, path);
        }

        FileTailPathState directories = CheckDirectories(root, path);
        if (directories != FileTailPathState.Ready)
        {
            return (directories, path);
        }

        FileInfo file = new(path);
        if (file.LinkTarget is { } target)
        {
            if (!allowSymlink)
            {
                return (FileTailPathState.Refused, path);
            }

            string resolved = Path.GetFullPath(target, Path.GetDirectoryName(path)!);
            string? targetRoot = RootOf(resolved, roots);
            if (targetRoot is null)
            {
                return (FileTailPathState.Refused, path);
            }

            FileTailPathState targetDirectories = CheckDirectories(targetRoot, resolved);
            if (targetDirectories != FileTailPathState.Ready)
            {
                return (targetDirectories, path);
            }

            return Final(new FileInfo(resolved), resolved);
        }

        return Final(file, path);
    }

    private static (FileTailPathState State, string Path) Final(FileInfo file, string path)
    {
        if (file.LinkTarget is not null || Directory.Exists(path))
        {
            return (FileTailPathState.Refused, path);
        }

        return (file.Exists ? FileTailPathState.Ready : FileTailPathState.Missing, path);
    }

    /// <summary>Every directory strictly between the root and the file name.</summary>
    private static FileTailPathState CheckDirectories(string root, string path)
    {
        string relative = Path.GetRelativePath(root, Path.GetDirectoryName(path)!);
        if (relative == ".")
        {
            return FileTailPathState.Ready;
        }

        string current = Path.TrimEndingDirectorySeparator(root);
        foreach (string segment in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (new DirectoryInfo(current).LinkTarget is not null)
            {
                return FileTailPathState.Refused;
            }

            if (!Directory.Exists(current))
            {
                return FileTailPathState.Missing;
            }
        }

        return FileTailPathState.Ready;
    }
}
