using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace Bower.Collector;

public enum SettingsFileState
{
    /// <summary><c>BOWER_SETTINGS_FILE</c> is unset.</summary>
    NotConfigured,

    /// <summary>The path is set but no file exists (a fresh MSI install). Not an error.</summary>
    NotPresent,

    /// <summary>The file passed its trust checks and its settings were applied.</summary>
    Applied
}

public sealed record SettingsFileResult(SettingsFileState State, string? Path, int Count);

/// <summary>
/// Optional operator settings file (<c>BOWER_SETTINGS_FILE</c>), applied to the process
/// environment before settings are read. File values override the service environment.
/// The MSI points it at <c>%ProgramData%\Bower\bower.env</c>, which upgrades and repairs never
/// rewrite. Format: one <c>KEY=VALUE</c> per line, only <c>BOWER_*</c> and <c>AZURE_*</c>
/// names, <c>#</c> or <c>;</c> comment lines, and a value optionally enclosed in one matching
/// pair of single or double quotes. There are no escapes, variable expansion or line
/// continuations (simpler than systemd <c>EnvironmentFile=</c>). Because the file can change
/// trust anchors, outputs and paths, it must be writable only by trusted principals: on
/// Windows only SYSTEM, Administrators or TrustedInstaller may own it or hold write rights on it
/// and its folder; on Unix it and its folder must not be group- or world-writable, must not be
/// a symbolic link, and (Linux) must be owned by root or the service account. A missing file is
/// not an error (fresh installs have none) unless a <c>.txt</c> sibling suggests a renamed file;
/// a file that exists but fails these checks or cannot be read stops startup. Values are never
/// echoed in errors.
/// </summary>
public static partial class CollectorSettingsFile
{
    public const string Variable = "BOWER_SETTINGS_FILE";
    public const long MaximumBytes = 65_536;
    public const int MaximumEntries = 256;

    public static SettingsFileResult Apply(
        Func<string, string?>? read = null,
        Action<string, string>? write = null)
    {
        read ??= Environment.GetEnvironmentVariable;
        write ??= Environment.SetEnvironmentVariable;
        string? path = read(Variable);
        if (string.IsNullOrWhiteSpace(path))
        {
            return new SettingsFileResult(SettingsFileState.NotConfigured, null, 0);
        }

        Dictionary<string, string>? values = Load(path);
        if (values is null)
        {
            return new SettingsFileResult(SettingsFileState.NotPresent, path, 0);
        }
        foreach ((string key, string value) in values)
        {
            write(key, value);
        }
        return new SettingsFileResult(SettingsFileState.Applied, path, values.Count);
    }

    /// <summary>Null when the file does not exist; otherwise the verified, parsed settings.</summary>
    public static Dictionary<string, string>? Load(string path)
    {
        string full = Path.GetFullPath(path);
        string content;
        try
        {
            using FileStream stream = new(full, FileMode.Open, FileAccess.Read, FileShare.Read);
            VerifyTrusted(full);
            if (stream.Length > MaximumBytes)
            {
                throw new InvalidOperationException($"{Variable} exceeds {MaximumBytes} bytes.");
            }
            using StreamReader reader = new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            content = reader.ReadToEnd();
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            if (File.Exists(full + ".txt"))
            {
                throw new InvalidOperationException(
                    $"{Variable} {full} does not exist but {Path.GetFileName(full)}.txt does; rename it (editors can add .txt).");
            }
            return null;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
        {
            throw new InvalidOperationException($"{Variable} {full} exists but cannot be read by the collector.", exception);
        }
        return Parse(content);
    }

    public static Dictionary<string, string> Parse(string content)
    {
        Dictionary<string, string> values = new(StringComparer.Ordinal);
        string[] lines = content.Split('\n');
        for (int index = 0; index < lines.Length; index++)
        {
            string line = lines[index].Trim();
            if (line.Length == 0 || line[0] is '#' or ';')
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
            if (value.Length > 0 && value[0] is '"' or '\'')
            {
                if (value.Length < 2 || value[^1] != value[0])
                {
                    throw new InvalidOperationException($"{Variable} line {index + 1} has an unterminated quote.");
                }
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

    /// <summary>Fails closed unless only trusted principals can change the file or its folder.</summary>
    public static void VerifyTrusted(string path)
    {
        string directory = Path.GetDirectoryName(path) ?? ".";
        if (new FileInfo(path).LinkTarget is not null)
        {
            throw new InvalidOperationException($"{Variable} must not be a symbolic link.");
        }
        if (OperatingSystem.IsWindows())
        {
            VerifyWindows(new FileInfo(path).GetAccessControl(), path, directory: false);
            VerifyWindows(new DirectoryInfo(directory).GetAccessControl(), directory, directory: true);
            return;
        }
        foreach (string item in new[] { path, directory })
        {
            if ((File.GetUnixFileMode(item) & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            {
                throw new InvalidOperationException($"{Variable}: {item} must not be group- or world-writable.");
            }
            if (OperatingSystem.IsLinux())
            {
                uint owner = UnixOwner(item);
                if (owner != 0 && owner != GetEffectiveUserId())
                {
                    throw new InvalidOperationException($"{Variable}: {item} must be owned by root or the collector's account.");
                }
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void VerifyWindows(FileSystemSecurity security, string item, bool directory)
    {
        const FileSystemRights WriteRights =
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
            | FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership
            | (FileSystemRights)0x40000000 /* GENERIC_WRITE */ | (FileSystemRights)0x10000000 /* GENERIC_ALL */;
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !IsTrustedWindows(owner))
        {
            throw new InvalidOperationException(
                $"{Variable}: {item} must be owned by SYSTEM or Administrators (icacls \"{item}\" /setowner *S-1-5-32-544).");
        }
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            // Inherit-only entries on the folder apply to children, which are checked themselves.
            bool appliesHere = !directory || !rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly);
            if (rule.AccessControlType == AccessControlType.Allow && appliesHere && (rule.FileSystemRights & WriteRights) != 0
                && !IsTrustedWindows((SecurityIdentifier)rule.IdentityReference))
            {
                throw new InvalidOperationException(
                    $"{Variable}: {item} grants write access to {rule.IdentityReference.Value}; only SYSTEM and Administrators may write it.");
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsTrustedWindows(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
        || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
        || sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; // TrustedInstaller

    /// <summary>Owner uid with Linux <c>statx</c> (fixed layout on every architecture), not following links.</summary>
    [SupportedOSPlatform("linux")]
    private static unsafe uint UnixOwner(string path)
    {
        const int AtFdCwd = -100;
        const int AtSymlinkNoFollow = 0x100;
        const uint StatxUid = 0x8;
        byte* buffer = stackalloc byte[256];
        if (Statx(AtFdCwd, path, AtSymlinkNoFollow, StatxUid, buffer) != 0 || (*(uint*)buffer & StatxUid) == 0)
        {
            throw new InvalidOperationException($"{Variable}: cannot read the owner of {path}.");
        }
        return *(uint*)(buffer + 20);
    }

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int Statx(int directory, string path, int flags, uint mask, byte* buffer);

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint GetEffectiveUserId();

    [GeneratedRegex("^(BOWER|AZURE)_[A-Z0-9_]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex Name();
}
