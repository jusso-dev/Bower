using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Bower.Collector;

/// <summary>Opens a settings file through verified Linux directory handles.</summary>
[SupportedOSPlatform("linux")]
internal static partial class LinuxSettingsFile
{
    private const int ReadOnly = 0;
    private const int DirectoryOnly = 0x10000;
    private const int NoFollow = 0x20000;
    private const int CloseOnExec = 0x80000;
    private const int NonBlock = 0x800;
    private const int EmptyPath = 0x1000;
    private const uint RequiredStat = 0x1 | 0x2 | 0x8; // type, mode and owner
    private const ushort TypeMask = 0xf000;
    private const ushort DirectoryType = 0x4000;
    private const ushort RegularType = 0x8000;
    private const ushort GroupOrOtherWrite = 0x12;
    private const ushort Sticky = 0x200;

    internal static FileStream Open(string path)
    {
        string[] components = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (components.Length == 0 || !Path.IsPathFullyQualified(path))
        {
            throw new InvalidOperationException("BOWER_SETTINGS_FILE must name a file.");
        }

        using SafeFileHandle root = OpenHandle(OpenNative("/", ReadOnly | DirectoryOnly | CloseOnExec));
        Verify(root, directory: true);
        SafeFileHandle? parent = null;
        try
        {
            SafeFileHandle current = root;
            for (int i = 0; i < components.Length - 1; i++)
            {
                SafeFileHandle next = OpenHandle(OpenAt(current, components[i], ReadOnly | DirectoryOnly | NoFollow | CloseOnExec));
                try { Verify(next, directory: true); }
                catch { next.Dispose(); throw; }
                parent?.Dispose();
                parent = next;
                current = next;
            }

            SafeFileHandle file = OpenHandle(OpenAt(current, components[^1], ReadOnly | NoFollow | CloseOnExec | NonBlock));
            try
            {
                Verify(file, directory: false);
                return new FileStream(file, FileAccess.Read);
            }
            catch { file.Dispose(); throw; }
        }
        finally { parent?.Dispose(); }
    }

    private static SafeFileHandle OpenHandle(int descriptor)
    {
        if (descriptor >= 0) return new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
        int error = Marshal.GetLastPInvokeError();
        if (error == 2) throw new FileNotFoundException("BOWER_SETTINGS_FILE does not exist.");
        if (error == 40) throw new InvalidOperationException("BOWER_SETTINGS_FILE must not be a symbolic link.");
        throw new InvalidOperationException("BOWER_SETTINGS_FILE cannot be read through trusted non-symbolic directories.");
    }

    private static unsafe void Verify(SafeFileHandle handle, bool directory)
    {
        byte* stat = stackalloc byte[256];
        if (Statx(handle, "", EmptyPath, RequiredStat, stat) != 0 || (*(uint*)stat & RequiredStat) != RequiredStat)
            throw new InvalidOperationException("BOWER_SETTINGS_FILE ownership and mode cannot be verified.");
        uint owner = *(uint*)(stat + 20);
        ushort mode = *(ushort*)(stat + 28);
        if (owner != 0 && owner != GetEffectiveUserId())
            throw new InvalidOperationException("BOWER_SETTINGS_FILE path must be owned by root or the collector's account.");
        if ((mode & TypeMask) != (directory ? DirectoryType : RegularType))
            throw new InvalidOperationException("BOWER_SETTINGS_FILE must be a regular file under trusted directories.");
        // A trusted-owned sticky directory such as /tmp protects existing children from
        // replacement by other users. Its children are opened without following links and
        // independently verified. Non-sticky writable directories cannot provide this.
        if ((mode & GroupOrOtherWrite) != 0 && !(directory && (mode & Sticky) != 0))
            throw new InvalidOperationException("BOWER_SETTINGS_FILE path must not be group- or world-writable.");
    }

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenNative(string path, int flags);

    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAt(SafeFileHandle directory, string path, int flags);

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static unsafe partial int Statx(SafeFileHandle descriptor, string path, int flags, uint mask, byte* buffer);

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint GetEffectiveUserId();
}
