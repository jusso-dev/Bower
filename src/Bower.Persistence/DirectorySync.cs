using System.Runtime.InteropServices;

namespace Bower.Persistence;

/// <summary>
/// Flushes a directory's entries to disk (<c>fsync</c> on the directory), so a file renamed
/// into it survives a power loss. .NET has no managed API for this: file handles refuse
/// directories. Linux and macOS only; elsewhere (Windows journals renames) it is a no-op.
/// </summary>
internal static partial class DirectorySync
{
    private const int ReadOnly = 0;
    private const int LinuxCloseOnExec = 0x80000;
    private const int MacCloseOnExec = 0x1000000;
    private const int InvalidArgument = 22;
    private const int LinuxNotSupported = 95;
    private const int MacNotSupported = 45;

    public static void Flush(string directory)
    {
        int flags;
        int notSupported;
        if (OperatingSystem.IsLinux())
        {
            flags = ReadOnly | LinuxCloseOnExec;
            notSupported = LinuxNotSupported;
        }
        else if (OperatingSystem.IsMacOS())
        {
            flags = ReadOnly | MacCloseOnExec;
            notSupported = MacNotSupported;
        }
        else
        {
            return;
        }

        int descriptor = Open(directory, flags);
        if (descriptor < 0)
        {
            throw new IOException(
                $"The archive directory could not be opened for fsync (errno {Marshal.GetLastPInvokeError()}).");
        }

        try
        {
            if (FileSync(descriptor) != 0)
            {
                int error = Marshal.GetLastPInvokeError();
                // File systems that cannot sync a directory report EINVAL or ENOTSUP; there
                // is nothing more to make durable there, and retrying would never succeed.
                if (error != InvalidArgument && error != notSupported)
                {
                    throw new IOException($"The archive directory could not be synced to disk (errno {error}).");
                }
            }
        }
        finally
        {
            _ = Close(descriptor);
        }
    }

    // "libc" resolves to the platform C library on Linux (glibc and musl) and macOS.
    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags);

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static partial int FileSync(int descriptor);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int Close(int descriptor);
}
