using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Bower.Source.File;

/// <summary>The opened file is not the validated regular file (a link or another file was swapped in).</summary>
public sealed class FileTailRefusedException() : IOException(FileTailFailures.PathRefused);

/// <summary>
/// One generation of a tailed file, opened once: its identity, length and write time come
/// from the same handle the lines are read from, so bytes of one generation can never move
/// another generation's cursor.
/// </summary>
public sealed class FileTailHandle : IDisposable
{
    /// <summary>The identity covers the first complete line, at least 64 and at most 4096 bytes.</summary>
    public const int MinimumIdentityBytes = 64;
    public const int MaximumIdentityBytes = 4_096;

    /// <summary>Tests only: runs before a validated path is opened (to swap the path).</summary>
    [ThreadStatic]
    internal static Action<string>? BeforeOpen;

    /// <summary>Tests only: runs once a path is opened and identified (to replace or rewrite the file).</summary>
    [ThreadStatic]
    internal static Action<string>? AfterOpen;

    /// <summary>
    /// Tests only: the <c>device:inode</c> of a path, replacing the platform's (the shared
    /// vectors model file identities so every platform agrees with the Rust port's real ones).
    /// </summary>
    [ThreadStatic]
    internal static Func<string, string?>? FileIds;

    /// <summary>Tests only: runs after the 64-byte length check of <see cref="OpenWithPrefixIdentity"/> (to shrink the file).</summary>
    [ThreadStatic]
    internal static Action<string>? BeforePrefixRead;

    /// <summary>Tests only: the most bytes one <see cref="ReadFully"/> read returns (a filesystem that returns short reads).</summary>
    [ThreadStatic]
    internal static int? ShortReads;

    /// <summary>The Docker json-file identity: SHA-256 of the first 64 bytes.</summary>
    public const int PrefixIdentityBytes = 64;

    private FileTailHandle(FileStream stream, long length, DateTime writeTime, string? fingerprint, string? fileId = null)
    {
        Stream = stream;
        Length = length;
        WriteTime = writeTime;
        Fingerprint = fingerprint;
        FileId = fileId;
    }

    public FileStream Stream { get; }

    /// <summary>
    /// Length when opened; bytes appended later wait for the next read. A policy that measures
    /// again (<see cref="FileTailLength.Measured"/>) uses <see cref="Stream"/>'s length instead.
    /// </summary>
    public long Length { get; }

    public DateTime WriteTime { get; }

    /// <summary>Null while the first line is incomplete (and shorter than 4096 bytes).</summary>
    public string? Fingerprint { get; }

    /// <summary><c>device:inode</c> of the opened file (Linux only), or null.</summary>
    public string? FileId { get; }

    /// <summary>Write time as 100 ns ticks since the Unix epoch (comparable across runtimes).</summary>
    public long WriteTicks => WriteTime.Ticks - DateTime.UnixEpoch.Ticks;

    /// <summary>
    /// Opens a path already checked by <see cref="FileTailPaths"/>, or returns null when it is
    /// missing or shorter than 64 bytes (never opened, so FIFOs and devices never block). On
    /// Linux the open does not follow a final symbolic link and does not block, and the
    /// handle must be a regular file with the same device and inode as the path; elsewhere
    /// the path must still not be a link after opening.
    /// </summary>
    /// <exception cref="FileTailRefusedException">The handle is not the validated regular file.</exception>
    public static FileTailHandle? Open(string? path)
    {
        if (path is null)
        {
            return null;
        }

        FileInfo info = new(path);
        if (info.LinkTarget is not null)
        {
            throw new FileTailRefusedException();
        }

        if (!info.Exists || info.Length < MinimumIdentityBytes)
        {
            return null;
        }

        BeforeOpen?.Invoke(path);
        FileStream stream;
        string? fileId = null;
        try
        {
            if (OperatingSystem.IsLinux())
            {
                (stream, fileId) = LinuxTailFile.Open(path);
            }
            else
            {
                stream = OpenShared(path);
            }
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }

        try
        {
            if (!OperatingSystem.IsLinux() && new FileInfo(path).LinkTarget is not null)
            {
                throw new FileTailRefusedException();
            }

            fileId = FileIds is { } ids ? ids(path) : fileId;
            long length = stream.Length;
            DateTime writeTime = System.IO.File.GetLastWriteTimeUtc(stream.SafeFileHandle);
            FileTailHandle handle = new(stream, length, writeTime, Identity(stream, length), fileId);
            AfterOpen?.Invoke(path);
            return handle;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The Docker source's open, exactly as before the shared tailer: a plain shared read
    /// (no link or handle checks; the Docker root is mounted read-only) and an identity of the
    /// first 64 bytes. Null when the file is missing or shorter. A file that shrinks between
    /// the length check and the read throws <see cref="EndOfStreamException"/>, which the
    /// sidecar logs and backs off from, as it did.
    /// </summary>
    public static FileTailHandle? OpenWithPrefixIdentity(string path)
    {
        FileStream stream;
        try
        {
            stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65_536);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }

        try
        {
            long length = stream.Length;
            if (length < PrefixIdentityBytes)
            {
                stream.Dispose();
                return null;
            }

            BeforePrefixRead?.Invoke(path);
            // Read past the stream's buffer, so the scan reads the file as it is then, as the
            // reader's separate opens did, never bytes buffered while the identity was read.
            byte[] prefix = new byte[PrefixIdentityBytes];
            if (ReadFully(stream.SafeFileHandle, prefix, 0) < PrefixIdentityBytes)
            {
                throw new EndOfStreamException();
            }

            FileTailHandle handle = new(stream, length, default, Convert.ToHexStringLower(SHA256.HashData(prefix)));
            AfterOpen?.Invoke(path);
            return handle;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Reads at <paramref name="offset"/> until <paramref name="buffer"/> is full or a read
    /// returns 0 (end of file), as a stream's <c>ReadExactly</c> and <c>ReadAtLeast</c> do: FUSE
    /// and network filesystems may return fewer bytes than asked before the end.
    /// </summary>
    internal static int ReadFully(SafeFileHandle handle, Span<byte> buffer, long offset)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            Span<byte> rest = buffer[total..];
            int read = RandomAccess.Read(handle, ShortReads is { } most ? rest[..Math.Min(most, rest.Length)] : rest, offset + total);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    /// <summary>
    /// <c>device:inode</c> of the regular file at <paramref name="path"/> without opening it
    /// (Linux only; null elsewhere, when missing or not a regular file).
    /// </summary>
    public static string? FileIdOf(string? path) =>
        path is null ? null
        : FileIds is { } ids ? ids(path)
        : OperatingSystem.IsLinux() ? LinuxTailFile.FileIdOf(path) : null;

    /// <summary>The identity of the file at <paramref name="path"/>, or null (tests and tools).</summary>
    public static string? FingerprintOf(string path)
    {
        using FileTailHandle? handle = Open(path);
        return handle?.Fingerprint;
    }

    public void Dispose() => Stream.Dispose();

    /// <summary>
    /// SHA-256 over the first complete line, extended to 64 bytes and capped at 4096. A line
    /// still being written has no identity yet (unless 4096 bytes already arrived).
    /// </summary>
    private static string? Identity(FileStream stream, long length)
    {
        int available = (int)Math.Min(length, MaximumIdentityBytes);
        byte[] prefix = new byte[available];
        int read = RandomAccess.Read(stream.SafeFileHandle, prefix, 0);
        if (read < MinimumIdentityBytes)
        {
            return null;
        }

        int newline = prefix.AsSpan(0, read).IndexOf((byte)'\n');
        int identity = newline >= 0 ? Math.Max(MinimumIdentityBytes, newline + 1)
            : read == MaximumIdentityBytes ? MaximumIdentityBytes : -1;
        return identity < 0 || identity > read ? null : Convert.ToHexStringLower(SHA256.HashData(prefix.AsSpan(0, identity)));
    }

    private static FileStream OpenShared(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4_096);
}

/// <summary>
/// Linux opens through libc, as the settings loader does: <c>O_NOFOLLOW | O_NONBLOCK</c>,
/// then <c>statx</c> on the handle (a regular file) and on the path without following links
/// (same device and inode), so a link or another file swapped in after validation is refused.
/// </summary>
internal static partial class LinuxTailFile
{
    private const int ReadOnly = 0;
    private const int CloseOnExec = 0x80000;
    private const int NonBlock = 0x800;
    private const int CurrentDirectory = -100;
    private const int EmptyPath = 0x1000;
    private const int SymlinkNoFollow = 0x100;
    private const uint TypeAndInode = 0x1 | 0x100;
    private const ushort TypeMask = 0xf000;
    private const ushort RegularType = 0x8000;

    /// <summary>
    /// <c>open</c> flags per architecture: <c>O_NOFOLLOW</c> is 0x20000 on x86-64 but 0x8000 on
    /// arm64 (where 0x20000 is <c>O_LARGEFILE</c>). Other architectures get null: the file is
    /// opened without it and only the post-open checks apply (fail closed).
    /// </summary>
    internal static int? OpenFlags(Architecture architecture) => architecture switch
    {
        Architecture.X64 => ReadOnly | 0x20000 | CloseOnExec | NonBlock,
        Architecture.Arm64 => ReadOnly | 0x8000 | CloseOnExec | NonBlock,
        _ => null
    };

    internal static (FileStream Stream, string FileId) Open(string path)
    {
        SafeFileHandle handle;
        if (OpenFlags(RuntimeInformation.ProcessArchitecture) is { } flags)
        {
            int descriptor = OpenNative(path, flags);
            if (descriptor < 0)
            {
                int error = Marshal.GetLastPInvokeError();
                throw error switch
                {
                    2 => new FileNotFoundException(),
                    40 => new FileTailRefusedException(), // ELOOP: the path is a symbolic link.
                    _ => new IOException(FileTailFailures.ReadFailed)
                };
            }

            handle = new SafeFileHandle(descriptor, ownsHandle: true);
        }
        else
        {
            handle = System.IO.File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }

        try
        {
            if (StatxHandle(handle, "", EmptyPath, TypeAndInode, out Statx opened) != 0
                || (opened.Mask & TypeAndInode) != TypeAndInode
                || (opened.Mode & TypeMask) != RegularType
                || StatxPath(CurrentDirectory, path, SymlinkNoFollow, TypeAndInode, out Statx named) != 0
                || (named.Mask & TypeAndInode) != TypeAndInode
                || opened.Inode != named.Inode
                || opened.DeviceMajor != named.DeviceMajor
                || opened.DeviceMinor != named.DeviceMinor)
            {
                throw new FileTailRefusedException();
            }

            return (new FileStream(handle, FileAccess.Read, 4_096), Id(opened));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static string? FileIdOf(string path) =>
        StatxPath(CurrentDirectory, path, SymlinkNoFollow, TypeAndInode, out Statx named) == 0
        && (named.Mask & TypeAndInode) == TypeAndInode
        && (named.Mode & TypeMask) == RegularType
            ? Id(named)
            : null;

    /// <summary>glibc <c>makedev</c>, so the device number equals Rust's <c>st_dev</c>.</summary>
    internal static string Id(Statx stat)
    {
        ulong major = stat.DeviceMajor;
        ulong minor = stat.DeviceMinor;
        ulong device = ((major & 0x00000fffUL) << 8) | ((major & 0xfffff000UL) << 32)
            | (minor & 0x000000ffUL) | ((minor & 0xffffff00UL) << 12);
        return string.Create(CultureInfo.InvariantCulture, $"{device}:{stat.Inode}");
    }

    /// <summary><c>struct statx</c>: the same layout on every Linux architecture.</summary>
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    internal struct Statx
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(28)] public ushort Mode;
        [FieldOffset(32)] public ulong Inode;
        [FieldOffset(136)] public uint DeviceMajor;
        [FieldOffset(140)] public uint DeviceMinor;
    }

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenNative(string path, int flags);

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int StatxHandle(SafeFileHandle descriptor, string path, int flags, uint mask, out Statx buffer);

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int StatxPath(int directory, string path, int flags, uint mask, out Statx buffer);
}
