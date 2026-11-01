using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

namespace Bower.Collector;

/// <summary>Reads operator settings through locked, non-reparse Windows handles.</summary>
[SupportedOSPlatform("windows")]
internal static partial class WindowsSettingsFile
{
    private const uint ReadControl = 0x00020000;
    private const uint ReadAttributes = 0x00000080;
    private const uint ListDirectory = 0x00000001;
    private const uint Synchronize = 0x00100000;
    private const uint GenericRead = 0x80000000;
    private const uint ShareRead = 1;
    private const uint OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint DirectoryAttribute = 0x10;
    private const uint ReparseAttribute = 0x400;

    internal static FileStream Open(string path)
    {
        // UNC/device paths have different trust and sharing semantics. The installer uses
        // a local drive path under ProgramData; accept only that Windows path family.
        string? root = Path.GetPathRoot(path);
        if (root is null || root.Length != 3 || !char.IsAsciiLetter(root[0])
            || root[1] != ':' || root[2] != '\\' || GetDriveType(root) != 3 /* DRIVE_FIXED */)
        {
            throw new InvalidOperationException("BOWER_SETTINGS_FILE must use a local fixed-drive path.");
        }
        string[] components = path[root.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (components.Length == 0 || components.Any(component => component.Contains(':')))
        {
            throw new InvalidOperationException("BOWER_SETTINGS_FILE must name a regular file, not an alternate stream.");
        }

        List<SafeFileHandle> directories = [];
        try
        {
            string current = root;
            SafeFileHandle directory = OpenHandle(current, directory: true);
            directories.Add(directory);
            Verify(directory, current, directory: true, ancestor: components.Length > 1);
            for (int index = 0; index < components.Length - 1; index++)
            {
                current = Path.Combine(current, components[index]);
                directory = OpenRelative(directory, components[index], directory: true);
                directories.Add(directory);
                Verify(directory, current, directory: true, ancestor: index < components.Length - 2);
            }

            SafeFileHandle file = OpenRelative(directory, components[^1], directory: false);
            try
            {
                Verify(file, path, directory: false, ancestor: false);
                return new FileStream(file, FileAccess.Read);
            }
            catch
            {
                file.Dispose();
                throw;
            }
        }
        finally
        {
            // Keep every ancestor locked until the final file has been opened and checked.
            // Subsequent renames cannot redirect reads through that verified file handle.
            for (int index = directories.Count - 1; index >= 0; index--) directories[index].Dispose();
        }
    }

    internal static SafeFileHandle OpenHandle(string path, bool directory)
    {
        // No sharing of delete or data-write access: existing writers cause a safe refusal,
        // and opened components cannot be replaced during the remaining path walk.
        // FILE_LIST_DIRECTORY is essential: metadata-only handles do not participate in
        // the read/write/delete sharing checks, so they would not lock the path component.
        SafeFileHandle handle = CreateFile(path, directory ? ReadControl | ReadAttributes | ListDirectory : GenericRead | ReadControl,
            ShareRead, IntPtr.Zero, OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        int error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        throw OpenError((uint)error);
    }

    internal static unsafe SafeFileHandle OpenRelative(SafeFileHandle parent, string name, bool directory)
    {
        if (name.Length is 0 or > 32_766 || name is "." or ".." || name.IndexOfAny(['\\', '/', ':', '\0']) >= 0)
            throw new InvalidOperationException("BOWER_SETTINGS_FILE contains an invalid path component.");
        bool addedReference = false;
        try
        {
            parent.DangerousAddRef(ref addedReference);
            fixed (char* characters = name)
            {
                UnicodeName component = new()
                {
                    Length = checked((ushort)(name.Length * sizeof(char))),
                    MaximumLength = checked((ushort)(name.Length * sizeof(char))),
                    Buffer = (IntPtr)characters
                };
                ObjectAttributes attributes = new()
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = parent.DangerousGetHandle(),
                    ObjectName = (IntPtr)(&component),
                    Attributes = 0x40 | 0x1000 // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
                };
                // Resolve one name against its already verified directory object, never
                // by rewalking an absolute string through mutable ancestor attributes.
                int status = NtCreateFile(out SafeFileHandle handle,
                    Synchronize | (directory ? ReadControl | ReadAttributes | ListDirectory : GenericRead | ReadControl),
                    in attributes, out _, IntPtr.Zero, 0, ShareRead, 1 /* FILE_OPEN */,
                    OpenReparsePoint | 0x20 /* FILE_SYNCHRONOUS_IO_NONALERT */
                        | (directory ? 1u /* FILE_DIRECTORY_FILE */ : 0x40u /* FILE_NON_DIRECTORY_FILE */),
                    IntPtr.Zero, 0);
                if (status >= 0 && !handle.IsInvalid) return handle;
                handle.Dispose();
                throw OpenError(RtlNtStatusToDosError(status));
            }
        }
        finally { if (addedReference) parent.DangerousRelease(); }
    }

    private static Exception OpenError(uint error) => error switch
    {
        2 => new FileNotFoundException("BOWER_SETTINGS_FILE does not exist."),
        3 => new DirectoryNotFoundException("BOWER_SETTINGS_FILE directory does not exist."),
        _ => new InvalidOperationException($"BOWER_SETTINGS_FILE cannot be opened through locked local handles (Win32 error {error}).")
    };

    private static void Verify(SafeFileHandle handle, string path, bool directory, bool ancestor)
    {
        if (!GetFileInformationByHandleEx(handle, 9 /* FileAttributeTagInfo */, out AttributeTagInfo info, 8)
            || (info.Attributes & ReparseAttribute) != 0
            || ((info.Attributes & DirectoryAttribute) != 0) != directory)
        {
            throw new InvalidOperationException("BOWER_SETTINGS_FILE must be a regular file under non-reparse directories.");
        }
        uint result = GetSecurityInfo(handle, 1 /* SE_FILE_OBJECT */, 5 /* OWNER | DACL */,
            out _, out _, out _, out _, out IntPtr descriptor);
        if (result != 0 || descriptor == IntPtr.Zero)
            throw new InvalidOperationException("BOWER_SETTINGS_FILE handle permissions cannot be verified.");
        try
        {
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length is 0 or > 1_048_576) throw new InvalidOperationException("BOWER_SETTINGS_FILE security descriptor is invalid.");
            byte[] bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            CollectorSettingsFile.VerifyWindows(new RawSecurityDescriptor(bytes, 0), path, directory, ancestor);
        }
        finally { _ = LocalFree(descriptor); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AttributeTagInfo
    {
        public uint Attributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeName
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [LibraryImport("ntdll.dll")]
    private static partial int NtCreateFile(out SafeFileHandle handle, uint access, in ObjectAttributes attributes,
        out IoStatusBlock status, IntPtr allocationSize, uint fileAttributes, uint sharing,
        uint disposition, uint options, IntPtr extendedAttributes, uint extendedAttributesLength);

    [LibraryImport("ntdll.dll")]
    private static partial uint RtlNtStatusToDosError(int status);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFile(string path, uint access, uint sharing, IntPtr security, uint creation, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", EntryPoint = "GetDriveTypeW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetDriveType(string root);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass, out AttributeTagInfo information, uint size);

    [LibraryImport("advapi32.dll")]
    private static partial uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint information,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

    [LibraryImport("advapi32.dll")]
    private static partial uint GetSecurityDescriptorLength(IntPtr descriptor);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr LocalFree(IntPtr memory);
}
