using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Bower.Collector;
using Microsoft.Win32.SafeHandles;

namespace Bower.UnitTests;

/// <summary>Real Win32 handle, ACL and reparse tests; required by the Windows CI job.</summary>
public sealed class WindowsSettingsFileTests
{
    [Fact]
    public void Load_UsesVerifiedHandlesAndRejectsUntrustedWindowsPaths()
    {
        if (!OperatingSystem.IsWindows() || !IsAdministrator())
        {
            Assert.False(Environment.GetEnvironmentVariable("BOWER_REQUIRE_WINDOWS_SETTINGS_TESTS") == "1",
                "Windows settings tests require an elevated Windows runner.");
            Assert.Skip("Requires Windows administrator rights to create the protected test fixture.");
            return;
        }
        Run();
    }

    [SupportedOSPlatform("windows")]
    private static void Run()
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Bower.SettingsTest." + Guid.NewGuid().ToString("N"));
        DirectorySecurity directories = new();
        Protect(directories);
        new DirectoryInfo(root).Create(directories);
        try
        {
            string outer = Path.Combine(root, "outer");
            string inner = Path.Combine(outer, "inner");
            new DirectoryInfo(outer).Create(directories);
            new DirectoryInfo(inner).Create(directories);
            string path = Path.Combine(inner, "bower.env");
            FileSecurity fileAcl = new();
            Protect(fileAcl);
            using (FileStream file = new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.None, 4096, FileOptions.None, fileAcl))
            using (StreamWriter writer = new(file)) writer.Write("BOWER_OUTPUT=none");

            Assert.Equal("none", CollectorSettingsFile.Load(path)!["BOWER_OUTPUT"]);
            using (SafeFileHandle lockedDirectory = WindowsSettingsFile.OpenHandle(outer, directory: true))
            {
                Exception? rename = Record.Exception(() => Directory.Move(outer, outer + ".renamed"));
                Assert.True(rename is IOException or UnauthorizedAccessException,
                    "A verified directory handle must prevent renaming its path component.");
                Assert.True(Directory.Exists(outer));
            }
            using (FileStream verified = WindowsSettingsFile.Open(path))
            {
                Assert.Throws<IOException>(() => File.Move(path, path + ".replaced"));
                using StreamReader reader = new(verified);
                Assert.Equal("BOWER_OUTPUT=none", reader.ReadToEnd());
            }
            using (FileStream writer = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
            {
                Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(path));
            }

            SecurityIdentifier users = new(WellKnownSidType.BuiltinUsersSid, null);
            fileAcl.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.WriteData, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(fileAcl);
            Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(path));
            fileAcl = new();
            Protect(fileAcl);
            new FileInfo(path).SetAccessControl(fileAcl);

            DirectorySecurity writableAncestor = new();
            Protect(writableAncestor);
            writableAncestor.AddAccessRule(new FileSystemAccessRule(users,
                FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes, AccessControlType.Allow));
            new DirectoryInfo(outer).SetAccessControl(writableAncestor);
            AssertUsersHaveRights(outer, users, FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes);
            Assert.Equal("none", CollectorSettingsFile.Load(path)!["BOWER_OUTPUT"]);
            // These same grants are unsafe on the immediate settings directory.
            // SetAccessControl consumes the descriptor's modification flags, so construct a
            // fresh descriptor rather than reusing the one already persisted for outer.
            DirectorySecurity writableImmediate = new();
            Protect(writableImmediate);
            writableImmediate.AddAccessRule(new FileSystemAccessRule(users,
                FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes, AccessControlType.Allow));
            new DirectoryInfo(inner).SetAccessControl(writableImmediate);
            AssertUsersHaveRights(inner, users, FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes);
            Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(path));
            DirectorySecurity restoredInner = new();
            Protect(restoredInner);
            new DirectoryInfo(inner).SetAccessControl(restoredInner);
            writableAncestor.AddAccessRule(new FileSystemAccessRule(users,
                FileSystemRights.DeleteSubdirectoriesAndFiles, AccessControlType.Allow));
            new DirectoryInfo(outer).SetAccessControl(writableAncestor);
            AssertUsersHaveRights(outer, users, FileSystemRights.DeleteSubdirectoriesAndFiles);
            Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(path));
            DirectorySecurity restoredOuter = new();
            Protect(restoredOuter);
            new DirectoryInfo(outer).SetAccessControl(restoredOuter);

            // A locked handle to a junction/symlink is checked as a reparse point;
            // its trusted target must never turn an untrusted path into an accepted one.
            string directoryLink = Path.Combine(root, "linked");
            Directory.CreateSymbolicLink(directoryLink, inner);
            try { Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(Path.Combine(directoryLink, "bower.env"))); }
            finally { Directory.Delete(directoryLink); }
            string fileLink = Path.Combine(inner, "linked.env");
            File.CreateSymbolicLink(fileLink, path);
            try { Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(fileLink)); }
            finally { File.Delete(fileLink); }

            RawSecurityDescriptor nullDacl = new("O:BAG:BAD:NO_ACCESS_CONTROL");
            Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.VerifyWindows(nullDacl, "fixture", false));
            SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
            RawAcl callbackAcl = new(GenericAcl.AclRevision, 1);
            callbackAcl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed,
                (int)FileSystemRights.FullControl, users, isCallback: true, opaque: []));
            RawSecurityDescriptor callback = new(ControlFlags.DiscretionaryAclPresent, administrators,
                administrators, null, callbackAcl);
            Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.VerifyWindows(callback, "fixture", false));
            Assert.Throws<InvalidOperationException>(() => CollectorSettingsFile.Load(path + ":alternate"));
            Assert.Equal("none", CollectorSettingsFile.Load(path)!["BOWER_OUTPUT"]);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [SupportedOSPlatform("windows")]
    private static void AssertUsersHaveRights(string path, SecurityIdentifier users, FileSystemRights rights)
    {
        DirectorySecurity actual = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
        Assert.Contains(actual.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>(), rule => rule.IdentityReference.Equals(users)
                && rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & rights) == rights);
    }

    [SupportedOSPlatform("windows")]
    private static void Protect(FileSystemSecurity security)
    {
        SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.SetOwner(administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, AccessControlType.Allow));
    }

    [SupportedOSPlatform("windows")]
    private static bool IsAdministrator()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
