Bower collector offline installer for Windows
=============================================

1. Verify the bundle before you copy it in: compare SHA256SUMS.txt with the value
   published for the release and check the MSI's Authenticode signature
   (Get-AuthenticodeSignature). UNSIGNED.txt means the build had no certificate.
2. On the target host, put the pre-seeded files in seed\:
     enrolment-token       one-time token from the console Enrolment page.
                           Single use, expires (24 hours by default, at most 7 days).
     pack-trusted.pem      public key trusted to sign packs (optional)
     command-trusted.pem   public key trusted to sign management commands (optional)
     packs\*.bowerpack     signed packs to load (optional, needs pack-trusted.pem)
3. Run as an administrator (Windows PowerShell 5.1 or PowerShell 7):
     powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-BowerCollector.ps1 `
       -ManagementEndpoint https://bower-management.example.com/ -Environment production
   It installs the MSI silently, moves the token into %ProgramData%\Bower\enrolment
   (deleting the seed copy), restarts the Bower service and waits for enrolment. The
   collector deletes its copy of the token. An approver approves the Pending collector.

Uninstall with msiexec /x bower-collector-<version>-x64.msi /qn (or Apps and Features).
Uninstall deletes the management credential, any unused token and
%ProgramData%\Bower\secrets. The queue in %ProgramData%\Bower\state stays.

Full guide: docs/deployment/installers.md in the Bower repository.
