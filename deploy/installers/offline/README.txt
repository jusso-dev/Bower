Bower collector offline installer
=================================

1. Verify the bundle before you copy it in: compare the SHA-256 of the archive with
   the value published for the release, and check the package signatures (rpm -K,
   or the Authenticode signature of the MSI). Unsigned CI builds say so.
2. On the target host, put the pre-seeded files in seed/:
     enrolment-token       one-time token from the console Enrolment page.
                           Single use, expires (24 hours by default, at most 7 days).
     pack-trusted.pem      public key trusted to sign packs (optional)
     command-trusted.pem   public key trusted to sign management commands (optional)
     packs/*.bowerpack     signed packs to load (optional, needs pack-trusted.pem)
     settings.env          BOWER_* settings, one per line, no secret values, e.g.
                           BOWER_MANAGEMENT_ENDPOINT=https://bower-management.example.com/
                           BOWER_COLLECTOR_ID=edge-01
                           BOWER_ENVIRONMENT=production
3. Run the installer as root:   sudo ./install.sh
   It installs the package, moves the token into /var/lib/bower/enrolment (deleting
   the seed copy), restarts bower.service and waits for enrolment. The collector then
   deletes its copy of the token. An approver approves the Pending collector.

Uninstall with apt remove bower-collector or dnf remove bower-collector. Removal
deletes the management credential, any unused token, /etc/bower/secrets and
/etc/bower/bower.env. The queue in /var/lib/bower stays until you purge it.

Full guide: docs/deployment/installers.md in the Bower repository.
