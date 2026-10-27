#!/bin/sh
# deb postrm (remove|purge|upgrade|...) and rpm %postun (0 erase, 1 upgrade).
#
# Removal deletes every secret the collector or an installer can leave behind: the
# key-bound management credential, any unused enrolment token, /etc/bower/secrets and
# the settings file (which an operator may have given an inline value). The durable
# queue in /var/lib/bower is kept, because it can hold events not yet acknowledged by
# the destination. deb purge also deletes the queue, configuration and the account.
set -eu

remove_secrets() {
  rm -rf /var/lib/bower/management-credential /var/lib/bower/enrolment /etc/bower/secrets
  rm -f /etc/bower/bower.env
}

case "${1:-}" in
  0|remove)
    remove_secrets
    ;;
  purge)
    remove_secrets
    rm -rf /var/lib/bower /var/spool/bower /var/log/bower /etc/bower
    if getent passwd bower >/dev/null 2>&1; then
      userdel bower >/dev/null 2>&1 || true
    fi
    if getent group bower >/dev/null 2>&1; then
      groupdel bower >/dev/null 2>&1 || true
    fi
    ;;
esac

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
