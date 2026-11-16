#!/bin/sh
# deb postinst (configure [old-version]) and rpm %post (1 install, 2 upgrade).
# Lays out owner-only state and secret directories, writes the default settings file
# once, then enables the service. Fresh installs start it; upgrades restart it only if
# it was running.
#
# Every package operation (install, upgrade, rollback, reinstall) starts the unit once.
# Those are operator actions, not a crash loop, so the start rate counter is flushed
# first: otherwise a rollback followed by an upgrade back within systemd's default
# StartLimitIntervalSec=10s / StartLimitBurst=5 refuses the start ('start-limit-hit')
# and leaves the collector stopped (#278). Restart=on-failure keeps its crash-loop limit.
set -eu

# A failed upgrade (for example a refused downgrade) left the installed package as it
# was; its prerm changes nothing on upgrade, so there is nothing to undo.
[ "${1:-}" != abort-upgrade ] || exit 0

umask 077
install -d -o root -g root -m 0755 /etc/bower /etc/bower/keys /etc/bower/packs
install -d -o root -g bower -m 0750 /etc/bower/secrets
install -d -o bower -g bower -m 0700 /var/lib/bower /var/lib/bower/enrolment
install -d -o bower -g bower -m 0750 /var/spool/bower
if [ ! -e /etc/bower/bower.env ]; then
  install -o root -g bower -m 0640 /usr/share/bower/bower.env.example /etc/bower/bower.env
fi

upgrade=false
case "${1:-}" in
  2) upgrade=true ;;
  configure) [ -n "${2:-}" ] && upgrade=true ;;
esac

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable bower.service >/dev/null 2>&1 || true
  systemctl reset-failed bower.service >/dev/null 2>&1 || true
  if [ "$upgrade" = true ]; then
    systemctl try-restart bower.service >/dev/null 2>&1 || true
  else
    systemctl start bower.service >/dev/null 2>&1 || true
  fi
fi
exit 0
