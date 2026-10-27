#!/bin/sh
# deb postinst (configure [old-version]) and rpm %post (1 install, 2 upgrade).
# Lays out owner-only state and secret directories, writes the default settings file
# once, then enables the service. Fresh installs start it; upgrades restart it only if
# it was running.
set -eu

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
  if [ "$upgrade" = true ]; then
    systemctl try-restart bower.service >/dev/null 2>&1 || true
  else
    systemctl start bower.service >/dev/null 2>&1 || true
  fi
fi
exit 0
