#!/bin/sh
# deb prerm (remove|upgrade|deconfigure|failed-upgrade) and rpm %preun (0 erase, 1 upgrade).
# Stops and disables the service on removal only; an upgrade keeps it running until
# the new package restarts it.
set -eu

case "${1:-}" in
  0|remove|deconfigure)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now bower.service >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
