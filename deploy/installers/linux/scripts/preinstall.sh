#!/bin/sh
# deb preinst (install|upgrade) and rpm %pre (1 install, 2 upgrade).
# Creates the unprivileged bower system account: no login shell, no home directory
# contents, no password, member of its own group only.
set -eu

if ! getent group bower >/dev/null 2>&1; then
  groupadd --system bower
fi
if ! getent passwd bower >/dev/null 2>&1; then
  useradd --system --gid bower --no-create-home --home-dir /var/lib/bower \
    --shell /usr/sbin/nologin --comment "Bower collector" bower
fi
exit 0
