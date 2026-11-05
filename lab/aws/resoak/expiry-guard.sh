#!/bin/bash
# Re-soak in-guest expiry guard (Linux, Sender): a systemd timer powers the host off at
# RESOAK_GUARD_AT (epoch, UTC). The instance's shutdown behaviour is terminate, so this ends the
# host even if nobody returns and the stack's scheduler guard fails. The timer is on disk and
# Persistent, so it survives the scheduled reboots and fires at the next boot if the host was down.
#   RESOAK_GUARD_ACTION=install|status, RESOAK_GUARD_AT (install)
set -euo pipefail
: "${BOWER_LAB_RUN:?}"
[[ "$BOWER_LAB_RUN" =~ ^bower-resoak-[0-9]{8}-[0-9]{6}$ ]]
[ "$(id -u)" = 0 ]
if [ "${RESOAK_GUARD_ACTION:-status}" = install ]; then
  : "${RESOAK_GUARD_AT:?}"
  [[ "$RESOAK_GUARD_AT" =~ ^[0-9]+$ && "$RESOAK_GUARD_AT" -gt $(( $(date +%s) + 3600 )) ]]
  at=$(date -u -d "@$RESOAK_GUARD_AT" '+%Y-%m-%d %H:%M:%S UTC')
  cat > /etc/systemd/system/bower-resoak-expiry.service <<'UNIT'
[Unit]
Description=Bower re-soak expiry guard: power off (instance terminates)
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl poweroff
UNIT
  cat > /etc/systemd/system/bower-resoak-expiry.timer <<UNIT
[Unit]
Description=Bower re-soak expiry guard at $at
[Timer]
OnCalendar=$at
Persistent=true
AccuracySec=1s
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now bower-resoak-expiry.timer >/dev/null 2>&1
fi
systemctl is-enabled bower-resoak-expiry.timer >/dev/null
printf '{"guard":"systemd","at":"%s","next":"%s","shutdownBehaviour":"terminate"}\n' \
  "$(sed -n 's/^OnCalendar=//p' /etc/systemd/system/bower-resoak-expiry.timer)" \
  "$(systemctl show bower-resoak-expiry.timer --property=NextElapseUSecRealtime --value)"
