#!/usr/bin/env bash
# Runs as root on the host under test (the CI runner or the Rocky Linux container).
#
#   assert-linux.sh installed <secrets-file>   service, account, permissions, token gone
#   assert-linux.sh removed                    no secret left, queue kept
#   assert-linux.sh purged                     nothing left, account gone
#
# The secrets file lists the enrolment tokens issued for the test; none may appear on
# disk or in the journal. Never prints a token.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
mode_of() { stat -c '%U:%G %a' "$1"; }
expect_mode() {
  local actual
  actual="$(mode_of "$1")"
  [ "$actual" = "$2" ] || fail "$1 is $actual, expected $2"
}

case "${1:-}" in
  installed)
    secrets="${2:?secrets file}"
    entry="$(getent passwd bower)" || fail "no bower account"
    uid="$(cut -d: -f3 <<<"$entry")"
    [ "$uid" -lt 1000 ] || fail "bower is not a system account (uid $uid)"
    [ "$(cut -d: -f7 <<<"$entry")" = /usr/sbin/nologin ] || fail "bower has a login shell"
    [ "$(id -Gn bower)" = bower ] || fail "bower is in other groups: $(id -Gn bower)"
    systemctl is-enabled --quiet bower.service || fail "bower.service is not enabled"
    systemctl is-active --quiet bower.service || fail "bower.service is not running"
    pid="$(systemctl show -p MainPID --value bower.service)"
    [ "$(awk '/^Uid:/ {print $2}' "/proc/$pid/status")" = "$uid" ] || fail "collector does not run as bower"
    [ "$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")" = 0000000000000000 ] || fail "collector holds capabilities"
    expect_mode /opt/bower/Bower.Collector "root:root 755"
    expect_mode /etc/bower "root:root 755"
    expect_mode /etc/bower/bower.env "root:bower 640"
    expect_mode /etc/bower/secrets "root:bower 750"
    expect_mode /etc/bower/keys "root:root 755"
    expect_mode /var/lib/bower "bower:bower 700"
    expect_mode /var/lib/bower/enrolment "bower:bower 700"
    expect_mode /var/lib/bower/management-credential "bower:bower 700"
    expect_mode /var/lib/bower/management-credential/credential.json "bower:bower 600"
    if [ -f /etc/bower/keys/pack-trusted.pem ]; then
      expect_mode /etc/bower/keys/pack-trusted.pem "root:root 644"
      grep -q '^BOWER_PACK_TRUSTED_KEYS=/etc/bower/keys/pack-trusted.pem$' /etc/bower/bower.env \
        || fail "trusted pack key not configured"
    fi
    # The collector deleted the used token; no token is on disk or in the journal.
    [ ! -e /var/lib/bower/enrolment/enrolment-token ] || fail "enrolment token left on disk"
    if grep -rqF -f "$secrets" /etc/bower /var/lib/bower /var/spool/bower 2>/dev/null; then
      fail "an enrolment token is on disk"
    fi
    if journalctl -u bower.service --no-pager 2>/dev/null | grep -qF -f "$secrets"; then
      fail "an enrolment token is in the journal"
    fi
    # No other user can read the state or secrets.
    if find /var/lib/bower /etc/bower/secrets -perm /o=rwx | grep -q .; then
      fail "world-accessible state or secret files"
    fi
    echo "installed: service, account, permissions and token removal verified"
    ;;
  removed)
    ! systemctl is-active --quiet bower.service || fail "bower.service still running"
    for path in /var/lib/bower/management-credential /var/lib/bower/enrolment /etc/bower/secrets /etc/bower/bower.env; do
      [ ! -e "$path" ] || fail "$path left behind after uninstall"
    done
    [ -f /var/lib/bower/queue.db ] || fail "queue deleted on remove (only purge deletes it)"
    echo "removed: no secret left behind; queue kept"
    ;;
  purged)
    for path in /var/lib/bower /var/spool/bower /etc/bower /opt/bower; do
      [ ! -e "$path" ] || fail "$path left behind after purge"
    done
    ! getent passwd bower >/dev/null || fail "bower account left behind after purge"
    echo "purged: nothing left behind"
    ;;
  *)
    echo "usage: $0 installed <secrets-file> | removed | purged" >&2
    exit 2
    ;;
esac
