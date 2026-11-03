#!/usr/bin/env bash
# Runs as root on the host under test (the CI runner or the Rocky Linux container).
#
#   upgrade-linux.sh <older-package> <newer-package> <newer-version>
#
# Installs the older package (the same binaries packaged as <core>-dev.0), upgrades to the
# newer one and checks every reported version. Then proves each downgrade path is refused
# with a clear message while the service, its settings and the queue stay untouched, and
# that BOWER_ALLOW_DOWNGRADE=1 rolls back on purpose (docs/operations/release-versioning.md).
# Leaves the newer package installed. Never prints the ingest token.
set -euo pipefail

old="${1:?older package}"
new="${2:?newer package}"
version="${3:?newer version}"
old_version="${version%%-*}-dev.0"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
if command -v dpkg >/dev/null 2>&1 && [ -f /etc/debian_version ]; then kind=deb; else kind=rpm; fi

package_version() {
  if [ "$kind" = deb ]; then dpkg-query -W -f='${Version}' bower-collector; else rpm -q --qf '%{VERSION}' bower-collector; fi
}
# nfpm writes a pre-release with ~ (sorts before the release); deb adds release 1.
expected_package_version() {
  local value
  # shellcheck disable=SC2001 # bash versions disagree on ~ in a ${//} replacement
  value="$(sed 's/-/~/' <<<"$1")"
  if [ "$kind" = deb ]; then echo "$value-1"; else echo "$value"; fi
}
wait_healthy() {
  for _ in $(seq 1 60); do
    curl -fsS http://127.0.0.1:4319/health >/dev/null 2>&1 && return 0
    sleep 1
  done
  fail "collector never became healthy"
}
main_pid() { systemctl show -p MainPID --value bower.service; }
status_version() {
  # The header comes from a file, so the token is never a command-line argument.
  curl -fsS -H "@$work/header" http://127.0.0.1:4319/v1/status \
    | grep -o '"version":"[^"]*"' | head -n 1 | cut -d'"' -f4
}
state() {
  # Everything a refused downgrade must leave alone.
  printf '%s %s %s %s\n' "$(package_version)" "$(cat /usr/share/bower/version)" "$(main_pid)" \
    "$(cat /etc/bower/bower.env /var/lib/bower/collector-id 2>/dev/null | sha256sum | cut -c1-16)"
  stat -c '%i' /var/lib/bower/queue.db
}
attempt() {
  # attempt <label> <expected message regex> <command...>
  local label="$1" message="$2" output
  shift 2
  if output="$("$@" 2>&1)"; then
    fail "downgrade was not refused ($label)"
  fi
  grep -qE "$message" <<<"$output" || { echo "$output" >&2; fail "no clear refusal ($label)"; }
  echo "refused ($label): $(grep -E "$message" <<<"$output" | head -n 1)"
}

echo "-- install $old_version"
if [ "$kind" = deb ]; then dpkg -i "$old" >/dev/null; else rpm -U "$old"; fi
[ "$(package_version)" = "$(expected_package_version "$old_version")" ] || fail "installed $(package_version)"
[ "$(cat /usr/share/bower/version)" = "$old_version" ] || fail "/usr/share/bower/version is not $old_version"
# An ingest token so /v1/status answers; root:bower 0640 like every secret.
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$work/token"
install -o root -g bower -m 0640 "$work/token" /etc/bower/secrets/ingest-token
printf 'Authorization: Bearer %s\n' "$(cat "$work/token")" >"$work/header"
echo 'BOWER_INGEST_TOKEN_FILE=/etc/bower/secrets/ingest-token' >>/etc/bower/bower.env
systemctl restart bower.service
wait_healthy

echo "-- upgrade to $version"
if [ "$kind" = deb ]; then dpkg -i "$new" >/dev/null; else rpm -U "$new"; fi
wait_healthy
[ "$(package_version)" = "$(expected_package_version "$version")" ] || fail "upgraded to $(package_version)"
[ "$(cat /usr/share/bower/version)" = "$version" ] || fail "/usr/share/bower/version is not $version"
[ "$(/usr/bin/bower --version)" = "bower $version" ] || fail "bower --version: $(/usr/bin/bower --version)"
[ "$(/opt/bower/Bower.Collector --version)" = "bower-collector $version" ] || fail "Bower.Collector --version"
[ "$(status_version)" = "$version" ] || fail "/v1/status reports $(status_version)"
grep -q '^BOWER_INGEST_TOKEN_FILE=' /etc/bower/bower.env || fail "upgrade lost bower.env"
[ -f /var/lib/bower/queue.db ] || fail "no queue after upgrade"
echo "upgraded: package, CLI, collector and /v1/status all report $version"

echo "-- downgrade to $old_version must be refused"
before="$(state)"
message="refusing to downgrade from $version to $old_version"
if [ "$kind" = deb ]; then
  attempt "dpkg -i" "$message" dpkg -i "$old"
  attempt "apt-get --allow-downgrades" "$message" apt-get install -y --allow-downgrades "$old"
else
  attempt "rpm -U" "is already installed|which is newer than" rpm -U "$old"
  attempt "rpm -U --oldpackage" "$message" rpm -U --oldpackage "$old"
  attempt "dnf downgrade" "$message" dnf -y --disablerepo='*' downgrade "$old"
fi
[ "$(state)" = "$before" ] || fail "a refused downgrade changed the package, service, settings or queue"
systemctl is-active --quiet bower.service || fail "service not running after a refused downgrade"
[ "$(status_version)" = "$version" ] || fail "status changed after a refused downgrade"
echo "refused downgrades left $version running with the same PID, settings and queue"

echo "-- explicit rollback with BOWER_ALLOW_DOWNGRADE=1"
if [ "$kind" = deb ]; then
  BOWER_ALLOW_DOWNGRADE=1 dpkg -i "$old" >/dev/null
else
  BOWER_ALLOW_DOWNGRADE=1 rpm -U --oldpackage "$old"
fi
wait_healthy
[ "$(package_version)" = "$(expected_package_version "$old_version")" ] || fail "rollback installed $(package_version)"
grep -q '^BOWER_INGEST_TOKEN_FILE=' /etc/bower/bower.env || fail "rollback lost bower.env"
[ -f /etc/bower/secrets/ingest-token ] || fail "rollback deleted a secret"
[ -f /var/lib/bower/queue.db ] || fail "rollback deleted the queue"

echo "-- same-version reinstall and upgrade back"
if [ "$kind" = deb ]; then dpkg -i "$new" >/dev/null; dpkg -i "$new" >/dev/null; else rpm -U "$new"; rpm -U --replacepkgs "$new"; fi
wait_healthy
[ "$(package_version)" = "$(expected_package_version "$version")" ] || fail "reinstalled $(package_version)"
[ "$(status_version)" = "$version" ] || fail "/v1/status reports $(status_version) after reinstall"
echo "versioning verified ($kind): upgrade, refused downgrade, explicit rollback, same-version reinstall"
