#!/usr/bin/env bash
# Bower collector offline installer for Linux (#112). Silent, no network needed.
#
# Installs the deb or rpm from packages/ (checked against SHA256SUMS), then applies the
# pre-seeded files from seed/ (or the options below) and restarts the service:
#
#   seed/enrolment-token     one-time enrolment token (bwe1.…), moved, never copied
#   seed/pack-trusted.pem    public key trusted to sign packs
#   seed/command-trusted.pem public key trusted to sign management commands
#   seed/packs/*.bowerpack   signed packs to load
#   seed/settings.env        BOWER_* settings (no secret values), e.g. the endpoint
#
# The enrolment token lands in /var/lib/bower/enrolment (bower 0600) and the seed copy
# is deleted. The collector deletes its copy once management consumed or refused it.
#
# Usage: sudo ./install.sh [--endpoint URL] [--collector-id ID] [--environment NAME]
#          [--token-file FILE] [--pack-key FILE] [--command-key FILE] [--wait SECONDS]
# Exit codes: 0 installed (and enrolled, Pending approval, when a token was given),
#             2 usage, 3 management refused the token, 4 enrolment not confirmed in time.
set -euo pipefail
umask 077

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
seed="$here/seed"
token_file="$seed/enrolment-token"
pack_key="$seed/pack-trusted.pem"
command_key="$seed/command-trusted.pem"
endpoint=""
collector_id=""
environment=""
wait_seconds=120
token_target=/var/lib/bower/enrolment/enrolment-token
env_file=/etc/bower/bower.env

die() { echo "bower install: $*" >&2; exit "${2:-1}"; }
usage() { sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --endpoint) endpoint="${2:?}"; shift 2 ;;
    --collector-id) collector_id="${2:?}"; shift 2 ;;
    --environment) environment="${2:?}"; shift 2 ;;
    --token-file) token_file="${2:?}"; shift 2 ;;
    --pack-key) pack_key="${2:?}"; shift 2 ;;
    --command-key) command_key="${2:?}"; shift 2 ;;
    --wait) wait_seconds="${2:?}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root" 2
[[ "$wait_seconds" =~ ^[0-9]+$ ]] || die "--wait takes whole seconds" 2

# Values end up in a systemd EnvironmentFile: one line, no quotes, no expansion.
safe() { [[ "$1" =~ ^[A-Za-z0-9._:/@%+=,~-]*$ ]]; }

# Settings from seed/settings.env first; options override them.
declare -A settings=()
if [ -f "$seed/settings.env" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    key="${line%%=*}"
    value="${line#*=}"
    [[ "$key" =~ ^BOWER_[A-Z0-9_]+$ ]] || die "seed/settings.env: not a BOWER_ setting: $key" 2
    [ "$key" != BOWER_INGEST_TOKEN ] || die "seed/settings.env: use BOWER_INGEST_TOKEN_FILE, never an inline token" 2
    safe "$value" || die "seed/settings.env: unsupported characters in $key" 2
    settings["$key"]="$value"
  done <"$seed/settings.env"
fi
[ -z "$endpoint" ] || settings[BOWER_MANAGEMENT_ENDPOINT]="$endpoint"
[ -z "$collector_id" ] || settings[BOWER_COLLECTOR_ID]="$collector_id"
[ -z "$environment" ] || settings[BOWER_ENVIRONMENT]="$environment"
for key in "${!settings[@]}"; do
  safe "${settings[$key]}" || die "unsupported characters in $key" 2
done

token=""
if [ -f "$token_file" ]; then
  [ "$(stat -c %s "$token_file")" -le 1024 ] || die "enrolment token file is too large" 2
  token="$(tr -d '[:space:]' <"$token_file")"
  [[ "$token" =~ ^bwe1\.[A-Za-z0-9]+\.[A-Za-z0-9_-]+$ ]] || die "enrolment token file does not hold a bwe1 token" 2
  [ -n "${settings[BOWER_MANAGEMENT_ENDPOINT]:-}" ] || die "an enrolment token needs --endpoint or BOWER_MANAGEMENT_ENDPOINT" 2
fi

# Install the package for this host after checking the bundle's checksums.
(cd "$here" && sha256sum --check --strict --quiet SHA256SUMS) || die "package checksum mismatch"
if command -v dpkg >/dev/null 2>&1 && [ -f /etc/debian_version ]; then
  package="$(find "$here/packages" -name 'bower-collector_*.deb' | head -n 1)"
  [ -n "$package" ] || die "no deb package in packages/"
  dpkg -i "$package" >/dev/null
elif command -v rpm >/dev/null 2>&1; then
  package="$(find "$here/packages" -name 'bower-collector-*.rpm' | head -n 1)"
  [ -n "$package" ] || die "no rpm package in packages/"
  rpm -U --replacepkgs --quiet "$package"
else
  die "neither dpkg nor rpm is available"
fi

# Trusted public keys: root-owned, world-readable, only root can change them.
if [ -f "$pack_key" ]; then
  install -o root -g root -m 0644 "$pack_key" /etc/bower/keys/pack-trusted.pem
  settings[BOWER_PACK_TRUSTED_KEYS]=/etc/bower/keys/pack-trusted.pem
fi
if [ -f "$command_key" ]; then
  install -o root -g root -m 0644 "$command_key" /etc/bower/keys/command-trusted.pem
  settings[BOWER_MANAGEMENT_COMMAND_TRUSTED_KEYS]=/etc/bower/keys/command-trusted.pem
fi
packs=""
if [ -d "$seed/packs" ]; then
  while IFS= read -r -d '' pack; do
    name="$(basename "$pack")"
    safe "$name" || die "unsupported characters in pack file name: $name" 2
    install -o root -g root -m 0644 "$pack" "/etc/bower/packs/$name"
    packs="${packs:+$packs,}/etc/bower/packs/$name"
  done < <(find "$seed/packs" -maxdepth 1 -name '*.bowerpack' -print0 | sort -z)
fi
[ -z "$packs" ] || settings[BOWER_PACKS]="$packs"
if [ -n "$token" ]; then
  settings[BOWER_MANAGEMENT_AUTH]=enrolment
  settings[BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE]="$token_target"
  settings[BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE]=true
fi

# Rewrite the settings file atomically: drop the keys being set, append their values.
temporary="$(mktemp /etc/bower/.bower.env.XXXXXX)"
trap 'rm -f "$temporary"' EXIT
pattern="^($(IFS='|'; echo "${!settings[*]}"))="
if [ "${#settings[@]}" -gt 0 ]; then
  grep -Ev "$pattern" "$env_file" >"$temporary" || true
  for key in $(printf '%s\n' "${!settings[@]}" | sort); do
    printf '%s=%s\n' "$key" "${settings[$key]}" >>"$temporary"
  done
else
  cat "$env_file" >"$temporary"
fi
chown root:bower "$temporary"
chmod 0640 "$temporary"
mv -f "$temporary" "$env_file"
trap - EXIT

# Move the token into place (bower 0600) and delete the seed copy.
token_sha256=""
if [ -n "$token" ]; then
  token_sha256="$(printf '%s' "$token" | sha256sum | cut -d ' ' -f 1)"
  install -d -o bower -g bower -m 0700 /var/lib/bower/enrolment
  printf '%s\n' "$token" >"$token_target.tmp"
  chown bower:bower "$token_target.tmp"
  chmod 0600 "$token_target.tmp"
  mv -f "$token_target.tmp" "$token_target"
  if command -v shred >/dev/null 2>&1; then shred -u "$token_file"; else rm -f "$token_file"; fi
  unset token
fi

systemctl restart bower.service
echo "Bower collector installed; service bower.service restarted."

[ -n "$token_sha256" ] || exit 0
# The collector records the hash of the token it exchanged (never the token) and then
# deletes the token file; a refused token is recorded under a different field.
credential=/var/lib/bower/management-credential/credential.json
for _ in $(seq 1 "$wait_seconds"); do
  if grep -q "\"consumedTokenSha256\":\"$token_sha256\"" "$credential" 2>/dev/null; then
    echo "Enrolled: the collector is Pending until an approver approves it in the console."
    exit 0
  fi
  if grep -q "\"refusedTokenSha256\":\"$token_sha256\"" "$credential" 2>/dev/null; then
    die "management refused the enrolment token; create a new token and run again" 3
  fi
  sleep 1
done
die "enrolment not confirmed after ${wait_seconds}s; the collector keeps retrying (journalctl -u bower)" 4
