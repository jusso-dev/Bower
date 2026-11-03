#!/bin/sh
# deb preinst (install|upgrade) and rpm %pre (1 install, 2 upgrade).
# Refuses a downgrade unless BOWER_ALLOW_DOWNGRADE=1, then creates the unprivileged bower
# system account: no login shell, no home directory contents, no password, member of its
# own group only. build.sh renders the package version below.
set -eu

# shellcheck disable=SC2016 # a placeholder that build.sh replaces
package_version='${BOWER_VERSION}'
installed_version_file=/usr/share/bower/version

# begin version functions (tools/ci/test_version.py runs these)
# Bower versions are MAJOR.MINOR.PATCH with an optional -dev.N or -rc.N
# (docs/operations/release-versioning.md). Prints "MAJOR MINOR PATCH STAGE N", where
# STAGE orders dev (0) < rc (1) < release (2); fails for anything else.
version_fields() {
  case "$1" in
    *-dev.*) stage=0 number=${1#*-dev.} ;;
    *-rc.*) stage=1 number=${1#*-rc.} ;;
    *-*) return 1 ;;
    *) stage=2 number=0 ;;
  esac
  core=${1%%-*}
  case "$core" in
    *[!0-9.]* | .* | *. | *..*) return 1 ;;
  esac
  case "$number" in
    '' | *[!0-9]*) return 1 ;;
  esac
  old_ifs=$IFS
  IFS=.
  # shellcheck disable=SC2086 # split the core on dots
  set -- $core
  IFS=$old_ifs
  [ "$#" -eq 3 ] || return 1
  for field in "$1" "$2" "$3" "$number"; do
    [ "${#field}" -le 9 ] || return 1
  done
  echo "$1 $2 $3 $stage $number"
}

# Succeeds when version $1 is older than version $2. Unrecognised versions are never older.
version_older() {
  older=$(version_fields "$1") || return 1
  newer=$(version_fields "$2") || return 1
  # shellcheck disable=SC2086 # pair each field of $1 with the same field of $2
  set -- $older
  pairs=
  for field in $newer; do
    pairs="$pairs $1 $field"
    shift
  done
  # shellcheck disable=SC2086
  set -- $pairs
  while [ "$#" -gt 0 ]; do
    [ "$1" -lt "$2" ] && return 0
    [ "$1" -gt "$2" ] && return 1
    shift 2
  done
  return 1
}
# end version functions

# The installed package wrote its version here; packages older than the guard did not.
if [ -r "$installed_version_file" ]; then
  installed_version=$(head -n 1 "$installed_version_file" | cut -c1-64)
  # A marker that is present but unreadable fails closed: it could hide a newer install.
  if ! version_fields "$installed_version" >/dev/null; then
    if [ "${BOWER_ALLOW_DOWNGRADE:-}" = 1 ]; then
      echo "bower-collector: installing $package_version over an unrecognised installed version (BOWER_ALLOW_DOWNGRADE=1)." >&2
    else
      echo "bower-collector: refusing to install $package_version: $installed_version_file does not hold a Bower version," \
        "so a downgrade cannot be ruled out. The installed collector, its settings and its queue are unchanged." \
        "If this is intended, back up the queue and rerun with BOWER_ALLOW_DOWNGRADE=1" \
        "(see docs/operations/release-versioning.md)." >&2
      exit 1
    fi
  elif version_older "$package_version" "$installed_version"; then
    if [ "${BOWER_ALLOW_DOWNGRADE:-}" = 1 ]; then
      echo "bower-collector: downgrading from $installed_version to $package_version (BOWER_ALLOW_DOWNGRADE=1)." >&2
    else
      echo "bower-collector: refusing to downgrade from $installed_version to $package_version." \
        "The installed collector, its settings and its queue are unchanged." \
        "To roll back on purpose, back up the queue and rerun with BOWER_ALLOW_DOWNGRADE=1" \
        "(see docs/operations/release-versioning.md)." >&2
      exit 1
    fi
  fi
fi

if ! getent group bower >/dev/null 2>&1; then
  groupadd --system bower
fi
if ! getent passwd bower >/dev/null 2>&1; then
  useradd --system --gid bower --no-create-home --home-dir /var/lib/bower \
    --shell /usr/sbin/nologin --comment "Bower collector" bower
fi
exit 0
