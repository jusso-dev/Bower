#!/usr/bin/env bash
# Builds the deb and rpm packages and the offline bundle for one architecture from a
# `publish` job artefact (collector/ and cli/ folders).
#
#   deploy/installers/linux/build.sh <artefact-dir> <amd64|arm64> <version> <output-dir>
#
# Run from the repository root with nfpm on PATH. When BOWER_GPG_KEY_FILE names an
# armored private key, nfpm signs both packages (passphrase in NFPM_PASSPHRASE);
# otherwise they are unsigned. This script renders the ${BOWER_*} placeholders in nfpm.yaml.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <artefact-dir> <amd64|arm64> <version> <output-dir>" >&2
  exit 2
fi
dist="$(cd "$1" && pwd)"
arch="$2"
version="$3"
out="$4"
case "$arch" in amd64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 2 ;; esac
# The Bower version scheme (docs/operations/release-versioning.md), with the limits
# tools/ci/version.py and Directory.Build.props enforce: MAJOR and MINOR 0-255, PATCH and N 0-65535.
version_byte='(0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
version_number='(0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9][0-9]|655[0-2][0-9]|6553[0-5])'
if ! [[ "$version" =~ ^$version_byte\.$version_byte\.$version_number(-(dev|rc)\.$version_number)?$ ]]; then
  echo "version must be MAJOR.MINOR.PATCH[-dev.N|-rc.N] (MAJOR, MINOR 0-255; PATCH, N 0-65535): $version" >&2
  exit 2
fi
for file in collector/Bower.Collector collector/libe_sqlite3.so cli/bower; do
  test -f "$dist/$file" || { echo "missing $dist/$file" >&2; exit 1; }
done

key_file="${BOWER_GPG_KEY_FILE:-}"
for value in "$dist" "$key_file"; do
  [[ "$value" =~ ^[A-Za-z0-9._/-]*$ ]] || { echo "unsupported characters in path: $value" >&2; exit 2; }
done

mkdir -p "$out"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
# nfpm does not expand variables in every field, so render the placeholders here. The
# preinstall script embeds the package version for its downgrade guard, and the package
# installs the version as /usr/share/bower/version for the next package's guard.
render() {
  sed -e "s|\${BOWER_DIST}|$dist|g" -e "s|\${BOWER_ARCH}|$arch|g" -e "s|\${BOWER_STAGE}|$stage|g" \
    -e "s|\${BOWER_VERSION}|$version|g" -e "s|\${BOWER_GPG_KEY_FILE}|$key_file|g" "$1" >"$2"
  # shellcheck disable=SC2016 # a literal placeholder, not an expansion
  if grep -qE '\$\{BOWER_(DIST|ARCH|STAGE|VERSION|GPG_KEY_FILE)\}' "$2"; then
    echo "unrendered placeholder in $1" >&2
    exit 1
  fi
}
render deploy/installers/linux/nfpm.yaml "$stage/nfpm.yaml"
render deploy/installers/linux/scripts/preinstall.sh "$stage/preinstall.sh"
printf '%s\n' "$version" >"$stage/version"
nfpm package --config "$stage/nfpm.yaml" --packager deb --target "$out/"
nfpm package --config "$stage/nfpm.yaml" --packager rpm --target "$out/"

# Offline bundle: both packages, the installer and an empty seed directory. The
# operator adds the enrolment token and trusted keys on the target host only.
bundle="bower-collector-offline-${version}-linux-${arch}"
mkdir -p "$stage/$bundle/packages" "$stage/$bundle/seed"
# rpm names the architecture x86_64/aarch64.
rpm_arch="$([ "$arch" = amd64 ] && echo x86_64 || echo aarch64)"
cp "$out"/bower-collector_*_"$arch".deb "$out"/bower-collector-*."$rpm_arch".rpm "$stage/$bundle/packages/"
install -m 0755 deploy/installers/offline/install.sh "$stage/$bundle/install.sh"
install -m 0644 deploy/installers/offline/README.txt "$stage/$bundle/README.txt"
if [ -z "$key_file" ]; then
  echo "These packages are NOT signed: the build had no signing key. Verify them by checksum from a trusted channel." \
    >"$stage/$bundle/UNSIGNED.txt"
fi
(cd "$stage/$bundle" && find packages -type f -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
test "$(wc -l <"$stage/$bundle/SHA256SUMS")" -eq 2
tar -C "$stage" --owner=0 --group=0 --numeric-owner -czf "$out/$bundle.tar.gz" "$bundle"
ls -l "$out"
