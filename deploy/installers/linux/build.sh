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
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "version must be semantic (1.2.3 or 1.2.3-dev.4): $version" >&2
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
# nfpm does not expand variables in every field, so render the placeholders here.
sed -e "s|\${BOWER_DIST}|$dist|g" -e "s|\${BOWER_ARCH}|$arch|g" \
  -e "s|\${BOWER_VERSION}|$version|g" -e "s|\${BOWER_GPG_KEY_FILE}|$key_file|g" \
  deploy/installers/linux/nfpm.yaml >"$stage/nfpm.yaml"
# shellcheck disable=SC2016 # a literal placeholder, not an expansion
if grep -qF '${BOWER_' "$stage/nfpm.yaml"; then
  echo "unrendered placeholder in nfpm.yaml" >&2
  exit 1
fi
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
