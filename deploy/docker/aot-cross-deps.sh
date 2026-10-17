#!/bin/sh
# Native AOT cross-compilation support for the Ubuntu -aot SDK images.
#
# Usage: aot-cross-deps.sh <BUILDARCH> <TARGETARCH>
#
# The build stage runs on the runner's own platform. When it targets a different
# architecture, ILCompiler links with clang --target, which needs the target's GCC
# runtime and zlib. This installs them from the Ubuntu archive for the target
# architecture, as in dotnet/dotnet-docker samples/AspNetCoreNativeAot. Native
# builds (same architecture) install nothing.
set -eu

build="$1"
target="$2"
[ "$build" = "$target" ] && exit 0

case "$target" in
  arm64) gcc=gcc-aarch64-linux-gnu; uri=http://ports.ubuntu.com/ubuntu-ports/ ;;
  amd64) gcc=gcc-x86-64-linux-gnu; uri=http://archive.ubuntu.com/ubuntu/ ;;
  *) echo "Unsupported Native AOT target architecture: $target" >&2; exit 1 ;;
esac

. /etc/os-release
cat > "/etc/apt/sources.list.d/cross-$target.sources" <<SOURCES
Types: deb
URIs: $uri
Suites: $VERSION_CODENAME $VERSION_CODENAME-updates $VERSION_CODENAME-security
Components: main restricted
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Architectures: $target
SOURCES
# Pin the existing sources to the build architecture so apt does not look for
# target-architecture packages on the build mirror.
sed -i "/^Signed-By/ a Architectures: $build" /etc/apt/sources.list.d/ubuntu.sources
dpkg --add-architecture "$target"
apt-get update
apt-get install -y --no-install-recommends clang llvm "$gcc" "zlib1g-dev:$target"
rm -rf /var/lib/apt/lists/*
