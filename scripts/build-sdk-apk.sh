#!/bin/sh
# Build and verify CoreDNS APKs with the official Linux/x86_64 OpenWrt SDK.
set -eu
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <OpenWrt version> <target/subtarget> <apk arch> <output directory>" >&2
    exit 2
fi
version=$1
target=$2
arch=$3
mkdir -p "$4"
out=$(cd "$4" && pwd)
source=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM
cd "$work"

base=https://downloads.openwrt.org/releases/$version/targets/$target
curl -fsSL --retry 3 -o sha256sums "$base/sha256sums"
entry=$(awk '$2 ~ /^\*openwrt-sdk-[-A-Za-z0-9_.]+\.Linux-x86_64\.tar\.zst$/ { print; n++ } END { if (n != 1) exit 1 }' sha256sums)
archive=${entry##*\*}
if [ -n "${OPENWRT_SDK_CACHE:-}" ] && [ -f "$OPENWRT_SDK_CACHE/$archive" ]; then
    cp "$OPENWRT_SDK_CACHE/$archive" "$archive"
else
    curl -fsSL --retry 3 -o "$archive" "$base/$archive"
fi
printf '%s\n' "$entry" | sha256sum -c -
if [ -n "${OPENWRT_SDK_CACHE:-}" ] && [ ! -f "$OPENWRT_SDK_CACHE/$archive" ]; then
    mkdir -p "$OPENWRT_SDK_CACHE"
    cp "$archive" "$OPENWRT_SDK_CACHE/$archive"
fi
mkdir sdk
tar --zstd -xf "$archive" -C sdk --strip-components=1
cd sdk

curl -fsSL --retry 3 -o feeds.buildinfo "$base/feeds.buildinfo"
: > feeds.conf
for feed in base packages luci; do
    # Download precisely the feed revision used by this OpenWrt release.
    metadata=feeds.buildinfo
    project=$feed
    if [ "$feed" = base ]; then
        metadata=feeds.conf.default
        project=openwrt
    fi
    rev=$(awk -v feed="$feed" '$(NF-1) == feed { sub(/^.*\^/, "", $NF); print $NF }' "$metadata")
    printf '%s\n' "$rev" | grep -Eq '^[0-9a-f]{40}$'
    mkdir "$work/$feed"
    curl -fsSL --retry 3 -o "$work/$feed.tar.gz" "https://codeload.github.com/openwrt/$project/tar.gz/$rev"
    tar -xzf "$work/$feed.tar.gz" -C "$work/$feed" --strip-components=1
    path=$work/$feed
    [ "$feed" != base ] || path=$path/package
    printf 'src-link %s %s\n' "$feed" "$path" >> feeds.conf
done
printf 'src-link coredns %s\n' "$source" >> feeds.conf
# The SDK bundles host binaries with their own libc; don't preload host libraries.
unset LD_PRELOAD
./scripts/feeds update base packages luci coredns
./scripts/feeds install -p packages coreutils-timeout
./scripts/feeds install -p luci luci-base
./scripts/feeds install -p coredns coredns luci-app-coredns

# Keep the SDK target/toolchain settings, but not its buildbot package matrix.
# OpenWrt will select dependencies of the two requested packages again.
if [ -f .config ]; then
    awk '!/^CONFIG_PACKAGE_/ && !/^# CONFIG_PACKAGE_/ &&
         !/^(# )?CONFIG_(ALL|ALL_KMODS|ALL_NONSHARED|BUILDBOT|SIGNED_PACKAGES|LUCI_SRCDIET|LUCI_JSMIN|LUCI_CSSTIDY)(=| )/' .config > .config.minimal
    mv .config.minimal .config
fi
cat >> .config <<'EOF'
CONFIG_USE_APK=y
CONFIG_PACKAGE_coredns=m
CONFIG_PACKAGE_luci-app-coredns=m
CONFIG_ALL=n
CONFIG_ALL_KMODS=n
CONFIG_ALL_NONSHARED=n
CONFIG_BUILDBOT=n
CONFIG_SIGNED_PACKAGES=n
CONFIG_LUCI_SRCDIET=n
CONFIG_LUCI_JSMIN=n
CONFIG_LUCI_CSSTIDY=n
EOF
make defconfig
if grep -E '^CONFIG_(ALL|ALL_KMODS|ALL_NONSHARED)=y$' .config; then
    echo 'SDK unexpectedly enabled a full package build' >&2
    exit 1
fi
export MAKEFLAGS="${MAKEFLAGS:-} -j${OPENWRT_JOBS:-$(getconf _NPROCESSORS_ONLN)}"
"$source/build-apk.sh" "$PWD" --with-luci

apk=staging_dir/host/bin/apk
set -- bin/packages/"$arch"/coredns/coredns-*.apk bin/packages/"$arch"/coredns/luci-app-coredns-*.apk
for package do
    test -f "$package"
    "$apk" verify --allow-untrusted "$package"
    cp "$package" "$out/"
done
