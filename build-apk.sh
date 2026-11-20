#!/bin/sh
# Build CoreDNS and, with --with-luci, its LuCI app in a configured OpenWrt tree.
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	echo "Usage: $0 <OpenWrt tree or SDK> [--with-luci]" >&2
	exit 1
fi
openwrt=$1
case "${2:-}" in
	'') packages='coredns' ;;
	--with-luci) packages='coredns luci-app-coredns' ;;
	*) echo "Usage: $0 <OpenWrt tree or SDK> [--with-luci]" >&2; exit 1 ;;
esac
go=${COREDNS_GO:-go}
case "$go" in /*) ;; *) go=$(command -v "$go") ;; esac
test -f "$openwrt/.config" || { echo 'OpenWrt .config is missing' >&2; exit 1; }
cd "$openwrt"
grep -qx CONFIG_USE_APK=y .config || { echo 'OpenWrt CONFIG_USE_APK=y is required' >&2; exit 1; }
for package in $packages; do
	test -f "package/feeds/coredns/$package/Makefile" || {
		echo "Run scripts/feeds update coredns and scripts/feeds install -p coredns $package first" >&2
		exit 1
	}
done

# Select new packages as modules without changing existing selections.
configure=0
for package in $packages; do
	if ! grep -Eq "^CONFIG_PACKAGE_$package=[my]$" .config; then
		printf '\nCONFIG_PACKAGE_%s=m\n' "$package" >> .config
		configure=1
	fi
done
if [ "$configure" -eq 1 ]; then
	make defconfig
fi

set --
for package in $packages; do
	if ! grep -Eq "^CONFIG_PACKAGE_$package=[my]$" .config; then
		echo "$package could not be selected; check its OpenWrt dependencies" >&2
		exit 1
	fi
	set -- "$@" "package/feeds/coredns/$package/compile"
done
exec make "$@" "COREDNS_GO=$go" V=s
