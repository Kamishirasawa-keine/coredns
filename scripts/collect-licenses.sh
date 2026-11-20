#!/bin/sh
# Run from the Go module root with the same GOOS/GOARCH as the binary build.
set -eu
out=${1:?Specify a license output directory}
mkdir -p "$out"
cp LICENSE THIRD_PARTY.md "$out/"
go_bin=${GO_BIN:-go}
modules=$("$go_bin" list -mod=readonly -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}{{"\t"}}{{.Dir}}{{end}}{{end}}' .)
printf '%s\n' "$modules" | sort -u | while IFS="$(printf '\t')" read -r module dir; do
        [ -n "$module" ] || continue
        for file in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
            [ -f "$file" ] || continue
            mkdir -p "$out/$module"
            install -m 644 "$file" "$out/$module/"
        done
    done
goroot=$("$go_bin" env GOROOT)
mkdir -p "$out/go"
for file in LICENSE PATENTS; do
    path=$goroot/$file
    [ -f "$path" ] || path=licenses/go/$file
    install -m 644 "$path" "$out/go/"
done
