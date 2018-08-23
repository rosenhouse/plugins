#!/usr/bin/env bash
set -e

PLUGINS=$(cat plugins/windows_only.txt)
for d in $PLUGINS; do
	if [ -d "$d" ]; then
		plugin="$(basename "$d")"
		output="win-$plugin.exe"
		if [ -z $(echo "$d" | grep "/windows/") ]; then
		    output="$plugin.exe"
		fi

		echo $output
		CXX=x86_64-w64-mingw32-g++ CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 $GO build -o "${PWD}/bin/$output" "$@" "$REPO_PATH"/$d
	fi
done
