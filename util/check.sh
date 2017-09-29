#!/bin/bash
# Checks a single certificate against the Mozilla trust store

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

set -o pipefail

debug=no
if [ "$1" = "--debug" ]; then
	debug=yes
	shift
fi

if [ ! -f "$1" ]; then
	echo "Not a file: $1"
	exit 1
fi

if [ "$(jq -r '.["validation"]["nss"]["type"]' "$1")" != "leaf" ]; then
	echo Not a leaf certificate, skipping
	exit 0
fi

if [ "$(jq -r '.["validation"]["nss"]["trusted_path"]' "$1")" != "true" ]; then
	echo Not a trusted path, skipping
	exit 0
fi

base="$(dirname "$1")"
certs=($(jq -r --arg pre "$base/" --arg post .der '.["validation"]["nss"]["paths"]|sort_by(.|length)[0][0:-1]|reverse|.[]|$pre+.+$post' "$1"))

if [ $debug = no ]; then
	cat "${certs[@]}" | ./bin/Debug/x509 --check "$base/nss.der" -
	exit $?
else
	for cert in "${certs[@]}"; do
		echo lldb -- ./bin/Debug/x509 "$(realpath --relative-base="$PWD" "$cert")"
	done
fi
