#!/bin/bash
# Finds missing intermediary certificates

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

base="$(dirname "$0")"

for cert in $base/../testcerts/*.json; do
	if [ $(jq -r '.["validation"]["nss"]["type"] != "leaf" or .["validation"]["nss"]["trusted_path"] != true' "$cert") = "true" ]; then
		continue
	fi

	hashes="$(jq -r '.["validation"]["nss"]["paths"][0][0:-1]|reverse|.[]' "$cert")"

	for h in $hashes; do
		if [ ! -f "$base/../testcerts/$h.der" ]; then
			echo "$h"
		fi
	done
done
