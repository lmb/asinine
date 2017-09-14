#!/bin/sh
# Checks all certificates against the Mozilla trust store

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

base="$(dirname "$0")"

for cert in $base/../testcerts/*.json; do
    if ! "$base/check.sh" "$cert" > /dev/null; then
        echo "$(realpath --relative-base="$PWD" "$cert")"
    fi
done
