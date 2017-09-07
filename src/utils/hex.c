/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <string.h>

#include "internal/utils.h"

#define BYTES_PER_LINE (12)

static char
to_printable(uint8_t value) {
	return (32 <= value && value <= 127) ? (char)value : '.';
}

void
hexdump(const uint8_t *buf, size_t num, int depth) {
	char printable[BYTES_PER_LINE + 1] = "";
	char hex[(3 * BYTES_PER_LINE) + 1] = "";

	if (buf == NULL) {
		return;
	}

	size_t i, j;
	for (i = 0, j = 0; i < num; ++i, j = (j + 1) % BYTES_PER_LINE) {
		if (j == 0 && i > 0) {
			printf("%*s", (depth * 2) + 2, "");
			printf("|%-*s| %s\n", BYTES_PER_LINE, printable, hex);
			memset(printable, 0, sizeof printable);
			memset(hex, 0, sizeof hex);
		}

		printable[j] = to_printable(buf[i]);
		snprintf(hex + (j * 3), 4, "%02X ", buf[i]);
	}

	if (j > 0) {
		printf("%*s", (depth * 2) + 2, "");
		printf("|%-*s| %s\n", BYTES_PER_LINE, printable, hex);
	}
}
