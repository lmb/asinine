/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "internal/utils.h"

#define BUF_SIZE (1024 * 1024)

uint8_t *
load(FILE *fd, size_t *length) {
	uint8_t *contents = calloc(1, BUF_SIZE);
	if (contents == NULL) {
		printf("Could not allocate memory\n");
		return NULL;
	}

	*length = fread(contents, 1, BUF_SIZE, fd);
	if (*length < BUF_SIZE) {
		return contents;
	}

	fprintf(stderr, "Input is longer than %d bytes\n", BUF_SIZE);
	free(contents);
	return NULL;
}
