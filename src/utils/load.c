/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal/utils.h"

#define BUF_SIZE (1024 * 1024)

uint8_t *
load(const char *name, size_t *length) {
	FILE *fd = stdin;
	if (strcmp(name, "-") != 0) {
		fd = fopen(name, "rb");
	}

	if (fd == NULL) {
		fprintf(stderr, "Can't open file '%s': %s\n", name, strerror(errno));
		return NULL;
	}

	uint8_t *contents = calloc(1, BUF_SIZE);
	if (contents == NULL) {
		perror("Could not allocate buffer");
		goto error;
	}

	*length = fread(contents, 1, BUF_SIZE, fd);
	if (*length < BUF_SIZE) {
		fclose(fd);
		return contents;
	}

	fprintf(stderr, "Input is longer than %d bytes\n", BUF_SIZE);
error:
	fclose(fd);
	free(contents);
	return NULL;
}
