/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "asinine/asn1.h"

static bool
dump_token(asn1_parser_t* parser, int depth)
{
	const asn1_token_t* const token = &parser->token;
	char buf[256] = "";

	if (!asn1_next(parser)) {
		return false;
	}

	asn1_to_string(buf, sizeof buf, &token->type);
	printf("%s\n", buf);

	if (!token->is_primitive) {
		const asn1_token_t parent = *token;

		asn1_descend(parser);
		while (!asn1_eot(parser, &parent)) {
			if (!dump_token(parser, depth+1)) {
				return false;
			}
		}
		asn1_ascend(parser, 1);
	}

	return true;
}

static const uint8_t* load(const char* filename, size_t* length);

int main(int argc, const char* argv[])
{
	asn1_parser_t parser;
	const uint8_t* contents;
	size_t length;

	if (argc < 2) {
		printf("%s <file>\n", argv[0]);
		return 1;
	}

	contents = load(argv[1], &length);

	if (contents == NULL) {
		return 1;
	}

	asn1_init(&parser, contents, length);

	if (!dump_token(&parser, 0)) {
		return 1;
	}
}

static const uint8_t*
load(const char* filename, size_t* length)
{
	int fd;
	struct stat stat;
	uint8_t* contents = NULL;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		printf("Could not open source\n");
		return NULL;
	}

	if (fstat(fd, &stat) != 0) {
		printf("fstat failed\n");
		goto error;
	}

	if (stat.st_size == 0) {
		printf("File is empty\n");
		goto error;
	}

	contents = malloc(stat.st_size);

	if (contents == NULL) {
		printf("Could not allocate memory\n");
		goto error;
	}

	if (read(fd, contents, stat.st_size) == -1) {
		printf("Could not read full file\n");
		goto error;
	}

	close(fd);

	*length = stat.st_size;
	return contents;

	error:
	close(fd);
	free(contents);
	return NULL;
}
