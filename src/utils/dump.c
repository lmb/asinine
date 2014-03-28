/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "asinine/asn1.h"

#define BYTES_PER_LINE (12)

static void
prelude(const asn1_token_t* token, int depth) {
	const asn1_type_t* const type = &token->type;

	char mark = (type->encoding == ASN1_ENCODING_PRIMITIVE) ? '-' : '*';
	char buf[256];

	asn1_to_string(buf, sizeof buf, type);
	printf("%*s%c %s", depth * 2, "", mark, buf);
}

static char
to_printable(uint8_t value)
{
	return (32 <= value && value <= 127) ? (char)value : '.';
}

static void
hexdump(const asn1_token_t* token, int depth)
{
	size_t i, j;
	char printable[BYTES_PER_LINE+1] = "";
	char hex[(3*BYTES_PER_LINE)+1] = "";

	if (token->data == NULL) {
		return;
	}

	for (i = 0, j = 0; i < token->length; ++i, j = (j + 1) % BYTES_PER_LINE) {
		if (j == 0 && i > 0) {
			printf("%*s", (depth*2) + 2, "");
			printf("|%-*s| %s\n", BYTES_PER_LINE, printable, hex);
			memset(printable, 0, sizeof printable);
			memset(hex, 0, sizeof hex);
		}

		printable[j] = to_printable(token->data[i]);
		snprintf(hex + (j * 3), 4, "%02X ", token->data[i]);
	}

	if (j > 0) {
		printf("%*s", (depth*2) + 2, "");
		printf("|%-*s| %s\n", BYTES_PER_LINE, printable, hex);
	}
}

static bool
dump_token(asn1_parser_t* parser, int depth)
{
	const asn1_token_t* const token = &parser->token;

	if (!asn1_next(parser)) {
		printf("Could not parse token\n");
		return false;
	}

	prelude(token, depth);

	if (token->type.encoding == ASN1_ENCODING_CONSTRUCTED) {
		const asn1_token_t parent = *token;

		printf("\n");

		asn1_descend(parser);
		while (!asn1_eot(parser, &parent)) {
			if (!dump_token(parser, depth+1)) {
				return false;
			}
		}
		asn1_ascend(parser, 1);
	} else if (token->type.class == ASN1_CLASS_UNIVERSAL) {
		char buf[256];

		switch ((asn1_tag_t)token->type.tag) {
			case ASN1_TAG_T61STRING:
			case ASN1_TAG_IA5STRING:
			case ASN1_TAG_UTF8STRING:
			case ASN1_TAG_VISIBLESTRING:
			case ASN1_TAG_PRINTABLESTRING: {
				if (asn1_string(token, buf, sizeof buf) < ASININE_OK) {
					printf(" <INVALID>\n");
					break;
				}

				printf(" '%s'\n", buf);
				break;
			}

			case ASN1_TAG_INT: {
				int value;

				if (asn1_int(token, &value) < ASININE_OK) {
					printf(" <INVALID>\n");
					break;
				}

				printf(" %d\n", value);
				break;
			}

			case ASN1_TAG_OID: {
				asn1_oid_t oid;

				if (asn1_oid(token, &oid) < ASININE_OK) {
					printf(" <INVALID>\n");
					break;
				}

				if (sizeof buf <= asn1_oid_to_string(buf, sizeof buf, &oid)) {
					printf(" <TOO LONG>\n");
					break;
				}

				printf(" %s\n", buf);
				break;
			}

			case ASN1_TAG_UTCTIME:
			case ASN1_TAG_GENERALIZEDTIME: {
				asn1_time_t time;

				if (asn1_time(token, &time) < ASININE_OK) {
					printf(" <INVALID>\n");
					break;
				}

				if (sizeof buf <= asn1_time_to_string(buf, sizeof buf, &time)) {
					printf(" <TOO LONG>\n");
					break;
				}

				printf(" %s\n", buf);
				break;
			}

			case ASN1_TAG_OCTETSTRING: {
				printf("\n");
				hexdump(token, depth);
				break;
			}

			case ASN1_TAG_BOOL: {
				bool value;

				if (asn1_bool(token, &value) < ASININE_OK) {
					printf(" <INVALID>\n");
					break;
				}

				printf(" %s\n", value ? "True" : "False");
				break;
			}

			case ASN1_TAG_NULL: {
				printf("\n");
				break;
			}

			default:
				printf(" <NOT IMPLEMENTED>\n");
				break;
		}
	} else {
		printf("\n");
		hexdump(token, depth);
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

	return 0;
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
