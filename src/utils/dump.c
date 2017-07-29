/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "asinine/asn1.h"

#define BYTES_PER_LINE (12)

static void
prelude(const asn1_token_t *token, int depth) {
	const asn1_type_t *const type = &token->type;

	char mark = (type->encoding == ASN1_ENCODING_PRIMITIVE) ? '-' : '*';
	char buf[256];

	asn1_to_string(buf, sizeof buf, type);
	printf("%*s%c %s", depth * 2, "", mark, buf);
}

static char
to_printable(uint8_t value) {
	return (32 <= value && value <= 127) ? (char)value : '.';
}

static void
hexdump(const asn1_token_t *token, int depth) {
	size_t i, j;
	char printable[BYTES_PER_LINE + 1] = "";
	char hex[(3 * BYTES_PER_LINE) + 1] = "";

	if (token->data == NULL) {
		return;
	}

	for (i = 0, j = 0; i < token->length; ++i, j = (j + 1) % BYTES_PER_LINE) {
		if (j == 0 && i > 0) {
			printf("%*s", (depth * 2) + 2, "");
			printf("|%-*s| %s\n", BYTES_PER_LINE, printable, hex);
			memset(printable, 0, sizeof printable);
			memset(hex, 0, sizeof hex);
		}

		printable[j] = to_printable(token->data[i]);
		snprintf(hex + (j * 3), 4, "%02X ", token->data[i]);
	}

	if (j > 0) {
		printf("%*s", (depth * 2) + 2, "");
		printf("|%-*s| %s\n", BYTES_PER_LINE, printable, hex);
	}
}

static void
dump_token(const asn1_token_t *token, uint8_t depth) {
	if (token->type.class == ASN1_CLASS_UNIVERSAL) {
		char buf[256];

		switch (token->type.tag) {
		case ASN1_TAG_T61STRING:
		case ASN1_TAG_IA5STRING:
		case ASN1_TAG_UTF8STRING:
		case ASN1_TAG_VISIBLESTRING:
		case ASN1_TAG_PRINTABLESTRING:
			if (asn1_string(token, buf, sizeof buf) < ASININE_OK) {
				printf(" <INVALID>\n");
				break;
			}

			printf(" '%s'\n", buf);
			break;

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

		case ASN1_TAG_OCTETSTRING:
			printf("\n");
			hexdump(token, depth);
			break;

		case ASN1_TAG_BOOL: {
			bool value;

			if (asn1_bool(token, &value) < ASININE_OK) {
				printf(" <INVALID>\n");
				break;
			}

			printf(" %s\n", value ? "True" : "False");
			break;
		}

		case ASN1_TAG_NULL:
			printf("\n");
			break;

		default:
			printf(" <NOT IMPLEMENTED>\n");
			break;
		}
	} else {
		printf("\n");
		hexdump(token, depth);
	}
}

static bool
dump_tokens(asn1_parser_t *parser) {
	const asn1_token_t *const token = &parser->token;

	while (!asn1_eof(parser)) {
		if (asn1_next(parser) != ASININE_OK) {
			fprintf(stderr, "Could not parse token\n");
			return false;
		}

		prelude(token, parser->depth);

		if (token->type.encoding == ASN1_ENCODING_CONSTRUCTED) {
			printf("\n");

			if (asn1_push(parser) != ASININE_OK) {
				return false;
			}

			if (!dump_tokens(parser)) {
				return false;
			}

			if (asn1_pop(parser) != ASININE_OK) {
				return false;
			}
		} else {
			dump_token(token, parser->depth);
		}
	}

	return true;
}

static const uint8_t *load(int fd, size_t *length);

int
main(int argc, const char *argv[]) {
	const uint8_t *contents;
	size_t length;

	if (argc < 2) {
		printf("%s <file>\n", argv[0]);
		return 1;
	}

	int fd = STDIN_FILENO;
	if (strcmp(argv[1], "-") != 0) {
		fd = open(argv[1], O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Could not open source\n");
			return 1;
		}
	}

	contents = load(fd, &length);
	close(fd);

	if (contents == NULL) {
		return 1;
	}

	asn1_parser_t parser;
	asn1_init(&parser, contents, length);

	if (!dump_tokens(&parser)) {
		return 2;
	}

	if (!asn1_end(&parser)) {
		fprintf(stderr, "Did not parse full file\n");
		return 3;
	}

	return 0;
}

static const uint8_t *
load(int fd, size_t *length) {
	uint8_t *contents = calloc(1, 1024 * 1024);
	if (contents == NULL) {
		printf("Could not allocate memory\n");
		return NULL;
	}

	*length = 0;
	while (*length < 1024 * 1024) {
		ssize_t n = read(fd, contents + *length, 1024 * 1024 - *length);
		if (n == 0) {
			return contents;
		} else if (n < 0) {
			perror("Could not read full file");
			return NULL;
		}
		*length += n;
	}

	fprintf(stderr, "Input too large\n");
	free(contents);
	return NULL;
}
