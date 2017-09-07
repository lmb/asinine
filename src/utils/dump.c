/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asinine/asn1.h"

#define BYTES_PER_LINE (12)

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

void
dump_token(const asn1_token_t *token, uint8_t depth, void *ctx) {
	(void)ctx;

	const asn1_type_t *type = &token->type;

	char mark = (type->encoding == ASN1_ENCODING_PRIMITIVE) ? '-' : '*';
	char buf[256];

	char *suffix = "";
	if (asn1_type_to_string(buf, sizeof(buf), type) >= sizeof(buf)) {
		suffix = "...";
	}
	printf("%*s%c %s%s", depth * 2, "", mark, buf, suffix);

	if (type->encoding == ASN1_ENCODING_CONSTRUCTED) {
		printf("\n");
	} else if (type->class == ASN1_CLASS_UNIVERSAL) {
		switch (type->tag) {
		case ASN1_TAG_T61STRING:
		case ASN1_TAG_IA5STRING:
		case ASN1_TAG_UTF8STRING:
		case ASN1_TAG_VISIBLESTRING:
		case ASN1_TAG_PRINTABLESTRING:
			if (asn1_string(token, buf, sizeof(buf)) < ASININE_OK) {
				printf(" <INVALID>\n");
				break;
			}

			printf(" '%s'\n", buf);
			break;

		case ASN1_TAG_INT: {
			asn1_word_t value;

			if (asn1_int(token, &value) < ASININE_OK) {
				printf(" <INVALID>\n");
				break;
			}

			printf(" %" PRIdPTR "\n", value);
			break;
		}

		case ASN1_TAG_OID: {
			asn1_oid_t oid;

			if (asn1_oid(token, &oid) < ASININE_OK) {
				printf(" <INVALID>\n");
				break;
			}

			if (asn1_oid_to_string(buf, sizeof(buf), &oid) >= sizeof(buf)) {
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

			if (asn1_time_to_string(buf, sizeof buf, &time) >= sizeof(buf)) {
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

static const uint8_t *load(FILE *fd, size_t *length);

int
main(int argc, const char *argv[]) {
	const uint8_t *contents;
	size_t length;

	if (argc < 2) {
		printf("%s <file>\n", argv[0]);
		return 1;
	}

	FILE *fd = stdin;
	if (strcmp(argv[1], "-") != 0) {
		fd = fopen(argv[1], "rb");
		if (fd == NULL) {
			perror("Couldn't open source");
			return 1;
		}
	}

	contents = load(fd, &length);
	fclose(fd);

	if (contents == NULL) {
		return 1;
	}

	asn1_parser_t parser;
	asn1_init(&parser, contents, length);

	asinine_err_t err = asn1_tokens(&parser, NULL, dump_token);
	if (err != ASININE_OK) {
		fprintf(stderr, "Failed: %s\n", asinine_strerror(err));
		return 2;
	}

	return 0;
}

static const uint8_t *
load(FILE *fd, size_t *length) {
#define BUF_SIZE (1024 * 1024)
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
#undef BUF_SIZE
}
