/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string.h>
#include <assert.h>

#include "asinine/asn1.h"

// X.690 11/2008 item 8.1.2.4.1
#define IDENTIFIER_MULTIPART_TAG     (31)

#define IDENTIFIER_TYPE_MASK  (1<<5)
#define IDENTIFIER_TAG_MASK   ((1<<5)-1)
#define IDENTIFIER_MULTIPART_TAG_MASK ((1<<7)-1)

#define IDENTIFIER_CLASS(x) (((x) & (3<<6)) >> 6)

#define IDENTIFIER_IS_PRIMITIVE(x) (((x) & IDENTIFIER_TYPE_MASK) == 0)
#define IDENTIFIER_TAG_IS_MULTIPART(x) (((x) & IDENTIFIER_TAG_MASK) == \
	IDENTIFIER_MULTIPART_TAG)

// X.690 11/2008 item 8.1.3.5 (a)
#define CONTENT_LENGTH_LONG_MASK       (1<<7)
#define CONTENT_LENGTH_MASK            ((1<<7)-1)
// X.690 11/2008 item 8.1.3.5 (c)
#define CONTENT_LENGTH_LONG_RESERVED   ((1<<7)-1)

#define CONTENT_LENGTH_IS_LONG_FORM(x) ((x) & CONTENT_LENGTH_LONG_MASK)

#define NUM(x) (sizeof x / sizeof *(x))

static void
update_depth(asn1_parser_t *parser)
{
	// Check whether we're at the end of the parent token. If so, we ascend one
	// level and update the depth.
	while (parser->current == parser->parents[parser->depth] &&
		parser->depth > 1) {
		parser->depth--;
	}
}

void
asn1_init(asn1_parser_t *parser, const uint8_t *data, size_t length)
{
	assert(parser != NULL);
	assert(data != NULL);
	assert(length != 0);

	memset(parser, 0, sizeof *parser);

	parser->current = data;
	parser->parents[0] = data + length;
}

asinine_err_t
asn1_ascend(asn1_parser_t *parser, size_t levels)
{
	if (levels >= parser->constraint) {
		return ASININE_ERROR_INVALID;
	}

	parser->constraint -= levels;
	return ASININE_OK;
}

asinine_err_t
asn1_descend(asn1_parser_t *parser)
{
	if (parser->constraint >= NUM(parser->parents)) {
		return ASININE_ERROR_INVALID;
	}

	parser->constraint += 1;
	return ASININE_OK;
}

void
asn1_skip(asn1_parser_t *parser)
{
	const asn1_token_t* const token = &parser->token;

	if (!token->is_primitive) {
		parser->current = token->data + token->length;

		update_depth(parser);
	}
}

bool
asn1_eot(const asn1_parser_t *parser, const asn1_token_t *token)
{
	return parser->current >= token->data + token->length;
}

bool
asn1_eof(const asn1_parser_t *parser)
{
	return parser->current == parser->parents[parser->depth];
}

asinine_err_t
asn1_next(asn1_parser_t *parser)
{
#define INC_CURRENT do { \
		parser->current++; \
		if (parser->current >= parent_end) { \
			return ASININE_ERROR_INVALID; \
		} \
	} while (0)

	const uint8_t* const parent_end = parser->parents[parser->depth];
	const uint8_t* end;
	asn1_token_t* token = &parser->token;

	if (parser->current >= parent_end) {
		return ASININE_ERROR_INVALID;
	}

	if (parser->constraint > 0 &&
		parser->constraint != parser->depth) {
		return ASININE_ERROR_INVALID;
	}

	memset(token, 0, sizeof *token);

	token->type.class = IDENTIFIER_CLASS(*parser->current);
	token->is_primitive = IDENTIFIER_IS_PRIMITIVE(*parser->current);

	// Type (8.1.2)
	token->type.tag = *parser->current & IDENTIFIER_TAG_MASK;
	INC_CURRENT;

	if (token->type.tag == IDENTIFIER_MULTIPART_TAG) {
		size_t bits;

		// 8.1.2.4.2
		bits = 0;
		token->type.tag = 0;

		do {
			token->type.tag <<= 7;
			token->type.tag |= *parser->current & IDENTIFIER_MULTIPART_TAG_MASK;
			INC_CURRENT;

			bits += 7;
			if (bits > sizeof token->type.tag * 8) {
				return ASININE_ERROR_MEMORY;
			}
		} while (*parser->current & 0x80);
	}

	// Length (8.1.3)
	if (CONTENT_LENGTH_IS_LONG_FORM(*parser->current)) {
		size_t i, num_bytes;

		num_bytes = *parser->current & CONTENT_LENGTH_MASK;

		if (num_bytes == CONTENT_LENGTH_LONG_RESERVED) {
			return ASININE_ERROR_INVALID;
		} else if (num_bytes == 0) {
			// Indefinite form is not supported (X.690 11/2008 8.1.3.6)
			return ASININE_ERROR_INVALID;
		} else if (num_bytes > sizeof token->length) {
			// TODO: Write a test for this
			return ASININE_ERROR_UNSUPPORTED;
		}

		token->length = 0;
		for (i = 0; i < num_bytes; i++) {
			INC_CURRENT;
			token->length = (token->length << 8) | *parser->current;
		}
	} else {
		token->length = *parser->current & CONTENT_LENGTH_MASK;
	}

	// At this point, parser->current is not necessarily valid. For example,
	// NULL tokens will have a data pointer that might well point after the
	// actual data.

	parser->current++;
	token->data = parser->current;
	end = token->data + token->length;

	if (parser->depth == 0 && end != parent_end) {
		return ASININE_ERROR_INVALID;
	} else if (end > parent_end) {
		return ASININE_ERROR_INVALID;
	}

	if (token->is_primitive) {
		parser->current = end;
	} else {
		parser->depth++;

		if (parser->depth >= NUM(parser->parents)) {
			return ASININE_ERROR_INVALID;
		}

		parser->parents[parser->depth] = end;
	}

	update_depth(parser);

	return ASININE_OK;
#undef INC_CURRENT
}
