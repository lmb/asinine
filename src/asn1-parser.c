/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <string.h>
#include <assert.h>

#include "asinine/asn1.h"

#if ASN1_MAXIMUM_DEPTH > UINT8_MAX
#	error Maximum ASN.1 depth must be smaller than UINT8_MAX
#endif

// X.690 11/2008 item 8.1.2.4.1
#define TYPE_MULTIPART_TAG (31)

#define TYPE_CLASS(x)      (((x) & (3<<6)) >> 6)
#define TYPE_ENCODING(x)   (((x) & (1<<5)) >> 5)
#define TYPE_TAG(x)        ((x) & ((1<<5)-1))

#define MULTIPART_TAG_BITS_PER_BYTE (7)
#define MULTIPART_TAG_MASK          ((1<<7)-1)
#define MULTIPART_TAG_CONTINUATION  (1<<7)

// X.690 11/2008 item 8.1.3.5 (a)
#define CONTENT_LENGTH_LONG_MASK       (1<<7)
#define CONTENT_LENGTH_MASK            ((1<<7)-1)
// X.690 11/2008 item 8.1.3.5 (c)
#define CONTENT_LENGTH_LONG_RESERVED   ((1<<7)-1)
#define CONTENT_LENGTH_LONG_MIN        (128)

#define CONTENT_LENGTH_IS_LONG_FORM(x) ((x) & CONTENT_LENGTH_LONG_MASK)

#define NUM(x) (sizeof x / sizeof *(x))

static void
update_depth(asn1_parser_t *parser)
{
	// Check whether we're at the end of the parent token. If so, we ascend one
	// level and update the depth.
	while (parser->current == parser->parents[parser->depth] &&
		parser->depth > 0) {
		parser->depth--;
	}
}

static inline bool
set_error(asn1_parser_t* parser, asinine_err_t error)
{
	parser->last_error = error;
	return false;
}

void
asn1_init(asn1_parser_t *parser, const uint8_t *data, size_t length)
{
	assert(parser != NULL);
	assert(data != NULL);

	memset(parser, 0, sizeof *parser);

	parser->last_error = ASININE_OK;
	parser->current = data;
	parser->parents[0] = data + length;
}

bool
asn1_ascend(asn1_parser_t *parser, uint8_t levels)
{
	if (levels > parser->constraint) {
		return set_error(parser, ASININE_ERROR_INVALID);
	}

	parser->constraint -= levels;

	return true;
}

bool
asn1_descend(asn1_parser_t *parser)
{
	if (parser->constraint >= NUM(parser->parents) - 1) {
		return set_error(parser, ASININE_ERROR_INVALID);
	}

	parser->constraint += 1;

	return true;
}

void
asn1_skip_unsafe(asn1_parser_t *parser)
{
	const asn1_token_t* const token = &parser->token;

	if (token->type.encoding == ASN1_ENCODING_CONSTRUCTED) {
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
asn1_eof(const asn1_parser_t* parser)
{
	return (parser->current == parser->parents[0]);
}

bool
asn1_valid(const asn1_parser_t* parser)
{
	return (parser->depth == 0) && (parser->current == parser->parents[0]) &&
	       (parser->last_error == ASININE_OK);
}

ASININE_API asinine_err_t
asn1_get_error(const asn1_parser_t* parser)
{
	return parser->last_error;
}

static inline bool
advance_pos(asn1_parser_t* parser, size_t num)
{
	parser->current += num;
	if (parser->current >= parser->parents[parser->depth]) {
		return set_error(parser, ASININE_ERROR_MALFORMED);
	}

	return true;
}

bool
asn1_next(asn1_parser_t *parser)
{
	asn1_token_t* const token = &parser->token;

	if (parser->current >= parser->parents[parser->depth]) {
		return set_error(parser, ASININE_ERROR_MALFORMED);
	}

	if (parser->constraint != parser->depth) {
		return set_error(parser, ASININE_ERROR_INVALID);
	}

	memset(token, 0, sizeof *token);

	// Type (8.1.2)
	token->type.class    = TYPE_CLASS(*parser->current);
	token->type.encoding = TYPE_ENCODING(*parser->current);
	token->type.tag      = TYPE_TAG(*parser->current);

	if (token->type.tag == TYPE_MULTIPART_TAG) {
		size_t bits;

		// 8.1.2.4.2
		bits = 0;
		token->type.tag = 0;

		do {
			if (!advance_pos(parser, 1)) {
				return false;
			}

			token->type.tag <<= MULTIPART_TAG_BITS_PER_BYTE;
			token->type.tag |= *parser->current & MULTIPART_TAG_MASK;

			// TODO: Could this overflow bits?
			bits += MULTIPART_TAG_BITS_PER_BYTE;
			if (bits > sizeof token->type.tag * 8) {
				return set_error(parser, ASININE_ERROR_MEMORY);
			}
		} while (*parser->current & MULTIPART_TAG_CONTINUATION);
	}

	// Length (8.1.3)
	if (!advance_pos(parser, 1)) {
		return false;
	}

	if (CONTENT_LENGTH_IS_LONG_FORM(*parser->current)) {
		size_t i, num_bytes;

		num_bytes = *parser->current & CONTENT_LENGTH_MASK;

		if (num_bytes == CONTENT_LENGTH_LONG_RESERVED) {
			return set_error(parser, ASININE_ERROR_MALFORMED);
		} else if (num_bytes == 0) {
			// Indefinite form is forbidden (X.690 11/2008 8.1.3.6)
			return set_error(parser, ASININE_ERROR_MALFORMED);
		} else if (num_bytes > sizeof token->length) {
			return set_error(parser, ASININE_ERROR_UNSUPPORTED);
		}

		token->length = 0;
		for (i = 0; i < num_bytes; i++) {
			if (!advance_pos(parser, 1)) {
				return false;
			}

			if (token->length == 0 && *parser->current == 0) {
				return set_error(parser, ASININE_ERROR_MALFORMED);
			}

			token->length = (token->length << 8) | *parser->current;
		}

		// 10.1
		if (token->length < CONTENT_LENGTH_LONG_MIN){
			return set_error(parser, ASININE_ERROR_MALFORMED);
		}
	} else {
		token->length = *parser->current & CONTENT_LENGTH_MASK;
	}

	// Contents
	if (token->length > 0) {
		token->data = parser->current + 1;

		if (parser->current + token->length > parser->parents[parser->depth]) {
			return set_error(parser, ASININE_ERROR_MALFORMED);
		}

		if (token->type.encoding == ASN1_ENCODING_PRIMITIVE) {
			// Jump to last valid byte, not past
			parser->current += token->length;
		} else {
			if (parser->depth >= NUM(parser->parents) - 1) {
				return set_error(parser, ASININE_ERROR_UNSUPPORTED);
			}

			parser->depth++;
			parser->parents[parser->depth] = token->data + token->length;
		}
	}

	// Token has been successfully parsed, we now step past the current token.
	// The error condition for this is checked on the next call of this
	// function.
	parser->current++;
	update_depth(parser);

	return true;
}
