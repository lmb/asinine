/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "asinine/macros.h"

#define ASN1_OID(...) \
	{ \
		.num = PP_NARG(__VA_ARGS__), .arcs = { __VA_ARGS__ } \
	}
#define ASN1_CONST_OID(...) PP_NARG(__VA_ARGS__), __VA_ARGS__
#define ASN1_OID_FROM_CONST(...) ASN1_OID_FROM_CONST_(__VA_ARGS__)
#define ASN1_OID_FROM_CONST_(x, ...) ASN1_OID(__VA_ARGS__)

#define ASN1_OID_MAXIMUM_ARCS (12)
#define ASN1_MAXIMUM_DEPTH (12)

/* cldoc:begin-category(ASN.1) */

typedef intptr_t asn1_word_t;
typedef uintptr_t asn1_uword_t;

// Error numbers
typedef enum asinine_errno {
	ASININE_OK              = 0,
	ASININE_ERR_MALFORMED   = 10, // Buffer isn't valid ASN.1 in DER form
	ASININE_ERR_MEMORY      = 11, // One of the static memory limits was hit
	ASININE_ERR_UNSUPPORTED = 12, // An unsupported feature was hit
	ASININE_ERR_INVALID     = 13,
	ASININE_ERR_EXPIRED     = 14, // X.509: Certificate has expired
	ASININE_ERR_UNTRUSTED   = 15, // X.509: Signature is invalid
	ASININE_ERR_DEPRECATED  = 16, // X.509: Deprecated algorithm used
	ASININE_ERR_NOT_FOUND   = 17, // X.509: No trust anchor found
} asinine_errno_t;

// Error type
typedef struct asinine_err {
	// Error number
	asinine_errno_t errno;
	// Detail why the error was raised, may be NULL
	const char *reason;
} asinine_err_t;

/* Class of a token
 *
 * See X.690 11/2008 item 8.1.2.2.
 */
typedef enum asn1_class {
	// Predefined ASN.1 types, see <asn1_tag_t>
	ASN1_CLASS_UNIVERSAL   = 0,
	ASN1_CLASS_APPLICATION = 1,
	ASN1_CLASS_CONTEXT     = 2,
	ASN1_CLASS_PRIVATE     = 3
} asn1_class_t;

// Predefined tags for ASN1_CLASS_UNIVERSAL
typedef enum asn1_tag {
	ASN1_TAG_BOOL            = 1,
	ASN1_TAG_INT             = 2,
	ASN1_TAG_BITSTRING       = 3,
	ASN1_TAG_OCTETSTRING     = 4,
	ASN1_TAG_NULL            = 5,
	ASN1_TAG_OID             = 6,
	ASN1_TAG_UTF8STRING      = 12,
	ASN1_TAG_SEQUENCE        = 16,
	ASN1_TAG_SET             = 17,
	ASN1_TAG_PRINTABLESTRING = 19,
	ASN1_TAG_T61STRING       = 20,
	ASN1_TAG_IA5STRING       = 22,
	ASN1_TAG_UTCTIME         = 23,
	ASN1_TAG_GENERALIZEDTIME = 24,
	ASN1_TAG_VISIBLESTRING   = 26
} asn1_tag_t;

// Encoding of a token
typedef enum asn1_encoding {
	// A scalar value
	ASN1_ENCODING_PRIMITIVE = 0,
	// A complex value, which contains valid ASN.1
	ASN1_ENCODING_CONSTRUCTED = 1
} asn1_encoding_t;

// An ASN.1 time value
typedef struct asn1_time {
	int32_t year;   // Year
	uint8_t month;  // Month (1-12)
	uint8_t day;    // Day (1-31)
	uint8_t hour;   // Hour (0-23)
	uint8_t minute; // Minute (0-59)
	uint8_t second; // Second (0-59)
} asn1_time_t;

//
typedef uint32_t asn1_oid_arc_t;

/* An ASN.1 OID
 *
 * Object Identifiers are made up of individual arcs.
 */
typedef struct asn1_oid {
	asn1_oid_arc_t arcs[ASN1_OID_MAXIMUM_ARCS];
	size_t num;
} asn1_oid_t;

/* The type of an <asn1_token_t>
 *
 * Class and tag identify a specific type of data, while the encoding
 * indicates whether a given token has children which can be parsed.
 */
typedef struct asn1_type {
#define ASN1_TYPE_TAG_BITS (24)
	asn1_tag_t tag : ASN1_TYPE_TAG_BITS;
#define ASN1_TYPE_CLASS_BITS (2)
	asn1_class_t class : ASN1_TYPE_CLASS_BITS;
#define ASN1_TYPE_ENCODING_BITS (1)
	asn1_encoding_t encoding : ASN1_TYPE_ENCODING_BITS;
} asn1_type_t;

// Unit emitted by <asn1_parser_t>
typedef struct asn1_token {
	// Start of the token (including header)
	const uint8_t *start;
	// Data contained in the token
	const uint8_t *data;
	// Length of data (0 if data is NULL)
	size_t length;
	// Type of the token
	asn1_type_t type;
} asn1_token_t;

// Splits a buffer into <asn1_token_t>
typedef struct asn1_parser {
	// Buffer of data to parse
	const uint8_t *current;
	// End of current
	const void *end;
	// Pointers to the ends of parent tokens
	const void *stack[ASN1_MAXIMUM_DEPTH];
	// Next unused element in the stack
	uint8_t depth;
	// Current decoded token
	asn1_token_t token;
} asn1_parser_t;

// Turn an error into its string representation
ASININE_API const char *asinine_strerror(asinine_err_t err);

/* Initialise a parser
 * @parser Struct to initialise
 * @data DER bytes to parse
 * @length Length of data
 *
 * The data passed to this function must not be de-allocated for the lifetime of
 * the parser.
 */
ASININE_API void asn1_init(
    asn1_parser_t *parser, const uint8_t *data, size_t length);

/* Abort parsing
 * @parser Parser to abort
 *
 * Abort parsing the current structure. Useful if a buffer contains multiple
 * independent structures, and one of them is corrupted.
 *
 * @return an error if the parse can't be aborted
 */
ASININE_API asinine_err_t asn1_abort(asn1_parser_t *parser);

/* Parse the next token
 *
 * Parses the next token into parser->token.
 */
ASININE_API asinine_err_t asn1_next(asn1_parser_t *parser);

/* Push the current token
 *
 * Push the current token onto the parsing stack. Subsequent calls to
 * <asn1_next> will parse children of that token.
 *
 * Use this function to descend into a nested ASN.1 structure.
 *
 * @return an error if token is not CONSTRUCTED encoding
 */
ASININE_API asinine_err_t asn1_push(asn1_parser_t *parser);

/* Force push the current token
 *
 * See <asn1_push> for details. This function does not check for CONSTRUCTED
 * encoding.
 */
ASININE_API asinine_err_t asn1_force_push(asn1_parser_t *parser);

/* Pop the top of the token stack
 *
 * Remove the topmost token from the token stack. This has the effect of
 * ascending one level in an ASN.1 structure.
 *
 * @return an error if the there is still data left to parse
 */
ASININE_API asinine_err_t asn1_pop(asn1_parser_t *parser);

/* Push the next sequence onto the stack
 *
 * Parse the next token, verify it is of type sequence, and push it
 * onto the stack.
 */
ASININE_API asinine_err_t asn1_push_next_seq(asn1_parser_t *parser);

/* Parse all tokens
 * @fn called for every parsed token
 * @ctx context passed to fn, may be NULL
 *
 * Parse all tokens, descending into each one with CONSTRUCTED encoding.
 */
ASININE_API asinine_err_t asn1_tokens(asn1_parser_t *parser, void *ctx,
    void (*fn)(const asn1_token_t *, uint8_t depth, void *ctx));

/* Detect the end of the stack
 *
 * Detect the end of the token on the top of the parsing stack. If no call to
 * <asn1_push> has been made it checks the end of the input buffer.
 *
 * Use <asn1_end> to determine whether all data has been parsed.
 *
 * @return true if all data
 */
ASININE_API bool asn1_eof(const asn1_parser_t *parser);

/* Detect the end of the input
 *
 * Detect the end of the input buffer.
 *
 * @return true if all data has been parsed
 */
ASININE_API bool asn1_end(const asn1_parser_t *parser);

/* Types */
ASININE_API asinine_err_t asn1_string(
    const asn1_token_t *token, char *buf, size_t num);

/* Decode a bitstring
 * @token Token to be decoded
 * @buf Output buffer
 * @num Length of buffer
 *
 * Decode a bitstring into a buffer, swapping bits into the correct order.
 * The caller can then assemble them into a bit flag type:
 *
 *     uint16_t flags = buf[0] << 8 | buf[1];
 *
 * Bit positions are transposed like this ('|' is a byte boundary):
 *
 *     | 0 1 2 3 4 5 6 7 | 8 9 … | -> | 7 6 5 4 3 2 1 0 | … 9 8 |
 */
ASININE_API asinine_err_t asn1_bitstring(
    const asn1_token_t *token, uint8_t *buf, const size_t len);

/* Decode an integer
 * @value Result integer
 *
 * Decode a token as a signed integer.
 *
 * @return an error if the value is outside of <asn1_word_t> range
 */
ASININE_API asinine_err_t asn1_int(
    const asn1_token_t *token, asn1_word_t *value);

/* Raw value of an unsigned integer
 * @buf Result buffer
 * @num Result length of buf
 *
 * Verify that token is a valid unsigned integer, and return a buffer
 * pointing to its contents.
 *
 * @return an error if the integer is signed.
 */
ASININE_API asinine_err_t asn1_uint_buf(
    const asn1_token_t *token, const uint8_t **buf, size_t *num);

/* Decode a time type
 * @time Result time
 *
 * Decode a token into an <asn1_time_t>. Doesn't support leap seconds.
 */
ASININE_API asinine_err_t asn1_time(
    const asn1_token_t *token, asn1_time_t *time);

/* Decode a boolean
 * @value Result boolean
 *
 * Decode a boolean.
 */
ASININE_API asinine_err_t asn1_bool(const asn1_token_t *token, bool *value);

/* Decode a null value
 *
 * Verify that token is a valid NULL token.
 */
ASININE_API asinine_err_t asn1_null(const asn1_token_t *token);

/* Compare a token and string
 * @str String to compare to
 *
 * Compare a token and a string. Verifies that token contains a valid string.
 *
 * @return true if the contents match
 */
ASININE_API bool asn1_string_eq(const asn1_token_t *token, const char *str);

/* Compare two tokens
 *
 * Compare two tokens and consider them equal if type and data match.
 *
 * @return true if both tokens are equal
 */
ASININE_API bool asn1_eq(const asn1_token_t *a, const asn1_token_t *b);

/* Compare two time values
 *
 * Compare two time values.
 *
 * @return 0 if equal, < 0 if a is before b and > 0 if a is after b
 */
ASININE_API int asn1_time_cmp(const asn1_time_t *a, const asn1_time_t *b);

/* Format an <asn1_type_t> as a string
 * @dst Destination buffer
 * @len Length of dst
 *
 * Format an ASN.1 type as a string, always terminating with NUL.
 * You can detect a truncated result by comparing the return value with the
 * size of the buffer:
 *
 *     if (asn1_type_to_string(buf, sizeof(buf), type) >= sizeof(buf)) {
 *         // buf contains truncated result
 *     }
 *
 * @return number of bytes written if dst were unlimited in size
 */
ASININE_API size_t asn1_type_to_string(
    char *dst, size_t len, const asn1_type_t *type);

/* Format an <asn1_time_t> as a string
 * @dst Destination buffer
 * @len Length of dst
 *
 * Format an ASN.1 time as a string, always terminating with NUL. See
 * <asn1_type_to_string> on how to check for a truncated result.
 *
 * @return number of bytes written if dst were unlimited in size
 */
ASININE_API size_t asn1_time_to_string(
    char *dst, size_t len, const asn1_time_t *time);

/* Check the type of a token
 *
 * @return true if class, tag and encoding match token
 */
ASININE_API bool asn1_is(const asn1_token_t *token, asn1_class_t class,
    asn1_tag_t tag, asn1_encoding_t encoding);

// Check if a token is a string
ASININE_API bool asn1_is_string(const asn1_token_t *token);
// Check if a token is a time value
ASININE_API bool asn1_is_time(const asn1_token_t *token);
// Check if a token is a sequence
ASININE_API bool asn1_is_sequence(const asn1_token_t *token);
// Check if a token is an OID
ASININE_API bool asn1_is_oid(const asn1_token_t *token);
// Check if a token is an integer
ASININE_API bool asn1_is_int(const asn1_token_t *token);
// Check if a token is a boolean
ASININE_API bool asn1_is_bool(const asn1_token_t *token);
// Check if a token is an set
ASININE_API bool asn1_is_set(const asn1_token_t *token);
// Check if a token is a bitstring
ASININE_API bool asn1_is_bitstring(const asn1_token_t *token);
// Check if a token is an octetstring
ASININE_API bool asn1_is_octetstring(const asn1_token_t *token);
// Check if a token is a NULL
ASININE_API bool asn1_is_null(const asn1_token_t *token);

/* Decode an OID
 * @oid Result
 */
ASININE_API asinine_err_t asn1_oid(const asn1_token_t *token, asn1_oid_t *oid);
/* Format an <asn1_oid_t> as a string
 * @dst Destination buffer
 * @len Length of dst
 *
 * Format an ASN.1 OID as a string, always terminating with NUL. See
 * <asn1_type_to_string> on how to check for a truncated result.
 *
 * @return number of bytes written if dst were unlimited in size
 */
ASININE_API size_t asn1_oid_to_string(
    char *dst, size_t len, const asn1_oid_t *oid);

/* Compare an OID to a list of arcs
 * @num Number of arcs
 * @... Num arcs
 *
 * @return true if arcs are equal
 */
ASININE_API bool asn1_oid_eq(const asn1_oid_t *oid, size_t num, ...);

/* Compare two OIDs
 *
 * Compare two OIDs according to a lexical ordering, e.g.:
 *
 *     1.2
 *     1.2.1
 *     1.3
 *
 * @return 0 if a and b are equal, < 0 if a is less than b, > 0 otherwise
 */
ASININE_API int asn1_oid_cmp(const asn1_oid_t *a, const asn1_oid_t *b);

/* cldoc:end-category() */

#ifdef __cplusplus
}
#endif
