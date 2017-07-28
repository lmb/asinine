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

#define ASN1_OID_MAXIMUM_DEPTH 12
#define ASN1_MAXIMUM_DEPTH 10

typedef enum asinine_err {
	ASININE_OK                      = 0,
	ASININE_ERROR_MALFORMED         = -10,
	ASININE_ERROR_MEMORY            = -20,
	ASININE_ERROR_UNSUPPORTED       = -30,
	ASININE_ERROR_UNSUPPORTED_ALGO  = -31,
	ASININE_ERROR_UNSUPPORTED_EXTN  = -32,
	ASININE_ERROR_INVALID           = -40,
	ASININE_ERROR_INVALID_UNTRUSTED = -41,
	ASININE_ERROR_INVALID_EXPIRED   = -42
} asinine_err_t;

/**
 * ASN.1 identifier classes, based on X.690 11/2008 item 8.1.2.2.
 */
typedef enum asn1_class {
	ASN1_CLASS_UNIVERSAL   = 0,
	ASN1_CLASS_APPLICATION = 1,
	ASN1_CLASS_CONTEXT     = 2,
	ASN1_CLASS_PRIVATE     = 3
} asn1_class_t;

typedef enum asn1_tag {
	// End-of-content is invalid in the DER encoding
	// ASN1_TAG_EOC          = 0,
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

typedef enum asn1_encoding {
	ASN1_ENCODING_PRIMITIVE   = 0,
	ASN1_ENCODING_CONSTRUCTED = 1
} asn1_encoding_t;

typedef struct asn1_time {
	int32_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
} asn1_time_t;

typedef uint32_t asn1_oid_arc_t;

typedef struct asn1_oid {
	asn1_oid_arc_t arcs[ASN1_OID_MAXIMUM_DEPTH];
	size_t num;
} asn1_oid_t;

typedef struct asn1_type {
	uint32_t tag;
	uint8_t class;
	uint8_t encoding;
} asn1_type_t;

typedef struct asn1_token {
	const uint8_t *data;
	size_t length;
	asn1_type_t type;
	bool is_primitive;
} asn1_token_t;

typedef struct asn1_parser {
	const uint8_t *current;
	const uint8_t *end;
	const uint8_t *stack[ASN1_MAXIMUM_DEPTH];
	uint8_t depth;
	asn1_token_t token;
} asn1_parser_t;

ASININE_API const char *asinine_strerror(asinine_err_t err);

/* Parser */
ASININE_API void asn1_init(
    asn1_parser_t *parser, const uint8_t *data, size_t length);

ASININE_API asinine_err_t asn1_next(asn1_parser_t *parser);
ASININE_API asinine_err_t asn1_push(asn1_parser_t *parser);
ASININE_API asinine_err_t asn1_force_push(asn1_parser_t *parser);
ASININE_API asinine_err_t asn1_pop(asn1_parser_t *parser);

/**
 * Skip to the end of the current token
 * @param  parser ASN.1 parser
 * @note   This function does not validate any skipped tokens. As such, it
 *         is possible to skip invalid tokens, which would have led to an error
 *         on a full parse.
 */
ASININE_API void asn1_skip_unsafe(asn1_parser_t *parser);
ASININE_API bool asn1_eof(const asn1_parser_t *parser);
ASININE_API bool asn1_end(const asn1_parser_t *parser);

/* Types */
ASININE_API asinine_err_t asn1_string(
    const asn1_token_t *token, char *buf, size_t num);

/**
 * Deserialize an ASN.1 Bitstring
 *
 * The unserialized bytes are in the correct bit, but not byte order. This means
 * that byte swapping has to be handled by the caller.
 *
 * Bit positions are transposed like this ('|' is a byte boundary) from the
 * bitstring specification:
 * | 0 1 2 3 4 5 6 7 | 8 9 … | -> | 7 6 5 4 3 2 1 0 | … 9 8 |
 *
 * @param  token Bitstring token
 * @param  buf   Target buffer
 * @param  num   Size of target buffer
 * @return       ASININE_OK on success, < ASININE_OK on error
 */
ASININE_API asinine_err_t asn1_bitstring(
    const asn1_token_t *token, uint8_t *buf, const size_t num);

ASININE_API asinine_err_t asn1_int(const asn1_token_t *token, int *value);

ASININE_API asinine_err_t asn1_time(
    const asn1_token_t *token, asn1_time_t *time);

ASININE_API asinine_err_t asn1_bool(const asn1_token_t *token, bool *value);
ASININE_API asinine_err_t asn1_null(const asn1_token_t *token);
ASININE_API const uint8_t *asn1_raw(const asn1_token_t *token);

ASININE_API bool asn1_string_eq(const asn1_token_t *token, const char *str);
ASININE_API bool asn1_eq(const asn1_token_t *a, const asn1_token_t *b);

ASININE_API int asn1_time_cmp(const asn1_time_t *a, const asn1_time_t *b);

ASININE_API size_t asn1_to_string(
    char *dst, size_t num, const asn1_type_t *type);
ASININE_API size_t asn1_time_to_string(
    char *dst, size_t num, const asn1_time_t *time);

ASININE_API bool asn1_is(const asn1_token_t *token, asn1_class_t class,
    asn1_tag_t tag, asn1_encoding_t encoding);
ASININE_API bool asn1_is_string(const asn1_token_t *token);
ASININE_API bool asn1_is_time(const asn1_token_t *token);
ASININE_API bool asn1_is_string(const asn1_token_t *token);
ASININE_API bool asn1_is_time(const asn1_token_t *token);
ASININE_API bool asn1_is_sequence(const asn1_token_t *token);
ASININE_API bool asn1_is_oid(const asn1_token_t *token);
ASININE_API bool asn1_is_int(const asn1_token_t *token);
ASININE_API bool asn1_is_bool(const asn1_token_t *token);
ASININE_API bool asn1_is_set(const asn1_token_t *token);
ASININE_API bool asn1_is_bitstring(const asn1_token_t *token);
ASININE_API bool asn1_is_octetstring(const asn1_token_t *token);
ASININE_API bool asn1_is_null(const asn1_token_t *token);

/* OID */
ASININE_API asinine_err_t asn1_oid(const asn1_token_t *token, asn1_oid_t *oid);
ASININE_API size_t asn1_oid_to_string(
    char *dst, size_t num, const asn1_oid_t *oid);
ASININE_API bool asn1_oid_eq(const asn1_oid_t *oid, size_t num, ...);
ASININE_API int asn1_oid_cmp(const asn1_oid_t *a, const asn1_oid_t *b);

#ifdef __cplusplus
}
#endif
