/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __ASININE_ASN1_H__
#define __ASININE_ASN1_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "asinine/macros.h"

#define ASN1_OID(...) { .num = PP_NARG(__VA_ARGS__), .arcs = {__VA_ARGS__} }
#define ASN1_CONST_OID(...) PP_NARG(__VA_ARGS__),__VA_ARGS__
#define ASN1_OID_FROM_CONST(...) ASN1_OID_FROM_CONST_(__VA_ARGS__)
#define ASN1_OID_FROM_CONST_(x, ...) ASN1_OID(__VA_ARGS__)

#define ASN1_OID_MAXIMUM_DEPTH 12
#define ASN1_MAXIMUM_DEPTH 10

typedef enum asn1_err {
	ASN1_OK                =  0,
	ASN1_ERROR_INVALID     = -1,
	ASN1_ERROR_MEMORY      = -2,
	ASN1_ERROR_UNSUPPORTED = -3,
	ASN1_ERROR_EOF         = -4
} asn1_err_t;

/**
 * ASN.1 identifier classes, based on X.690 11/2008 item 8.1.2.2.
 */
typedef enum asn1_class {
	ASN1_CLASS_UNIVERSAL   = 0,
	ASN1_CLASS_APPLICATION = 1,
	ASN1_CLASS_CONTEXT     = 2,
	ASN1_CLASS_PRIVATE     = 3
} asn1_class_t;

typedef enum asn1_universal_type {
	// ASN1_TYPE_INVALID         =  0,
	ASN1_TYPE_BOOL            =  1,
	ASN1_TYPE_INT             =  2,
	ASN1_TYPE_BITSTRING       =  3,
	ASN1_TYPE_OCTETSTRING     =  4,
	ASN1_TYPE_NULL            =  5,
	ASN1_TYPE_OID             =  6,
	ASN1_TYPE_UTF8STRING      = 12,
	ASN1_TYPE_SEQUENCE        = 16,
	ASN1_TYPE_SET             = 17,
	ASN1_TYPE_PRINTABLESTRING = 19,
	ASN1_TYPE_IA5STRING       = 22,
	ASN1_TYPE_UTCTIME         = 23,
	ASN1_TYPE_GENERALIZEDTIME = 24
} asn1_universal_type_t;

typedef unsigned int asn1_type_t;
typedef int64_t asn1_time_t;

typedef struct asn1_token {
	const uint8_t *data;
	const uint8_t *end;
	size_t length;
	asn1_class_t class;
	asn1_type_t type;
	bool is_primitive;
} asn1_token_t;

typedef struct asn1_parser {
	const uint8_t *current;
	asn1_token_t *token;
	const uint8_t *parents[ASN1_MAXIMUM_DEPTH];
	size_t depth;
	size_t constraint;
} asn1_parser_t;

asn1_err_t asn1_parser_init(asn1_parser_t *parser, asn1_token_t *token,
	const uint8_t *data, size_t length);
const asn1_token_t* asn1_parser_token(const asn1_parser_t *parser);
asn1_err_t asn1_parser_next(asn1_parser_t *parser);
asn1_err_t asn1_parser_next_child(asn1_parser_t *parser,
	const asn1_token_t *parent);
/**
 * Skip over all children of the current token
 * @param  parser ASN.1 parser
 * @note   This function does not validate the skipped tokens. As such, it
 *         is possible to skip invalid tokens, which would have led to an error
 *         on a full parse.
 */
void asn1_parser_skip_children(asn1_parser_t *parser);
bool asn1_parser_is_within(const asn1_parser_t *parser, const asn1_token_t *token);
asn1_err_t asn1_parser_ascend(asn1_parser_t *parser, size_t levels);
asn1_err_t asn1_parser_descend(asn1_parser_t *parser);

typedef unsigned int asn1_oid_arc_t;

typedef struct asn1_oid {
	asn1_oid_arc_t arcs[ASN1_OID_MAXIMUM_DEPTH];
	size_t num;
} asn1_oid_t;

/* Types */
asn1_err_t asn1_string(const asn1_token_t *token, char *buf, size_t num);
int asn1_string_eq(const asn1_token_t *token, const char *str);

asn1_err_t asn1_int(const asn1_token_t *token, int *value);
asn1_err_t asn1_int_unsafe(const asn1_token_t *token, int *value);

asn1_err_t asn1_time(const asn1_token_t *token, asn1_time_t *time);

asn1_err_t asn1_bool(const asn1_token_t *token, bool *value);
asn1_err_t asn1_bool_unsafe(const asn1_token_t *token, bool *value);


const uint8_t* asn1_raw(const asn1_token_t *token);
const char* asn1_type_to_string(asn1_type_t type);
bool asn1_eq(const asn1_token_t *a, const asn1_token_t *b);

int asn1_is(const asn1_token_t *token, asn1_class_t class, asn1_type_t type);
int asn1_is_string(const asn1_token_t *token);
int asn1_is_time(const asn1_token_t *token);
#define asn1_is_sequence(token) \
	asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE)
#define asn1_is_oid(token) \
	asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OID)
#define asn1_is_int(token) \
	asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_INT)
#define asn1_is_set(token) \
	asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_SET)
#define asn1_is_bool(token) \
	asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BOOL)

/* OID */
asn1_err_t asn1_oid(const asn1_token_t *token, asn1_oid_t *oid);
bool asn1_oid_to_string(const asn1_oid_t *oid, char *buffer,
	size_t num);
int asn1_oid_eq(const asn1_oid_t *oid, size_t num, ...);
int asn1_oid_cmp(const asn1_oid_t *a, const asn1_oid_t *b);

#ifdef __cplusplus
}
#endif

#endif /* __ASININE_ASN1_H__ */
