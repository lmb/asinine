/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "asinine/x509.h"
#include "asinine/asn1.h"

#define NUM(x) (sizeof(x) / sizeof(*x))

#define OID_COMMON_NAME       ASN1_CONST_OID(2,5,4,3)
#define OID_COUNTRY_NAME      ASN1_CONST_OID(2,5,4,6)
#define OID_LOCALITY          ASN1_CONST_OID(2,5,4,7)
#define OID_STATE_OR_PROVINCE ASN1_CONST_OID(2,5,4,8)
// #define OID_STREET_ADDRESS    ASN1_CONST_OID(2,5,4,9)
#define OID_ORGANIZATION      ASN1_CONST_OID(2,5,4,10)
#define OID_ORGANIZATION_UNIT ASN1_CONST_OID(2,5,4,11)

typedef asinine_err_t (*delegate_parser_t)(asn1_parser_t *, x509_cert_t *);

typedef struct {
	asn1_oid_t oid;
	x509_algorithm_t type;
	delegate_parser_t parser;
} algorithm_lookup_t;

static asinine_err_t parse_optional(asn1_parser_t *, const asn1_token_t *,
	x509_cert_t *);
static asinine_err_t parse_extensions(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_null_args(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_signature(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_validity(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_name(asn1_parser_t *, asn1_token_t *);

#define DELEGATE_PARSING(func, parser, ...) do { \
		asinine_err_t ret = func((parser), __VA_ARGS__); \
		if (ret < ASININE_OK) return ret; \
	} while (0)

asinine_err_t
x509_parse(x509_cert_t *cert, const uint8_t *data, size_t num)
{
	asn1_token_t token, tbs_certificate, signature;
	asn1_parser_t parser;

	memset(cert, 0, sizeof(*cert));

	if (asn1_parser_init(&parser, &token, data, num) < ASININE_OK) {
		// TODO: This error code chaining is stupid
		return ASININE_ERROR_INVALID;
	}

	// Certificate
	if (asn1_parser_next(&parser) < ASININE_OK || !asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_parser_descend(&parser);

	// tbsCertificate
	if (asn1_parser_next(&parser) < ASININE_OK || !asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	tbs_certificate = token;
	asn1_parser_descend(&parser);

	// version
	if (asn1_parser_next(&parser) < ASININE_OK) {
		return ASININE_ERROR_INVALID;
	}

	if (asn1_is(&token, ASN1_CLASS_CONTEXT, 0)) {
		int version;

		asn1_parser_descend(&parser);

		if (asn1_parser_next(&parser) < ASININE_OK ||
			asn1_int(&token, &version) < ASININE_OK) {
			return ASININE_ERROR_INVALID;
		}

		if (version != X509_V2 && version != X509_V3) {
			return ASININE_ERROR_INVALID;
		}

		cert->version = (x509_version_t)version;
		asn1_parser_ascend(&parser, 1);

		if (asn1_parser_next(&parser) < ASININE_OK) {
			return ASININE_ERROR_INVALID;
		}
	} else {
		cert->version = X509_V1;
	}

	// serialNumber
	// TODO: As per X.509 guide, this should be treated as a binary blob
	if (!asn1_is_int(&token)) {
		return ASININE_ERROR_INVALID;
	}

	// signature
	if (asn1_parser_next(&parser) < ASININE_OK) {
		return ASININE_ERROR_INVALID;
	}

	signature = token;
	DELEGATE_PARSING(parse_signature, &parser, cert);

	// issuer
	// TODO: Sequence might be zero-length, with name in subjectAltName
	if (asn1_parser_next(&parser) < ASININE_OK || !asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	cert->issuer = token;
	asn1_parser_skip_children(&parser);

	// validity
	DELEGATE_PARSING(parse_validity, &parser, cert);

	// subject
	if (asn1_parser_next(&parser) < ASININE_OK || !asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	cert->subject = token;
	asn1_parser_skip_children(&parser);

	// subjectPublicKeyInfo
	if (asn1_parser_next(&parser) < ASININE_OK) {
		return ASININE_ERROR_INVALID;
	}

	if (asn1_is_sequence(&token)) {
		asn1_parser_skip_children(&parser);
	} else if (!asn1_is_int(&token)) {
		return ASININE_ERROR_INVALID;
	}

	// Optional items (X.509 v2 and up)
	DELEGATE_PARSING(parse_optional, &parser, &tbs_certificate, cert);

	// End of tbsCertificate
	asn1_parser_ascend(&parser, 1);

	// signatureAlgorithm
	if (asn1_parser_next(&parser) < ASININE_OK ||
		!asn1_eq(&token, &signature)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_parser_skip_children(&parser);

	// signature
	// TODO: Do something with the signature
	if (asn1_parser_next(&parser) < ASININE_OK ||
		!asn1_is(&token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BITSTRING)) {
		return ASININE_ERROR_INVALID;
	}

	return (asn1_parser_next(&parser) == ASININE_EOF) ?
		ASININE_OK : ASININE_ERROR_INVALID;
}

// TODO: Make runtime possibly?
static const algorithm_lookup_t algorithms[] = {
	{
		ASN1_OID(1,2,840,113549,1,1,5),
		X509_ALGORITHM_SHA1_RSA,
		&parse_null_args
	}
};

static delegate_parser_t
find_algorithm(x509_cert_t *cert, const asn1_oid_t *oid)
{
	size_t i;
	for (i = 0; i < NUM(algorithms); i++) {
		if (asn1_oid_cmp(oid, &(algorithms[i].oid)) == 0) {
			cert->algorithm = algorithms[i].type;
			return algorithms[i].parser;
		}
	}

	return NULL;
}

static asinine_err_t
parse_optional(asn1_parser_t *parser, const asn1_token_t *parent,
	x509_cert_t *cert)
{
#define NEXT_CHILD do { \
		asinine_err_t ret = asn1_parser_next_child(parser, parent); \
		if (ret == ASININE_EOF) { \
			return ASININE_OK; \
		} else if (ret < ASININE_OK) { \
			return ASININE_ERROR_INVALID; \
		} \
	} while (0)

	const asn1_token_t * const token = parser->token;

	NEXT_CHILD;

	if (cert->version >= X509_V2) {
		// issuerUniqueID
		if (asn1_is(token, ASN1_CLASS_CONTEXT, 1)) {
			// TODO: Do something
			printf("Got issuerUniqueID\n");

			NEXT_CHILD;
		}

		// subjectUniqueID
		if (asn1_is(token, ASN1_CLASS_CONTEXT, 2)) {
			// TODO: Do something
			printf("Got subjectUniqueID\n");

			NEXT_CHILD;
		}
	}

	// extensions
	if (cert->version >= X509_V3 && asn1_is(token, ASN1_CLASS_CONTEXT, 3)) {
		DELEGATE_PARSING(parse_extensions, parser, cert);
	}

	return asn1_parser_is_within(parser, parent) ? ASININE_ERROR_INVALID : ASININE_OK;
#undef NEXT_CHILD
}

static asinine_err_t
parse_extensions(asn1_parser_t *parser, x509_cert_t *cert)
{
	const asn1_token_t * const token = parser->token;
	const asn1_token_t parent = *token;

	(void) cert;

	asn1_parser_descend(parser);

	if (asn1_parser_next(parser) < ASININE_OK || !asn1_is_sequence(token)) {
		return ASININE_ERROR_INVALID;
	}
	asn1_parser_descend(parser);

	while (asn1_parser_is_within(parser, &parent)) {
		asn1_oid_t extnid;
		bool critical;

		if (asn1_parser_next(parser) < ASININE_OK || !asn1_is_sequence(token)) {
			return ASININE_ERROR_INVALID;
		}
		asn1_parser_descend(parser);

		// extnid
		if (asn1_parser_next(parser) < ASININE_OK || !asn1_is_oid(token)) {
			return ASININE_ERROR_INVALID;
		}

		if (asn1_oid(token, &extnid) < ASININE_OK) {
			return ASININE_ERROR_INVALID;
		}

		// critical
		if (asn1_parser_next(parser) < ASININE_OK) {
			return ASININE_ERROR_INVALID;
		}

		if (asn1_is_bool(token)) {
			if (asn1_bool_unsafe(token, &critical) < ASININE_OK) {
				return ASININE_ERROR_INVALID;
			}

			if (asn1_parser_next(parser) < ASININE_OK) {
				return ASININE_ERROR_INVALID;
			}
		} else {
			critical = false;
		}

		// extnValue
		if (!asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OCTETSTRING)) {
			return ASININE_ERROR_INVALID;
		}

		// TODO: Remove me
		char buf[128];
		if (!asn1_oid_to_string(&extnid, buf, sizeof buf)) {
			continue;
		}
		printf("Extension OID: %s\n", buf);

		asn1_parser_ascend(parser, 1);
	}

	asn1_parser_ascend(parser, 2);

	return ASININE_OK;
}

static asinine_err_t
parse_signature(asn1_parser_t *parser, x509_cert_t *cert)
{
	const asn1_token_t * const token = parser->token;
	delegate_parser_t algorithm_parser;
	asn1_oid_t oid;

	if (!asn1_is_sequence(token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_parser_descend(parser);

	if (asn1_parser_next(parser) < ASININE_OK || !asn1_is_oid(token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_oid(token, &oid);
	algorithm_parser = find_algorithm(cert, &oid);

	if (algorithm_parser == NULL) {
		return ASININE_ERROR_UNSUPPORTED;
	}

	DELEGATE_PARSING(algorithm_parser, parser, cert);

	asn1_parser_ascend(parser, 1);

	return ASININE_OK;
}

asinine_err_t
parse_validity(asn1_parser_t *parser, x509_cert_t *cert)
{
	const asn1_token_t *token = parser->token;

	if (asn1_parser_next(parser) < ASININE_OK || !asn1_is_sequence(token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_parser_descend(parser);

	// Valid from
	if (asn1_parser_next(parser) < ASININE_OK || !asn1_is_time(token)) {
		return ASININE_ERROR_INVALID;
	}
	if (asn1_time(token, &cert->valid_from) < ASININE_OK) {
		return ASININE_ERROR_INVALID;
	}

	// Valid to
	if (asn1_parser_next(parser) < ASININE_OK || !asn1_is_time(token)) {
		return ASININE_ERROR_INVALID;
	}
	if (asn1_time(token, &cert->valid_to) != ASININE_OK) {
		return ASININE_ERROR_INVALID;
	}

	asn1_parser_ascend(parser, 1);

	return ASININE_OK;
}

static asinine_err_t
parse_null_args(asn1_parser_t *parser, x509_cert_t *cert)
{
	const asn1_token_t *token = parser->token;
	(void) cert;

	if (asn1_parser_next(parser) < ASININE_OK ||
		!asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_NULL)) {
		return ASININE_ERROR_INVALID;
	}

	return ASININE_OK;
}
