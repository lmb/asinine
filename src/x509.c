/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "asinine/x509.h"
#include "asinine/asn1.h"

#define NUM(x) (sizeof(x) / sizeof(*x))

// Common OID prefixes
#define _OID_KEY_USAGE 1,3,6,1,5,5,7,3
#define _OID_CE        2,5,29

// These are found in DNs
#define OID_DN_COMMON_NAME       ASN1_CONST_OID(2,5,4,3)
#define OID_DN_COUNTRY_NAME      ASN1_CONST_OID(2,5,4,6)
#define OID_DN_LOCALITY          ASN1_CONST_OID(2,5,4,7)
#define OID_DN_STATE_OR_PROVINCE ASN1_CONST_OID(2,5,4,8)
// #define OID_DN_STREET_ADDRESS    ASN1_CONST_OID(2,5,4,9)
#define OID_DN_ORGANIZATION      ASN1_CONST_OID(2,5,4,10)
#define OID_DN_ORGANIZATION_UNIT ASN1_CONST_OID(2,5,4,11)

// These are possible extensions
#define OID_EXTN_KEY_USAGE         ASN1_CONST_OID(_OID_CE,15)
#define OID_EXTN_EXT_KEY_USAGE     ASN1_CONST_OID(_OID_CE,37)
#define OID_EXTN_BASIC_CONSTRAINTS ASN1_CONST_OID(_OID_CE,19)

// These are possible extended key usage OIDs
#define OID_EXT_KEY_USAGE_ANY          ASN1_CONST_OID(_OID_CE,37,0)
#define OID_EXT_KEY_USAGE_SERVER_AUTH  ASN1_CONST_OID(_OID_KEY_USAGE,1)
#define OID_EXT_KEY_USAGE_CLIENT_AUTH  ASN1_CONST_OID(_OID_KEY_USAGE,2)
#define OID_EXT_KEY_USAGE_CODE_SIGNING ASN1_CONST_OID(_OID_KEY_USAGE,3)
#define OID_EXT_KEY_USAGE_EMAIL_PROT   ASN1_CONST_OID(_OID_KEY_USAGE,4)
#define OID_EXT_KEY_USAGE_TIME_STAMP   ASN1_CONST_OID(_OID_KEY_USAGE,8)
#define OID_EXT_KEY_USAGE_OCSP_SIGN    ASN1_CONST_OID(_OID_KEY_USAGE,9)


typedef asinine_err_t (*delegate_parser_t)(asn1_parser_t *, x509_cert_t *);
typedef asinine_err_t (*extension_parser_t)(x509_cert_t *,
	const asn1_token_t *);

typedef struct {
	asn1_oid_t oid;
	x509_algorithm_t type;
	delegate_parser_t parser;
} algorithm_lookup_t;

typedef struct {
	asn1_oid_t oid;
	extension_parser_t parser;
} extension_lookup_t;

static asinine_err_t parse_optional(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_extensions(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_null_args(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_signature(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_validity(asn1_parser_t *, x509_cert_t *);

static asinine_err_t parse_extn_key_usage(x509_cert_t *, const asn1_token_t *);
static asinine_err_t parse_extn_ext_key_usage(x509_cert_t *,
	const asn1_token_t *);
static asinine_err_t parse_extn_basic_constraints(x509_cert_t *,
	const asn1_token_t *);

// TODO: Make runtime possibly?
static const algorithm_lookup_t algorithms[] = {
	{
		ASN1_OID(1,2,840,113549,1,1,5),
		X509_ALGORITHM_SHA1_RSA,
		&parse_null_args
	}
};

static const extension_lookup_t extensions[] = {
	{
		ASN1_OID_FROM_CONST(OID_EXTN_KEY_USAGE),
		&parse_extn_key_usage
	},
	{
		ASN1_OID_FROM_CONST(OID_EXTN_EXT_KEY_USAGE),
		&parse_extn_ext_key_usage
	},
	{
		ASN1_OID_FROM_CONST(OID_EXTN_BASIC_CONSTRAINTS),
		&parse_extn_basic_constraints
	}
};

#define RETURN_ON_ERROR(expr) do { \
		asinine_err_t ret = expr; \
		if (ret < ASININE_OK) { return ret; } \
	} while(0)
#define NEXT_TOKEN(parser) RETURN_ON_ERROR(asn1_parser_next(parser))
#define NEXT_CHILD(parser, parent) do { \
		asinine_err_t ret = asn1_parser_next(parser); \
		if (ret < ASININE_OK) { \
			return asn1_parser_eot(parser, parent) ? ASININE_OK : \
				ret; \
		} \
	} while (0)

asinine_err_t
x509_parse(x509_cert_t *cert, const uint8_t *data, size_t num)
{
	asn1_token_t token, signature;
	asn1_parser_t parser;

	memset(cert, 0, sizeof(*cert));

	RETURN_ON_ERROR(asn1_parser_init(&parser, &token, data, num));

	// Certificate
	NEXT_TOKEN(&parser);

	if (!asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_parser_descend(&parser);

	// tbsCertificate
	NEXT_TOKEN(&parser);

	if (!asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	cert->certificate = token;
	asn1_parser_descend(&parser);

	// version
	NEXT_TOKEN(&parser);

	if (asn1_is(&token, ASN1_CLASS_CONTEXT, 0)) {
		int version;

		asn1_parser_descend(&parser);

		NEXT_TOKEN(&parser);

		if (asn1_int(&token, &version) < ASININE_OK) {
			return ASININE_ERROR_INVALID;
		}

		if (version != X509_V2 && version != X509_V3) {
			return ASININE_ERROR_INVALID;
		}

		cert->version = (x509_version_t)version;
		asn1_parser_ascend(&parser, 1);

		NEXT_TOKEN(&parser);
	} else {
		cert->version = X509_V1;
	}

	// serialNumber
	// TODO: As per X.509 guide, this should be treated as a binary blob
	if (!asn1_is_int(&token)) {
		return ASININE_ERROR_INVALID;
	}

	// signature
	NEXT_TOKEN(&parser);

	signature = token;
	RETURN_ON_ERROR(parse_signature(&parser, cert));

	// issuer
	NEXT_TOKEN(&parser);

	// TODO: Sequence might be zero-length, with name in subjectAltName
	if (!asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	cert->issuer = token;
	asn1_parser_skip_children(&parser);

	// validity
	RETURN_ON_ERROR(parse_validity(&parser, cert));

	// subject
	NEXT_TOKEN(&parser);

	if (!asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	cert->subject = token;
	asn1_parser_skip_children(&parser);

	// subjectPublicKeyInfo
	NEXT_TOKEN(&parser);

	if (asn1_is_sequence(&token)) {
		asn1_parser_skip_children(&parser);
	} else if (!asn1_is_int(&token)) {
		return ASININE_ERROR_INVALID;
	}

	// Optional items (X.509 v2 and up)
	RETURN_ON_ERROR(parse_optional(&parser, cert));

	// End of tbsCertificate
	asn1_parser_ascend(&parser, 1);

	// signatureAlgorithm
	NEXT_TOKEN(&parser);

	if (!asn1_eq(&token, &signature)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_parser_skip_children(&parser);

	// signature
	NEXT_TOKEN(&parser);

	// TODO: Do something with the signature
	if (!asn1_is(&token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BITSTRING)) {
		return ASININE_ERROR_INVALID;
	}

	return asn1_parser_eof(&parser) ? ASININE_OK : ASININE_ERROR_INVALID;
}

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
parse_optional(asn1_parser_t *parser, x509_cert_t *cert)
{
	const asn1_token_t * const parent = &cert->certificate;
	const asn1_token_t * const token = parser->token;

	if (cert->version >= X509_V2) {
		NEXT_CHILD(parser, parent);

		// issuerUniqueID
		if (asn1_is(token, ASN1_CLASS_CONTEXT, 1)) {
			// TODO: Do something
			printf("Got issuerUniqueID\n");

			NEXT_CHILD(parser, parent);
		}

		// subjectUniqueID
		if (asn1_is(token, ASN1_CLASS_CONTEXT, 2)) {
			// TODO: Do something
			printf("Got subjectUniqueID\n");

			NEXT_CHILD(parser, parent);
		}

		// extensions
		if (cert->version != X509_V3) {
			// We should not be here if this is not a V3 cert
			return ASININE_ERROR_INVALID;
		}

		if (!asn1_is(token, ASN1_CLASS_CONTEXT, 3)) {
			return ASININE_ERROR_INVALID;
		}

		RETURN_ON_ERROR(parse_extensions(parser, cert));
	}

	return !asn1_parser_eot(parser, parent) ? ASININE_ERROR_INVALID :
		ASININE_OK;
}

static extension_parser_t
find_extension_parser(const asn1_oid_t *oid)
{
	size_t i;

	for (i = 0; i < NUM(extensions); i++) {
		if (asn1_oid_cmp(&extensions[i].oid, oid) == 0) {
			return extensions[i].parser;
		}
	}

	return NULL;
}

static asinine_err_t
parse_extensions(asn1_parser_t *parser, x509_cert_t *cert)
{
	const asn1_token_t * const token = parser->token;
	const asn1_token_t parent = *token;

	asn1_parser_descend(parser);

	NEXT_TOKEN(parser);

	if (!asn1_is_sequence(token)) {
		return ASININE_ERROR_INVALID;
	}
	asn1_parser_descend(parser);

	while (!asn1_parser_eot(parser, &parent)) {
		asn1_oid_t id;
		bool critical;
		extension_parser_t extn_parser;

		NEXT_TOKEN(parser);

		if (!asn1_is_sequence(token)) {
			return ASININE_ERROR_INVALID;
		}
		asn1_parser_descend(parser);

		// extnid
		NEXT_TOKEN(parser);

		if (!asn1_is_oid(token)) {
			return ASININE_ERROR_INVALID;
		}

		if (asn1_oid(token, &id) < ASININE_OK) {
			return ASININE_ERROR_INVALID;
		}

		// critical
		NEXT_TOKEN(parser);

		if (asn1_is_bool(token)) {
			if (asn1_bool_unsafe(token, &critical) < ASININE_OK) {
				return ASININE_ERROR_INVALID;
			}

			NEXT_TOKEN(parser);
		} else {
			critical = false;
		}

		// extnValue
		if (!asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_OCTETSTRING)) {
			return ASININE_ERROR_INVALID;
		}

		extn_parser = find_extension_parser(&id);
		if (extn_parser != NULL) {
			RETURN_ON_ERROR(extn_parser(cert, token));
		} else if (critical) {
			return ASININE_ERROR_UNSUPPORTED;
		}

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

	NEXT_TOKEN(parser);

	if (!asn1_is_oid(token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_oid(token, &oid);
	algorithm_parser = find_algorithm(cert, &oid);

	if (algorithm_parser == NULL) {
		return ASININE_ERROR_UNSUPPORTED;
	}

	RETURN_ON_ERROR(algorithm_parser(parser, cert));

	asn1_parser_ascend(parser, 1);

	return ASININE_OK;
}

asinine_err_t
parse_validity(asn1_parser_t *parser, x509_cert_t *cert)
{
	const asn1_token_t *token = parser->token;

	NEXT_TOKEN(parser);

	if (!asn1_is_sequence(token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_parser_descend(parser);

	// Valid from
	NEXT_TOKEN(parser);
	if (!asn1_is_time(token)) {
		return ASININE_ERROR_INVALID;
	}
	if (asn1_time(token, &cert->valid_from) < ASININE_OK) {
		return ASININE_ERROR_INVALID;
	}

	// Valid to
	NEXT_TOKEN(parser);

	if (!asn1_is_time(token)) {
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

	NEXT_TOKEN(parser);

	if (!asn1_is(token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_NULL)) {
		return ASININE_ERROR_INVALID;
	}

	return ASININE_OK;
}

static asinine_err_t
parse_extn_key_usage(x509_cert_t *cert, const asn1_token_t *extension)
{
	asn1_parser_t parser;
	asn1_token_t token;
	uint8_t buf[2];

	RETURN_ON_ERROR(asn1_parser_init(&parser, &token, extension->data,
		extension->length));

	NEXT_TOKEN(&parser);

	if (!asn1_is(&token, ASN1_CLASS_UNIVERSAL, ASN1_TYPE_BITSTRING)) {
		return ASININE_ERROR_INVALID;
	}

	RETURN_ON_ERROR(asn1_bitstring(&token, buf, sizeof buf));

	cert->key_usage = (buf[1] << 8) | buf[0];

	/* RFC 5280, p.30: "When the keyUsage extension appears in a certificate, at
	 * least one of the bits MUST be set to 1."
	 */
	return (asn1_parser_eof(&parser) && cert->key_usage != 0) ? ASININE_OK :
		ASININE_ERROR_INVALID;
}

static asinine_err_t
parse_extn_ext_key_usage(x509_cert_t *cert, const asn1_token_t *extension)
{
	asn1_parser_t parser;
	asn1_token_t token, parent;

	RETURN_ON_ERROR(asn1_parser_init(&parser, &token, extension->data,
		extension->length));

	NEXT_TOKEN(&parser);

	if (!asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_parser_descend(&parser);

	cert->ext_key_usage = 0;

	parent = token;
	while (!asn1_parser_eot(&parser, &parent)) {
		asn1_oid_t oid;

		NEXT_TOKEN(&parser);

		if (!asn1_is_oid(&token)) {
			return ASININE_ERROR_INVALID;
		}

		RETURN_ON_ERROR(asn1_oid(&token, &oid));

		/* RFC 5280, p. 43
		 * If multiple purposes are indicated the application need not recognize
		 * all purposes indicated, as long as the intended purpose is present.
		 */
		if (asn1_oid_eq(&oid, OID_EXT_KEY_USAGE_SERVER_AUTH)) {
			cert->ext_key_usage |= X509_EXT_KEYUSE_SERVER_AUTH;
		} else if (asn1_oid_eq(&oid, OID_EXT_KEY_USAGE_CLIENT_AUTH)) {
			cert->ext_key_usage |= X509_EXT_KEYUSE_CLIENT_AUTH;
		} else if (asn1_oid_eq(&oid, OID_EXT_KEY_USAGE_CODE_SIGNING)) {
			cert->ext_key_usage |= X509_EXT_KEYUSE_CODE_SIGNING;
		} else if (asn1_oid_eq(&oid, OID_EXT_KEY_USAGE_EMAIL_PROT)) {
			cert->ext_key_usage |= X509_EXT_KEYUSE_EMAIL_PROT;
		} else if (asn1_oid_eq(&oid, OID_EXT_KEY_USAGE_TIME_STAMP)) {
			cert->ext_key_usage |= X509_EXT_KEYUSE_TIME_STAMP;
		} else if (asn1_oid_eq(&oid, OID_EXT_KEY_USAGE_OCSP_SIGN)) {
			cert->ext_key_usage |= X509_EXT_KEYUSE_OCSP_SIGN;
		} else if (asn1_oid_eq(&oid, OID_EXT_KEY_USAGE_ANY)) {
			cert->ext_key_usage |= X509_EXT_KEYUSE_ANY;
		}
	}

	return asn1_parser_eof(&parser) ? ASININE_OK : ASININE_ERROR_INVALID;
}

static asinine_err_t
parse_extn_basic_constraints(x509_cert_t *cert,
	const asn1_token_t *extension) {
	asn1_parser_t parser;
	asn1_token_t token, parent;
	int value;

	RETURN_ON_ERROR(asn1_parser_init(&parser, &token, extension->data,
		extension->length));

	NEXT_TOKEN(&parser);

	if (!asn1_is_sequence(&token)) {
		return ASININE_ERROR_INVALID;
	}

	parent = token;
	cert->is_ca = false;
	cert->path_len_constraint = -1;

	NEXT_CHILD(&parser, &parent);

	if (asn1_is_bool(&token)) {
		asn1_bool_unsafe(&token, &cert->is_ca);
		NEXT_CHILD(&parser, &parent);
	}

	RETURN_ON_ERROR(asn1_int(&token, &value));

	if (value < 0) {
		return ASININE_ERROR_INVALID;
	}

	if (value > INT8_MAX) {
		return ASININE_ERROR_UNSUPPORTED;
	}

	cert->path_len_constraint = (int8_t)value;

	return asn1_parser_eof(&parser) ? ASININE_OK : ASININE_ERROR_INVALID;
}
