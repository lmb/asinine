/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "asinine/dsl.h"
#include "asinine/x509.h"
#include "internal/macros.h"

// Common OID prefixes
#define _OID_KEY_USAGE 1, 3, 6, 1, 5, 5, 7, 3

// These are found in DNs
#define OID_DN_COMMON_NAME ASN1_CONST_OID(2, 5, 4, 3)
#define OID_DN_COUNTRY_NAME ASN1_CONST_OID(2, 5, 4, 6)
#define OID_DN_LOCALITY ASN1_CONST_OID(2, 5, 4, 7)
#define OID_DN_STATE_OR_PROVINCE ASN1_CONST_OID(2, 5, 4, 8)
// #define OID_DN_STREET_ADDRESS    ASN1_CONST_OID(2,5,4,9)
#define OID_DN_ORGANIZATION ASN1_CONST_OID(2, 5, 4, 10)
#define OID_DN_ORGANIZATION_UNIT ASN1_CONST_OID(2, 5, 4, 11)

// These are possible extended key usage OIDs
#define OID_EXT_KEY_USAGE_ANY ASN1_CONST_OID(2, 5, 29, 37, 0)
#define OID_EXT_KEY_USAGE_SERVER_AUTH ASN1_CONST_OID(_OID_KEY_USAGE, 1)
#define OID_EXT_KEY_USAGE_CLIENT_AUTH ASN1_CONST_OID(_OID_KEY_USAGE, 2)
#define OID_EXT_KEY_USAGE_CODE_SIGNING ASN1_CONST_OID(_OID_KEY_USAGE, 3)
#define OID_EXT_KEY_USAGE_EMAIL_PROT ASN1_CONST_OID(_OID_KEY_USAGE, 4)
#define OID_EXT_KEY_USAGE_TIME_STAMP ASN1_CONST_OID(_OID_KEY_USAGE, 8)
#define OID_EXT_KEY_USAGE_OCSP_SIGN ASN1_CONST_OID(_OID_KEY_USAGE, 9)

typedef asinine_err_t (*delegate_parser_t)(asn1_parser_t *, x509_cert_t *);

typedef struct {
	asn1_oid_t oid;
	x509_algorithm_t type;
	delegate_parser_t parser;
	bool deprecated;
} algorithm_lookup_t;

typedef struct {
	asn1_oid_t oid;
	delegate_parser_t parser;
} extension_lookup_t;

static asinine_err_t parse_optional(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_extensions(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_null_or_empty_args(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_empty_args(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_signature_info(
    asn1_parser_t *, x509_cert_t *, asn1_token_t *sig);
static asinine_err_t parse_validity(asn1_parser_t *, x509_cert_t *);

static asinine_err_t parse_extn_key_usage(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_extn_ext_key_usage(asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_extn_basic_constraints(
    asn1_parser_t *, x509_cert_t *);
static asinine_err_t parse_extn_subject_alt_name(
    asn1_parser_t *, x509_cert_t *);

static const algorithm_lookup_t algorithms[] = {
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 2), X509_ALGORITHM_MD2_RSA,
        &parse_null_or_empty_args, true,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 4), X509_ALGORITHM_MD5_RSA,
        &parse_null_or_empty_args, true,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 5), X509_ALGORITHM_SHA1_RSA,
        &parse_null_or_empty_args, true,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 11), X509_ALGORITHM_SHA256_RSA,
        &parse_null_or_empty_args, false,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 12), X509_ALGORITHM_SHA384_RSA,
        &parse_null_or_empty_args, false,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 13), X509_ALGORITHM_SHA512_RSA,
        &parse_null_or_empty_args, false,
    },
    {
        ASN1_OID(1, 2, 840, 10045, 4, 3, 2), X509_ALGORITHM_SHA256_ECDSA,
        &parse_empty_args, false,
    },
    {
        ASN1_OID(1, 2, 840, 10045, 4, 3, 3), X509_ALGORITHM_SHA384_ECDSA,
        &parse_empty_args, false,
    },
    {
        ASN1_OID(1, 2, 840, 10045, 4, 3, 3), X509_ALGORITHM_SHA512_ECDSA,
        &parse_empty_args, false,
    },
    {
        ASN1_OID(2, 16, 840, 1, 101, 3, 4, 3, 2), X509_ALGORITHM_SHA256_DSA,
        &parse_empty_args, false,
    },
};

static const extension_lookup_t extensions[] = {
    {ASN1_OID(2, 5, 29, 15), &parse_extn_key_usage},
    {ASN1_OID(2, 5, 29, 17), &parse_extn_subject_alt_name},
    {ASN1_OID(2, 5, 29, 19), &parse_extn_basic_constraints},
    {ASN1_OID(2, 5, 29, 37), &parse_extn_ext_key_usage},
};

asinine_err_t
x509_parse(asn1_parser_t *parser, x509_cert_t *cert) {
	*cert = (x509_cert_t){0};

	// Certificate
	RETURN_ON_ERROR(asn1_push_seq(parser));

	// tbsCertificate
	RETURN_ON_ERROR(asn1_push_seq(parser));

	cert->certificate = parser->token;

	// version
	NEXT_TOKEN(parser);

	if (asn1_is(
	        &parser->token, ASN1_CLASS_CONTEXT, 0, ASN1_ENCODING_CONSTRUCTED)) {
		asn1_word_t version;

		RETURN_ON_ERROR(asn1_push(parser));

		NEXT_TOKEN(parser);

		RETURN_ON_ERROR(asn1_int(&parser->token, &version));

		if (version != X509_V2 && version != X509_V3) {
			return ASININE_ERROR_INVALID;
		}

		cert->version = (x509_version_t)version;

		RETURN_ON_ERROR(asn1_pop(parser));
		NEXT_TOKEN(parser);
	} else {
		cert->version = X509_V1;
	}

	// serialNumber
	// TODO: As per X.509 guide, this should be treated as a binary blob
	if (!asn1_is_int(&parser->token)) {
		return ASININE_ERROR_INVALID;
	}

	// signature
	asn1_token_t signature;
	RETURN_ON_ERROR(parse_signature_info(parser, cert, &signature));

	// issuer
	RETURN_ON_ERROR(x509_parse_name(parser, &cert->issuer));
	// validity
	RETURN_ON_ERROR(parse_validity(parser, cert));

	// subject
	RETURN_ON_ERROR(x509_parse_optional_name(parser, &cert->subject));

	// subjectPublicKeyInfo
	NEXT_TOKEN(parser);

	if (!asn1_is_int(&parser->token) && !asn1_is_sequence(&parser->token)) {
		return ASININE_ERROR_INVALID;
	}

	// Optional items (X.509 v2 and up)
	RETURN_ON_ERROR(parse_optional(parser, cert));

	// End of tbsCertificate
	RETURN_ON_ERROR(asn1_pop(parser));

	// signatureAlgorithm
	NEXT_TOKEN(parser);

	if (!asn1_eq(&parser->token, &signature)) {
		return ASININE_ERROR_INVALID;
	}

	// signature
	NEXT_TOKEN(parser);

	// TODO: Do something with the signature
	if (!asn1_is_bitstring(&parser->token)) {
		return ASININE_ERROR_INVALID;
	}

	// RFC5280 4.1.2.6.
	if (cert->is_ca && cert->subject.num == 0) {
		return ASININE_ERROR_INVALID;
	}

	if ((cert->key_usage & X509_KEYUSE_CRL_SIGN) != 0 &&
	    cert->subject.num == 0) {
		return ASININE_ERROR_INVALID;
	}

	return asn1_pop(parser);
}

static const algorithm_lookup_t *
find_algorithm(const asn1_oid_t *oid) {
	size_t i;
	for (i = 0; i < NUM(algorithms); i++) {
		if (asn1_oid_cmp(oid, &(algorithms[i].oid)) == 0) {
			return &algorithms[i];
		}
	}

	return NULL;
}

static asinine_err_t
parse_optional(asn1_parser_t *parser, x509_cert_t *cert) {
	const asn1_token_t *const token = &parser->token;

	if (cert->version >= X509_V2) {
		NEXT_CHILD(parser);

		// issuerUniqueID
		if (asn1_is(token, ASN1_CLASS_CONTEXT, 1, ASN1_ENCODING_PRIMITIVE)) {
			// TODO: Do something
			printf("Got issuerUniqueID\n");

			NEXT_CHILD(parser);
		}

		// subjectUniqueID
		if (asn1_is(token, ASN1_CLASS_CONTEXT, 2, ASN1_ENCODING_PRIMITIVE)) {
			// TODO: Do something
			printf("Got subjectUniqueID\n");

			NEXT_CHILD(parser);
		}

		// extensions
		if (cert->version != X509_V3) {
			// We should not be here if this is not a V3 cert
			return ASININE_ERROR_INVALID;
		}

		if (!asn1_is(token, ASN1_CLASS_CONTEXT, 3, ASN1_ENCODING_CONSTRUCTED)) {
			return ASININE_ERROR_INVALID;
		}

		RETURN_ON_ERROR(asn1_push(parser));
		RETURN_ON_ERROR(parse_extensions(parser, cert));
		RETURN_ON_ERROR(asn1_pop(parser));
	}

	return !asn1_eof(parser) ? ASININE_ERROR_INVALID : ASININE_OK;
}

static delegate_parser_t
find_extension_parser(const asn1_oid_t *oid) {
	size_t i;

	for (i = 0; i < NUM(extensions); i++) {
		if (asn1_oid_cmp(&extensions[i].oid, oid) == 0) {
			return extensions[i].parser;
		}
	}

	return NULL;
}

static asinine_err_t
parse_extensions(asn1_parser_t *parser, x509_cert_t *cert) {
	const asn1_token_t *const token = &parser->token;

	RETURN_ON_ERROR(asn1_push_seq(parser));

	while (!asn1_eof(parser)) {
		RETURN_ON_ERROR(asn1_push_seq(parser));

		// extnid
		NEXT_TOKEN(parser);

		if (!asn1_is_oid(token)) {
			return ASININE_ERROR_INVALID;
		}

		asn1_oid_t id;
		RETURN_ON_ERROR(asn1_oid(token, &id));

		// critical
		NEXT_TOKEN(parser);

		bool critical = false;
		if (asn1_is_bool(token)) {
			RETURN_ON_ERROR(asn1_bool(token, &critical));
			NEXT_TOKEN(parser);
		}

		// extnValue
		if (!asn1_is_octetstring(token)) {
			return ASININE_ERROR_INVALID;
		}

		delegate_parser_t extn_parser = find_extension_parser(&id);
		if (extn_parser != NULL) {
			RETURN_ON_ERROR(asn1_force_push(parser));
			RETURN_ON_ERROR(extn_parser(parser, cert));
			RETURN_ON_ERROR(asn1_pop(parser));
		} else if (critical) {
			char buf[256];
			asn1_oid_to_string(buf, sizeof(buf), &id);
			fprintf(stderr, "%s\n", buf);
			return ASININE_ERROR_UNSUPPORTED;
		}

		RETURN_ON_ERROR(asn1_pop(parser));
	}

	return asn1_pop(parser);
}

static asinine_err_t
parse_signature_info(
    asn1_parser_t *parser, x509_cert_t *cert, asn1_token_t *sig) {
	const asn1_token_t *const token = &parser->token;

	RETURN_ON_ERROR(asn1_push_seq(parser));
	*sig = *token;

	NEXT_TOKEN(parser);

	if (!asn1_is_oid(token)) {
		return ASININE_ERROR_INVALID;
	}

	asn1_oid_t oid;
	asn1_oid(token, &oid);

	const algorithm_lookup_t *result = find_algorithm(&oid);
	if (result == NULL) {
		return ASININE_ERROR_UNSUPPORTED;
	}

	cert->algorithm  = result->type;
	cert->deprecated = cert->deprecated || result->deprecated;

	RETURN_ON_ERROR(result->parser(parser, cert));

	return asn1_pop(parser);
}

asinine_err_t
parse_validity(asn1_parser_t *parser, x509_cert_t *cert) {
	const asn1_token_t *const token = &parser->token;

	RETURN_ON_ERROR(asn1_push_seq(parser));

	// Valid from
	NEXT_TOKEN(parser);
	if (!asn1_is_time(token)) {
		return ASININE_ERROR_INVALID;
	}
	RETURN_ON_ERROR(asn1_time(token, &cert->valid_from));

	// Valid to
	NEXT_TOKEN(parser);

	if (!asn1_is_time(token)) {
		return ASININE_ERROR_INVALID;
	}
	RETURN_ON_ERROR(asn1_time(token, &cert->valid_to));

	return asn1_pop(parser);
}

static asinine_err_t
parse_null_or_empty_args(asn1_parser_t *parser, x509_cert_t *cert) {
	const asn1_token_t *const token = &parser->token;

	(void)cert;

	// There is at least one implementation which skips the null.
	// This deviates from the spec.
	if (asn1_eof(parser)) {
		return ASININE_OK;
	}

	NEXT_TOKEN(parser);

	if (!asn1_is_null(token)) {
		return ASININE_ERROR_INVALID;
	}

	return ASININE_OK;
}

static asinine_err_t
parse_empty_args(asn1_parser_t *parser, x509_cert_t *cert) {
	(void)cert;

	return asn1_eof(parser) ? ASININE_OK : ASININE_ERROR_MALFORMED;
}

static asinine_err_t
parse_extn_key_usage(asn1_parser_t *parser, x509_cert_t *cert) {
	NEXT_TOKEN(parser);

	if (!asn1_is_bitstring(&parser->token)) {
		return ASININE_ERROR_INVALID;
	}

	uint8_t buf[2];
	RETURN_ON_ERROR(asn1_bitstring(&parser->token, buf, sizeof buf));

	cert->key_usage = (uint16_t)(buf[1] << 8) | buf[0];

	/* RFC 5280, p.30: "When the keyUsage extension appears in a certificate, at
	 * least one of the bits MUST be set to 1."
	 */
	return (asn1_eof(parser) && cert->key_usage != 0) ? ASININE_OK
	                                                  : ASININE_ERROR_INVALID;
}

static asinine_err_t
parse_extn_ext_key_usage(asn1_parser_t *parser, x509_cert_t *cert) {
	RETURN_ON_ERROR(asn1_push_seq(parser));

	cert->ext_key_usage = 0;

	while (!asn1_eof(parser)) {
		asn1_oid_t oid;

		NEXT_TOKEN(parser);

		if (!asn1_is_oid(&parser->token)) {
			return ASININE_ERROR_INVALID;
		}

		RETURN_ON_ERROR(asn1_oid(&parser->token, &oid));

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

	return asn1_pop(parser);
}

static asinine_err_t
parse_extn_basic_constraints(asn1_parser_t *parser, x509_cert_t *cert) {
	RETURN_ON_ERROR(asn1_push_seq(parser));

	cert->is_ca               = false;
	cert->path_len_constraint = -1;

	NEXT_CHILD(parser);

	if (asn1_is_bool(&parser->token)) {
		RETURN_ON_ERROR(asn1_bool(&parser->token, &cert->is_ca));
		NEXT_CHILD(parser);
	}

	asn1_word_t value;
	RETURN_ON_ERROR(asn1_int(&parser->token, &value));

	if (value < 0) {
		return ASININE_ERROR_INVALID;
	}

	if (value > INT8_MAX) {
		return ASININE_ERROR_UNSUPPORTED;
	}

	cert->path_len_constraint = (int8_t)value;
	return asn1_pop(parser);
}

static asinine_err_t
parse_extn_subject_alt_name(asn1_parser_t *parser, x509_cert_t *cert) {
	return x509_parse_alt_names(parser, &cert->subject_alt_names);
}
