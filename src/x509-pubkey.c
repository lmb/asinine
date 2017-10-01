/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdint.h>
#include <string.h>

#include "asinine/dsl.h"
#include "asinine/x509.h"
#include "internal/macros.h"
#include "internal/x509.h"

typedef asinine_err_t (*pubkey_parser_t)(asn1_parser_t *, x509_pubkey_t *);
typedef asinine_err_t (*params_parser_t)(
    asn1_parser_t *, x509_pubkey_params_t *, bool *);

typedef struct {
	asn1_oid_t oid;
	x509_pubkey_algo_t algorithm;
	params_parser_t param_parser;
	pubkey_parser_t pubkey_parser;
	bool broken_encoding;
} pubkey_lookup_t;

typedef struct {
	asn1_oid_t oid;
	x509_ecdsa_curve_t curve;
} curve_lookup_t;

static asinine_err_t parse_null_or_empty_params(
    asn1_parser_t *, x509_pubkey_params_t *params, bool *has_params);
static asinine_err_t parse_ecdsa_params(
    asn1_parser_t *, x509_pubkey_params_t *params, bool *has_params);

static asinine_err_t parse_rsa_pubkey(asn1_parser_t *, x509_pubkey_t *);
static asinine_err_t parse_ecdsa_pubkey(asn1_parser_t *, x509_pubkey_t *);

static const pubkey_lookup_t pubkey_algorithms[] = {
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 1), X509_PUBKEY_RSA,
        // TODO: Should be parse_null
        &parse_null_or_empty_params, &parse_rsa_pubkey, false,
    },
    {
        ASN1_OID(1, 2, 840, 10045, 2, 1), X509_PUBKEY_ECDSA,
        &parse_ecdsa_params, &parse_ecdsa_pubkey, true,
    },
};

static const curve_lookup_t curves[] = {
    {ASN1_OID(1, 2, 840, 10045, 3, 1, 7), X509_ECDSA_CURVE_SECP256R1},
    {ASN1_OID(1, 3, 132, 0, 34), X509_ECDSA_CURVE_SECP384R1},
    {ASN1_OID(1, 3, 132, 0, 35), X509_ECDSA_CURVE_SECP521R1},

};

static const pubkey_lookup_t *
find_pubkey_algorithm(const asn1_oid_t *oid) {
	size_t i;
	for (i = 0; i < NUM(pubkey_algorithms); i++) {
		if (asn1_oid_cmp(oid, &(pubkey_algorithms[i].oid)) == 0) {
			return &pubkey_algorithms[i];
		}
	}

	return NULL;
}

asinine_err_t
x509_parse_pubkey(asn1_parser_t *parser, x509_pubkey_t *pubkey,
    x509_pubkey_params_t *params, bool *has_params) {
	*pubkey     = (x509_pubkey_t){0};
	*params     = (x509_pubkey_params_t){0};
	*has_params = false;

	// SubjectPublicKeyInfo
	RETURN_ON_ERROR(asn1_push_seq(parser));

	// AlgorithmIdentifier
	RETURN_ON_ERROR(asn1_push_seq(parser));

	NEXT_TOKEN(parser);
	if (!asn1_is_oid(&parser->token)) {
		return ERROR(ASININE_ERR_INVALID, "pubkey: token isn't an OID");
	}

	asn1_oid_t oid;
	asn1_oid(&parser->token, &oid);

	const pubkey_lookup_t *result = find_pubkey_algorithm(&oid);
	if (result == NULL) {
		return ERROR(ASININE_ERR_UNSUPPORTED, "pubkey: algorithm unknown");
	}

	pubkey->algorithm = result->algorithm;

	RETURN_ON_ERROR(result->param_parser(parser, params, has_params));

	// End of AlgorithmIdentifier
	RETURN_ON_ERROR(asn1_pop(parser));

	NEXT_TOKEN(parser);
	if (!asn1_is_bitstring(&parser->token)) {
		return ERROR(ASININE_ERR_INVALID, "pubkey: token isn't a bitstring");
	}

	if (result->broken_encoding) {
		// This is why we can't have nice things. ECDSA pubkeys aren't
		// really bitstrings, but octet strings stuffed into a bitstring.
		RETURN_ON_ERROR(result->pubkey_parser(parser, pubkey));
	} else {
		RETURN_ON_ERROR(asn1_force_push(parser));
		RETURN_ON_ERROR(result->pubkey_parser(parser, pubkey));
		RETURN_ON_ERROR(asn1_pop(parser));
	}

	// End of SubjectPublicKeyInfo
	return asn1_pop(parser);
}

static asinine_err_t
parse_null_or_empty_params(
    asn1_parser_t *parser, x509_pubkey_params_t *params, bool *has_params) {
	(void)params;
	(void)has_params;
	return _x509_parse_null_or_empty_args(parser);
}

static asinine_err_t
parse_rsa_pubkey(asn1_parser_t *parser, x509_pubkey_t *pubkey) {
	const asn1_token_t *token = &parser->token;

	RETURN_ON_ERROR(asn1_push_seq(parser));

	// modulus (n)
	NEXT_TOKEN(parser);
	if (!asn1_is_int(token)) {
		return ERROR(ASININE_ERR_INVALID, "rsa pubkey: token isn't an int");
	}

	RETURN_ON_ERROR(
	    asn1_uint_buf(token, &pubkey->key.rsa.n, &pubkey->key.rsa.n_num));

	// public exponent (e)
	NEXT_TOKEN(parser);
	if (!asn1_is_int(token)) {
		return ERROR(ASININE_ERR_INVALID, "rsa pubkey: token isn't an int");
	}

	RETURN_ON_ERROR(
	    asn1_uint_buf(token, &pubkey->key.rsa.e, &pubkey->key.rsa.e_num));

	return asn1_pop(parser);
}

static x509_ecdsa_curve_t
find_curve(const asn1_oid_t *oid) {
	for (size_t i = 0; i < NUM(curves); i++) {
		if (asn1_oid_cmp(oid, &curves[i].oid) == 0) {
			return curves[i].curve;
		}
	}
	return X509_ECDSA_CURVE_INVALID;
}

static asinine_err_t
parse_ecdsa_params(
    asn1_parser_t *parser, x509_pubkey_params_t *params, bool *has_params) {
	NEXT_TOKEN(parser);
	if (asn1_is_null(&parser->token)) {
		return asn1_null(&parser->token);
	}

	if (!asn1_is_oid(&parser->token)) {
		return ERROR(ASININE_ERR_INVALID, "ecdsa params: token isn't an OID");
	}

	asn1_oid_t oid;
	RETURN_ON_ERROR(asn1_oid(&parser->token, &oid));

	x509_ecdsa_curve_t curve = find_curve(&oid);
	if (curve == X509_ECDSA_CURVE_INVALID) {
		return ERROR(ASININE_ERR_UNSUPPORTED, "ecsda params: unkown algorithm");
	}

	*has_params         = true;
	params->ecdsa_curve = curve;
	return ERROR(ASININE_OK, NULL);
}

static asinine_err_t
parse_ecdsa_pubkey(asn1_parser_t *parser, x509_pubkey_t *pubkey) {
	if (parser->token.length < 2) {
		return ERROR(ASININE_ERR_INVALID, "ecdsa pubkey: too short");
	}
	pubkey->key.ecdsa.point     = parser->token.data + 1;
	pubkey->key.ecdsa.point_num = parser->token.length - 1;
	return ERROR(ASININE_OK, NULL);
}
