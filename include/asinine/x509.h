/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "asinine/asn1.h"

typedef struct x509_cert x509_cert_t;

typedef enum x509_version {
	X509_V1 = 0,
	X509_V2 = 1,
	X509_V3 = 2
} x509_version_t;

typedef enum x509_algorithm {
	X509_ALGORITHM_INVALID = 0,
	X509_ALGORITHM_MD5_RSA,
	X509_ALGORITHM_SHA1_RSA,
	X509_ALGORITHM_SHA256_RSA,
} x509_algorithm_t;

/**
 * Key usage flags
 * @note from RFC 5280, p.29
 */
typedef enum x509_keyuse {
	X509_KEYUSE_DIGITAL_SIGNATURE  = (1 << 0),
	X509_KEYUSE_CONTENT_COMMITMENT = (1 << 1),
	X509_KEYUSE_KEY_ENCIPHERMENT   = (1 << 2),
	X509_KEYUSE_DATA_ENCIPHERMENT  = (1 << 3),
	X509_KEYUSE_KEY_AGREEMENT      = (1 << 4),
	X509_KEYUSE_KEY_CERT_SIGN      = (1 << 5),
	X509_KEYUSE_CRL_SIGN           = (1 << 6),
	X509_KEYUSE_ENCIPHER_ONLY      = (1 << 7),
	X509_KEYUSE_DECIPHER_ONLY      = (1 << 8)
} x509_keyuse_t;

typedef enum x509_ext_keyuse {
	X509_EXT_KEYUSE_SERVER_AUTH  = 1,
	X509_EXT_KEYUSE_CLIENT_AUTH  = 2,
	X509_EXT_KEYUSE_CODE_SIGNING = 4,
	X509_EXT_KEYUSE_EMAIL_PROT   = 8,
	X509_EXT_KEYUSE_TIME_STAMP   = 16,
	X509_EXT_KEYUSE_OCSP_SIGN    = 32,
	X509_EXT_KEYUSE_ANY          = 63
} x509_ext_keyuse_t;

struct x509_cert {
	x509_version_t version;
	x509_algorithm_t algorithm;
	asn1_token_t certificate;
	asn1_token_t issuer;
	asn1_token_t subject;
	asn1_time_t valid_from;
	asn1_time_t valid_to;
	uint16_t key_usage;
	uint8_t ext_key_usage;
	bool is_ca;
	int8_t path_len_constraint;
};

ASININE_API asinine_err_t x509_parse(
    x509_cert_t *cert, const uint8_t *data, size_t num);

#ifdef __cplusplus
}
#endif
