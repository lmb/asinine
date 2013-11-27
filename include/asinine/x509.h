/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __ASININE_X509_H__
#define __ASININE_X509_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "asinine/asn1.h"

typedef struct x509_parser x509_parser_t;
typedef struct x509_cert x509_cert_t;

typedef enum x509_err {
	X509_OK = 0,
	X509_ERROR_INVALID = -1,
	X509_ERROR_UNSUPPORTED = -2
} x509_err_t;

typedef enum x509_version {
	X509_V1 = 0,
	X509_V2 = 1,
	X509_V3 = 2
} x509_version_t;

typedef enum x509_algorithm {
	X509_ALGORITHM_INVALID = 0,
	X509_ALGORITHM_SHA1_RSA,
} x509_algorithm_t;

typedef struct {
	asn1_token_t common_name;
	asn1_token_t country_name;
	asn1_token_t organization;
	asn1_token_t organization_unit;
} x509_name_t;

struct x509_cert {
	x509_version_t version;
	x509_algorithm_t algorithm;
	x509_name_t issuer;
	asn1_time_t valid_from;
	asn1_time_t valid_to;
	x509_name_t subject;
};

void x509_init(x509_parser_t *parser, const uint8_t *data);
void x509_cert_init(x509_cert_t *cert);

x509_err_t x509_parse(x509_cert_t *cert, const uint8_t *data, size_t num);
x509_err_t x509_validate(const x509_cert_t *cert);

#ifdef __cplusplus
}
#endif

#endif /* __ASININE_X509_H__ */
