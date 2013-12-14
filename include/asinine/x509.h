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

typedef enum x509_version {
	X509_V1 = 0,
	X509_V2 = 1,
	X509_V3 = 2
} x509_version_t;

typedef enum x509_algorithm {
	X509_ALGORITHM_INVALID = 0,
	X509_ALGORITHM_SHA1_RSA,
} x509_algorithm_t;

struct x509_cert {
	x509_version_t version;
	x509_algorithm_t algorithm;
	asn1_token_t issuer;
	asn1_token_t subject;
	asn1_time_t valid_from;
	asn1_time_t valid_to;
};

asinine_err_t x509_parse(x509_cert_t *cert, const uint8_t *data, size_t num);

#ifdef __cplusplus
}
#endif

#endif /* __ASININE_X509_H__ */
