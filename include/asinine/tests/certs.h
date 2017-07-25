/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __ASININE_TESTS_CERTS_H__
#define __ASININE_TESTS_CERTS_H__

#include <stddef.h>
#include <stdint.h>

typedef struct {
	const char *host;
	const uint8_t *data;
	const size_t length;
} test_cert_t;

extern const test_cert_t x509_certs[];
extern const size_t x509_certs_num;

#endif /* __ASININE_TESTS_CERTS_H__ */
