/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>
#include <stdlib.h>

#include "asinine/x509.h"
#include "internal/macros.h"
#include "internal/utils.h"
#include "tests/test.h"
#include "tests/x509.h"

static const char *certs[] = {
    "testdata/server-ecdsa-v1.der", "testdata/server-ecdsa.der",
};

static char *
test_x509_certs(void) {
	bool errors = false;
	for (size_t i = 0; i < NUM(certs); i++) {
		size_t length;
		const uint8_t *data = load(certs[i], &length);
		assert(data != NULL);

		asn1_parser_t parser;
		asn1_init(&parser, data, length);

		x509_cert_t cert;
		asinine_err_t err = x509_parse_cert(&parser, &cert);
		if (err.errno != ASININE_OK) {
			printf(
			    "> %s: %s: %s\n", certs[i], asinine_strerror(err), err.reason);
			errors = true;
		}

		if (!errors && !asn1_end(&parser)) {
			printf("> %s: did not consume input\n", certs[i]);
			errors = true;
		}
	}

	return (!errors) ? 0 : "Some certificates failed to parse";
}

static char *
test_x509_parse_name() {
	// clang-format off
	const uint8_t a_raw[] = {
		SEQ(
			SET(
				SEQ(
					OID(0x55, 0x04, 0x06),
					STR('Z','a','p','h','o','d')
				)
			),
			SET(
				SEQ(
					OID(0x55, 0x04, 0x03),
					STR('B','e','e','b','l','e','b','r','o','x')
				)
			)
		),
	};
	// clang-format on

	asn1_parser_t parser;
	asn1_init(&parser, a_raw, sizeof(a_raw));

	x509_name_t a;
	check_OK(x509_parse_name(&parser, &a));

	check(a.num == 2);
	check(a.rdns[0].type == X509_RDN_COUNTRY);
	check(a.rdns[1].type == X509_RDN_COMMON_NAME);

	check(x509_name_eq(&a, &a, NULL));

	x509_name_t b = {
	    .num = 1,
	    .rdns =
	        {
	            {
	                .type  = X509_RDN_COUNTRY,
	                .value = STR_TOKEN(ASN1_TAG_UTF8STRING, "Slartibartfass"),
	            },
	        },
	};
	check(!x509_name_eq(&a, &b, NULL));

	return 0;
}

static char *
test_x509_sort_name() {
	x509_name_t name = {
	    .num = 3,
	    .rdns =
	        {
	            {
	                .type  = X509_RDN_ORGANIZATION,
	                .value = STR_TOKEN(ASN1_TAG_UTF8STRING, "Warudo"),
	            },
	            {
	                .type  = X509_RDN_COMMON_NAME,
	                .value = STR_TOKEN(ASN1_TAG_UTF8STRING, "!!!"),
	            },
	            {
	                .type  = X509_RDN_COUNTRY,
	                .value = STR_TOKEN(ASN1_TAG_UTF8STRING, "Za"),
	            },
	        },
	};

	x509_sort_name(&name);

	check(strncmp((char *)name.rdns[0].value.data, "Za", 2) == 0);
	check(strncmp((char *)name.rdns[1].value.data, "Warudo", 6) == 0);
	check(strncmp((char *)name.rdns[2].value.data, "!!!", 3) == 0);

	return 0;
}

int
test_x509_all(int *tests_run) {
	declare_set;

	printf("sizeof x509_rdn_t: %zu\n", sizeof(x509_rdn_t));
	printf("sizeof x509_name_t: %zu\n", sizeof(x509_name_t));
	printf("sizeof x509_cert_t: %zu\n", sizeof(x509_cert_t));

	run_test(test_x509_certs);
	run_test(test_x509_parse_name);
	run_test(test_x509_sort_name);

	end_set;
}
