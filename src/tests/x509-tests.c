/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>
#include <stdlib.h>

#include "asinine/x509.h"

#include "tests/certs.h"
#include "tests/test.h"
#include "tests/x509.h"

static char *
test_x509_certs(void) {
	x509_cert_t *cert = calloc(1, sizeof(x509_cert_t));
	assert(cert != NULL);

	bool errors = false;
	for (size_t i = 0; i < x509_certs_num; i++) {
		const char *const host    = x509_certs[i].host;
		const uint8_t *const data = x509_certs[i].data;
		const size_t length       = x509_certs[i].length;
		asn1_parser_t parser;

		asn1_init(&parser, data, length);
		asinine_err_t result = x509_parse(&parser, cert);

		if (result != ASININE_OK) {
			const char *error = asinine_strerror(result);

			printf("> %s (#%zu): %s\n", host, i, error);
			errors = true;
		}

		if (!asn1_end(&parser)) {
			printf("> %s (#%zu): did not consume input\n", host, i);
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
					OID(0x29, 0x02, 0x04),
					STR('Z','a','p','h','o','d')
				)
			),
			SET(
				SEQ(
					OID(0x88, 0x37, 0x01),
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
	check(asn1_oid_eq(&a.rdns[0].oid, ASN1_CONST_OID(1, 1, 2, 4)));
	check(asn1_oid_eq(&a.rdns[1].oid, ASN1_CONST_OID(2, 999, 1)));

	check(x509_name_eq(&a, &a, NULL));

	x509_name_t b = {
	    .num = 1,
	    .rdns =
	        {
	            {
	                .oid   = ASN1_OID(1, 1, 2, 4),
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
	                .oid   = ASN1_OID(1, 2, 3),
	                .value = STR_TOKEN(ASN1_TAG_UTF8STRING, "Warudo"),
	            },
	            {
	                .oid   = ASN1_OID(1, 2, 4),
	                .value = STR_TOKEN(ASN1_TAG_UTF8STRING, "!!!"),
	            },
	            {
	                .oid   = ASN1_OID(1, 2),
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
