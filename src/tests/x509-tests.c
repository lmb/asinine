/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "asinine/x509.h"

#include "asinine/test.h"
#include "asinine/tests/certs.h"
#include "asinine/tests/x509.h"

static char *
test_x509_certs(void) {
	x509_cert_t cert;
	size_t i;
	bool errors;

	for (errors = false, i = 0; i < x509_certs_num; i++) {
		const char *const host    = x509_certs[i].host;
		const uint8_t *const data = x509_certs[i].data;
		const size_t length       = x509_certs[i].length;

		asinine_err_t result = x509_parse(&cert, data, length);

		if (result != ASININE_OK) {
			const char *error = asinine_err_to_string(result);

			printf("> %s (#%lu): %s\n", host, i, error);
			errors = true;
		}
	}

	return (!errors) ? 0 : "Some certificates failed to parse";
}

int
test_x509_all(int *tests_run) {
	declare_set;

	printf("sizeof x509_cert_t: %lu\n", sizeof(x509_cert_t));

	run_test(test_x509_certs);

	end_set;
}
